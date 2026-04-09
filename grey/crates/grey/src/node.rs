//! JAM validator node service.
//!
//! Runs the main validator loop:
//! 1. Monitor timeslots (6-second intervals)
//! 2. Author blocks when this validator is the slot leader
//! 3. Import blocks received from peers
//! 4. Track finalization
//! 5. Propagate blocks via the network
//! 6. Process work packages and generate guarantees/assurances

use crate::audit::{self, AuditState};
use crate::finality::{self, GrandpaState};
use crate::guarantor::{self, GuarantorState};
use crate::tickets::{self, TicketState};

use grey_consensus::authoring;

use grey_network::service::{
    COMMAND_CHANNEL_CAPACITY, EVENT_CHANNEL_CAPACITY, NetworkCommand, NetworkConfig, NetworkEvent,
};
use grey_store::Store;
use grey_types::config::Config;
use grey_types::header::{Assurance, Block};
use grey_types::state::State;
use grey_types::{BandersnatchPublicKey, Hash, Timeslot};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Maximum number of out-of-order blocks to buffer. Prevents memory
/// exhaustion from peers sending blocks far ahead of our current state.
const MAX_PENDING_BLOCKS: usize = 100;

/// Encode a finality vote message and broadcast it to the network.
fn broadcast_vote(
    net_commands: &tokio::sync::mpsc::Sender<NetworkCommand>,
    msg: &finality::VoteMessage,
) {
    let data = finality::encode_vote_message(msg);
    let _ = net_commands.try_send(NetworkCommand::BroadcastFinalityVote { data });
}

/// Node configuration.
pub struct NodeConfig {
    /// Validator index in the genesis set.
    pub validator_index: u16,
    /// Network listen address (e.g. "127.0.0.1" or "0.0.0.0").
    pub listen_addr: String,
    /// Network listen port.
    pub listen_port: u16,
    /// Boot peer addresses.
    pub boot_peers: Vec<String>,
    /// Protocol configuration.
    pub protocol_config: Config,
    /// Base timeslot offset (Unix seconds at timeslot 0).
    /// For test networks, we use the current time.
    pub genesis_time: u64,
    /// Database path for persistent storage.
    pub db_path: String,
    /// JSON-RPC server port (0 to disable).
    pub rpc_port: u16,
    /// Enable CORS on the RPC server.
    pub rpc_cors: bool,
    /// RPC listen address (e.g. "127.0.0.1" or "0.0.0.0").
    pub rpc_host: String,
    /// Maximum RPC requests per IP per minute (0 = unlimited).
    pub rpc_rate_limit: u64,
    /// Optional pre-configured genesis state (with services installed, etc.).
    /// If None, the default genesis from create_genesis is used.
    pub genesis_state: Option<State>,
    /// Number of blocks to keep after finalization (0 = archive mode, no pruning).
    pub pruning_depth: u32,
    /// Optional keystore path for persistent validator keys.
    pub keystore_path: Option<String>,
    /// Expose Prometheus metrics on a separate port (0 = disabled).
    pub metrics_port: u16,
    /// Path to the TOML config file (for SIGHUP reload). None if no config file.
    pub config_path: Option<String>,
}

// FinalityTracker replaced by GrandpaState (see finality.rs)

/// Persist a block to the store and send a WebSocket notification.
fn persist_and_notify_block(
    store: &Store,
    block: &Block,
    hash: &Hash,
    slot: Timeslot,
    state: &State,
    protocol: &grey_types::config::Config,
    rpc_state: &Option<std::sync::Arc<grey_rpc::RpcState>>,
) {
    if let Err(e) = store.put_block(block) {
        tracing::error!("Failed to persist block: {}", e);
    }
    if let Err(e) = store.put_state(hash, state, protocol) {
        tracing::error!("Failed to persist state: {}", e);
    }
    if let Err(e) = store.set_head(hash, slot) {
        tracing::error!("Failed to update head: {}", e);
    }
    if let Some(rpc_st) = rpc_state {
        let _ = rpc_st.block_notifications.send(serde_json::json!({
            "hash": hex::encode(hash.0),
            "slot": slot,
            "author_index": block.header.author_index,
            "parent_hash": hex::encode(block.header.parent_hash.0),
            "guarantees": block.extrinsic.guarantees.len(),
            "assurances": block.extrinsic.assurances.len(),
        }));
    }
}

/// Run the validator node.
pub async fn run_node(config: NodeConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let protocol = &config.protocol_config;

    // Open persistent store
    let db_path = format!("{}/node-{}.redb", config.db_path, config.validator_index);
    std::fs::create_dir_all(&config.db_path)?;
    let store_raw = Store::open(&db_path)?;
    tracing::info!("Opened database at {}", db_path);

    // Create genesis state and validator secrets
    let (default_genesis, all_secrets) = grey_consensus::genesis::create_genesis(protocol);
    let genesis_state = config.genesis_state.unwrap_or(default_genesis);

    tracing::info!(
        "Validator {} starting with V={}, C={}, E={}",
        config.validator_index,
        protocol.validators_count,
        protocol.core_count,
        protocol.epoch_length
    );

    // Get our validator's secrets
    let my_secrets = &all_secrets[config.validator_index as usize];
    let my_bandersnatch = BandersnatchPublicKey(my_secrets.bandersnatch.public_key_bytes());

    // Save keys to keystore if configured (first-time initialization)
    if let Some(ref ks_path) = config.keystore_path {
        let ks =
            crate::keystore::Keystore::open(ks_path).map_err(|e| format!("keystore error: {e}"))?;
        if !ks.has_keys(config.validator_index) {
            // Derive seeds for persistence (same deterministic derivation as genesis)
            let mut ed_seed = [0u8; 32];
            ed_seed[0] = config.validator_index as u8;
            ed_seed[1] = (config.validator_index >> 8) as u8;
            ed_seed[31] = 0xED;
            let mut band_seed = [0u8; 32];
            band_seed[0] = config.validator_index as u8;
            band_seed[1] = (config.validator_index >> 8) as u8;
            band_seed[31] = 0xBA;
            let mut bls_seed = [0u8; 32];
            bls_seed[0] = config.validator_index as u8;
            bls_seed[1] = (config.validator_index >> 8) as u8;
            bls_seed[31] = 0xBB;
            let ed_public = my_secrets.ed25519.public_key().0;
            ks.save_seeds(
                config.validator_index,
                &ed_seed,
                &band_seed,
                &bls_seed,
                &ed_public,
            )
            .map_err(|e| format!("keystore save error: {e}"))?;
        } else {
            tracing::info!(
                "Loaded keys for validator {} from keystore at {}",
                config.validator_index,
                ks_path
            );
        }
    }

    tracing::info!(
        "Validator {} bandersnatch key: 0x{}",
        config.validator_index,
        hex::encode(my_bandersnatch.0)
    );

    // Start the network
    let boot_peers: Vec<libp2p::Multiaddr> = config
        .boot_peers
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    let (mut net_events, net_commands, net_event_monitor) =
        grey_network::service::start_network(NetworkConfig {
            listen_addr: config.listen_addr.clone(),
            listen_port: config.listen_port,
            boot_peers,
            validator_index: config.validator_index,
        })
        .await?;

    // Start RPC server
    let store = std::sync::Arc::new(store_raw);
    let mut rpc_rx = None;
    let rpc_state;
    if config.rpc_port > 0 {
        let (state_arc, rx) = grey_rpc::create_rpc_channel(
            store.clone(),
            config.protocol_config.clone(),
            config.validator_index,
        );
        rpc_state = Some(state_arc.clone());
        let metrics_state = state_arc.clone();
        let (_addr, _handle) = grey_rpc::start_rpc_server(
            &config.rpc_host,
            config.rpc_port,
            state_arc,
            config.rpc_cors,
            config.rpc_rate_limit,
        )
        .await?;
        rpc_rx = Some(rx);

        // Start separate metrics server if configured
        if config.metrics_port > 0 {
            let (_metrics_addr, _metrics_handle) = grey_rpc::start_metrics_server(
                &config.rpc_host,
                config.metrics_port,
                metrics_state,
            )
            .await?;
        }
    } else {
        rpc_state = None;
    }

    // Initialize state
    let mut state = genesis_state;
    let mut grandpa = GrandpaState::new(protocol.validators_count);

    // Load persisted GRANDPA votes from previous session (if any).
    match store.get_latest_grandpa_round() {
        Ok(round) if round > 0 => match store.get_grandpa_votes_for_round(round) {
            Ok(votes) if !votes.is_empty() => {
                let loaded = grandpa.load_persisted_votes(round, &votes);
                tracing::info!(
                    "Loaded {} persisted GRANDPA votes for round {}",
                    loaded,
                    round
                );
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("Failed to load GRANDPA votes: {}", e),
        },
        Ok(_) => {} // No persisted votes
        Err(e) => tracing::warn!("Failed to read GRANDPA round: {}", e),
    }

    let mut blocks_authored = 0u64;
    let mut blocks_imported = 0u64;
    let genesis_time = config.genesis_time;

    // Guarantor state: pending guarantees and availability tracking
    let mut guarantor_state = GuarantorState::new();
    // Collected assurances from peers for block inclusion
    let mut collected_assurances: Vec<Assurance> = Vec::new();
    // Audit state: tranche-based audit of guaranteed work reports
    let mut audit_state = AuditState::new();
    // Ticket state: Safrole ticket generation and collection
    let mut ticket_state = TicketState::new();
    // Track last slot where we submitted a work package (for pacing)
    let mut last_wp_slot: Timeslot = 0;
    // Buffer for blocks received out of order (keyed by timeslot).
    // When we receive a block at slot X but our state is at slot < X-1,
    // we may be missing intermediate blocks. Buffer the block and try
    // to apply it after the missing ones arrive.
    let mut pending_blocks: std::collections::BTreeMap<Timeslot, (Block, Hash)> =
        std::collections::BTreeMap::new();
    let mut saturation_tracker = SaturationTracker::new();
    // Recently-seen block hashes: skip re-processing blocks we already validated.
    // Bounded to avoid unbounded growth; old entries are evicted when full.
    let mut seen_block_hashes: std::collections::HashSet<Hash> =
        std::collections::HashSet::with_capacity(256);
    // Recently-seen work report hashes: skip re-processing guarantees for
    // work reports we already handled. Bounded to 256 entries.
    let mut seen_report_hashes: std::collections::HashSet<Hash> =
        std::collections::HashSet::with_capacity(256);

    tracing::info!(
        "Validator {} node started, genesis_time={}",
        config.validator_index,
        genesis_time
    );

    // Graceful shutdown on SIGINT (Ctrl+C) or SIGTERM (kill)
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to register SIGTERM handler");
    let shutdown = async {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => "SIGINT",
            _ = sigterm.recv() => "SIGTERM",
        }
    };
    tokio::pin!(shutdown);

    // SIGUSR1: dump debug state to log
    let mut sigusr1 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
        .expect("failed to register SIGUSR1 handler");

    // SIGHUP: reload config file
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .expect("failed to register SIGHUP handler");
    let config_path = config.config_path.clone();

    // Main loop: check timeslots every 500ms
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    let mut last_authored_slot: Timeslot = 0;
    let mut last_assurance_slot: Timeslot = 0;
    let mut monitor_tick: u64 = 0;

    loop {
        tokio::select! {
            signal_name = &mut shutdown => {
                tracing::info!(
                    "Validator {} received {}, flushing state...",
                    config.validator_index,
                    signal_name
                );
                // Persist final head state
                let head_hash = state
                    .recent_blocks
                    .headers
                    .last()
                    .map(|h| h.header_hash)
                    .unwrap_or(Hash::ZERO);
                let _ = store.set_head(&head_hash, state.timeslot);
                tracing::info!(
                    "Validator {} shutdown complete. Authored={}, Imported={}, Finalized=slot {}",
                    config.validator_index,
                    blocks_authored,
                    blocks_imported,
                    grandpa.finalized_slot
                );
                break;
            }
            // SIGUSR1: dump debug state snapshot to log
            _ = sigusr1.recv() => {
                let head_hash = state
                    .recent_blocks
                    .headers
                    .last()
                    .map(|h| hex::encode(&h.header_hash.0[..8]))
                    .unwrap_or_else(|| "none".into());
                tracing::info!(
                    "=== SIGUSR1 debug dump (validator {}) ===\n\
                     State: slot={}, head=0x{}, services={}\n\
                     Finality: round={}, finalized_slot={}, prevotes={}, precommits={}\n\
                     Guarantor: pending_guarantees={}, available_cores={}, received_chunks={}\n\
                     Assurances: collected={}\n\
                     Pending blocks: {}\n\
                     Counters: authored={}, imported={}",
                    config.validator_index,
                    state.timeslot,
                    head_hash,
                    state.services.len(),
                    grandpa.round,
                    grandpa.finalized_slot,
                    grandpa.prevotes.len(),
                    grandpa.precommits.len(),
                    guarantor_state.pending_guarantees.len(),
                    guarantor_state.available_cores.len(),
                    guarantor_state.received_chunks.len(),
                    collected_assurances.len(),
                    pending_blocks.len(),
                    blocks_authored,
                    blocks_imported,
                );
            }
            _ = sighup.recv() => {
                if let Some(ref path) = config_path {
                    tracing::info!("SIGHUP received — reloading config from {}", path);
                    match crate::config::ConfigFile::load(std::path::Path::new(path)) {
                        Ok(new_cfg) => {
                            if let Some(ref level) = new_cfg.logging.level {
                                tracing::info!("Config reload: log level = {:?}", level);
                            }
                            if let Some(ref peers) = new_cfg.network.boot_peers {
                                tracing::info!("Config reload: boot_peers = {:?} ({} entries)", peers, peers.len());
                            }
                            if let Some(ref format) = new_cfg.logging.format {
                                tracing::info!("Config reload: log format = {:?}", format);
                            }
                            tracing::info!("Config reload complete (note: only logging changes are informational; runtime values are not yet hot-swapped)");
                        }
                        Err(e) => {
                            tracing::warn!("SIGHUP config reload failed: {}", e);
                        }
                    }
                } else {
                    tracing::info!("SIGHUP received but no config file was specified (--config)");
                }
            }
            _ = interval.tick() => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                // slot = (now - genesis_time) / slot_period
                let current_slot = ((now - genesis_time) / 6) as Timeslot + 1; // +1 because genesis is slot 0

                // Queue depth monitoring: check every 12 ticks (~6 seconds, once per slot).
                monitor_tick += 1;
                if monitor_tick.is_multiple_of(12) {
                    check_queue_depths(
                        config.validator_index,
                        &net_event_monitor,
                        &net_commands,
                        rpc_state.as_ref(),
                        pending_blocks.len(),
                        &mut saturation_tracker,
                    );
                }

                // Only attempt authoring if this is a new slot we haven't authored yet
                if current_slot > state.timeslot && current_slot > last_authored_slot {
                    // Generate our own assurance once at the START of the slot.
                    // Broadcast it immediately so other validators receive it before authoring.
                    if current_slot > last_assurance_slot {
                        last_assurance_slot = current_slot;
                        let parent_hash = state
                            .recent_blocks
                            .headers
                            .last()
                            .map(|h| h.header_hash)
                            .unwrap_or(Hash::ZERO);

                        if let Some(my_assurance) = guarantor_state.generate_assurance(
                            protocol,
                            &parent_hash,
                            config.validator_index,
                            my_secrets,
                            &state,
                        ) {
                            tracing::info!(
                                "Validator {} generated assurance for {} cores",
                                config.validator_index,
                                my_assurance.bitfield.iter().map(|b| b.count_ones()).sum::<u32>()
                            );
                            let assurance_data = guarantor::encode_assurance(&my_assurance);
                            let _ = net_commands.try_send(NetworkCommand::BroadcastAssurance {
                                data: assurance_data,
                            });
                            collected_assurances.push(my_assurance);
                        }
                    }

                    // Delay block authoring by 2 seconds into the slot to allow
                    // assurances from other validators to arrive via gossip.
                    // Without this delay, the author only has its own assurance,
                    // which is insufficient for super-majority (need 4 of 6).
                    let slot_start_time = genesis_time + (current_slot as u64 - 1) * 6;
                    let time_into_slot = now - slot_start_time;
                    if time_into_slot < 2 {
                        continue; // Wait for next tick (500ms later)
                    }

                    // Generate and broadcast tickets if in submission window
                    ticket_state.check_epoch(current_slot, protocol);
                    if tickets::is_ticket_submission_window(current_slot, protocol) {
                        let new_tickets = ticket_state.generate_tickets(
                            protocol,
                            &state,
                            my_secrets,
                            config.validator_index,
                        );
                        for ticket in &new_tickets {
                            let ticket_data = tickets::encode_ticket_proof(ticket);
                            let _ = net_commands.try_send(NetworkCommand::BroadcastTicket {
                                data: ticket_data,
                            });
                        }
                        if !new_tickets.is_empty() {
                            tracing::info!(
                                "Validator {} generated {} ticket proofs",
                                config.validator_index,
                                new_tickets.len()
                            );
                        }
                    }

                    // Validator 0: generate work packages if service 1000 is installed
                    if config.validator_index == 0
                        && state.services.contains_key(&1000)
                        && current_slot >= 3
                        && current_slot > last_wp_slot + 2
                        && guarantor_state.pending_guarantees.is_empty()
                    {
                        let service_id: u32 = 1000;
                        if let Some(svc) = state.services.get(&service_id) {
                            let code_hash = svc.code_hash;
                            let payload = format!("wp-slot-{}", current_slot).into_bytes();
                            let pkg = create_demo_work_package(
                                &state,
                                service_id,
                                code_hash,
                                &payload,
                                current_slot,
                            );
                            match guarantor::process_work_package(
                                protocol,
                                &pkg,
                                &state,
                                &store,
                                config.validator_index,
                                my_secrets,
                                current_slot,
                                &mut guarantor_state,
                            ) {
                                Ok(report_hash) => {
                                    // Add a second guarantor co-signature (minimum 2 required)
                                    crate::guarantor::cosign_last_guarantee(
                                        &mut guarantor_state,
                                        &report_hash,
                                        config.validator_index,
                                        &all_secrets,
                                    );

                                    tracing::info!(
                                        "Validator {} created WP guarantee (2 signers), report_hash=0x{}",
                                        config.validator_index,
                                        hex::encode(&report_hash.0[..8])
                                    );
                                    // Broadcast only the new guarantee to peers
                                    if let Some(g) = guarantor_state.pending_guarantees.last() {
                                        let g_data = guarantor::encode_guarantee(g);
                                        let _ = net_commands.try_send(NetworkCommand::BroadcastGuarantee {
                                            data: g_data,
                                        });
                                    }
                                    last_wp_slot = current_slot;
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "Validator {} WP processing failed: {}",
                                        config.validator_index,
                                        e
                                    );
                                }
                            }
                        }
                    }

                    // Check if we are the slot author
                    if let Some(author_idx) = authoring::is_slot_author_with_keypair(
                        &state,
                        protocol,
                        current_slot,
                        &my_bandersnatch,
                        Some(&my_secrets.bandersnatch),
                    ) {
                        tracing::info!(
                            "=== Validator {} IS SLOT AUTHOR for slot {} ===",
                            config.validator_index,
                            current_slot
                        );

                        // Collect guarantees and assurances for this block
                        let all_guarantees = guarantor_state.take_guarantees();
                        let all_assurances = std::mem::take(&mut collected_assurances);

                        // Filter assurances: only include those whose anchor matches
                        // the current parent hash. Assurances with stale anchors would
                        // cause BadAttestationParent during state transition.
                        let block_parent = state
                            .recent_blocks
                            .headers
                            .last()
                            .map(|h| h.header_hash)
                            .unwrap_or(Hash::ZERO);
                        let mut assurances = Vec::new();
                        for a in all_assurances {
                            if a.anchor == block_parent {
                                assurances.push(a);
                            } else {
                                // Return stale assurances — they're useless now
                                tracing::debug!(
                                    "Dropping stale assurance from validator {} (anchor mismatch)",
                                    a.validator_index,
                                );
                            }
                        }

                        // Deduplicate assurances by validator index (keep first occurrence)
                        {
                            let mut seen = std::collections::HashSet::new();
                            assurances.retain(|a| seen.insert(a.validator_index));
                        }

                        // Sort assurances by validator index (required by state transition)
                        assurances.sort_by_key(|a| a.validator_index);

                        // Prune stale guarantees whose anchor is no longer in recent_blocks
                        let recent_hashes: std::collections::HashSet<_> = state
                            .recent_blocks
                            .headers
                            .iter()
                            .map(|h| h.header_hash)
                            .collect();
                        let all_guarantees: Vec<_> = all_guarantees
                            .into_iter()
                            .filter(|g| {
                                let fresh = recent_hashes.contains(&g.report.context.anchor);
                                if !fresh {
                                    tracing::warn!(
                                        "Pruning stale guarantee: anchor=0x{} not in recent blocks",
                                        hex::encode(&g.report.context.anchor.0[..8])
                                    );
                                }
                                fresh
                            })
                            .collect();

                        // Predict which cores will be cleared by the included assurances.
                        // The transition processes assurances BEFORE guarantees, so a core
                        // that reaches super-majority assurance count will be free for a
                        // new guarantee in the same block.
                        let num_cores = state.pending_reports.len();
                        let threshold = config.protocol_config.super_majority() as u32;
                        let mut assurance_counts = vec![0u32; num_cores];
                        for a in &assurances {
                            for (core, count) in assurance_counts.iter_mut().enumerate() {
                                let byte_idx = core / 8;
                                let bit_idx = core % 8;
                                if byte_idx < a.bitfield.len()
                                    && (a.bitfield[byte_idx] >> bit_idx) & 1 == 1
                                {
                                    *count += 1;
                                }
                            }
                        }
                        let mut cores_will_clear = std::collections::HashSet::new();
                        for (core, &count) in assurance_counts.iter().enumerate() {
                            if count >= threshold && state.pending_reports[core].is_some() {
                                cores_will_clear.insert(core);
                            }
                        }

                        // Also check for availability timeout: cores that have timed out
                        // will be cleared even without assurances.
                        for (core, slot) in state.pending_reports.iter().enumerate() {
                            if let Some(pending) = slot
                                && current_slot >= pending.timeslot + config.protocol_config.availability_timeout {
                                    cores_will_clear.insert(core);
                                }
                        }

                        // Filter out guarantees for cores that are occupied AND won't be
                        // cleared by the assurances in this block.
                        let mut guarantees = Vec::new();
                        let mut deferred_guarantees = Vec::new();
                        let mut included_cores = std::collections::HashSet::new();
                        for g in all_guarantees {
                            let core = g.report.core_index as usize;
                            let core_occupied = core < state.pending_reports.len()
                                && state.pending_reports[core].is_some()
                                && !cores_will_clear.contains(&core);
                            let core_duplicate = !included_cores.insert(g.report.core_index);
                            if core_occupied || core_duplicate {
                                deferred_guarantees.push(g);
                            } else {
                                guarantees.push(g);
                            }
                        }
                        // Return deferred guarantees for later inclusion
                        for g in deferred_guarantees {
                            guarantor_state.return_guarantee(g);
                        }

                        if !guarantees.is_empty() {
                            tracing::info!(
                                "Including {} guarantees in block",
                                guarantees.len()
                            );
                        }
                        if !assurances.is_empty() {
                            tracing::info!(
                                "Including {} assurances in block",
                                assurances.len()
                            );
                        }

                        // Compute state root (simplified: hash of timeslot for now)
                        let state_root = compute_state_root(&state);

                        // Collect tickets for block inclusion
                        let block_tickets = ticket_state.take_tickets_for_block(protocol);
                        if !block_tickets.is_empty() {
                            tracing::info!(
                                "Including {} tickets in block",
                                block_tickets.len()
                            );
                        }

                        // Author block with guarantees, assurances, and tickets
                        let block = authoring::author_block_with_extrinsics(
                            &state,
                            protocol,
                            current_slot,
                            author_idx,
                            my_secrets,
                            state_root,
                            guarantees,
                            assurances,
                            block_tickets,
                        );

                        // Apply block to our state
                        match grey_state::transition::apply_with_config(
                            &state,
                            &block,
                            protocol,
                            &[],
                        ) {
                            Ok((new_state, _)) => {
                                let header_hash = grey_crypto::blake2b_256(&scale::Encode::encode(&block.header));
                                // Capture pre-transition seal mode: the block was sealed under
                                // the current epoch's key series, not the post-transition one.
                                let ticket_sealed = grey_consensus::safrole::is_ticket_sealed(
                                    &state.safrole.seal_key_series,
                                );
                                state = new_state;
                                blocks_authored += 1;
                                last_authored_slot = current_slot;
                                seen_block_hashes.insert(header_hash);

                                persist_and_notify_block(
                                    &store, &block, &header_hash, current_slot,
                                    &state, protocol, &rpc_state,
                                );

                                tracing::info!(
                                    "Validator {} authored block #{} at slot {}, hash=0x{}",
                                    config.validator_index,
                                    blocks_authored,
                                    current_slot,
                                    hex::encode(&header_hash.0[..8])
                                );

                                // Register guarantees from this block for auditing
                                // and mark cores as available for assurance generation
                                for guarantee in &block.extrinsic.guarantees {
                                    let report_hash = grey_crypto::blake2b_256(
                                        &scale::Encode::encode(&block.header),
                                    );
                                    let our_tranche = audit::compute_audit_tranche(
                                        &state.entropy[0],
                                        &report_hash,
                                        config.validator_index,
                                        30,
                                    );
                                    audit_state.add_pending(
                                        report_hash,
                                        guarantee.report.clone(),
                                        guarantee.report.core_index,
                                        current_slot,
                                        Some(our_tranche),
                                    );
                                    // Mark core as available so we generate assurances
                                    guarantor_state.available_cores.insert(
                                        guarantee.report.core_index,
                                        report_hash,
                                    );
                                }

                                // Broadcast block
                                let block_data = encode_block_message(&block, &header_hash);
                                let _ = net_commands.try_send(NetworkCommand::BroadcastBlock {
                                    data: block_data,
                                });

                                // Register block in ancestry map and update best block
                                let authored_report_hashes: Vec<grey_types::Hash> = block
                                    .extrinsic
                                    .guarantees
                                    .iter()
                                    .map(|g| grey_crypto::blake2b_256(&scale::Encode::encode(&g.report)))
                                    .collect();
                                grandpa.register_block(
                                    header_hash,
                                    block.header.parent_hash,
                                    block.header.timeslot,
                                    ticket_sealed,
                                    authored_report_hashes,
                                );
                                grandpa.update_best_block(header_hash, &audit_state.completed_audits);

                                // Send prevote for the new block
                                if let Some(prevote_msg) = grandpa.create_prevote(
                                    config.validator_index,
                                    my_secrets,
                                ) {
                                    broadcast_vote(&net_commands, &prevote_msg);
                                }

                                // Try to precommit if prevote threshold reached
                                if let Some(precommit_msg) = grandpa.create_precommit(
                                    config.validator_index,
                                    my_secrets,
                                ) {
                                    broadcast_vote(&net_commands, &precommit_msg);
                                }
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Validator {} block authoring failed at slot {}: {}",
                                    config.validator_index,
                                    current_slot,
                                    e
                                );
                                // Return assurances so they aren't lost on failed authoring
                                for a in block.extrinsic.assurances {
                                    collected_assurances.push(a);
                                }
                            }
                        }
                    }
                }

                // Process due audits on each tick
                let pending_hashes: Vec<grey_types::Hash> = audit_state
                    .pending_audits
                    .keys()
                    .copied()
                    .collect();
                for report_hash in pending_hashes {
                    if audit_state.completed_audits.contains(&report_hash) {
                        continue;
                    }
                    if let Some(pending) = audit_state.pending_audits.get(&report_hash)
                        && let Some(our_tranche) = pending.our_tranche {
                            let elapsed_secs = (state.timeslot.saturating_sub(pending.report_timeslot)) as u64 * 6;
                            let current_tranche = (elapsed_secs / 8) as u32;
                            if our_tranche <= current_tranche {
                                // Time to audit this report
                                let empty_ctx = grey_state::refine::SimpleRefineContext {
                                    code_blobs: std::collections::BTreeMap::new(),
                                    storage: std::collections::BTreeMap::new(),
                                    preimages: std::collections::BTreeMap::new(),
                                };
                                let is_valid = audit::audit_work_report(
                                    protocol,
                                    &pending.report,
                                    &empty_ctx,
                                );
                                let ann = audit::create_announcement(
                                    &report_hash,
                                    is_valid,
                                    config.validator_index,
                                    my_secrets,
                                );
                                tracing::info!(
                                    "Validator {} audited report 0x{}: {}",
                                    config.validator_index,
                                    hex::encode(&report_hash.0[..8]),
                                    if is_valid { "VALID" } else { "INVALID" }
                                );
                                let ann_data = audit::encode_announcement(&ann);
                                let _ = net_commands.try_send(NetworkCommand::BroadcastAnnouncement {
                                    data: ann_data,
                                });
                                audit_state.add_announcement(ann);
                                audit_state.mark_completed(&report_hash);
                            }
                        }
                }

                // Prune old audits (older than 30 slots)
                if state.timeslot > 30 {
                    audit_state.prune_old_audits(state.timeslot - 30);
                }
            }

            // Handle network events
            event = net_events.recv() => {
                let Some(event) = event else { break };
                match event {
                    NetworkEvent::BlockReceived { data, source } => {
                        match decode_block_message(&data, protocol) {
                            Some((block, _hash)) => {
                                let block_hash = grey_crypto::blake2b_256(&scale::Encode::encode(&block.header));
                                // Skip blocks we've already seen (dedup)
                                if seen_block_hashes.contains(&block_hash) {
                                    tracing::trace!(
                                        "Validator {} skipping duplicate block {}",
                                        config.validator_index,
                                        hex::encode(&block_hash.0[..4])
                                    );
                                } else if block.header.timeslot > state.timeslot {
                                    let slot = block.header.timeslot;
                                    // Buffer this block for ordered import.
                                    // Only keep the first block per slot (no forks).
                                    pending_blocks
                                        .entry(slot)
                                        .or_insert((block, block_hash));

                                    // Evict the furthest-ahead block if buffer is full.
                                    // Keeps blocks closest to current state (most useful).
                                    while pending_blocks.len() > MAX_PENDING_BLOCKS {
                                        if let Some((&evicted_slot, _)) =
                                            pending_blocks.iter().next_back()
                                        {
                                            tracing::warn!(
                                                "Validator {} pending blocks buffer full ({}), \
                                                 evicting slot {}",
                                                config.validator_index,
                                                pending_blocks.len(),
                                                evicted_slot
                                            );
                                            pending_blocks.remove(&evicted_slot);
                                        }
                                    }
                                }
                            }
                            None => {
                                tracing::warn!(
                                    "Validator {} received invalid block data from {}",
                                    config.validator_index,
                                    source
                                );
                            }
                        }

                        // Drain pending blocks in timeslot order.
                        // Apply each block whose slot > current state timeslot.
                        while let Some((&next_slot, _)) = pending_blocks.iter().next() {
                            if next_slot <= state.timeslot {
                                // Already at or past this slot — discard
                                pending_blocks.remove(&next_slot);
                                continue;
                            }
                            let (block, import_hash) = pending_blocks.remove(&next_slot).unwrap();
                            let slot = block.header.timeslot;
                            match grey_state::transition::apply_with_config(
                                &state,
                                &block,
                                protocol,
                                &[],
                            ) {
                                Ok((new_state, _)) => {
                                    // Capture pre-transition seal mode: the block was sealed under
                                    // the current epoch's key series, not the post-transition one.
                                    let ticket_sealed = grey_consensus::safrole::is_ticket_sealed(
                                        &state.safrole.seal_key_series,
                                    );
                                    state = new_state;
                                    blocks_imported += 1;

                                    // Mark block as seen to skip duplicates
                                    if seen_block_hashes.len() >= 256 {
                                        // Evict a random entry to bound memory
                                        if let Some(&old) =
                                            seen_block_hashes.iter().next()
                                        {
                                            seen_block_hashes.remove(&old);
                                        }
                                    }
                                    seen_block_hashes.insert(import_hash);

                                    persist_and_notify_block(
                                        &store, &block, &import_hash, slot,
                                        &state, protocol, &rpc_state,
                                    );

                                    // Register guarantees from imported block for auditing,
                                    // mark cores as available for assurance generation,
                                    // and remove matching guarantees from our pending list
                                    // (prevents zombie guarantees that block future work).
                                    for guarantee in &block.extrinsic.guarantees {
                                        let report_hash = grey_crypto::blake2b_256(
                                            &scale::Encode::encode(&block.header),
                                        );
                                        let our_tranche = audit::compute_audit_tranche(
                                            &state.entropy[0],
                                            &report_hash,
                                            config.validator_index,
                                            30,
                                        );
                                        audit_state.add_pending(
                                            report_hash,
                                            guarantee.report.clone(),
                                            guarantee.report.core_index,
                                            slot,
                                            Some(our_tranche),
                                        );
                                        // Mark core as available so we generate assurances
                                        guarantor_state.available_cores.insert(
                                            guarantee.report.core_index,
                                            report_hash,
                                        );
                                    }

                                    // Clean up pending guarantees that were included in the
                                    // imported block — otherwise they become zombies that
                                    // endlessly defer and block new work package processing.
                                    if !block.extrinsic.guarantees.is_empty() {
                                        use scale::Encode;
                                        let included_hashes: std::collections::HashSet<_> =
                                            block.extrinsic.guarantees.iter().map(|g| {
                                                grey_crypto::blake2b_256(&g.report.encode())
                                            }).collect();
                                        let before = guarantor_state.pending_guarantees.len();
                                        guarantor_state.pending_guarantees.retain(|g| {
                                            let h = grey_crypto::blake2b_256(&g.report.encode());
                                            !included_hashes.contains(&h)
                                        });
                                        let removed = before - guarantor_state.pending_guarantees.len();
                                        if removed > 0 {
                                            tracing::info!(
                                                "Validator {} cleaned up {} zombie guarantee(s) after importing slot {}",
                                                config.validator_index, removed, slot
                                            );
                                        }
                                    }

                                    tracing::info!(
                                        "Validator {} imported block at slot {} (total imported: {})",
                                        config.validator_index,
                                        slot,
                                        blocks_imported
                                    );

                                    // Register block in ancestry map and update best block
                                    let imported_report_hashes: Vec<grey_types::Hash> = block
                                        .extrinsic
                                        .guarantees
                                        .iter()
                                        .map(|g| grey_crypto::blake2b_256(&scale::Encode::encode(&g.report)))
                                        .collect();
                                    grandpa.register_block(
                                        import_hash,
                                        block.header.parent_hash,
                                        block.header.timeslot,
                                        ticket_sealed,
                                        imported_report_hashes,
                                    );
                                    grandpa.update_best_block(import_hash, &audit_state.completed_audits);
                                    if let Some(prevote_msg) = grandpa.create_prevote(
                                        config.validator_index,
                                        my_secrets,
                                    ) {
                                        broadcast_vote(&net_commands, &prevote_msg);
                                    }
                                    if let Some(precommit_msg) = grandpa.create_precommit(
                                        config.validator_index,
                                        my_secrets,
                                    ) {
                                        broadcast_vote(&net_commands, &precommit_msg);
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "Validator {} rejected block at slot {}: {}",
                                        config.validator_index,
                                        slot,
                                        e
                                    );
                                    // Stop draining — later blocks may depend on this one
                                    break;
                                }
                            }
                        }

                        // Prune stale buffered blocks (already behind our state)
                        while let Some((&oldest_slot, _)) = pending_blocks.iter().next() {
                            if oldest_slot <= state.timeslot {
                                pending_blocks.remove(&oldest_slot);
                            } else {
                                break;
                            }
                        }
                    }
                    NetworkEvent::FinalityVote { data, source } => {
                        if let Some(vote_msg) = finality::decode_vote_message(&data) {
                            if finality::verify_vote(&vote_msg.vote, vote_msg.vote_type, &state) {
                                // Persist vote to store for crash recovery
                                let vote_type_byte = match vote_msg.vote_type {
                                    finality::VoteType::Prevote => 0x01,
                                    finality::VoteType::Precommit => 0x02,
                                };
                                let _ = store.put_grandpa_vote(
                                    vote_msg.vote.round,
                                    vote_type_byte,
                                    vote_msg.vote.validator_index,
                                    &vote_msg.vote.block_hash,
                                    vote_msg.vote.block_slot,
                                    &vote_msg.vote.signature.0,
                                );

                                match vote_msg.vote_type {
                                    finality::VoteType::Prevote => {
                                        let threshold_reached = grandpa.add_prevote(vote_msg.vote);
                                        if threshold_reached {
                                            tracing::info!(
                                                "Validator {} prevote threshold reached in round {}",
                                                config.validator_index,
                                                grandpa.round
                                            );
                                            // Try to precommit now that we have prevote supermajority
                                            if let Some(precommit_msg) = grandpa.create_precommit(
                                                config.validator_index,
                                                my_secrets,
                                            ) {
                                                broadcast_vote(&net_commands, &precommit_msg);
                                            }
                                        }
                                    }
                                    finality::VoteType::Precommit => {
                                        if let Some((fin_hash, fin_slot)) = grandpa.add_precommit(vote_msg.vote) {
                                            tracing::info!(
                                                "Validator {} GRANDPA FINALIZED slot {} hash=0x{}",
                                                config.validator_index,
                                                fin_slot,
                                                hex::encode(&fin_hash.0[..8])
                                            );
                                            let _ = store.set_finalized(&fin_hash, fin_slot);

                                            // Push finality notification to WebSocket subscribers
                                            if let Some(ref rpc_st) = rpc_state {
                                                let _ = rpc_st.finality_notifications.send(serde_json::json!({
                                                    "hash": hex::encode(fin_hash.0),
                                                    "slot": fin_slot,
                                                    "round": grandpa.round,
                                                }));
                                            }

                                            // Prune finalized GRANDPA votes
                                            if grandpa.round > 1 {
                                                let _ = store.prune_grandpa_votes(grandpa.round - 1);
                                            }

                                            // Prune old blocks/state if pruning is enabled
                                            if config.pruning_depth > 0 && fin_slot > config.pruning_depth {
                                                let keep_after = fin_slot - config.pruning_depth;
                                                match store.prune_before_slot(keep_after) {
                                                    Ok(0) => {}
                                                    Ok(n) => tracing::debug!(
                                                        "Pruned {} blocks (keeping slots >= {})",
                                                        n, keep_after
                                                    ),
                                                    Err(e) => tracing::warn!("Pruning failed: {}", e),
                                                }
                                            }

                                            // Expire old DA chunks (TTL = 2 * epoch_length)
                                            let chunk_ttl = 2 * protocol.epoch_length;
                                            match store.prune_expired_chunks(fin_slot, chunk_ttl) {
                                                Ok(0) => {}
                                                Ok(n) => tracing::debug!(
                                                    "Expired chunks for {} reports (TTL={})",
                                                    n, chunk_ttl
                                                ),
                                                Err(e) => tracing::warn!("Chunk expiration failed: {}", e),
                                            }

                                            // Advance to next round
                                            if grandpa.should_advance_round() {
                                                grandpa.advance_round();
                                            }
                                        }
                                    }
                                }
                            } else {
                                tracing::warn!(
                                    "Validator {} received invalid finality vote from {}",
                                    config.validator_index,
                                    source
                                );
                            }
                        }
                    }
                    NetworkEvent::AnnouncementReceived { data, source } => {
                        if let Some(ann) = audit::decode_announcement(&data) {
                            if audit::verify_announcement(&ann, &state) {
                                tracing::info!(
                                    "Validator {} received valid audit announcement from {} for report 0x{}: {}",
                                    config.validator_index,
                                    source,
                                    hex::encode(&ann.report_hash.0[..8]),
                                    if ann.is_valid { "VALID" } else { "INVALID" }
                                );
                                audit_state.add_announcement(ann);

                                // Check for escalations
                                let escalations = audit_state.reports_needing_escalation(
                                    protocol.validators_count as usize / 3,
                                );
                                for hash in &escalations {
                                    tracing::warn!(
                                        "Validator {} ESCALATION needed for report 0x{}",
                                        config.validator_index,
                                        hex::encode(&hash.0[..8])
                                    );
                                }
                            } else {
                                tracing::warn!(
                                    "Validator {} received invalid announcement from {}",
                                    config.validator_index,
                                    source
                                );
                            }
                        }
                    }
                    NetworkEvent::GuaranteeReceived { data, source } => {
                        // Extract work report hash (first 32 bytes) for dedup
                        if data.len() >= 32 {
                            let mut rh = [0u8; 32];
                            rh.copy_from_slice(&data[..32]);
                            let report_hash = Hash(rh);
                            if seen_report_hashes.contains(&report_hash) {
                                tracing::trace!(
                                    "Validator {} skipping duplicate work report {}",
                                    config.validator_index,
                                    hex::encode(&rh[..4])
                                );
                                continue;
                            }
                            // Evict oldest if at capacity
                            if seen_report_hashes.len() >= 256
                                && let Some(&old) = seen_report_hashes.iter().next()
                            {
                                seen_report_hashes.remove(&old);
                            }
                            seen_report_hashes.insert(report_hash);
                        }
                        tracing::info!(
                            "Validator {} received guarantee from {}",
                            config.validator_index,
                            source
                        );
                        guarantor::handle_received_guarantee(
                            &data,
                            &mut guarantor_state,
                            &store,
                        );
                    }
                    NetworkEvent::AssuranceReceived { data, source } => {
                        tracing::debug!(
                            "Validator {} received assurance from {}",
                            config.validator_index,
                            source
                        );
                        guarantor::handle_received_assurance(
                            &data,
                            &mut collected_assurances,
                        );
                    }
                    NetworkEvent::ChunkRequest { report_hash, chunk_index, response_tx } => {
                        let hash = grey_types::Hash(report_hash);
                        let chunk = store.get_chunk(&hash, chunk_index).ok();
                        let _ = response_tx.send(chunk);
                    }
                    NetworkEvent::BlockRequest { block_hash, response_tx } => {
                        let hash = grey_types::Hash(block_hash);
                        // Return encoded block if we have it
                        let block_data = store.get_block(&hash).ok().map(|block| {
                            encode_block_message(&block, &hash)
                        });
                        let _ = response_tx.send(block_data);
                    }
                    NetworkEvent::TicketReceived { data, source } => {
                        if let Some(proof) = tickets::decode_ticket_proof(&data)
                            && ticket_state.add_ticket(proof, protocol, &state) {
                                tracing::debug!(
                                    "Validator {} received ticket from {}",
                                    config.validator_index,
                                    source
                                );
                            }
                    }
                    NetworkEvent::PeerIdentified { peer_id, validator_index: vi } => {
                        tracing::info!(
                            "Validator {} peer identified: {} (validator={:?})",
                            config.validator_index,
                            peer_id,
                            vi
                        );
                        // Increment peer count for metrics
                        if let Some(ref rpc_st) = rpc_state {
                            rpc_st.peer_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
            }

            // Handle RPC commands
            rpc_cmd = async {
                match rpc_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(cmd) = rpc_cmd {
                    match cmd {
                        grey_rpc::RpcCommand::SubmitWorkPackage { data } => {
                            let hash = grey_crypto::blake2b_256(&data);
                            tracing::info!(
                                "Validator {} received work package via RPC, hash=0x{}",
                                config.validator_index,
                                hex::encode(&hash.0[..8])
                            );

                            // Decode work package from JAM codec and process it
                            use scale::Decode;
                            match grey_types::work::WorkPackage::decode(&data) {
                                Ok((wp, _consumed)) => {
                                    tracing::info!(
                                        "Decoded work package via RPC: {} items, auth_host={}",
                                        wp.items.len(),
                                        wp.auth_code_host
                                    );
                                    let rpc_slot = state.timeslot + 1;
                                    match guarantor::process_work_package(
                                        &config.protocol_config,
                                        &wp,
                                        &state,
                                        &store,
                                        config.validator_index,
                                        my_secrets,
                                        rpc_slot,
                                        &mut guarantor_state,
                                    ) {
                                        Ok(report_hash) => {
                                            // Co-sign with a second validator (testnet only)
                                            crate::guarantor::cosign_last_guarantee(
                                                &mut guarantor_state,
                                                &report_hash,
                                                config.validator_index,
                                                &all_secrets,
                                            );
                                            // Broadcast only the new guarantee to peers
                                            if let Some(g) = guarantor_state.pending_guarantees.last() {
                                                let g_data = guarantor::encode_guarantee(g);
                                                let _ = net_commands.try_send(NetworkCommand::BroadcastGuarantee {
                                                    data: g_data,
                                                });
                                            }
                                            tracing::info!(
                                                "RPC work package processed (2 signers), report_hash=0x{}",
                                                hex::encode(&report_hash.0[..8])
                                            );
                                        }
                                        Err(e) => {
                                            tracing::warn!("RPC work package processing failed: {}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "Failed to decode work package ({} bytes): {:?}",
                                        data.len(), e
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // Update RPC status after each loop iteration
        if let Some(ref rpc_st) = rpc_state {
            let mut status = rpc_st.status.write().await;
            status.head_slot = state.timeslot;
            status.blocks_authored = blocks_authored;
            status.blocks_imported = blocks_imported;
            status.finalized_slot = grandpa.finalized_slot;
            status.grandpa_round = grandpa.round;
            if let Ok((h, _)) = store.get_head() {
                status.head_hash = hex::encode(h.0);
            }
            if let Ok((h, _)) = store.get_finalized() {
                status.finalized_hash = hex::encode(h.0);
            }
        }
    }

    Ok(())
}

/// Compute a simplified state root.
fn compute_state_root(state: &State) -> Hash {
    let mut data = Vec::new();
    data.extend_from_slice(&state.timeslot.to_le_bytes());
    data.extend_from_slice(&state.entropy[0].0);
    grey_crypto::blake2b_256(&data)
}

/// Encode a block for network transmission.
/// Format: [header_hash (32)][block_len (4)][JAM-encoded block (header + extrinsic)]
fn encode_block_message(block: &Block, header_hash: &Hash) -> Vec<u8> {
    use scale::Encode;
    let encoded_block = block.encode();
    let mut msg = Vec::with_capacity(32 + 4 + encoded_block.len());
    msg.extend_from_slice(&header_hash.0);
    msg.extend_from_slice(&(encoded_block.len() as u32).to_le_bytes());
    msg.extend_from_slice(&encoded_block);
    msg
}

/// Decode a block message received from the network.
/// Returns (Block, header_hash) with full extrinsics.
fn decode_block_message(data: &[u8], _config: &Config) -> Option<(Block, Hash)> {
    use scale::Decode;
    if data.len() < 32 + 4 {
        return None;
    }
    let mut header_hash = [0u8; 32];
    header_hash.copy_from_slice(&data[..32]);
    let block_len = u32::from_le_bytes(data[32..36].try_into().ok()?) as usize;
    if data.len() < 36 + block_len {
        return None;
    }
    let block_data = &data[36..36 + block_len];
    let (block, _consumed) = Block::decode(block_data).ok()?;
    Some((block, Hash(header_hash)))
}

/// Create a demo work package for service testing.
fn create_demo_work_package(
    state: &State,
    service_id: u32,
    code_hash: Hash,
    payload: &[u8],
    _timeslot: u32,
) -> grey_types::work::WorkPackage {
    use grey_types::work::*;

    let (anchor, state_root, beefy_root) = if let Some(recent) = state.recent_blocks.headers.last()
    {
        (
            recent.header_hash,
            recent.state_root,
            recent.accumulation_root,
        )
    } else {
        (Hash::ZERO, Hash::ZERO, Hash::ZERO)
    };

    WorkPackage {
        auth_code_host: service_id,
        auth_code_hash: code_hash,
        context: RefinementContext {
            anchor,
            state_root,
            beefy_root,
            lookup_anchor: anchor,
            lookup_anchor_timeslot: state.timeslot,
            prerequisites: vec![],
        },
        authorization: vec![],
        authorizer_config: vec![],
        items: vec![WorkItem {
            service_id,
            code_hash,
            gas_limit: 5_000_000,
            accumulate_gas_limit: 1_000_000,
            exports_count: 0,
            payload: payload.to_vec(),
            imports: vec![],
            extrinsics: vec![],
        }],
    }
}

/// Tracks consecutive ticks where queues exceed the warning threshold.
/// After `ALERT_TICKS` consecutive ticks, escalates from warn to error.
struct SaturationTracker {
    events: u32,
    commands: u32,
    rpc: u32,
    pending_blocks: u32,
}

impl SaturationTracker {
    fn new() -> Self {
        Self {
            events: 0,
            commands: 0,
            rpc: 0,
            pending_blocks: 0,
        }
    }
}

/// Number of consecutive ticks above 80% before escalating to error.
const SATURATION_ALERT_TICKS: u32 = 10;

/// Check queue depths for all inter-component channels and the pending blocks buffer.
/// Logs at debug level normally, warns when any queue exceeds 80% capacity,
/// and escalates to error after persistent saturation.
fn check_queue_depths(
    validator_index: u16,
    net_event_tx: &tokio::sync::mpsc::Sender<NetworkEvent>,
    net_cmd_tx: &tokio::sync::mpsc::Sender<NetworkCommand>,
    rpc_state: Option<&std::sync::Arc<grey_rpc::RpcState>>,
    pending_blocks_len: usize,
    saturation: &mut SaturationTracker,
) {
    const WARN_THRESHOLD: f64 = 0.8;

    let event_depth = EVENT_CHANNEL_CAPACITY - net_event_tx.capacity();
    let cmd_depth = COMMAND_CHANNEL_CAPACITY - net_cmd_tx.capacity();
    let rpc_depth = rpc_state.map(|s| 256 - s.commands.capacity()).unwrap_or(0);
    let rpc_capacity: usize = 256;

    // Update RpcState atomics for /metrics endpoint
    if let Some(state) = rpc_state {
        use std::sync::atomic::Ordering::Relaxed;
        state.queue_depth_events.store(event_depth as u32, Relaxed);
        state.queue_depth_commands.store(cmd_depth as u32, Relaxed);
        state.queue_depth_rpc.store(rpc_depth as u32, Relaxed);
        state
            .pending_blocks_depth
            .store(pending_blocks_len as u32, Relaxed);
    }

    tracing::debug!(
        "Validator {} queue depths: events={}/{}, commands={}/{}, rpc={}/{}, pending_blocks={}/{}",
        validator_index,
        event_depth,
        EVENT_CHANNEL_CAPACITY,
        cmd_depth,
        COMMAND_CHANNEL_CAPACITY,
        rpc_depth,
        rpc_capacity,
        pending_blocks_len,
        MAX_PENDING_BLOCKS,
    );

    // Helper: check a single queue, track saturation, and log at appropriate level.
    macro_rules! check_queue {
        ($depth:expr, $capacity:expr, $counter:expr, $name:expr) => {
            if $depth as f64 > $capacity as f64 * WARN_THRESHOLD {
                $counter += 1;
                if $counter >= SATURATION_ALERT_TICKS {
                    tracing::error!(
                        "Validator {} {} PERSISTENTLY SATURATED at {:.0}% ({}/{}) for {} ticks",
                        validator_index,
                        $name,
                        $depth as f64 / $capacity as f64 * 100.0,
                        $depth,
                        $capacity,
                        $counter,
                    );
                } else {
                    tracing::warn!(
                        "Validator {} {} at {:.0}% capacity ({}/{})",
                        validator_index,
                        $name,
                        $depth as f64 / $capacity as f64 * 100.0,
                        $depth,
                        $capacity,
                    );
                }
            } else {
                $counter = 0;
            }
        };
    }

    check_queue!(
        event_depth,
        EVENT_CHANNEL_CAPACITY,
        saturation.events,
        "network event queue"
    );
    check_queue!(
        cmd_depth,
        COMMAND_CHANNEL_CAPACITY,
        saturation.commands,
        "network command queue"
    );
    if rpc_state.is_some() {
        check_queue!(rpc_depth, rpc_capacity, saturation.rpc, "RPC command queue");
    }
    check_queue!(
        pending_blocks_len,
        MAX_PENDING_BLOCKS,
        saturation.pending_blocks,
        "pending blocks buffer"
    );
}
