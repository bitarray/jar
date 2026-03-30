//! Deterministic sequential testnet.
//!
//! Simulates V validators in a single thread with deterministic message passing.
//! No wall-clock delays — slots advance as fast as the CPU can process them.
//! Each slot: deliver messages → generate assurances → author block → broadcast.
//!
//! Invoked via `grey --seq-testnet`. Starts an RPC server on the configured port
//! so the integration harness can interact with it identically to the real testnet.

use grey_codec::header_codec::compute_header_hash;
use grey_consensus::authoring;
use grey_consensus::genesis::create_genesis;
use grey_rpc::{self, RpcCommand};
use grey_store::Store;
use grey_types::config::Config;
use grey_types::header::{Assurance, Guarantee};
use grey_types::state::{ServiceAccount, State};
use grey_types::work::WorkPackage;
use grey_types::{BandersnatchPublicKey, Hash, Timeslot};
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::finality::GrandpaState;
use crate::guarantor::GuarantorState;
use crate::testnet::{build_test_assurances, build_test_guarantee_with_payload};

include!(concat!(env!("OUT_DIR"), "/service_blobs.rs"));

/// Per-node state in the sequential testnet.
struct SeqNode {
    _index: u16,
    state: State,
    _grandpa: GrandpaState,
    guarantor_state: GuarantorState,
    _collected_assurances: Vec<Assurance>,
}

impl SeqNode {
    fn new(index: u16, state: State, total_validators: u16) -> Self {
        Self {
            _index: index,
            state,
            _grandpa: GrandpaState::new(total_validators),
            guarantor_state: GuarantorState::new(),
            _collected_assurances: Vec::new(),
        }
    }
}

/// Run the deterministic sequential testnet with an RPC server.
pub async fn run_seq_testnet(
    rpc_port: u16,
    rpc_cors: bool,
    max_blocks: Option<u32>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = Config::tiny();
    let (mut genesis_state, secrets) = create_genesis(&config);

    // Install services (same as run_sequential_test)
    install_services(&mut genesis_state, &config);

    let v = config.validators_count;

    // Create a tmpdir store for the RPC server
    let tmp_dir = std::env::temp_dir().join(format!("grey-seq-testnet-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir)?;
    let db_path = tmp_dir.join("node-0.redb");
    let store = Arc::new(Store::open(db_path.to_str().unwrap())?);

    // Set up RPC
    let (rpc_state, mut rpc_rx) = grey_rpc::create_rpc_channel(store.clone(), config.clone(), 0);

    if rpc_port > 0 {
        let (addr, _handle) =
            grey_rpc::start_rpc_server(rpc_port, rpc_state.clone(), rpc_cors).await?;
        tracing::info!("Sequential testnet RPC on {addr}");
    }

    // Initialize nodes
    let mut nodes: Vec<SeqNode> = (0..v)
        .map(|i| SeqNode::new(i, genesis_state.clone(), v))
        .collect();

    let mut current_slot: Timeslot = 0;
    let mut blocks_produced: u32 = 0;
    let finality_depth: u32 = 3;

    // Pending work packages from RPC submissions
    let mut pending_guarantees: Vec<Guarantee> = Vec::new();

    // Shutdown signal
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        shutdown_clone.store(true, std::sync::atomic::Ordering::Relaxed);
    });

    tracing::info!(
        "Sequential testnet started: V={}, C={}, RPC={}",
        config.validators_count,
        config.core_count,
        rpc_port,
    );

    loop {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::info!("Shutting down sequential testnet");
            break;
        }
        if let Some(max) = max_blocks
            && blocks_produced >= max
        {
            tracing::info!(
                "Reached {} blocks, stopping sequential testnet",
                blocks_produced
            );
            break;
        }
        // Check for RPC commands (non-blocking)
        while let Ok(cmd) = rpc_rx.try_recv() {
            match cmd {
                RpcCommand::SubmitWorkPackage { data } => {
                    // Decode work package and create a guarantee
                    match <WorkPackage as grey_codec::Decode>::decode(&data) {
                        Ok((wp, _len)) => {
                            let service_id = wp.items.first().map(|i| i.service_id).unwrap_or(0);
                            let code_hash =
                                wp.items.first().map(|i| i.code_hash).unwrap_or(Hash::ZERO);
                            let payload = wp
                                .items
                                .first()
                                .map(|i| i.payload.clone())
                                .unwrap_or_default();

                            let (guarantee, _pkg_hash) = build_test_guarantee_with_payload(
                                &nodes[0].state,
                                &config,
                                &secrets,
                                service_id,
                                code_hash,
                                current_slot + 1,
                                0, // core 0
                                payload,
                            );
                            tracing::info!(
                                "RPC: work package → guarantee for service {service_id}"
                            );
                            pending_guarantees.push(guarantee);
                        }
                        Err(e) => {
                            tracing::warn!("RPC: failed to decode work package: {e}");
                        }
                    }
                }
            }
        }

        current_slot += 1;
        let slot = current_slot;

        // Find author for this slot
        for (i, secret) in secrets.iter().enumerate() {
            let pk = BandersnatchPublicKey(secret.bandersnatch.public_key_bytes());
            if let Some(author_idx) = authoring::is_slot_author_with_keypair(
                &nodes[0].state,
                &config,
                slot,
                &pk,
                Some(&secret.bandersnatch),
            ) {
                let node = &mut nodes[i];

                // Compute state root
                let state_root = {
                    let mut data = Vec::new();
                    data.extend_from_slice(&node.state.timeslot.to_le_bytes());
                    data.extend_from_slice(&node.state.entropy[0].0);
                    grey_crypto::blake2b_256(&data)
                };

                // Collect guarantees (from RPC submissions)
                let mut guarantees = std::mem::take(&mut pending_guarantees);
                guarantees.extend(node.guarantor_state.take_guarantees());

                // Collect assurances from all nodes
                let parent_hash = node
                    .state
                    .recent_blocks
                    .headers
                    .last()
                    .map(|h| h.header_hash)
                    .unwrap_or(Hash::ZERO);

                // Generate assurances from all validators for pending reports
                let mut assurances = Vec::new();
                for (core_idx, report) in node.state.pending_reports.iter().enumerate() {
                    if report.is_some() {
                        let core_assurances =
                            build_test_assurances(&config, &secrets, parent_hash, core_idx as u16);
                        assurances.extend(core_assurances);
                    }
                }

                let block = authoring::author_block_with_extrinsics(
                    &node.state,
                    &config,
                    slot,
                    author_idx,
                    secret,
                    state_root,
                    guarantees,
                    assurances,
                    vec![],
                );

                // Apply to author's state
                match grey_state::transition::apply_with_config(&node.state, &block, &config, &[]) {
                    Ok((new_state, _)) => {
                        let header_hash = compute_header_hash(&block.header);

                        // Update store for RPC (order matters: block+state first, then head)
                        let _ = store.put_block(&block);
                        let _ = store.put_state(&header_hash, &new_state, &config);
                        let _ = store.set_head(&header_hash, slot);

                        // Simple depth-based finalization
                        let finalized_slot = slot.saturating_sub(finality_depth);

                        // Update RPC status (use try_write to avoid blocking)
                        if let Ok(mut status) = rpc_state.status.try_write() {
                            status.head_slot = slot;
                            status.head_hash = hex::encode(header_hash.0);
                            status.finalized_slot = finalized_slot;
                            status.blocks_authored = blocks_produced as u64 + 1;
                            status.blocks_imported = blocks_produced as u64 + 1;
                        }

                        // Apply to all other nodes too
                        #[allow(clippy::needless_range_loop)]
                        for j in 0..nodes.len() {
                            if j != i
                                && let Ok((ns, _)) = grey_state::transition::apply_with_config(
                                    &nodes[j].state,
                                    &block,
                                    &config,
                                    &[],
                                )
                            {
                                nodes[j].state = ns;
                            }
                        }

                        nodes[i].state = new_state;
                        blocks_produced += 1;

                        if blocks_produced.is_multiple_of(10) || blocks_produced <= 5 {
                            let rss_mb = get_rss_mb();
                            tracing::info!(
                                "Slot {slot}: block #{blocks_produced} by v{author_idx}, hash=0x{}, rss={rss_mb:.1}MB",
                                hex::encode(&header_hash.0[..8])
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!("Slot {slot}: block by v{author_idx} FAILED: {e}");
                    }
                }
                break; // Only one author per slot
            }
        }

        // Yield to tokio periodically so the RPC server can process requests.
        // Without this, the slot loop monopolizes the runtime and RPC calls
        // never get a chance to execute.
        if slot.is_multiple_of(2) {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    }

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp_dir);
    Ok(())
}

/// Install test services into genesis state.
fn install_services(state: &mut State, config: &Config) {
    // Pixels service (ID 2000)
    let pixels_blob = PIXELS_SERVICE_BLOB.to_vec();
    let pixels_code_hash = grey_crypto::blake2b_256(&pixels_blob);
    let mut pixels_preimage = BTreeMap::new();
    pixels_preimage.insert(pixels_code_hash, pixels_blob);
    state.services.insert(
        2000,
        ServiceAccount {
            code_hash: pixels_code_hash,
            balance: 1_000_000_000,
            min_accumulate_gas: 100_000,
            min_on_transfer_gas: 0,
            storage: BTreeMap::new(),
            preimage_lookup: pixels_preimage,
            preimage_info: BTreeMap::new(),
            free_storage_offset: 0,
            total_footprint: 0,
            accumulation_counter: 0,
            last_accumulation: 0,
            last_activity: 0,
            preimage_count: 0,
        },
    );

    // Sample service (ID 1000)
    let sample_blob = SAMPLE_SERVICE_BLOB.to_vec();
    let sample_code_hash = grey_crypto::blake2b_256(&sample_blob);
    let mut sample_preimage = BTreeMap::new();
    sample_preimage.insert(sample_code_hash, sample_blob);
    state.services.insert(
        1000,
        ServiceAccount {
            code_hash: sample_code_hash,
            balance: 1_000_000_000,
            min_accumulate_gas: 100_000,
            min_on_transfer_gas: 0,
            storage: BTreeMap::new(),
            preimage_lookup: sample_preimage,
            preimage_info: BTreeMap::new(),
            free_storage_offset: 0,
            total_footprint: 0,
            accumulation_counter: 0,
            last_accumulation: 0,
            last_activity: 0,
            preimage_count: 0,
        },
    );

    // Populate auth_pool
    for core in 0..config.core_count as usize {
        if state.auth_pool[core].is_empty() {
            state.auth_pool[core].push(Hash::ZERO);
        }
    }
}

/// Get the current process RSS (Resident Set Size) in megabytes.
/// Reads from /proc/self/statm on Linux; returns 0 on other platforms.
fn get_rss_mb() -> f64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm")
            && let Some(rss_pages) = statm.split_whitespace().nth(1)
            && let Ok(pages) = rss_pages.parse::<u64>()
        {
            let page_size = 4096u64; // standard page size
            return (pages * page_size) as f64 / (1024.0 * 1024.0);
        }
        0.0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0.0
    }
}
