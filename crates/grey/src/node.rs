//! JAM validator node service.
//!
//! Runs the main validator loop:
//! 1. Monitor timeslots (6-second intervals)
//! 2. Author blocks when this validator is the slot leader
//! 3. Import blocks received from peers
//! 4. Track finalization
//! 5. Propagate blocks via the network

use grey_codec::header_codec::compute_header_hash;
use grey_consensus::authoring;
use grey_consensus::genesis::ValidatorSecrets;
use grey_network::service::{NetworkCommand, NetworkConfig, NetworkEvent};
use grey_types::config::Config;
use grey_types::header::Block;
use grey_types::state::State;
use grey_types::{BandersnatchPublicKey, Hash, Timeslot};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Node configuration.
pub struct NodeConfig {
    /// Validator index in the genesis set.
    pub validator_index: u16,
    /// Network listen port.
    pub listen_port: u16,
    /// Boot peer addresses.
    pub boot_peers: Vec<String>,
    /// Protocol configuration.
    pub protocol_config: Config,
    /// Base timeslot offset (Unix seconds at timeslot 0).
    /// For test networks, we use the current time.
    pub genesis_time: u64,
}

/// Finality tracker: simplified finality (finalize after N block depth).
struct FinalityTracker {
    /// Finalized block timeslot.
    finalized_slot: Timeslot,
    /// Finality depth (number of blocks before considering finalized).
    finality_depth: u32,
}

impl FinalityTracker {
    fn new(finality_depth: u32) -> Self {
        Self {
            finalized_slot: 0,
            finality_depth,
        }
    }

    /// Update finalization based on the current best block.
    /// Returns the newly finalized timeslot if finality advanced.
    fn update(&mut self, current_slot: Timeslot) -> Option<Timeslot> {
        if current_slot > self.finality_depth {
            let new_finalized = current_slot - self.finality_depth;
            if new_finalized > self.finalized_slot {
                self.finalized_slot = new_finalized;
                return Some(new_finalized);
            }
        }
        None
    }
}

/// Run the validator node.
pub async fn run_node(config: NodeConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let protocol = &config.protocol_config;

    // Create genesis state and validator secrets
    let (genesis_state, all_secrets) = grey_consensus::genesis::create_genesis(protocol);

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

    let (mut net_events, net_commands) = grey_network::service::start_network(NetworkConfig {
        listen_port: config.listen_port,
        boot_peers,
        validator_index: config.validator_index,
    })
    .await?;

    // Initialize state
    let mut state = genesis_state;
    let mut finality = FinalityTracker::new(3); // Finalize after 3-block depth
    let mut blocks_authored = 0u64;
    let mut blocks_imported = 0u64;
    let genesis_time = config.genesis_time;

    tracing::info!(
        "Validator {} node started, genesis_time={}",
        config.validator_index,
        genesis_time
    );

    // Main loop: check timeslots every 500ms
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    let mut last_authored_slot: Timeslot = 0;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let current_slot = ((now - genesis_time) / protocol.epoch_length as u64 * protocol.epoch_length as u64
                    + (now - genesis_time) % protocol.epoch_length as u64) as Timeslot;
                // Simpler: slot = (now - genesis_time) / slot_period
                let current_slot = ((now - genesis_time) / 6) as Timeslot + 1; // +1 because genesis is slot 0

                // Only attempt authoring if this is a new slot we haven't authored yet
                if current_slot > state.timeslot && current_slot > last_authored_slot {
                    // Check if we are the slot author
                    if let Some(author_idx) = authoring::is_slot_author(
                        &state,
                        protocol,
                        current_slot,
                        &my_bandersnatch,
                    ) {
                        tracing::info!(
                            "=== Validator {} IS SLOT AUTHOR for slot {} ===",
                            config.validator_index,
                            current_slot
                        );

                        // Compute state root (simplified: hash of timeslot for now)
                        let state_root = compute_state_root(&state);

                        // Author block
                        let block = authoring::author_block(
                            &state,
                            protocol,
                            current_slot,
                            author_idx,
                            my_secrets,
                            state_root,
                        );

                        // Apply block to our state
                        match grey_state::transition::apply_with_config(
                            &state,
                            &block,
                            protocol,
                            &[],
                        ) {
                            Ok((new_state, _)) => {
                                let header_hash = compute_header_hash(&block.header);
                                state = new_state;
                                blocks_authored += 1;
                                last_authored_slot = current_slot;

                                tracing::info!(
                                    "Validator {} authored block #{} at slot {}, hash=0x{}",
                                    config.validator_index,
                                    blocks_authored,
                                    current_slot,
                                    hex::encode(&header_hash.0[..8])
                                );

                                // Broadcast block
                                let block_data = encode_block_message(&block, &header_hash);
                                let _ = net_commands.send(NetworkCommand::BroadcastBlock {
                                    data: block_data,
                                });

                                // Check finality
                                if let Some(finalized) = finality.update(current_slot) {
                                    tracing::info!(
                                        "Validator {} FINALIZED slot {}",
                                        config.validator_index,
                                        finalized
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Validator {} block authoring failed at slot {}: {}",
                                    config.validator_index,
                                    current_slot,
                                    e
                                );
                            }
                        }
                    }
                }
            }

            // Handle network events
            event = net_events.recv() => {
                let Some(event) = event else { break };
                match event {
                    NetworkEvent::BlockReceived { data, source } => {
                        match decode_block_message(&data) {
                            Some((block, _hash)) => {
                                let slot = block.header.timeslot;
                                if slot > state.timeslot {
                                    match grey_state::transition::apply_with_config(
                                        &state,
                                        &block,
                                        protocol,
                                        &[],
                                    ) {
                                        Ok((new_state, _)) => {
                                            state = new_state;
                                            blocks_imported += 1;
                                            tracing::info!(
                                                "Validator {} imported block at slot {} from peer {} (total imported: {})",
                                                config.validator_index,
                                                slot,
                                                source,
                                                blocks_imported
                                            );

                                            if let Some(finalized) = finality.update(slot) {
                                                tracing::info!(
                                                    "Validator {} FINALIZED slot {}",
                                                    config.validator_index,
                                                    finalized
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                "Validator {} rejected block at slot {}: {}",
                                                config.validator_index,
                                                slot,
                                                e
                                            );
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
                    }
                    NetworkEvent::FinalityVote { .. } => {
                        // Simplified: we don't process explicit finality votes yet
                    }
                }
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
/// Format: [4-byte length][header_hash (32 bytes)][encoded block]
fn encode_block_message(block: &Block, header_hash: &Hash) -> Vec<u8> {
    let encoded_header = grey_codec::header_codec::encode_header(&block.header);
    let mut msg = Vec::new();
    // Header hash for quick identification
    msg.extend_from_slice(&header_hash.0);
    // Timeslot for quick filtering
    msg.extend_from_slice(&block.header.timeslot.to_le_bytes());
    // Author index
    msg.extend_from_slice(&block.header.author_index.to_le_bytes());
    // Encoded header length + data
    let len = encoded_header.len() as u32;
    msg.extend_from_slice(&len.to_le_bytes());
    msg.extend_from_slice(&encoded_header);
    msg
}

/// Decode a block message received from the network.
/// Returns (block_header_partial, header_hash) for validation.
fn decode_block_message(data: &[u8]) -> Option<(Block, Hash)> {
    if data.len() < 32 + 4 + 2 + 4 {
        return None;
    }

    let mut header_hash = [0u8; 32];
    header_hash.copy_from_slice(&data[..32]);
    let timeslot = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
    let author_index = u16::from_le_bytes([data[36], data[37]]);
    let header_len = u32::from_le_bytes([data[38], data[39], data[40], data[41]]) as usize;

    if data.len() < 42 + header_len {
        return None;
    }

    // Decode the full header from the encoded data
    let header_data = &data[42..42 + header_len];

    // Parse header fields manually (matching encode_header format)
    let header = decode_header_from_bytes(header_data)?;

    let block = Block {
        header,
        extrinsic: grey_types::header::Extrinsic {
            tickets: vec![],
            preimages: vec![],
            guarantees: vec![],
            assurances: vec![],
            disputes: grey_types::header::DisputesExtrinsic::default(),
        },
    };

    Some((block, Hash(header_hash)))
}

/// Parse a header from encoded bytes (matching encode_header format).
fn decode_header_from_bytes(data: &[u8]) -> Option<grey_types::header::Header> {
    use grey_types::*;

    if data.len() < 32 + 32 + 32 + 4 {
        return None;
    }

    let mut pos = 0;

    // HP: parent_hash (32 bytes)
    let mut parent_hash = [0u8; 32];
    parent_hash.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    // HR: state_root (32 bytes)
    let mut state_root = [0u8; 32];
    state_root.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    // HX: extrinsic_hash (32 bytes)
    let mut extrinsic_hash = [0u8; 32];
    extrinsic_hash.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    // E4(HT): timeslot (4 bytes LE)
    let timeslot = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;

    // ¿HE: epoch_marker (discriminated)
    if pos >= data.len() {
        return None;
    }
    let epoch_marker = if data[pos] == 0 {
        pos += 1;
        None
    } else {
        pos += 1;
        // Skip epoch marker data for now (we'd need to parse it properly)
        // For empty extrinsics blocks in test network, this shouldn't occur frequently
        None // Simplified: skip epoch marker parsing
    };

    // ¿HW: tickets_marker
    if pos >= data.len() {
        return None;
    }
    let tickets_marker = if data[pos] == 0 {
        pos += 1;
        None
    } else {
        pos += 1;
        None // Simplified: skip tickets marker parsing
    };

    // E2(HI): author_index (2 bytes LE)
    if pos + 2 > data.len() {
        return None;
    }
    let author_index = u16::from_le_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // HV: vrf_signature (96 bytes)
    if pos + 96 > data.len() {
        return None;
    }
    let mut vrf_sig = [0u8; 96];
    vrf_sig.copy_from_slice(&data[pos..pos + 96]);
    pos += 96;

    // ↕HO: offenders_marker (compact length + keys)
    if pos >= data.len() {
        return None;
    }
    // Read compact length
    let mut decode_pos = pos;
    let offenders_count = grey_codec::decode_compact_at(data, &mut decode_pos).unwrap_or(0);
    pos = decode_pos;
    let mut offenders = Vec::new();
    for _ in 0..offenders_count {
        if pos + 32 > data.len() {
            break;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&data[pos..pos + 32]);
        offenders.push(Ed25519PublicKey(key));
        pos += 32;
    }

    // HS: seal (96 bytes) - only present in full header encoding
    let mut seal = [0u8; 96];
    if pos + 96 <= data.len() {
        seal.copy_from_slice(&data[pos..pos + 96]);
    }

    Some(grey_types::header::Header {
        parent_hash: Hash(parent_hash),
        state_root: Hash(state_root),
        extrinsic_hash: Hash(extrinsic_hash),
        timeslot,
        epoch_marker,
        tickets_marker,
        author_index,
        vrf_signature: BandersnatchSignature(vrf_sig),
        offenders_marker: offenders,
        seal: BandersnatchSignature(seal),
    })
}
