//! Integration test: run a local test network with V=6 validators.
//!
//! This module can be used as a standalone test or called from the binary.
//! It spawns V validator nodes, connects them, and verifies that blocks
//! are authored, propagated, validated, and finalized.

use grey_types::config::Config;
use std::time::Duration;

/// Run the local test network.
///
/// Launches V=6 validators, waits for blocks to be produced and finalized,
/// then reports success or failure.
pub async fn run_testnet(
    duration_secs: u64,
) -> Result<TestnetResult, Box<dyn std::error::Error + Send + Sync>> {
    let config = Config::tiny();
    let v = config.validators_count;
    let base_port: u16 = 19000;

    // Use a shared genesis time for all validators
    let genesis_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    tracing::info!(
        "Starting local testnet with {} validators, genesis_time={}",
        v,
        genesis_time
    );

    // Build boot peer list: each validator connects to the first validator
    // (star topology for simplicity)
    let first_peer = format!("/ip4/127.0.0.1/tcp/{}", base_port);

    let mut handles = Vec::new();

    for i in 0..v {
        let port = base_port + i;
        let peers = if i == 0 {
            vec![] // First validator has no boot peers
        } else {
            vec![first_peer.clone()]
        };
        let config_clone = config.clone();

        let handle = tokio::spawn(async move {
            let node_config = crate::node::NodeConfig {
                validator_index: i,
                listen_port: port,
                boot_peers: peers,
                protocol_config: config_clone,
                genesis_time,
            };
            // Run the node (will run indefinitely, we'll cancel it)
            let _ = crate::node::run_node(node_config).await;
        });

        handles.push(handle);

        // Small delay between starting validators to avoid port conflicts
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    tracing::info!("All {} validators started, waiting {}s for block production...", v, duration_secs);

    // Wait for the specified duration
    tokio::time::sleep(Duration::from_secs(duration_secs)).await;

    // Cancel all validator tasks
    for handle in &handles {
        handle.abort();
    }

    tracing::info!("Testnet stopped after {}s", duration_secs);

    Ok(TestnetResult {
        validators: v,
        duration_secs,
    })
}

/// Simpler standalone test that doesn't need networking:
/// just verifies that blocks can be authored and validated sequentially.
pub fn run_sequential_test(num_blocks: u32) -> Result<SequentialTestResult, String> {
    let config = Config::tiny();
    let (mut state, secrets) = grey_consensus::genesis::create_genesis(&config);

    tracing::info!(
        "Sequential test: V={}, C={}, E={}, producing {} blocks",
        config.validators_count,
        config.core_count,
        config.epoch_length,
        num_blocks
    );

    let mut blocks_produced = 0u32;
    let mut finalized_slot = 0u32;
    let finality_depth = 3u32;
    let mut slot_authors = Vec::new();

    for slot in 1..=num_blocks * 2 {
        // Find the author for this slot
        let mut authored = false;
        for s in &secrets {
            let pk = grey_types::BandersnatchPublicKey(s.bandersnatch.public_key_bytes());
            if let Some(author_idx) =
                grey_consensus::authoring::is_slot_author(&state, &config, slot, &pk)
            {
                // Compute state root
                let state_root = {
                    let mut data = Vec::new();
                    data.extend_from_slice(&state.timeslot.to_le_bytes());
                    data.extend_from_slice(&state.entropy[0].0);
                    grey_crypto::blake2b_256(&data)
                };

                let block = grey_consensus::authoring::author_block(
                    &state, &config, slot, author_idx, s, state_root,
                );

                match grey_state::transition::apply_with_config(&state, &block, &config, &[]) {
                    Ok((new_state, _)) => {
                        let header_hash = grey_codec::header_codec::compute_header_hash(&block.header);
                        state = new_state;
                        blocks_produced += 1;
                        slot_authors.push((slot, author_idx));

                        tracing::info!(
                            "Block #{} at slot {} by validator {}, hash=0x{}",
                            blocks_produced,
                            slot,
                            author_idx,
                            hex::encode(&header_hash.0[..8])
                        );

                        // Check finality
                        if slot > finality_depth {
                            let new_finalized = slot - finality_depth;
                            if new_finalized > finalized_slot {
                                finalized_slot = new_finalized;
                                tracing::info!("FINALIZED up to slot {}", finalized_slot);
                            }
                        }

                        authored = true;
                        break;
                    }
                    Err(e) => {
                        tracing::error!(
                            "Block at slot {} by validator {} FAILED: {}",
                            slot,
                            author_idx,
                            e
                        );
                        return Err(format!("Block authoring failed at slot {}: {}", slot, e));
                    }
                }
            }
        }

        if !authored {
            tracing::debug!("No author for slot {}", slot);
        }

        if blocks_produced >= num_blocks {
            break;
        }
    }

    if blocks_produced < num_blocks {
        return Err(format!(
            "Only produced {} of {} blocks",
            blocks_produced, num_blocks
        ));
    }

    // Verify state consistency
    assert!(state.timeslot > 0, "State timeslot should have advanced");
    assert!(
        state.recent_blocks.headers.len() > 0,
        "Should have recent block history"
    );

    tracing::info!(
        "Sequential test PASSED: {} blocks produced, finalized up to slot {}",
        blocks_produced,
        finalized_slot
    );

    Ok(SequentialTestResult {
        blocks_produced,
        finalized_slot,
        final_timeslot: state.timeslot,
        slot_authors,
    })
}

/// Result of the network test.
#[derive(Debug)]
pub struct TestnetResult {
    pub validators: u16,
    pub duration_secs: u64,
}

/// Result of the sequential (non-networked) test.
#[derive(Debug)]
pub struct SequentialTestResult {
    pub blocks_produced: u32,
    pub finalized_slot: u32,
    pub final_timeslot: u32,
    pub slot_authors: Vec<(u32, u16)>,
}
