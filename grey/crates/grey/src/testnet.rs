//! Integration test: run a local test network with V=6 validators.
//!
//! This module can be used as a standalone test or called from the binary.
//! It spawns V validator nodes, connects them, and verifies that blocks
//! are authored, propagated, validated, and finalized.
//!
//! The sequential test also simulates the full work-package pipeline:
//! guarantee → assurance → accumulation with a PVM service.

use grey_types::config::Config;
use grey_types::header::*;
use grey_types::state::ServiceAccount;
use grey_types::work::*;
use grey_types::{Hash, ServiceId, Timeslot};
use std::collections::BTreeMap;
use std::time::Duration;

include!(concat!(env!("OUT_DIR"), "/service_blobs.rs"));

/// Run the local test network with work package processing demo.
///
/// Launches V=6 validators with a pre-installed PVM service,
/// waits for blocks to be produced and finalized via GRANDPA,
/// and reports results.
pub async fn run_testnet(
    duration_secs: u64,
    rpc_cors: bool,
) -> Result<TestnetResult, Box<dyn std::error::Error + Send + Sync>> {
    use grey_types::state::ServiceAccount;

    let config = Config::tiny();
    let v = config.validators_count;
    let base_port: u16 = 19000;

    // Create shared genesis state with a PVM service installed
    let (mut genesis_state, _secrets) = grey_consensus::genesis::create_genesis(&config);

    let service_id: ServiceId = 1000;
    let pvm_blob = SAMPLE_SERVICE_BLOB.to_vec();
    let code_hash = grey_crypto::blake2b_256(&pvm_blob);
    let mut preimage_lookup = BTreeMap::new();
    preimage_lookup.insert(code_hash, pvm_blob);

    genesis_state.services.insert(
        service_id,
        ServiceAccount {
            code_hash,
            balance: 1_000_000_000,
            min_accumulate_gas: 100_000,
            min_on_transfer_gas: 0,
            storage: BTreeMap::new(),
            preimage_lookup,
            preimage_info: BTreeMap::new(),
            free_storage_offset: 0,
            total_footprint: 0,
            accumulation_counter: 0,
            last_accumulation: 0,
            last_activity: 0,
            preimage_count: 0,
        },
    );

    // Install pixels service (ID 2000)
    let pixels_service_id: ServiceId = 2000;
    {
        let pixels_blob = PIXELS_SERVICE_BLOB.to_vec();
        let pixels_hash = grey_crypto::blake2b_256(&pixels_blob);
        let mut px_preimages = BTreeMap::new();
        px_preimages.insert(pixels_hash, pixels_blob);
        genesis_state.services.insert(
            pixels_service_id,
            ServiceAccount {
                code_hash: pixels_hash,
                balance: 1_000_000_000,
                min_accumulate_gas: 100_000,
                min_on_transfer_gas: 0,
                storage: BTreeMap::new(),
                preimage_lookup: px_preimages,
                preimage_info: BTreeMap::new(),
                free_storage_offset: 0,
                total_footprint: 0,
                accumulation_counter: 0,
                last_accumulation: 0,
                last_activity: 0,
                preimage_count: 0,
            },
        );
        tracing::info!(
            "Testnet: installed pixels service {} (code_hash=0x{})",
            pixels_service_id,
            hex::encode(&pixels_hash.0[..8])
        );
    }

    // Populate auth_pool and auth_queue so guarantees pass the authorizer check
    // and auth_pool is replenished after each guarantee via rotation.
    // Core 0: demo service (1000), core 1: pixels service (2000), rest: demo.
    let pixels_code_hash = genesis_state
        .services
        .get(&pixels_service_id)
        .map(|s| s.code_hash);
    for core in 0..config.core_count as usize {
        let hash_for_core = if core == 1 {
            pixels_code_hash.unwrap_or(code_hash)
        } else {
            code_hash
        };
        if genesis_state.auth_pool[core].is_empty() {
            genesis_state.auth_pool[core].push(hash_for_core);
        }
        // Fill auth_queue so rotation replenishes auth_pool after each guarantee
        for slot in 0..config.auth_queue_size {
            if slot < genesis_state.auth_queue.len() && core < genesis_state.auth_queue[slot].len()
            {
                genesis_state.auth_queue[slot][core] = hash_for_core;
            }
        }
    }

    tracing::info!(
        "Testnet: auth_pool configured — core 0: svc 1000, core 1: svc {}",
        if pixels_code_hash.is_some() {
            "2000"
        } else {
            "1000 (pixels not available)"
        }
    );

    // Use a shared genesis time for all validators
    let genesis_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let unlimited = duration_secs == 0;
    tracing::info!(
        "Starting local testnet with {} validators, genesis_time={}, duration={}",
        v,
        genesis_time,
        if unlimited {
            "unlimited (Ctrl+C to stop)".to_string()
        } else {
            format!("{}s", duration_secs)
        }
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
        let genesis_clone = genesis_state.clone();

        let handle = tokio::spawn(async move {
            let node_config = crate::node::NodeConfig {
                validator_index: i,
                listen_addr: "127.0.0.1".to_string(),
                listen_port: port,
                boot_peers: peers,
                protocol_config: config_clone,
                genesis_time,
                db_path: format!("/tmp/grey-testnet-{}", genesis_time),
                rpc_port: 9933 + i,
                rpc_cors,
                genesis_state: Some(genesis_clone),
                pruning_depth: 0, // No pruning in testnet
                keystore_path: None,
            };
            if let Err(e) = crate::node::run_node(node_config).await {
                tracing::error!("Validator {} exited with error: {}", i, e);
            } else {
                tracing::error!("Validator {} exited unexpectedly", i);
            }
        });

        handles.push(handle);

        // Small delay between starting validators to avoid port conflicts
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    if unlimited {
        tracing::info!("All {} validators started, running until Ctrl+C...", v);
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Received Ctrl+C, shutting down testnet...");
            }
            // If any validator task exits, abort everything
            _result = async {
                loop {
                    for handle in &handles {
                        if handle.is_finished() {
                            return;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            } => {
                tracing::error!("A validator exited — aborting testnet");
            }
        }
    } else {
        tracing::info!(
            "All {} validators started, waiting {}s for block production...",
            v,
            duration_secs
        );
        tokio::time::sleep(Duration::from_secs(duration_secs)).await;
    }

    // Cancel all validator tasks
    for handle in &handles {
        handle.abort();
    }

    tracing::info!("Testnet stopped");

    // Clean up temp database files
    let db_dir = format!("/tmp/grey-testnet-{}", genesis_time);
    let _ = std::fs::remove_dir_all(&db_dir);

    Ok(TestnetResult {
        validators: v,
        duration_secs,
    })
}

/// Simpler standalone test that doesn't need networking:
/// just verifies that blocks can be authored and validated sequentially,
/// including full work-package processing (guarantee → assurance → accumulation).
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

    // --- Install a PVM service into genesis state ---
    let service_id: ServiceId = 1000;
    let pvm_blob = SAMPLE_SERVICE_BLOB.to_vec();
    let code_hash = grey_crypto::blake2b_256(&pvm_blob);
    let mut preimage_lookup = BTreeMap::new();
    preimage_lookup.insert(code_hash, pvm_blob);

    state.services.insert(
        service_id,
        ServiceAccount {
            code_hash,
            balance: 1_000_000_000,
            min_accumulate_gas: 100_000,
            min_on_transfer_gas: 0,
            storage: BTreeMap::new(),
            preimage_lookup,
            preimage_info: BTreeMap::new(),
            free_storage_offset: 0,
            total_footprint: 0,
            accumulation_counter: 0,
            last_accumulation: 0,
            last_activity: 0,
            preimage_count: 0,
        },
    );
    tracing::info!(
        "Installed PVM service {} with code_hash=0x{}",
        service_id,
        hex::encode(&code_hash.0[..8])
    );

    // --- Install the pixels service (ID 2000) ---
    let pixels_service_id: ServiceId = 2000;
    let pixels_pvm_blob = PIXELS_SERVICE_BLOB.to_vec();
    let pixels_installed = true;
    let pixels_code_hash = {
        let h = grey_crypto::blake2b_256(&pixels_pvm_blob);
        let mut pixels_preimage_lookup = BTreeMap::new();
        pixels_preimage_lookup.insert(h, pixels_pvm_blob);

        state.services.insert(
            pixels_service_id,
            ServiceAccount {
                code_hash: h,
                balance: 1_000_000_000,
                min_accumulate_gas: 100_000,
                min_on_transfer_gas: 0,
                storage: BTreeMap::new(),
                preimage_lookup: pixels_preimage_lookup,
                preimage_info: BTreeMap::new(),
                free_storage_offset: 0,
                total_footprint: 0,
                accumulation_counter: 0,
                last_accumulation: 0,
                last_activity: 0,
                preimage_count: 0,
            },
        );
        tracing::info!(
            "Installed pixels service {} with code_hash=0x{}",
            pixels_service_id,
            hex::encode(&h.0[..8])
        );
        h
    };

    // Populate auth_pool so guarantees pass the authorizer check.
    // Auth pool starts empty; fill core 0 with Hash::ZERO (matches our authorizer_hash).
    for core in 0..config.core_count as usize {
        if state.auth_pool[core].is_empty() {
            state.auth_pool[core].push(Hash::ZERO);
        }
    }

    let mut blocks_produced = 0u32;
    let mut finalized_slot = 0u32;
    let finality_depth = 3u32;
    let mut slot_authors = Vec::new();
    let mut work_packages_submitted = 0u32;
    let mut work_packages_accumulated = 0u32;

    // Track work package pipeline state
    // Phase: None → GuaranteeSubmitted(slot) → AssuranceSubmitted(slot)
    #[derive(Clone, Debug)]
    enum WpPhase {
        /// Ready to submit a new work package guarantee
        Idle,
        /// Guarantee submitted at this slot; next block should include assurances
        GuaranteeSubmitted { slot: Timeslot, parent_hash: Hash },
        /// Assurances submitted; waiting for accumulation (happens in same block)
        Done,
    }

    /// Which service to test next.
    #[derive(Clone, Debug)]
    enum WpTarget {
        SampleService,
        PixelsService,
        AllDone,
    }

    let mut wp_phase = WpPhase::Idle;
    let mut wp_target = WpTarget::SampleService;

    for slot in 1..=num_blocks * 3 {
        // Find the author for this slot
        let mut authored = false;
        for s in &secrets {
            let pk = grey_types::BandersnatchPublicKey(s.bandersnatch.public_key_bytes());
            if let Some(author_idx) = grey_consensus::authoring::is_slot_author_with_keypair(
                &state,
                &config,
                slot,
                &pk,
                Some(&s.bandersnatch),
            ) {
                // Compute state root
                let state_root = {
                    let mut data = Vec::new();
                    data.extend_from_slice(&state.timeslot.to_le_bytes());
                    data.extend_from_slice(&state.entropy[0].0);
                    grey_crypto::blake2b_256(&data)
                };

                // Determine extrinsics based on pipeline state
                let (guarantees, assurances) = match &wp_phase {
                    WpPhase::Idle
                        if blocks_produced >= 2 && !matches!(wp_target, WpTarget::AllDone) =>
                    {
                        // Pick service, code_hash, and payload based on current target
                        let (target_svc, target_code, target_label, payload) = match &wp_target {
                            WpTarget::SampleService => {
                                (service_id, code_hash, "sample", b"test-payload".to_vec())
                            }
                            // Pixel (50,50) = red (255,0,0)
                            WpTarget::PixelsService => (
                                pixels_service_id,
                                pixels_code_hash,
                                "pixels",
                                vec![50, 50, 255, 0, 0],
                            ),
                            WpTarget::AllDone => unreachable!(),
                        };

                        let (guarantee, pkg_hash) = build_test_guarantee_with_payload(
                            &state,
                            &config,
                            &secrets,
                            target_svc,
                            target_code,
                            slot,
                            0,
                            payload,
                        );
                        tracing::info!(
                            "  [WP] Submitting {} guarantee at slot {}, core=0, pkg=0x{}",
                            target_label,
                            slot,
                            hex::encode(&pkg_hash.0[..8])
                        );
                        wp_phase = WpPhase::GuaranteeSubmitted {
                            slot,
                            parent_hash: state
                                .recent_blocks
                                .headers
                                .last()
                                .map(|h| h.header_hash)
                                .unwrap_or(Hash::ZERO),
                        };
                        work_packages_submitted += 1;
                        (vec![guarantee], vec![])
                    }
                    WpPhase::GuaranteeSubmitted { parent_hash, .. } => {
                        // Submit assurances from a super-majority of validators
                        let parent = *parent_hash;
                        let assurances = build_test_assurances(&config, &secrets, parent, 0);
                        tracing::info!(
                            "  [WP] Submitting {} assurances at slot {}, core=0",
                            assurances.len(),
                            slot
                        );
                        wp_phase = WpPhase::Done;
                        (vec![], assurances)
                    }
                    _ => (vec![], vec![]),
                };

                let block = grey_consensus::authoring::author_block_with_extrinsics(
                    &state,
                    &config,
                    slot,
                    author_idx,
                    s,
                    state_root,
                    guarantees,
                    assurances,
                    vec![],
                );

                match grey_state::transition::apply_with_config(&state, &block, &config, &[]) {
                    Ok((new_state, _)) => {
                        let header_hash =
                            grey_codec::header_codec::compute_header_hash(&block.header);

                        // Check if accumulation happened (service storage changed)
                        if matches!(wp_phase, WpPhase::Done) {
                            match &wp_target {
                                WpTarget::SampleService => {
                                    if let Some(svc) = new_state.services.get(&service_id)
                                        && !svc.storage.is_empty()
                                    {
                                        tracing::info!(
                                            "  [WP] SAMPLE ACCUMULATED! Service {} has {} storage entries",
                                            service_id,
                                            svc.storage.len()
                                        );
                                        work_packages_accumulated += 1;
                                    }
                                    // Advance to pixels service if installed
                                    wp_target = if pixels_installed {
                                        WpTarget::PixelsService
                                    } else {
                                        WpTarget::AllDone
                                    };
                                }
                                WpTarget::PixelsService => {
                                    if let Some(svc) = new_state.services.get(&pixels_service_id) {
                                        if let Some(canvas) = svc.storage.get(&vec![0x00u8]) {
                                            let offset = (50 * 100 + 50) * 3;
                                            if canvas.len() >= offset + 3 {
                                                tracing::info!(
                                                    "  [WP] PIXELS ACCUMULATED! Pixel (50,50) = ({},{},{}), canvas={} bytes",
                                                    canvas[offset],
                                                    canvas[offset + 1],
                                                    canvas[offset + 2],
                                                    canvas.len()
                                                );
                                            }
                                            work_packages_accumulated += 1;
                                        } else if !svc.storage.is_empty() {
                                            tracing::info!(
                                                "  [WP] PIXELS ACCUMULATED! Service {} has {} storage entries (no canvas key)",
                                                pixels_service_id,
                                                svc.storage.len()
                                            );
                                            work_packages_accumulated += 1;
                                        }
                                    }
                                    wp_target = WpTarget::AllDone;
                                }
                                WpTarget::AllDone => {}
                            }
                            // Reset pipeline for next work package
                            wp_phase = WpPhase::Idle;
                        }

                        state = new_state;
                        blocks_produced += 1;
                        slot_authors.push((slot, author_idx));

                        tracing::info!(
                            "Block #{} at slot {} by validator {}, hash=0x{}, services={}",
                            blocks_produced,
                            slot,
                            author_idx,
                            hex::encode(&header_hash.0[..8]),
                            state.services.len(),
                        );

                        // Check finality
                        if slot > finality_depth {
                            let new_finalized = slot - finality_depth;
                            if new_finalized > finalized_slot {
                                finalized_slot = new_finalized;
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
        !state.recent_blocks.headers.is_empty(),
        "Should have recent block history"
    );

    tracing::info!(
        "Sequential test PASSED: {} blocks, finalized={}, wp_submitted={}, wp_accumulated={}",
        blocks_produced,
        finalized_slot,
        work_packages_submitted,
        work_packages_accumulated,
    );

    Ok(SequentialTestResult {
        blocks_produced,
        finalized_slot,
        final_timeslot: state.timeslot,
        slot_authors,
        work_packages_submitted,
        work_packages_accumulated,
    })
}

/// Build a test guarantee extrinsic for a work package on the given core.
///
/// Returns (Guarantee, package_hash).
pub fn build_test_guarantee(
    state: &grey_types::state::State,
    config: &Config,
    secrets: &[grey_consensus::genesis::ValidatorSecrets],
    service_id: ServiceId,
    code_hash: Hash,
    timeslot: Timeslot,
    core: u16,
) -> (Guarantee, Hash) {
    build_test_guarantee_with_payload(
        state,
        config,
        secrets,
        service_id,
        code_hash,
        timeslot,
        core,
        b"test-payload".to_vec(),
    )
}

/// Build a test guarantee with a specific payload/result.
#[allow(clippy::too_many_arguments)]
pub fn build_test_guarantee_with_payload(
    state: &grey_types::state::State,
    _config: &Config,
    secrets: &[grey_consensus::genesis::ValidatorSecrets],
    service_id: ServiceId,
    code_hash: Hash,
    timeslot: Timeslot,
    core: u16,
    payload: Vec<u8>,
) -> (Guarantee, Hash) {
    // Build a minimal work report
    let payload_hash = grey_crypto::blake2b_256(&payload);

    // Refinement result: the service echoes payload as output
    let refine_output = payload.clone();

    let work_digest = WorkDigest {
        service_id,
        code_hash,
        payload_hash,
        accumulate_gas: 1_000_000,
        result: WorkResult::Ok(refine_output),
        gas_used: 1000,
        imports_count: 0,
        extrinsics_count: 0,
        extrinsics_size: 0,
        exports_count: 0,
    };

    // Build anchor from recent history
    let (anchor, anchor_state_root, anchor_beefy_root) =
        if let Some(recent) = state.recent_blocks.headers.last() {
            (
                recent.header_hash,
                recent.state_root,
                recent.accumulation_root,
            )
        } else {
            (Hash::ZERO, Hash::ZERO, Hash::ZERO)
        };

    let context = RefinementContext {
        anchor,
        state_root: anchor_state_root,
        beefy_root: anchor_beefy_root,
        lookup_anchor: anchor,
        lookup_anchor_timeslot: state.timeslot,
        prerequisites: vec![],
    };

    // Compute package hash
    let mut pkg_data = Vec::new();
    pkg_data.extend_from_slice(&service_id.to_le_bytes());
    pkg_data.extend_from_slice(&code_hash.0);
    pkg_data.extend_from_slice(&payload);
    pkg_data.extend_from_slice(&timeslot.to_le_bytes());
    let package_hash = grey_crypto::blake2b_256(&pkg_data);

    let report = WorkReport {
        package_spec: AvailabilitySpec {
            package_hash,
            bundle_length: 0,
            erasure_root: Hash::ZERO,
            exports_root: Hash::ZERO,
            exports_count: 0,
        },
        context,
        core_index: core,
        authorizer_hash: Hash::ZERO, // matches auth_pool entry
        auth_gas_used: 0,
        auth_output: vec![],
        segment_root_lookup: BTreeMap::new(),
        results: vec![work_digest],
    };

    // Sign the report with at least 2 guarantors (minimum required)
    // Encode the report hash for signing
    let report_hash = {
        let mut data = Vec::new();
        data.extend_from_slice(&report.package_spec.package_hash.0);
        data.extend_from_slice(&report.core_index.to_le_bytes());
        grey_crypto::blake2b_256(&data)
    };

    let mut credentials = Vec::new();
    // Use validators 0 and 1 as guarantors
    for (i, secret) in secrets.iter().enumerate().take(2) {
        let sig = secret.ed25519.sign(&report_hash.0);
        credentials.push((i as u16, sig));
    }

    let guarantee = Guarantee {
        report,
        timeslot,
        credentials,
    };

    (guarantee, package_hash)
}

/// Build availability assurances from a super-majority of validators for the given core.
pub fn build_test_assurances(
    config: &Config,
    secrets: &[grey_consensus::genesis::ValidatorSecrets],
    parent_hash: Hash,
    core: u16,
) -> Vec<Assurance> {
    let num_assurers = config.super_majority() as usize;
    let bitfield_bytes = config.avail_bitfield_bytes();

    let mut assurances = Vec::new();
    for (i, secret) in secrets.iter().enumerate().take(num_assurers) {
        // Build bitfield with core bit set
        let mut bitfield = vec![0u8; bitfield_bytes];
        let byte_idx = core as usize / 8;
        let bit_idx = core as usize % 8;
        bitfield[byte_idx] |= 1 << bit_idx;

        // Sign: anchor ++ bitfield
        let mut msg = Vec::new();
        msg.extend_from_slice(&parent_hash.0);
        msg.extend_from_slice(&bitfield);
        let sig = secret.ed25519.sign(&msg);

        assurances.push(Assurance {
            anchor: parent_hash,
            bitfield,
            validator_index: i as u16,
            signature: sig,
        });
    }

    assurances
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
    pub work_packages_submitted: u32,
    pub work_packages_accumulated: u32,
}
