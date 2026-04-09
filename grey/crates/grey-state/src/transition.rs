//! Block state transition implementation (eq 4.1, 4.5-4.20).

use crate::TransitionError;

use grey_types::Hash;
use grey_types::config::Config;
#[cfg(test)]
use grey_types::constants::*;
use grey_types::header::Block;
use grey_types::state::{PendingReport, State};

const MINIMUM_GUARANTORS: usize = 2; // Minimum credential count for guarantees

/// Apply a block to produce the posterior state.
///
/// The transition follows the dependency graph in eq 4.5-4.20:
/// 1. Timekeeping: τ' = HT
/// 2. Judgments: ψ' from ED
/// 3. Recent history: β' from prior state
/// 4. Safrole: γ', κ', λ', ι', η' from consensus
/// 5. Reporting/assurance: ρ' from EA, EG
/// 6. Accumulation: δ', χ', ι', ϕ' from R (available reports)
/// 7. Statistics: π' from block activity
/// 8. Authorization: α' from ϕ'
pub fn apply(state: &State, block: &Block) -> Result<State, TransitionError> {
    let (new_state, _opaque) = apply_with_config(state, block, &Config::full(), &[])?;
    Ok(new_state)
}

/// Apply a block with a specific configuration (for testing with tiny constants).
/// Returns (new_state, remaining_opaque_data) where remaining_opaque_data is the
/// opaque service data after consuming entries accessed during accumulation.
#[allow(clippy::type_complexity)]
pub fn apply_with_config(
    state: &State,
    block: &Block,
    config: &Config,
    opaque_data: &[([u8; 31], Vec<u8>)],
) -> Result<(State, Vec<([u8; 31], Vec<u8>)>), TransitionError> {
    let header = &block.header;
    let extrinsic = &block.extrinsic;

    // Basic validation
    validate_header(state, header, config)?;

    // Clone state for mutation
    let mut new_state = state.clone();
    let prior_timeslot = state.timeslot;

    // Step 1: Timekeeping (eq 6.1)
    new_state.timeslot = header.timeslot;

    // Step 2: Process judgments/disputes (Section 10)
    apply_judgments(&mut new_state, &extrinsic.disputes, config);

    // Step 3: Clear disputed pending reports (eq 10.15)
    clear_disputed_reports(&mut new_state, &extrinsic.disputes, config);

    // Step 4: Safrole sub-transition (Section 6)
    apply_safrole(
        &mut new_state,
        header,
        &block.extrinsic.tickets,
        config,
        prior_timeslot,
    );

    // Step 5: Process availability assurances (Section 11.2)
    let available_reports = process_assurances(
        &mut new_state,
        &extrinsic.assurances,
        header.timeslot,
        config,
    );

    // Step 6: Process work report guarantees (Section 11.4)
    // Collect incoming reports (I) before processing guarantees
    let incoming_reports: Vec<&grey_types::work::WorkReport> =
        extrinsic.guarantees.iter().map(|g| &g.report).collect();
    process_guarantees(&mut new_state, &extrinsic.guarantees, header.timeslot)?;

    // Step 7: Accumulation (Section 12)
    let (accumulate_root, accumulation_stats, remaining_opaque) =
        crate::accumulate::run_accumulation(
            config,
            &mut new_state,
            state.timeslot,
            available_reports.clone(),
            opaque_data,
        );

    // Step 8: Update recent block history β' (Section 7)
    {
        let header_hash = grey_crypto::header_hash(header);
        let work_packages: Vec<(Hash, Hash)> = extrinsic
            .guarantees
            .iter()
            .map(|g| {
                (
                    g.report.package_spec.package_hash,
                    g.report.package_spec.exports_root,
                )
            })
            .collect();
        let input = crate::history::HistoryInput {
            header_hash,
            parent_state_root: header.state_root,
            accumulate_root,
            work_packages,
        };
        crate::history::update_history(&mut new_state.recent_blocks, &input);
    }

    // Step 9: Update validator statistics (Section 13)
    crate::statistics::update_statistics(
        config,
        &mut new_state.statistics,
        state.timeslot,
        header.timeslot,
        header.author_index,
        extrinsic,
        &incoming_reports,
        &available_reports,
        &accumulation_stats,
    );

    // Step 10: Process preimages (Section 12.4)
    process_preimages(
        &mut new_state,
        &extrinsic.preimages,
        header.timeslot,
        &remaining_opaque,
    );

    // Step 11: Authorization pool rotation (Section 8)
    rotate_auth_pool(&mut new_state, &extrinsic.guarantees, config);

    Ok((new_state, remaining_opaque))
}

/// Validate block header against current state.
fn validate_header(
    state: &State,
    header: &grey_types::header::Header,
    _config: &Config,
) -> Result<(), TransitionError> {
    // Timeslot must advance (eq 6.1: τ' > τ)
    if header.timeslot <= state.timeslot {
        return Err(TransitionError::InvalidTimeslot {
            block_slot: header.timeslot,
            prior_slot: state.timeslot,
        });
    }

    // Author index must be valid
    if header.author_index as usize >= state.current_validators.len() {
        return Err(TransitionError::InvalidAuthorIndex(header.author_index));
    }

    Ok(())
}

/// Process disputes extrinsic to update judgments (Section 10, eq 10.16-10.19).
fn apply_judgments(
    state: &mut State,
    disputes: &grey_types::header::DisputesExtrinsic,
    _config: &Config,
) {
    let val_count = state.current_validators.len();
    let supermajority = Config::super_majority_of(val_count);
    let one_third = val_count / 3;

    // Process verdicts (eq 10.12-10.19)
    for verdict in &disputes.verdicts {
        let positive_count: usize = verdict.positive_count();

        if positive_count >= supermajority {
            state.judgments.good.insert(verdict.report_hash);
        } else if positive_count == 0 {
            state.judgments.bad.insert(verdict.report_hash);
        } else if positive_count <= one_third {
            state.judgments.wonky.insert(verdict.report_hash);
        }
    }

    // Process culprits — add offending validator keys (eq 10.19)
    for culprit in &disputes.culprits {
        state.judgments.offenders.insert(culprit.validator_key);
    }

    // Process faults — add offending validator keys (eq 10.19)
    for fault in &disputes.faults {
        state.judgments.offenders.insert(fault.validator_key);
    }
}

/// Clear pending reports that have been judged non-good (eq 10.15).
fn clear_disputed_reports(
    state: &mut State,
    disputes: &grey_types::header::DisputesExtrinsic,
    _config: &Config,
) {
    let supermajority = Config::super_majority_of(state.current_validators.len());

    for verdict in &disputes.verdicts {
        let positive_count: usize = verdict.positive_count();

        // If not supermajority good, clear from pending
        if positive_count < supermajority {
            for slot in state.pending_reports.iter_mut() {
                if let Some(pending) = slot {
                    let report_hash = grey_crypto::report_hash(&pending.report);
                    if report_hash == verdict.report_hash {
                        *slot = None;
                    }
                }
            }
        }
    }
}

/// Apply Safrole sub-transition (Section 6).
///
/// Updates entropy, and on epoch boundaries: key rotation, seal-key series.
/// `prior_timeslot` is the pre-state timeslot τ (before τ' = H_T update).
fn apply_safrole(
    state: &mut State,
    header: &grey_types::header::Header,
    tickets: &[grey_types::header::TicketProof],
    config: &Config,
    prior_timeslot: u32,
) {
    // Extract VRF output Y(H_V) from the entropy source signature
    let vrf_output = grey_crypto::bandersnatch::vrf_output_hash(&header.vrf_signature.0)
        .map(Hash)
        .unwrap_or(Hash::ZERO);

    // Build Safrole state from the main state, using prior timeslot (not already-updated τ')
    let safrole_pre = crate::safrole::SafroleState {
        tau: prior_timeslot,
        eta: state.entropy,
        lambda: state.previous_validators.clone(),
        kappa: state.current_validators.clone(),
        gamma_k: state.safrole.pending_keys.clone(),
        iota: state.pending_validators.clone(),
        gamma_a: state.safrole.ticket_accumulator.clone(),
        gamma_s: state.safrole.seal_key_series.clone(),
        gamma_z: state.safrole.ring_root.clone(),
        offenders: state.judgments.offenders.iter().cloned().collect(),
    };

    let input = crate::safrole::SafroleInput {
        slot: header.timeslot,
        entropy: vrf_output,
        extrinsic: tickets.to_vec(),
    };

    let ring_size = safrole_pre.gamma_k.len();
    let verifier = move |tp: &grey_types::header::TicketProof,
                         gamma_z: &grey_types::BandersnatchRingRoot,
                         eta2: &Hash,
                         attempt: u8|
          -> Option<Hash> {
        let ticket_id_bytes = grey_crypto::bandersnatch::verify_ticket(
            ring_size, &gamma_z.0, &eta2.0, attempt, &tp.proof,
        )?;
        Some(Hash(ticket_id_bytes))
    };

    match crate::safrole::process_safrole(config, &input, &safrole_pre, Some(&verifier)) {
        Ok(output) => {
            state.entropy = output.state.eta;
            state.previous_validators = output.state.lambda;
            state.current_validators = output.state.kappa;
            state.safrole.pending_keys = output.state.gamma_k;
            state.safrole.ring_root = output.state.gamma_z;
            state.safrole.seal_key_series = output.state.gamma_s;
            state.safrole.ticket_accumulator = output.state.gamma_a;
        }
        Err(_e) => {
            // If Safrole fails, still update entropy: η₀' = H(η₀ ⌢ Y(H_V))
            state.entropy[0] = crate::safrole::accumulate_entropy(&state.entropy[0], &vrf_output);
        }
    }
}

/// Process availability assurances (Section 11.2, eq 11.10-11.17).
fn process_assurances(
    state: &mut State,
    assurances: &grey_types::header::AssurancesExtrinsic,
    current_timeslot: grey_types::Timeslot,
    config: &Config,
) -> Vec<grey_types::work::WorkReport> {
    let threshold = Config::super_majority_of(state.current_validators.len()) as u32;
    let mut available = Vec::new();

    let num_cores = state.pending_reports.len();
    let mut assurance_counts = vec![0u32; num_cores];

    for assurance in assurances {
        for (core, count) in assurance_counts.iter_mut().enumerate() {
            if assurance.has_bit(core) {
                *count += 1;
            }
        }
    }

    for (core, count) in assurance_counts.iter().enumerate() {
        if *count >= threshold
            && let Some(pending) = &state.pending_reports[core]
        {
            available.push(pending.report.clone());
        }
    }

    for (core, slot) in state.pending_reports.iter_mut().enumerate() {
        if let Some(pending) = slot {
            let is_available = assurance_counts.get(core).copied().unwrap_or(0) >= threshold;
            let is_timed_out = current_timeslot >= pending.timeslot + config.availability_timeout;

            if is_available || is_timed_out {
                *slot = None;
            }
        }
    }

    available
}

/// Process work report guarantees (Section 11.4, eq 11.23-11.42).
fn process_guarantees(
    state: &mut State,
    guarantees: &grey_types::header::GuaranteesExtrinsic,
    current_timeslot: grey_types::Timeslot,
) -> Result<(), TransitionError> {
    for guarantee in guarantees {
        let report = &guarantee.report;

        // Validate: core index must be valid
        if report.core_index as usize >= state.pending_reports.len() {
            return Err(TransitionError::InvalidExtrinsic(format!(
                "invalid core index: {}",
                report.core_index
            )));
        }

        // Validate: core slot must be empty
        let core = report.core_index as usize;
        if state.pending_reports[core].is_some() {
            return Err(TransitionError::InvalidExtrinsic(format!(
                "core {} already has pending report",
                core
            )));
        }

        // Validate: minimum number of guarantors (eq 11.24-11.26)
        if guarantee.credentials.len() < MINIMUM_GUARANTORS {
            return Err(TransitionError::InvalidExtrinsic(format!(
                "insufficient guarantors: {} < {}",
                guarantee.credentials.len(),
                MINIMUM_GUARANTORS
            )));
        }

        // Place report in pending slot
        state.pending_reports[core] = Some(PendingReport {
            report: report.clone(),
            timeslot: current_timeslot,
        });
    }

    Ok(())
}

/// Process preimage submissions — preimage integration function I (GP section 12.4).
///
/// δ' = I(δ‡, E_P) where:
/// - Y(d, s, i) checks d[s].l[(H(i), |i|)] == [] (requested state with empty timeslots)
/// - For valid preimages: d'[s].l[(H(i), |i|)] = [τ'], d'[s].p[H(i)] = i
fn process_preimages(
    state: &mut State,
    preimages: &grey_types::header::PreimagesExtrinsic,
    current_timeslot: grey_types::Timeslot,
    opaque_data: &[([u8; 31], Vec<u8>)],
) {
    for (service_id, data) in preimages {
        if let Some(account) = state.services.get_mut(service_id) {
            let hash = grey_crypto::blake2b_256(data);
            let key = (hash, data.len() as u32);

            // Promote from opaque data if not in structured preimage_info
            if let std::collections::btree_map::Entry::Vacant(e) = account.preimage_info.entry(key)
            {
                let state_key = grey_merkle::state_serial::compute_preimage_info_state_key(
                    *service_id,
                    &hash,
                    data.len() as u32,
                );
                if let Some(opaque_entry) = opaque_data.iter().find(|(k, _)| *k == state_key) {
                    let timeslots =
                        crate::accumulate::decode_preimage_info_timeslots(&opaque_entry.1);
                    e.insert(timeslots);
                }
            }

            // GP eq 12.35: preimage_info entry must exist (solicited)
            let timeslots = match account.preimage_info.get(&key) {
                Some(ts) => ts.clone(),
                None => continue, // Not solicited; ignore
            };

            // Store the preimage blob: d'[s].p[H(i)] = i
            account.preimage_lookup.insert(hash, data.clone());

            // Append current timeslot: d'[s].l[(H(i), |i|)] = ts ++ [τ']
            let mut new_ts = timeslots;
            new_ts.push(current_timeslot);
            account.preimage_info.insert(key, new_ts);
        }
    }
}

/// Rotate authorization pool from queue (Section 8, eq 8.2-8.3).
///
/// α'[c] = ←(F(c) ⧺ φ'[c][H_T]^↻)^O
///
/// F(c) = α[c] minus the used authorizer if a guarantee was submitted for core c,
///        or α[c] unchanged otherwise.
/// ⧺ = concatenate new auth from queue
/// ← = take the rightmost O elements
fn rotate_auth_pool(
    state: &mut State,
    guarantees: &grey_types::header::GuaranteesExtrinsic,
    config: &Config,
) {
    let timeslot = state.timeslot;
    let q = config.auth_queue_size;

    for core in 0..state.auth_pool.len().min(config.core_count as usize) {
        // F(c): remove used authorizer if a guarantee was submitted for this core
        // α[c] ⊢ {(g_r)_a} — remove the specific authorizer hash by VALUE
        if let Some(guarantee) = guarantees
            .iter()
            .find(|g| g.report.core_index as usize == core)
        {
            let auth_hash = &guarantee.report.authorizer_hash;
            if let Some(pos) = state.auth_pool[core].iter().position(|h| h == auth_hash) {
                state.auth_pool[core].remove(pos);
            }
        }

        // Append new auth from queue: φ'[c][H_T mod Q]
        // auth_queue is indexed [slot][core], so: auth_queue[H_T % Q][c]
        let queue_slot_idx = timeslot as usize % q;
        if queue_slot_idx < state.auth_queue.len() {
            let new_auth = state.auth_queue[queue_slot_idx]
                .get(core)
                .copied()
                .unwrap_or(Hash::ZERO);
            state.auth_pool[core].push(new_auth);
        }

        // Truncate to O: take rightmost O elements (← ... ^O)
        let o = config.auth_pool_size;
        if state.auth_pool[core].len() > o {
            let start = state.auth_pool[core].len() - o;
            state.auth_pool[core].drain(..start);
        }
    }
}

// Debug wrapper functions for step-by-step conformance debugging
pub fn debug_apply_safrole(
    state: &mut State,
    header: &grey_types::header::Header,
    tickets: &[grey_types::header::TicketProof],
    config: &Config,
    prior_timeslot: u32,
) {
    apply_safrole(state, header, tickets, config, prior_timeslot);
}

pub fn debug_process_assurances(
    state: &mut State,
    assurances: &grey_types::header::AssurancesExtrinsic,
    timeslot: grey_types::Timeslot,
    config: &Config,
) -> Vec<grey_types::work::WorkReport> {
    process_assurances(state, assurances, timeslot, config)
}

pub fn debug_process_guarantees(
    state: &mut State,
    guarantees: &grey_types::header::GuaranteesExtrinsic,
    timeslot: grey_types::Timeslot,
) -> Result<(), TransitionError> {
    process_guarantees(state, guarantees, timeslot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use grey_types::header::*;
    use grey_types::state::*;
    use grey_types::validator::ValidatorKey;
    use grey_types::*;
    use std::collections::BTreeMap;

    fn make_default_state() -> State {
        let validators: Vec<ValidatorKey> = (0..TOTAL_VALIDATORS)
            .map(|_| ValidatorKey::default())
            .collect();

        State {
            auth_pool: vec![vec![]; TOTAL_CORES as usize],
            recent_blocks: RecentBlocks {
                headers: vec![],
                accumulation_log: vec![],
            },
            accumulation_outputs: vec![],
            safrole: SafroleState {
                pending_keys: vec![],
                ring_root: BandersnatchRingRoot::default(),
                seal_key_series: SealKeySeries::Fallback(vec![]),
                ticket_accumulator: vec![],
            },
            services: BTreeMap::new(),
            entropy: [Hash::ZERO; 4],
            pending_validators: validators.clone(),
            current_validators: validators.clone(),
            previous_validators: validators,
            pending_reports: vec![None; TOTAL_CORES as usize],
            timeslot: 0,
            auth_queue: vec![vec![]; TOTAL_CORES as usize],
            privileged_services: PrivilegedServices::default(),
            judgments: Judgments::default(),
            statistics: ValidatorStatistics {
                current: vec![ValidatorRecord::default(); TOTAL_VALIDATORS as usize],
                last: vec![],
                core_stats: vec![],
                service_stats: BTreeMap::new(),
            },
            accumulation_queue: vec![],
            accumulation_history: vec![],
        }
    }

    fn make_empty_block(timeslot: Timeslot) -> Block {
        Block {
            header: Header {
                data: UnsignedHeader {
                    parent_hash: Hash::ZERO,
                    state_root: Hash::ZERO,
                    extrinsic_hash: Hash::ZERO,
                    timeslot,
                    epoch_marker: None,
                    tickets_marker: None,
                    author_index: 0,
                    vrf_signature: BandersnatchSignature::default(),
                    offenders_marker: vec![],
                },
                seal: BandersnatchSignature::default(),
            },
            extrinsic: Extrinsic {
                tickets: vec![],
                preimages: vec![],
                guarantees: vec![],
                assurances: vec![],
                disputes: DisputesExtrinsic::default(),
            },
        }
    }

    #[test]
    fn test_apply_block_advances_timeslot() {
        let state = make_default_state();
        let block = make_empty_block(1);
        let new_state = apply(&state, &block).unwrap();
        assert_eq!(new_state.timeslot, 1);
    }

    #[test]
    fn test_timeslot_must_advance() {
        let state = make_default_state();
        let block = make_empty_block(0); // same timeslot
        assert!(apply(&state, &block).is_err());
    }

    #[test]
    fn test_invalid_author_index() {
        let state = make_default_state();
        let mut block = make_empty_block(1);
        block.header.author_index = TOTAL_VALIDATORS; // out of range
        assert!(apply(&state, &block).is_err());
    }

    #[test]
    fn test_judgments_good_verdict() {
        let state = make_default_state();
        let hash = Hash([1u8; 32]);

        // Create a verdict with supermajority positive judgments
        let supermajority = (TOTAL_VALIDATORS * 2 / 3) + 1;
        let judgments: Vec<Judgment> = (0..supermajority)
            .map(|i| Judgment {
                is_valid: true,
                validator_index: i,
                signature: Ed25519Signature::default(),
            })
            .collect();

        let mut block = make_empty_block(1);
        block.extrinsic.disputes.verdicts.push(Verdict {
            report_hash: hash,
            age: 0,
            judgments,
        });

        let new_state = apply(&state, &block).unwrap();
        assert!(new_state.judgments.good.contains(&hash));
    }

    #[test]
    fn test_judgments_bad_verdict() {
        let state = make_default_state();
        let hash = Hash([2u8; 32]);

        // All judgments say invalid
        let mut block = make_empty_block(1);
        block.extrinsic.disputes.verdicts.push(Verdict {
            report_hash: hash,
            age: 0,
            judgments: vec![], // 0 positive = bad
        });

        let new_state = apply(&state, &block).unwrap();
        assert!(new_state.judgments.bad.contains(&hash));
    }

    #[test]
    fn test_statistics_block_produced() {
        let state = make_default_state();
        let mut block = make_empty_block(1);
        block.header.author_index = 5;

        let new_state = apply(&state, &block).unwrap();
        assert_eq!(new_state.statistics.current[5].blocks_produced, 1);
    }

    #[test]
    fn test_statistics_epoch_rotation() {
        let mut state = make_default_state();
        state.statistics.current[0].blocks_produced = 10;

        // Block in a new epoch
        let block = make_empty_block(EPOCH_LENGTH + 1);

        let new_state = apply(&state, &block).unwrap();
        // Old stats should be in `last`
        assert_eq!(new_state.statistics.last[0].blocks_produced, 10);
        // Current should be reset (except for this block's author)
        assert_eq!(new_state.statistics.current[0].blocks_produced, 1);
    }

    #[test]
    fn test_recent_history_updated() {
        let state = make_default_state();
        let block = make_empty_block(1);

        let new_state = apply(&state, &block).unwrap();
        assert_eq!(new_state.recent_blocks.headers.len(), 1);
    }

    #[test]
    fn test_recent_history_capped() {
        let mut state = make_default_state();
        // Fill with H entries
        for i in 0..RECENT_HISTORY_SIZE {
            state.recent_blocks.headers.push(RecentBlockInfo {
                header_hash: Hash([i as u8; 32]),
                state_root: Hash::ZERO,
                accumulation_root: Hash::ZERO,
                reported_packages: BTreeMap::new(),
            });
        }
        state.timeslot = RECENT_HISTORY_SIZE as u32;

        let block = make_empty_block(RECENT_HISTORY_SIZE as u32 + 1);
        let new_state = apply(&state, &block).unwrap();
        assert_eq!(new_state.recent_blocks.headers.len(), RECENT_HISTORY_SIZE);
    }

    #[test]
    fn test_preimage_processing() {
        let mut state = make_default_state();
        let service_id: ServiceId = 1;
        let preimage_data = b"hello world".to_vec();
        let hash = grey_crypto::blake2b_256(&preimage_data);
        let key = (hash, preimage_data.len() as u32);

        // Create service with a solicited preimage_info entry (empty timeslots = requested)
        let mut preimage_info = BTreeMap::new();
        preimage_info.insert(key, vec![]); // empty timeslots = solicited
        state.services.insert(
            service_id,
            ServiceAccount {
                code_hash: Hash::ZERO,
                quota_items: 1_000_000,
                min_accumulate_gas: 0,
                min_on_transfer_gas: 0,
                storage: BTreeMap::new(),
                preimage_lookup: BTreeMap::new(),
                preimage_info,
                quota_bytes: 1_000_000_000,
                total_footprint: 0,
                accumulation_counter: 0,
                last_accumulation: 0,
                last_activity: 0,
                preimage_count: 0,
            },
        );

        let mut block = make_empty_block(1);
        block
            .extrinsic
            .preimages
            .push((service_id, preimage_data.clone()));

        let new_state = apply(&state, &block).unwrap();
        let account = new_state.services.get(&service_id).unwrap();
        // After providing the preimage, preimage_lookup should contain it
        assert!(account.preimage_lookup.contains_key(&hash));
        // preimage_info should be updated with the current timeslot
        assert_eq!(account.preimage_info.get(&key), Some(&vec![1u32]));
    }
}
