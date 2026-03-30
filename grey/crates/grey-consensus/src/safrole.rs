//! Safrole consensus mechanism (Section 6 of the Gray Paper).
//!
//! Key operations:
//! - Outside-in sequencer Z for ordering tickets (eq 6.25)
//! - Fallback key sequence F (eq 6.26)
//! - Seal-key series generation (eq 6.24)
//! - Entropy accumulation (eq 6.22-6.23)
//! - Key rotation on epoch boundaries (eq 6.13-6.14)
//! - Ticket contest management (eq 6.29-6.35)

pub use grey_state::safrole::{compute_ring_root, merge_tickets, outside_in_sequence};
use grey_types::constants::*;
use grey_types::header::{EpochMarker, Ticket, TicketProof};
use grey_types::state::{Judgments, SafroleState, SealKeySeries, State};
use grey_types::validator::ValidatorKey;
use grey_types::{BandersnatchPublicKey, Hash};

/// Errors from Safrole state transition.
#[derive(Debug, thiserror::Error)]
pub enum SafroleError {
    #[error("tickets submitted outside submission window (slot {0} >= Y={1})")]
    TicketSubmissionClosed(u32, u32),

    #[error("too many tickets submitted: {0} > K={1}")]
    TooManyTickets(usize, usize),

    #[error("submitted tickets not sorted by identifier")]
    TicketsNotSorted,

    #[error("duplicate ticket identifier")]
    DuplicateTicket,

    #[error("submitted ticket not retained in accumulator (eq 6.35)")]
    TicketNotRetained,
}

/// Fallback key sequence F (eq 6.26).
///
/// F(r, k) generates E Bandersnatch keys, one per slot, by deterministically
/// selecting validators using entropy `r` as a seed.
///
/// For each slot i in 0..E:
///   idx = LE32(H(r ++ LE32(i))[0..4]) mod |k|
///   `result[i]` = `k[idx]`.bandersnatch
pub fn fallback_key_sequence(
    entropy: &Hash,
    validators: &[ValidatorKey],
) -> Vec<BandersnatchPublicKey> {
    let v = validators.len();
    if v == 0 {
        return vec![BandersnatchPublicKey::default(); EPOCH_LENGTH as usize];
    }

    (0..EPOCH_LENGTH)
        .map(|i| {
            // H(r ++ E4(i))
            let mut preimage = Vec::with_capacity(36);
            preimage.extend_from_slice(&entropy.0);
            preimage.extend_from_slice(&i.to_le_bytes());
            let hash = grey_crypto::blake2b_256(&preimage);

            // E4⁻¹(hash[0..4]) mod |k|
            let idx = u32::from_le_bytes([hash.0[0], hash.0[1], hash.0[2], hash.0[3]]) as usize % v;
            validators[idx].bandersnatch
        })
        .collect()
}

/// Filter offending validators from a key set (eq 6.14: Φ).
///
/// Replaces any validator whose Ed25519 key is in the offenders set with the null key.
pub fn filter_offenders(keys: &[ValidatorKey], offenders: &Judgments) -> Vec<ValidatorKey> {
    keys.iter()
        .map(|k| {
            if offenders.offenders.contains(&k.ed25519) {
                ValidatorKey::null()
            } else {
                k.clone()
            }
        })
        .collect()
}

/// Accumulate entropy (eq 6.22).
///
/// η₀' = H(η₀ ++ Y(H_V))
///
/// `vrf_output` is Y(H_V), the VRF output from the block header's entropy signature.
pub fn accumulate_entropy(current_entropy: &Hash, vrf_output: &[u8; 32]) -> Hash {
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(&current_entropy.0);
    preimage.extend_from_slice(vrf_output);
    grey_crypto::blake2b_256(&preimage)
}

/// Apply the full Safrole state transition for a block.
///
/// This handles:
/// - Entropy accumulation (eq 6.22-6.23)
/// - Key rotation on epoch boundaries (eq 6.13-6.14)
/// - Seal-key series generation (eq 6.24)
/// - Ticket accumulation (eq 6.34)
/// - Epoch and winning-tickets markers (eq 6.27-6.28)
pub fn apply_safrole(
    state: &State,
    new_timeslot: u32,
    vrf_output: &[u8; 32],
    ticket_proofs: &[TicketProof],
) -> Result<SafroleOutput, SafroleError> {
    let old_epoch = state.timeslot / EPOCH_LENGTH;
    let new_epoch = new_timeslot / EPOCH_LENGTH;
    let old_slot = state.timeslot % EPOCH_LENGTH;
    let new_slot = new_timeslot % EPOCH_LENGTH;
    let is_epoch_change = new_epoch > old_epoch;

    // --- Entropy (eq 6.22-6.23) ---

    // η₀' = H(η₀ ++ Y(H_V))
    let new_eta0 = accumulate_entropy(&state.entropy[0], vrf_output);

    // History rotation on epoch boundary
    let (new_eta1, new_eta2, new_eta3) = if is_epoch_change {
        // (η₁', η₂', η₃') = (η₀, η₁, η₂) — note: pre-update η₀
        (state.entropy[0], state.entropy[1], state.entropy[2])
    } else {
        (state.entropy[1], state.entropy[2], state.entropy[3])
    };

    let new_entropy = [new_eta0, new_eta1, new_eta2, new_eta3];

    // --- Key rotation (eq 6.13-6.14) ---

    let (new_pending_keys, new_current_validators, new_previous_validators, new_ring_root) =
        if is_epoch_change {
            // Φ(ι): filter offenders from staging keys
            let filtered = filter_offenders(&state.pending_validators, &state.judgments);

            // z = O([k_b | k ← γP]) — ring root from pending keys' Bandersnatch components
            let ring_root = compute_ring_root(&state.safrole.pending_keys);

            (
                filtered,                           // γP' = Φ(ι)
                state.safrole.pending_keys.clone(), // κ' = γP
                state.current_validators.clone(),   // λ' = κ
                ring_root,                          // γZ' = O([k_b | k ← γP])
            )
        } else {
            (
                state.safrole.pending_keys.clone(),
                state.current_validators.clone(),
                state.previous_validators.clone(),
                state.safrole.ring_root.clone(),
            )
        };

    // --- Seal-key series (eq 6.24) ---

    let new_seal_key_series = if is_epoch_change {
        let single_epoch_advance = new_epoch == old_epoch + 1;
        let was_in_closing = old_slot >= TICKET_SUBMISSION_END;
        let accumulator_full = state.safrole.ticket_accumulator.len() == EPOCH_LENGTH as usize;

        if single_epoch_advance && was_in_closing && accumulator_full {
            // Case 1: Use tickets — Z(γA)
            let sequenced = outside_in_sequence(&state.safrole.ticket_accumulator);
            SealKeySeries::Tickets(sequenced)
        } else {
            // Case 3: Fallback — F(η₂', κ')
            let keys = fallback_key_sequence(&new_eta2, &new_current_validators);
            SealKeySeries::Fallback(keys)
        }
    } else {
        // Case 2: Same epoch, no change
        state.safrole.seal_key_series.clone()
    };

    // --- Ticket accumulation (eq 6.30-6.35) ---

    // Validate ticket submissions
    if !ticket_proofs.is_empty() {
        if new_slot >= TICKET_SUBMISSION_END {
            return Err(SafroleError::TicketSubmissionClosed(
                new_slot,
                TICKET_SUBMISSION_END,
            ));
        }
        if ticket_proofs.len() > MAX_TICKETS_PER_EXTRINSIC {
            return Err(SafroleError::TooManyTickets(
                ticket_proofs.len(),
                MAX_TICKETS_PER_EXTRINSIC,
            ));
        }
    }

    // Derive tickets from proofs (eq 6.31).
    // Full Ring VRF verification is done in grey-state/src/safrole.rs via the
    // ring_vrf_verify callback. This consensus-layer code uses a simplified
    // hash-based derivation for its own ticket management.
    let new_tickets: Vec<Ticket> = ticket_proofs
        .iter()
        .map(|tp| {
            let ticket_id = grey_crypto::blake2b_256(&tp.proof);
            Ticket {
                id: ticket_id,
                attempt: tp.attempt,
            }
        })
        .collect();

    // Validate sorting (eq 6.32)
    for window in new_tickets.windows(2) {
        if window[0].id.0 >= window[1].id.0 {
            return Err(SafroleError::TicketsNotSorted);
        }
    }

    // Validate no duplicates with existing accumulator (eq 6.33)
    let existing_ids: std::collections::BTreeSet<_> = if is_epoch_change {
        // On epoch change, accumulator is cleared
        std::collections::BTreeSet::new()
    } else {
        state
            .safrole
            .ticket_accumulator
            .iter()
            .map(|t| t.id)
            .collect()
    };

    for ticket in &new_tickets {
        if existing_ids.contains(&ticket.id) {
            return Err(SafroleError::DuplicateTicket);
        }
    }

    // Merge into accumulator (eq 6.34)
    let base = if is_epoch_change {
        &[] as &[Ticket]
    } else {
        &state.safrole.ticket_accumulator
    };
    let new_accumulator = merge_tickets(base, &new_tickets, EPOCH_LENGTH as usize);

    // Validate all submitted tickets are retained (eq 6.35)
    let retained_ids: std::collections::BTreeSet<_> =
        new_accumulator.iter().map(|t| t.id).collect();
    for ticket in &new_tickets {
        if !retained_ids.contains(&ticket.id) {
            return Err(SafroleError::TicketNotRetained);
        }
    }

    // --- Epoch marker (eq 6.27) ---

    let epoch_marker = if is_epoch_change {
        Some(EpochMarker {
            entropy: new_eta0,
            entropy_previous: new_eta1,
            validators: new_pending_keys
                .iter()
                .map(|k| (k.bandersnatch, k.ed25519))
                .collect(),
        })
    } else {
        None
    };

    // --- Winning-tickets marker (eq 6.28) ---

    let winning_tickets_marker = if !is_epoch_change
        && old_slot < TICKET_SUBMISSION_END
        && new_slot >= TICKET_SUBMISSION_END
        && new_accumulator.len() == EPOCH_LENGTH as usize
    {
        Some(outside_in_sequence(&new_accumulator))
    } else {
        None
    };

    Ok(SafroleOutput {
        safrole: SafroleState {
            pending_keys: new_pending_keys.clone(),
            ring_root: new_ring_root,
            seal_key_series: new_seal_key_series,
            ticket_accumulator: new_accumulator,
        },
        entropy: new_entropy,
        current_validators: new_current_validators,
        previous_validators: new_previous_validators,
        pending_validators: new_pending_keys,
        epoch_marker,
        winning_tickets_marker,
    })
}

/// Output of the Safrole state transition.
#[derive(Clone, Debug)]
pub struct SafroleOutput {
    /// Updated Safrole state γ'.
    pub safrole: SafroleState,
    /// Updated entropy η'.
    pub entropy: [Hash; 4],
    /// Updated current validators κ'.
    pub current_validators: Vec<ValidatorKey>,
    /// Updated previous validators λ'.
    pub previous_validators: Vec<ValidatorKey>,
    /// Updated pending validators (ι filtered through Φ on epoch change).
    pub pending_validators: Vec<ValidatorKey>,
    /// Epoch marker for header (None if not an epoch boundary).
    pub epoch_marker: Option<EpochMarker>,
    /// Winning tickets for header (None unless crossing Y boundary with full accumulator).
    pub winning_tickets_marker: Option<Vec<Ticket>>,
}

/// Check if the current seal-key series uses tickets (T = 1) or fallback (T = 0).
/// Used for best-chain selection (eq 19.4).
pub fn is_ticket_sealed(series: &SealKeySeries) -> bool {
    matches!(series, SealKeySeries::Tickets(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use grey_types::state::*;
    use std::collections::BTreeMap;

    fn make_validator(seed: u8) -> ValidatorKey {
        ValidatorKey {
            bandersnatch: BandersnatchPublicKey([seed; 32]),
            ed25519: grey_types::Ed25519PublicKey([seed; 32]),
            bls: grey_types::BlsPublicKey([seed; 144]),
            metadata: [seed; 128],
        }
    }

    fn make_test_state() -> State {
        let validators: Vec<ValidatorKey> = (0..TOTAL_VALIDATORS)
            .map(|i| make_validator(i as u8))
            .collect();

        State {
            auth_pool: vec![vec![]; TOTAL_CORES as usize],
            recent_blocks: RecentBlocks {
                headers: vec![],
                accumulation_log: vec![],
            },
            accumulation_outputs: vec![],
            safrole: SafroleState {
                pending_keys: validators.clone(),
                ring_root: grey_types::BandersnatchRingRoot::default(),
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
            statistics: ValidatorStatistics::default(),
            accumulation_queue: vec![],
            accumulation_history: vec![],
        }
    }

    #[test]
    fn test_outside_in_even() {
        let items = vec![0, 1, 2, 3, 4, 5];
        let result = outside_in_sequence(&items);
        assert_eq!(result, vec![0, 5, 1, 4, 2, 3]);
    }

    #[test]
    fn test_outside_in_odd() {
        let items = vec![0, 1, 2, 3, 4];
        let result = outside_in_sequence(&items);
        assert_eq!(result, vec![0, 4, 1, 3, 2]);
    }

    #[test]
    fn test_outside_in_empty() {
        let items: Vec<i32> = vec![];
        let result = outside_in_sequence(&items);
        assert!(result.is_empty());
    }

    #[test]
    fn test_outside_in_single() {
        let items = vec![42];
        let result = outside_in_sequence(&items);
        assert_eq!(result, vec![42]);
    }

    #[test]
    fn test_fallback_key_sequence() {
        let validators: Vec<ValidatorKey> = (0..10).map(make_validator).collect();
        let entropy = Hash([42u8; 32]);

        let keys = fallback_key_sequence(&entropy, &validators);
        assert_eq!(keys.len(), EPOCH_LENGTH as usize);

        // All keys should be from our validator set
        for key in &keys {
            assert!(validators.iter().any(|v| v.bandersnatch == *key));
        }
    }

    #[test]
    fn test_fallback_deterministic() {
        let validators: Vec<ValidatorKey> = (0..10).map(make_validator).collect();
        let entropy = Hash([42u8; 32]);

        let keys1 = fallback_key_sequence(&entropy, &validators);
        let keys2 = fallback_key_sequence(&entropy, &validators);
        assert_eq!(keys1.len(), keys2.len());
        for (a, b) in keys1.iter().zip(keys2.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_entropy_accumulation() {
        let eta0 = Hash([1u8; 32]);
        let vrf = [2u8; 32];
        let result = accumulate_entropy(&eta0, &vrf);
        // Should be deterministic
        assert_eq!(result, accumulate_entropy(&eta0, &vrf));
        // Should differ from input
        assert_ne!(result, eta0);
    }

    #[test]
    fn test_entropy_rotation_on_epoch_boundary() {
        let mut state = make_test_state();
        state.timeslot = 599; // last slot of epoch 0
        state.entropy = [
            Hash([1u8; 32]),
            Hash([2u8; 32]),
            Hash([3u8; 32]),
            Hash([4u8; 32]),
        ];

        let vrf = [10u8; 32];
        let output = apply_safrole(&state, 600, &vrf, &[]).unwrap();

        // η₁' = η₀ (pre-update), η₂' = η₁, η₃' = η₂
        assert_eq!(output.entropy[1], Hash([1u8; 32]));
        assert_eq!(output.entropy[2], Hash([2u8; 32]));
        assert_eq!(output.entropy[3], Hash([3u8; 32]));
        // η₀' should be H(η₀ ++ vrf)
        assert_ne!(output.entropy[0], Hash([1u8; 32]));
    }

    #[test]
    fn test_no_entropy_rotation_same_epoch() {
        let mut state = make_test_state();
        state.timeslot = 10;
        state.entropy = [
            Hash([1u8; 32]),
            Hash([2u8; 32]),
            Hash([3u8; 32]),
            Hash([4u8; 32]),
        ];

        let vrf = [10u8; 32];
        let output = apply_safrole(&state, 11, &vrf, &[]).unwrap();

        // No rotation: η₁', η₂', η₃' unchanged
        assert_eq!(output.entropy[1], Hash([2u8; 32]));
        assert_eq!(output.entropy[2], Hash([3u8; 32]));
        assert_eq!(output.entropy[3], Hash([4u8; 32]));
    }

    #[test]
    fn test_key_rotation_epoch_boundary() {
        let mut state = make_test_state();
        state.timeslot = 599;

        let pending_val = make_validator(42);
        state.safrole.pending_keys = vec![pending_val.clone()];

        let staging_val = make_validator(99);
        state.pending_validators = vec![staging_val.clone()];

        let vrf = [0u8; 32];
        let output = apply_safrole(&state, 600, &vrf, &[]).unwrap();

        // κ' = γP (pending becomes active)
        assert_eq!(output.current_validators, vec![pending_val]);
        // λ' = κ (old active becomes previous)
        assert_eq!(output.previous_validators, state.current_validators);
        // γP' = Φ(ι) (staging, filtered for offenders)
        assert_eq!(output.pending_validators, vec![staging_val]);
    }

    #[test]
    fn test_offender_filtering() {
        let v1 = make_validator(1);
        let v2 = make_validator(2);
        let v3 = make_validator(3);

        let mut judgments = Judgments::default();
        judgments.offenders.insert(v2.ed25519);

        let filtered = filter_offenders(&[v1.clone(), v2, v3.clone()], &judgments);
        assert_eq!(filtered[0], v1);
        assert_eq!(filtered[1], ValidatorKey::null());
        assert_eq!(filtered[2], v3);
    }

    #[test]
    fn test_fallback_on_epoch_change_no_tickets() {
        let mut state = make_test_state();
        state.timeslot = 599;
        // Empty accumulator → fallback
        state.safrole.ticket_accumulator = vec![];

        let vrf = [0u8; 32];
        let output = apply_safrole(&state, 600, &vrf, &[]).unwrap();

        assert!(matches!(
            output.safrole.seal_key_series,
            SealKeySeries::Fallback(_)
        ));
    }

    #[test]
    fn test_ticket_mode_on_full_accumulator() {
        let mut state = make_test_state();
        state.timeslot = 599; // slot 599, epoch boundary at 600

        // Fill accumulator with E=600 tickets
        let tickets: Vec<Ticket> = (0..EPOCH_LENGTH)
            .map(|i| Ticket {
                id: Hash({
                    let mut h = [0u8; 32];
                    h[0..4].copy_from_slice(&i.to_le_bytes());
                    h
                }),
                attempt: 0,
            })
            .collect();
        state.safrole.ticket_accumulator = tickets;

        let vrf = [0u8; 32];
        let output = apply_safrole(&state, 600, &vrf, &[]).unwrap();

        // Should use tickets (single epoch advance, was in closing period, full accumulator)
        assert!(matches!(
            output.safrole.seal_key_series,
            SealKeySeries::Tickets(_)
        ));
    }

    #[test]
    fn test_seal_key_unchanged_same_epoch() {
        let mut state = make_test_state();
        state.timeslot = 10;
        state.safrole.seal_key_series =
            SealKeySeries::Fallback(vec![BandersnatchPublicKey([99u8; 32])]);

        let vrf = [0u8; 32];
        let output = apply_safrole(&state, 11, &vrf, &[]).unwrap();

        // Same epoch: seal_key_series unchanged
        match &output.safrole.seal_key_series {
            SealKeySeries::Fallback(keys) => {
                assert_eq!(keys.len(), 1);
                assert_eq!(keys[0], BandersnatchPublicKey([99u8; 32]));
            }
            _ => panic!("expected fallback"),
        }
    }

    #[test]
    fn test_epoch_marker_on_boundary() {
        let mut state = make_test_state();
        state.timeslot = 599;

        let vrf = [0u8; 32];
        let output = apply_safrole(&state, 600, &vrf, &[]).unwrap();

        assert!(output.epoch_marker.is_some());
    }

    #[test]
    fn test_no_epoch_marker_same_epoch() {
        let mut state = make_test_state();
        state.timeslot = 10;

        let vrf = [0u8; 32];
        let output = apply_safrole(&state, 11, &vrf, &[]).unwrap();

        assert!(output.epoch_marker.is_none());
    }

    #[test]
    fn test_ticket_submission_closed() {
        let mut state = make_test_state();
        state.timeslot = 500; // already past Y

        let proof = TicketProof {
            attempt: 0,
            proof: vec![1, 2, 3],
        };

        let result = apply_safrole(&state, 501, &[0u8; 32], &[proof]);
        assert!(result.is_err());
    }

    #[test]
    fn test_ticket_accumulation() {
        let mut state = make_test_state();
        state.timeslot = 0;

        // Create two ticket proofs with different data so they produce different IDs
        let proof1 = TicketProof {
            attempt: 0,
            proof: vec![1],
        };
        let proof2 = TicketProof {
            attempt: 1,
            proof: vec![2],
        };

        // Get their IDs to ensure correct ordering
        let id1 = grey_crypto::blake2b_256(&proof1.proof);
        let id2 = grey_crypto::blake2b_256(&proof2.proof);

        // Sort proofs by their derived ticket IDs
        let mut proofs = vec![(id1, proof1), (id2, proof2)];
        proofs.sort_by(|a, b| a.0.0.cmp(&b.0.0));
        let sorted_proofs: Vec<TicketProof> = proofs.into_iter().map(|(_, p)| p).collect();

        let output = apply_safrole(&state, 1, &[0u8; 32], &sorted_proofs).unwrap();

        assert_eq!(output.safrole.ticket_accumulator.len(), 2);
    }

    #[test]
    fn test_ticket_accumulator_cleared_on_epoch() {
        let mut state = make_test_state();
        state.timeslot = 599;
        state.safrole.ticket_accumulator = vec![Ticket {
            id: Hash([1u8; 32]),
            attempt: 0,
        }];

        let output = apply_safrole(&state, 600, &[0u8; 32], &[]).unwrap();

        // Accumulator should be cleared on epoch boundary
        assert!(output.safrole.ticket_accumulator.is_empty());
    }

    #[test]
    fn test_is_ticket_sealed() {
        assert!(is_ticket_sealed(&SealKeySeries::Tickets(vec![])));
        assert!(!is_ticket_sealed(&SealKeySeries::Fallback(vec![])));
    }

    #[test]
    fn test_merge_tickets_keeps_lowest() {
        let existing = vec![
            Ticket {
                id: Hash([1u8; 32]),
                attempt: 0,
            },
            Ticket {
                id: Hash([3u8; 32]),
                attempt: 0,
            },
        ];
        let new = vec![
            Ticket {
                id: Hash([2u8; 32]),
                attempt: 0,
            },
            Ticket {
                id: Hash([4u8; 32]),
                attempt: 0,
            },
        ];

        let result = merge_tickets(&existing, &new, 3);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].id, Hash([1u8; 32]));
        assert_eq!(result[1].id, Hash([2u8; 32]));
        assert_eq!(result[2].id, Hash([3u8; 32]));
    }
}
