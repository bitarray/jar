//! Safrole consensus sub-transition (Section 6, eq 6.1-6.35).
//!
//! Handles epoch management, entropy accumulation, key rotation,
//! seal-key series generation, and ticket accumulation.

use grey_types::config::Config;
use grey_types::header::{Ticket, TicketProof};
use grey_types::state::SealKeySeries;
use grey_types::validator::ValidatorKey;
use grey_types::{BandersnatchPublicKey, BandersnatchRingRoot, Ed25519PublicKey, Hash};
use std::collections::BTreeSet;

stf_error! {
    /// Errors from the Safrole sub-transition.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum SafroleError {
        BadSlot => "bad_slot",
        UnexpectedTicket => "unexpected_ticket",
        BadTicketAttempt => "bad_ticket_attempt",
        BadTicketOrder => "bad_ticket_order",
        BadTicketProof => "bad_ticket_proof",
        DuplicateTicket => "duplicate_ticket",
        TicketNotRetained => "ticket_not_retained",
    }
}

/// Input to the Safrole sub-transition.
pub struct SafroleInput {
    /// H_T: The block's timeslot.
    pub slot: u32,
    /// Y(H_V): The VRF output (entropy contribution).
    pub entropy: Hash,
    /// E_T: Ticket extrinsic.
    pub extrinsic: Vec<TicketProof>,
}

/// State relevant to the Safrole sub-transition.
#[derive(Clone, Debug)]
pub struct SafroleState {
    /// τ: Current timeslot.
    pub tau: u32,
    /// η: Entropy accumulator (4 hashes).
    pub eta: [Hash; 4],
    /// λ: Previous epoch's validator keys.
    pub lambda: Vec<ValidatorKey>,
    /// κ: Active validator keys.
    pub kappa: Vec<ValidatorKey>,
    /// γP: Pending (next-epoch) validator keys.
    pub gamma_k: Vec<ValidatorKey>,
    /// ι: Incoming (staging) validator keys.
    pub iota: Vec<ValidatorKey>,
    /// γA: Ticket accumulator.
    pub gamma_a: Vec<Ticket>,
    /// γS: Seal-key series.
    pub gamma_s: SealKeySeries,
    /// γZ: Bandersnatch ring root.
    pub gamma_z: BandersnatchRingRoot,
    /// ψO': Offender Ed25519 keys (from judgments).
    pub offenders: Vec<Ed25519PublicKey>,
}

/// Output of a successful Safrole sub-transition.
pub struct SafroleOutput {
    /// The updated state.
    pub state: SafroleState,
    /// H_E: Epoch marker (eq 6.27).
    pub epoch_mark: Option<EpochMark>,
    /// H_W: Winning-tickets marker (eq 6.28).
    pub tickets_mark: Option<Vec<Ticket>>,
}

/// Epoch marker data (eq 6.27).
pub struct EpochMark {
    /// η₀ (pre-state).
    pub entropy: Hash,
    /// η₁ (pre-state).
    pub tickets_entropy: Hash,
    /// [(k_b, k_e) | k ← γP'].
    pub validators: Vec<(BandersnatchPublicKey, Ed25519PublicKey)>,
}

/// Callback for Ring VRF verification and ticket ID extraction.
/// Returns the ticket ID (VRF output Y(p)) or None if verification fails.
pub type RingVrfVerifier = dyn Fn(&TicketProof, &BandersnatchRingRoot, &Hash, u8) -> Option<Hash>;

/// Apply the Safrole sub-transition (eq 6.1-6.35).
///
/// `ring_vrf_verify` is an optional callback to verify Ring VRF proofs and
/// extract ticket IDs. If None, any ticket submission returns BadTicketProof.
pub fn process_safrole(
    config: &Config,
    input: &SafroleInput,
    pre: &SafroleState,
    ring_vrf_verify: Option<&RingVrfVerifier>,
) -> Result<SafroleOutput, SafroleError> {
    let e = config.epoch_length;
    let y = config.ticket_submission_end();

    // eq 6.1: τ' = H_T, but first validate slot > τ
    if input.slot <= pre.tau {
        return Err(SafroleError::BadSlot);
    }

    // eq 6.2: Compute epoch indices
    let old_epoch = config.epoch_of(pre.tau);
    let new_epoch = config.epoch_of(input.slot);
    let old_slot_in_epoch = config.slot_in_epoch(pre.tau);
    let new_slot_in_epoch = config.slot_in_epoch(input.slot);
    let is_epoch_change = new_epoch > old_epoch;

    // Validate ticket extrinsic (eq 6.30)
    if !input.extrinsic.is_empty() {
        // Tickets only allowed before submission end
        if new_slot_in_epoch >= y {
            return Err(SafroleError::UnexpectedTicket);
        }

        // Validate attempt values (must be < N)
        let n = config.tickets_per_validator;
        for tp in &input.extrinsic {
            if tp.attempt as u16 >= n {
                return Err(SafroleError::BadTicketAttempt);
            }
        }
    }

    // eq 6.23: Entropy rotation on epoch boundary
    let (new_eta1, new_eta2, new_eta3) = if is_epoch_change {
        (pre.eta[0], pre.eta[1], pre.eta[2])
    } else {
        (pre.eta[1], pre.eta[2], pre.eta[3])
    };

    // eq 6.13: Key rotation on epoch boundary
    let (new_gamma_k, new_kappa, new_lambda, new_gamma_z) = if is_epoch_change {
        // eq 6.14: Φ(ι) — filter offenders from incoming keys
        let filtered = filter_offenders(&pre.iota, &pre.offenders);
        // Ring root from new pending keys' Bandersnatch components
        let ring_root = compute_ring_root(&filtered);
        (
            filtered,            // γP' = Φ(ι)
            pre.gamma_k.clone(), // κ' = γP
            pre.kappa.clone(),   // λ' = κ
            ring_root,           // γZ' = O([k_b | k ← γP'])
        )
    } else {
        (
            pre.gamma_k.clone(),
            pre.kappa.clone(),
            pre.lambda.clone(),
            pre.gamma_z.clone(),
        )
    };

    // eq 6.22: Entropy accumulation — η₀' = H(η₀ ⊕ Y(H_V))
    let new_eta0 = accumulate_entropy(&pre.eta[0], &input.entropy);

    // eq 6.29-6.31: Process ticket extrinsic
    let new_tickets = if !input.extrinsic.is_empty() {
        extract_tickets(&input.extrinsic, &new_gamma_z, &new_eta2, ring_vrf_verify)?
    } else {
        vec![]
    };

    // eq 6.33: No duplicate ticket IDs with existing accumulator
    if !new_tickets.is_empty() {
        let existing_ids: BTreeSet<[u8; 32]> = if is_epoch_change {
            BTreeSet::new()
        } else {
            pre.gamma_a.iter().map(|t| t.id.0).collect()
        };
        for t in &new_tickets {
            if existing_ids.contains(&t.id.0) {
                return Err(SafroleError::DuplicateTicket);
            }
        }
    }

    // eq 6.34: Ticket accumulator update
    let base = if is_epoch_change {
        &[] as &[Ticket]
    } else {
        &pre.gamma_a
    };
    let new_gamma_a = merge_tickets(base, &new_tickets, e as usize);

    // eq 6.35: All submitted tickets must be retained
    if !new_tickets.is_empty() {
        let retained_ids: BTreeSet<[u8; 32]> = new_gamma_a.iter().map(|t| t.id.0).collect();
        for t in &new_tickets {
            if !retained_ids.contains(&t.id.0) {
                return Err(SafroleError::TicketNotRetained);
            }
        }
    }

    // eq 6.24: Seal-key series
    let new_gamma_s = if is_epoch_change {
        let single_advance = new_epoch == old_epoch + 1;
        let was_past_y = old_slot_in_epoch >= y;
        let accumulator_full = pre.gamma_a.len() == e as usize;

        if single_advance && was_past_y && accumulator_full {
            // Case 1: Z(γA) — use tickets
            SealKeySeries::Tickets(outside_in_sequence(&pre.gamma_a))
        } else {
            // Case 3: F(η₂', κ') — fallback
            SealKeySeries::Fallback(fallback_key_sequence(config, &new_eta2, &new_kappa))
        }
    } else {
        // Case 2: Same epoch, no change
        pre.gamma_s.clone()
    };

    // eq 6.27: Epoch marker
    let epoch_mark = if is_epoch_change {
        Some(EpochMark {
            entropy: pre.eta[0],
            tickets_entropy: pre.eta[1],
            validators: new_gamma_k
                .iter()
                .map(|k| (k.bandersnatch, k.ed25519))
                .collect(),
        })
    } else {
        None
    };

    // eq 6.28: Winning-tickets marker
    let tickets_mark = if !is_epoch_change
        && old_slot_in_epoch < y
        && new_slot_in_epoch >= y
        && new_gamma_a.len() == e as usize
    {
        Some(outside_in_sequence(&new_gamma_a))
    } else {
        None
    };

    Ok(SafroleOutput {
        state: SafroleState {
            tau: input.slot,
            eta: [new_eta0, new_eta1, new_eta2, new_eta3],
            lambda: new_lambda,
            kappa: new_kappa,
            gamma_k: new_gamma_k,
            iota: pre.iota.clone(),
            gamma_a: new_gamma_a,
            gamma_s: new_gamma_s,
            gamma_z: new_gamma_z,
            offenders: pre.offenders.clone(),
        },
        epoch_mark,
        tickets_mark,
    })
}

/// Entropy accumulation (eq 6.22): η₀' = H(η₀ ++ entropy).
pub(crate) fn accumulate_entropy(eta0: &Hash, entropy: &Hash) -> Hash {
    grey_crypto::accumulate_entropy(eta0, entropy)
}

/// Filter offenders from a validator key set (eq 6.14: Φ).
pub fn filter_offenders(
    keys: &[ValidatorKey],
    offenders: &[Ed25519PublicKey],
) -> Vec<ValidatorKey> {
    let offender_set: BTreeSet<_> = offenders.iter().collect();
    keys.iter()
        .map(|k| {
            if offender_set.contains(&k.ed25519) {
                ValidatorKey::null()
            } else {
                k.clone()
            }
        })
        .collect()
}

/// Fallback key sequence F(r, k) (eq 6.26).
///
/// For each slot i in 0..E:
///   idx = LE32(H(r ++ LE32(i))[0..4]) mod |k|
///   `result[i]` = `k[idx]`.bandersnatch
pub fn fallback_key_sequence(
    config: &Config,
    entropy: &Hash,
    validators: &[ValidatorKey],
) -> Vec<BandersnatchPublicKey> {
    fallback_key_sequence_raw(config.epoch_length, entropy, validators)
}

/// Core fallback key sequence generation parameterized by epoch length.
///
/// Shared implementation used by both `grey-state` (with Config) and
/// `grey-consensus` (with compile-time EPOCH_LENGTH constant).
pub fn fallback_key_sequence_raw(
    epoch_length: u32,
    entropy: &Hash,
    validators: &[ValidatorKey],
) -> Vec<BandersnatchPublicKey> {
    let v = validators.len();
    if v == 0 {
        return vec![BandersnatchPublicKey::default(); epoch_length as usize];
    }

    let mut preimage = [0u8; 36];
    preimage[..32].copy_from_slice(&entropy.0);
    (0..epoch_length)
        .map(|i| {
            preimage[32..].copy_from_slice(&i.to_le_bytes());
            let hash = grey_crypto::blake2b_256(&preimage);
            let idx = u32::from_le_bytes([hash.0[0], hash.0[1], hash.0[2], hash.0[3]]) as usize % v;
            validators[idx].bandersnatch
        })
        .collect()
}

/// Outside-in sequencer Z (eq 6.25).
///
/// Z(s) = [s₀, s_{n-1}, s₁, s_{n-2}, ...]
pub fn outside_in_sequence<T: Clone>(items: &[T]) -> Vec<T> {
    let n = items.len();
    let mut result = Vec::with_capacity(n);
    let mut lo = 0;
    let mut hi = n.wrapping_sub(1);

    for i in 0..n {
        if i % 2 == 0 {
            result.push(items[lo].clone());
            lo += 1;
        } else {
            result.push(items[hi].clone());
            hi = hi.wrapping_sub(1);
        }
    }

    result
}

/// Merge new tickets into accumulator, keeping only the lowest E entries (eq 6.34).
pub fn merge_tickets(existing: &[Ticket], new_tickets: &[Ticket], max_size: usize) -> Vec<Ticket> {
    let mut all = Vec::with_capacity(existing.len() + new_tickets.len());
    all.extend_from_slice(existing);
    all.extend_from_slice(new_tickets);
    all.sort_by_key(|a| a.id.0);
    all.truncate(max_size);
    all
}

/// Verify Ring VRF proofs and extract ticket IDs (eq 6.29-6.33).
fn extract_tickets(
    proofs: &[TicketProof],
    ring_root: &BandersnatchRingRoot,
    eta2: &Hash,
    ring_vrf_verify: Option<&RingVrfVerifier>,
) -> Result<Vec<Ticket>, SafroleError> {
    let verifier = ring_vrf_verify.ok_or(SafroleError::BadTicketProof)?;

    let mut tickets: Vec<Ticket> = Vec::with_capacity(proofs.len());
    for tp in proofs {
        match verifier(tp, ring_root, eta2, tp.attempt) {
            Some(id) => tickets.push(Ticket {
                id,
                attempt: tp.attempt,
            }),
            None => return Err(SafroleError::BadTicketProof),
        }
    }

    // eq 6.32: Must be sorted ascending by ticket ID
    if !crate::is_strictly_sorted_by_key(&tickets, |t| t.id.0) {
        return Err(SafroleError::BadTicketOrder);
    }

    // eq 6.33: No duplicates with existing accumulator
    // Note: duplicate check with accumulator happens at the call site

    Ok(tickets)
}

/// Compute ring root from validator Bandersnatch keys (eq 6.13: γZ' = O([k_b | k ← γP'])).
pub fn compute_ring_root(keys: &[ValidatorKey]) -> BandersnatchRingRoot {
    let bandersnatch_keys: Vec<[u8; 32]> = keys.iter().map(|k| k.bandersnatch.0).collect();
    BandersnatchRingRoot(grey_crypto::bandersnatch::compute_ring_commitment(
        &bandersnatch_keys,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{make_hash, make_validator};
    use grey_types::header::Ticket;

    fn make_ticket(id_byte: u8, attempt: u8) -> Ticket {
        Ticket {
            id: make_hash(id_byte),
            attempt,
        }
    }

    // --- accumulate_entropy ---

    #[test]
    fn test_accumulate_entropy_deterministic() {
        let eta0 = make_hash(1);
        let entropy = make_hash(2);
        let result1 = accumulate_entropy(&eta0, &entropy);
        let result2 = accumulate_entropy(&eta0, &entropy);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_accumulate_entropy_different_inputs() {
        let eta0 = make_hash(1);
        let r1 = accumulate_entropy(&eta0, &make_hash(2));
        let r2 = accumulate_entropy(&eta0, &make_hash(3));
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_accumulate_entropy_is_blake2b() {
        let eta0 = make_hash(1);
        let entropy = make_hash(2);
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&eta0.0);
        data.extend_from_slice(&entropy.0);
        let expected = grey_crypto::blake2b_256(&data);
        assert_eq!(accumulate_entropy(&eta0, &entropy), expected);
    }

    // --- filter_offenders ---

    #[test]
    fn test_filter_offenders_none() {
        let keys = vec![make_validator(1), make_validator(2)];
        let result = filter_offenders(&keys, &[]);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].ed25519, keys[0].ed25519);
        assert_eq!(result[1].ed25519, keys[1].ed25519);
    }

    #[test]
    fn test_filter_offenders_replaces_with_null() {
        let keys = vec![make_validator(1), make_validator(2), make_validator(3)];
        let offenders = vec![Ed25519PublicKey([2; 32])];
        let result = filter_offenders(&keys, &offenders);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].ed25519, keys[0].ed25519); // kept
        assert_eq!(result[1], ValidatorKey::null()); // nulled
        assert_eq!(result[2].ed25519, keys[2].ed25519); // kept
    }

    #[test]
    fn test_filter_offenders_all() {
        let keys = vec![make_validator(1), make_validator(2)];
        let offenders = vec![Ed25519PublicKey([1; 32]), Ed25519PublicKey([2; 32])];
        let result = filter_offenders(&keys, &offenders);
        assert!(result.iter().all(|k| *k == ValidatorKey::null()));
    }

    // --- fallback_key_sequence_raw ---

    #[test]
    fn test_fallback_key_sequence_raw_empty_validators() {
        let result = fallback_key_sequence_raw(12, &make_hash(1), &[]);
        assert_eq!(result.len(), 12);
        assert!(
            result
                .iter()
                .all(|k| *k == BandersnatchPublicKey::default())
        );
    }

    #[test]
    fn test_fallback_key_sequence_raw_length() {
        let validators = vec![make_validator(1), make_validator(2)];
        let result = fallback_key_sequence_raw(10, &make_hash(1), &validators);
        assert_eq!(result.len(), 10);
    }

    #[test]
    fn test_fallback_key_sequence_raw_deterministic() {
        let validators = vec![make_validator(1), make_validator(2), make_validator(3)];
        let entropy = make_hash(42);
        let r1 = fallback_key_sequence_raw(12, &entropy, &validators);
        let r2 = fallback_key_sequence_raw(12, &entropy, &validators);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_fallback_key_sequence_raw_uses_validator_keys() {
        let validators = vec![make_validator(10), make_validator(20), make_validator(30)];
        let result = fallback_key_sequence_raw(100, &make_hash(1), &validators);
        // Every entry must be one of the validator bandersnatch keys
        for key in &result {
            assert!(validators.iter().any(|v| v.bandersnatch == *key));
        }
    }

    // --- merge_tickets ---

    #[test]
    fn test_merge_tickets_empty() {
        let result = merge_tickets(&[], &[], 10);
        assert!(result.is_empty());
    }

    #[test]
    fn test_merge_tickets_keeps_lowest() {
        let existing = vec![make_ticket(1, 0), make_ticket(3, 0)];
        let new = vec![make_ticket(2, 0), make_ticket(4, 0)];
        let result = merge_tickets(&existing, &new, 3);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].id, make_hash(1));
        assert_eq!(result[1].id, make_hash(2));
        assert_eq!(result[2].id, make_hash(3));
    }

    #[test]
    fn test_merge_tickets_truncates() {
        let tickets: Vec<Ticket> = (0..10).map(|i| make_ticket(i, 0)).collect();
        let result = merge_tickets(&tickets, &[], 5);
        assert_eq!(result.len(), 5);
    }

    // --- SafroleError ---

    #[test]
    fn test_safrole_error_as_str() {
        assert_eq!(SafroleError::BadSlot.as_str(), "bad_slot");
        assert_eq!(SafroleError::UnexpectedTicket.as_str(), "unexpected_ticket");
        assert_eq!(SafroleError::BadTicketProof.as_str(), "bad_ticket_proof");
        assert_eq!(SafroleError::DuplicateTicket.as_str(), "duplicate_ticket");
        assert_eq!(
            SafroleError::TicketNotRetained.as_str(),
            "ticket_not_retained"
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::test_helpers::{make_hash, make_validator};
    use grey_types::header::Ticket;
    use grey_types::testing::arb_hash;
    use proptest::prelude::*;

    proptest! {
        /// outside_in_sequence preserves length and all elements.
        #[test]
        fn outside_in_preserves_elements(values in proptest::collection::vec(any::<u32>(), 0..20)) {
            let result = outside_in_sequence(&values);
            prop_assert_eq!(result.len(), values.len());
            let mut sorted_input = values.clone();
            sorted_input.sort();
            let mut sorted_result = result.clone();
            sorted_result.sort();
            prop_assert_eq!(sorted_input, sorted_result);
        }

        /// outside_in_sequence: first element is items[0], second is items[last].
        #[test]
        fn outside_in_first_and_second(values in proptest::collection::vec(any::<u32>(), 2..20)) {
            let result = outside_in_sequence(&values);
            prop_assert_eq!(result[0], values[0]);
            prop_assert_eq!(result[1], values[values.len() - 1]);
        }

        /// merge_tickets output is sorted by ticket ID.
        #[test]
        fn merge_tickets_sorted(
            existing_ids in proptest::collection::vec(any::<u8>(), 0..10),
            new_ids in proptest::collection::vec(any::<u8>(), 0..10),
            max_size in 1usize..20,
        ) {
            let existing: Vec<Ticket> = existing_ids.iter().map(|&b| Ticket {
                id: make_hash(b), attempt: 0,
            }).collect();
            let new: Vec<Ticket> = new_ids.iter().map(|&b| Ticket {
                id: make_hash(b), attempt: 0,
            }).collect();
            let result = merge_tickets(&existing, &new, max_size);
            prop_assert!(result.len() <= max_size);
            // Check sorted
            for w in result.windows(2) {
                prop_assert!(w[0].id.0 <= w[1].id.0);
            }
        }

        /// merge_tickets keeps the lowest IDs.
        #[test]
        fn merge_tickets_keeps_lowest(max_size in 1usize..10) {
            let all: Vec<Ticket> = (0..15u8).map(|i| Ticket {
                id: make_hash(i), attempt: 0,
            }).collect();
            let result = merge_tickets(&all, &[], max_size);
            // Should have the first max_size elements (they have lowest IDs)
            for (i, t) in result.iter().enumerate() {
                prop_assert_eq!(t.id, make_hash(i as u8));
            }
        }

        /// fallback_key_sequence_raw length matches epoch_length.
        #[test]
        fn fallback_length_matches(
            epoch_length in 1u32..50,
            entropy in arb_hash(),
            num_validators in 1usize..10,
        ) {
            let validators: Vec<ValidatorKey> = (0..num_validators)
                .map(|i| make_validator(i as u8))
                .collect();
            let result = fallback_key_sequence_raw(epoch_length, &entropy, &validators);
            prop_assert_eq!(result.len(), epoch_length as usize);
        }

        /// fallback_key_sequence_raw is deterministic.
        #[test]
        fn fallback_deterministic(
            entropy in arb_hash(),
            num_validators in 1usize..10,
        ) {
            let validators: Vec<ValidatorKey> = (0..num_validators)
                .map(|i| make_validator(i as u8))
                .collect();
            let r1 = fallback_key_sequence_raw(12, &entropy, &validators);
            let r2 = fallback_key_sequence_raw(12, &entropy, &validators);
            prop_assert_eq!(r1, r2);
        }

        /// filter_offenders preserves length.
        #[test]
        fn filter_preserves_length(
            num_validators in 1usize..10,
            num_offenders in 0usize..5,
        ) {
            let validators: Vec<ValidatorKey> = (0..num_validators)
                .map(|i| make_validator(i as u8))
                .collect();
            let offenders: Vec<Ed25519PublicKey> = (0..num_offenders)
                .map(|i| Ed25519PublicKey([i as u8; 32]))
                .collect();
            let result = filter_offenders(&validators, &offenders);
            prop_assert_eq!(result.len(), validators.len());
        }

        /// accumulate_entropy is deterministic.
        #[test]
        fn entropy_deterministic(
            eta0 in arb_hash(),
            entropy in arb_hash(),
        ) {
            let r1 = accumulate_entropy(&eta0, &entropy);
            let r2 = accumulate_entropy(&eta0, &entropy);
            prop_assert_eq!(r1, r2);
        }
    }
}
