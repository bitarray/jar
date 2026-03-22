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

/// Errors from the Safrole sub-transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafroleError {
    BadSlot,
    UnexpectedTicket,
    BadTicketAttempt,
    BadTicketOrder,
    BadTicketProof,
    DuplicateTicket,
    TicketNotRetained,
}

impl SafroleError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BadSlot => "bad_slot",
            Self::UnexpectedTicket => "unexpected_ticket",
            Self::BadTicketAttempt => "bad_ticket_attempt",
            Self::BadTicketOrder => "bad_ticket_order",
            Self::BadTicketProof => "bad_ticket_proof",
            Self::DuplicateTicket => "duplicate_ticket",
            Self::TicketNotRetained => "ticket_not_retained",
        }
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
pub type RingVrfVerifier =
    dyn Fn(&TicketProof, &BandersnatchRingRoot, &Hash, u8) -> Option<Hash>;

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
    let old_epoch = pre.tau / e;
    let new_epoch = input.slot / e;
    let old_slot_in_epoch = pre.tau % e;
    let new_slot_in_epoch = input.slot % e;
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
        let retained_ids: BTreeSet<[u8; 32]> =
            new_gamma_a.iter().map(|t| t.id.0).collect();
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
fn accumulate_entropy(eta0: &Hash, entropy: &Hash) -> Hash {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(&eta0.0);
    data.extend_from_slice(&entropy.0);
    grey_crypto::blake2b_256(&data)
}

/// Filter offenders from a validator key set (eq 6.14: Φ).
fn filter_offenders(keys: &[ValidatorKey], offenders: &[Ed25519PublicKey]) -> Vec<ValidatorKey> {
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
///   result[i] = k[idx].bandersnatch
pub fn fallback_key_sequence(
    config: &Config,
    entropy: &Hash,
    validators: &[ValidatorKey],
) -> Vec<BandersnatchPublicKey> {
    let v = validators.len();
    if v == 0 {
        return vec![BandersnatchPublicKey::default(); config.epoch_length as usize];
    }

    (0..config.epoch_length)
        .map(|i| {
            let mut preimage = Vec::with_capacity(36);
            preimage.extend_from_slice(&entropy.0);
            preimage.extend_from_slice(&i.to_le_bytes());
            let hash = grey_crypto::blake2b_256(&preimage);
            let idx =
                u32::from_le_bytes([hash.0[0], hash.0[1], hash.0[2], hash.0[3]]) as usize % v;
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
fn merge_tickets(existing: &[Ticket], new_tickets: &[Ticket], max_size: usize) -> Vec<Ticket> {
    let mut all: Vec<Ticket> = existing.to_vec();
    all.extend(new_tickets.iter().cloned());
    all.sort_by(|a, b| a.id.0.cmp(&b.id.0));
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
    for w in tickets.windows(2) {
        if w[0].id.0 >= w[1].id.0 {
            return Err(SafroleError::BadTicketOrder);
        }
    }

    // eq 6.33: No duplicates with existing accumulator
    // Note: duplicate check with accumulator happens at the call site

    Ok(tickets)
}

/// Compute ring root from validator Bandersnatch keys (eq 6.13: γZ' = O([k_b | k ← γP'])).
fn compute_ring_root(keys: &[ValidatorKey]) -> BandersnatchRingRoot {
    let bandersnatch_keys: Vec<[u8; 32]> = keys.iter().map(|k| k.bandersnatch.0).collect();
    BandersnatchRingRoot(grey_crypto::bandersnatch::compute_ring_commitment(&bandersnatch_keys))
}
