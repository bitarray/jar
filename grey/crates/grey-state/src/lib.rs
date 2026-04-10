//! Chain state and block-level state transitions (Sections 4-13).
//!
//! Implements the state transition function Υ(σ, B) → σ' (eq 4.1).

/// Define an STF error enum with an `as_str()` method for test-vector output.
///
/// Each variant maps to a snake_case string. Variants are listed once;
/// the macro generates both the enum and the `as_str()` match.
macro_rules! stf_error {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $( $variant:ident => $str:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis enum $name {
            $( $variant, )+
        }

        impl $name {
            pub fn as_str(&self) -> &'static str {
                match self {
                    $( Self::$variant => $str, )+
                }
            }
        }
    };
}

pub mod accumulate;
pub mod assurances;
pub mod authorizations;
pub mod disputes;
pub mod history;
pub mod preimages;
pub mod pvm_backend;
pub mod refine;
pub mod reports;
pub mod safrole;
pub mod statistics;
pub mod transition;

#[cfg(test)]
pub(crate) mod test_helpers {
    use grey_types::validator::ValidatorKey;
    use grey_types::{BandersnatchPublicKey, BlsPublicKey, Ed25519PublicKey, Hash};

    pub fn make_hash(byte: u8) -> Hash {
        Hash([byte; 32])
    }

    pub fn make_validator(byte: u8) -> ValidatorKey {
        ValidatorKey {
            ed25519: Ed25519PublicKey([byte; 32]),
            bandersnatch: BandersnatchPublicKey([byte; 32]),
            bls: BlsPublicKey([byte; 144]),
            metadata: [byte; 128],
        }
    }

    pub fn make_validators(n: usize) -> Vec<ValidatorKey> {
        (0..n).map(|i| make_validator(i as u8)).collect()
    }
}

/// Count how many assurances have their bit set for each core.
///
/// Returns a vector of length `num_cores` where element `i` is the number of
/// assurances that have bit `i` set in their bitfield.
pub fn count_assurance_bits(
    assurances: &[grey_types::header::Assurance],
    num_cores: usize,
) -> Vec<u32> {
    let mut counts = vec![0u32; num_cores];
    for a in assurances {
        for (core, count) in counts.iter_mut().enumerate() {
            if a.has_bit(core) {
                *count += 1;
            }
        }
    }
    counts
}

/// Collect available work reports and clear resolved pending report slots.
///
/// A pending report is "available" if its assurance count meets the threshold.
/// A pending report is cleared if it is available OR timed out.
/// Returns the list of newly available work reports.
pub fn collect_and_clear_available(
    pending_reports: &mut [Option<grey_types::state::PendingReport>],
    assurance_counts: &[u32],
    threshold: u32,
    current_timeslot: grey_types::Timeslot,
    timeout: u32,
) -> Vec<grey_types::work::WorkReport> {
    let mut available = Vec::new();
    for (core, slot) in pending_reports.iter_mut().enumerate() {
        if let Some(pending) = slot {
            let is_available = assurance_counts.get(core).copied().unwrap_or(0) >= threshold;
            if is_available {
                available.push(pending.report.clone());
            }
            let is_timed_out = current_timeslot >= pending.timeslot + timeout;
            if is_available || is_timed_out {
                *slot = None;
            }
        }
    }
    available
}

/// Check that a slice is strictly sorted by the given key (no duplicates).
///
/// Returns `true` if `key(items[i]) < key(items[i+1])` for all consecutive pairs.
/// Empty and single-element slices are trivially sorted.
pub fn is_strictly_sorted_by_key<T, K: Ord>(items: &[T], key: impl Fn(&T) -> K) -> bool {
    items.windows(2).all(|w| key(&w[0]) < key(&w[1]))
}

use grey_types::header::Block;
use grey_types::state::State;
use thiserror::Error;

/// Errors that can occur during block state transition.
#[derive(Debug, Error)]
pub enum TransitionError {
    #[error("invalid parent hash: expected {expected}, got {got}")]
    InvalidParentHash {
        expected: grey_types::Hash,
        got: grey_types::Hash,
    },

    #[error("timeslot {block_slot} is not after prior timeslot {prior_slot}")]
    InvalidTimeslot {
        block_slot: grey_types::Timeslot,
        prior_slot: grey_types::Timeslot,
    },

    #[error("invalid block author index: {0}")]
    InvalidAuthorIndex(u16),

    #[error("invalid seal signature")]
    InvalidSeal,

    #[error("invalid extrinsic: {0}")]
    InvalidExtrinsic(String),
}

/// Apply a block to the current state, producing a new state (eq 4.1).
///
/// Υ(σ, B) → σ'
pub fn apply_block(state: &State, block: &Block) -> Result<State, TransitionError> {
    transition::apply(state, block)
}
