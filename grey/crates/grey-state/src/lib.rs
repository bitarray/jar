//! Chain state and block-level state transitions (Sections 4-13).
//!
//! Implements the state transition function Υ(σ, B) → σ' (eq 4.1).

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
    use grey_types::Hash;

    pub fn make_hash(byte: u8) -> Hash {
        Hash([byte; 32])
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

    #[error("accumulation error: {0}")]
    AccumulationError(String),
}

/// Apply a block to the current state, producing a new state (eq 4.1).
///
/// Υ(σ, B) → σ'
pub fn apply_block(state: &State, block: &Block) -> Result<State, TransitionError> {
    transition::apply(state, block)
}
