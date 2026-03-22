//! Chain state and block-level state transitions (Sections 4-13).
//!
//! Implements the state transition function Υ(σ, B) → σ' (eq 4.1).

pub mod accumulate;
pub mod assurances;
pub mod pvm_backend;
pub mod refine;
pub mod authorizations;
pub mod disputes;
pub mod history;
pub mod preimages;
pub mod reports;
pub mod safrole;
pub mod statistics;
pub mod transition;

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
