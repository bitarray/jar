//! `apply_block` — stub for the event-redesign migration.
//!
//! The new design walks `σ.transact_endpoints` (flat Vec<CapId>) in slot
//! order, running per-slot verify-then-process. Concrete implementation
//! lands in Stage C.

use crate::runtime::Hardware;
use crate::state::state_root;
use crate::types::{Block, BlockHash, Command, Hash, KResult, MerkleProof, State};

/// Outcome of apply_block.
#[derive(Debug)]
pub struct ApplyBlockOutcome {
    pub state_next: State,
    pub block: Block,
    pub commands: Vec<Command>,
    pub block_outcome: BlockOutcome,
    pub state_root: Hash,
    pub merkle_traces: Vec<MerkleProof>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockOutcome {
    Accepted,
    Panicked(String),
}

/// Stub apply_block. Returns Accepted with empty commands and identity σ.
/// Concrete implementation in Stage C.
pub fn apply_block<H: Hardware>(
    state_in: &State,
    prior_block_hash: BlockHash,
    block_in: &Block,
    _hw: &H,
) -> KResult<ApplyBlockOutcome> {
    let block = block_in.clone();
    let state = state_in.clone();
    let merkle_traces: Vec<MerkleProof> = Vec::new();

    if block.parent != prior_block_hash {
        return Ok(ApplyBlockOutcome {
            state_next: state_in.clone(),
            block,
            commands: Vec::new(),
            block_outcome: BlockOutcome::Panicked(format!(
                "parent hash mismatch: header={:?} expected={:?}",
                block_in.parent, prior_block_hash
            )),
            state_root: state_root::state_root(state_in),
            merkle_traces,
        });
    }

    let post_root = state_root::state_root(&state);
    Ok(ApplyBlockOutcome {
        state_next: state,
        block,
        commands: Vec::new(),
        block_outcome: BlockOutcome::Accepted,
        state_root: post_root,
        merkle_traces,
    })
}
