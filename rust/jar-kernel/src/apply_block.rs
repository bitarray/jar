//! `apply_block` — the kernel's pure-function block-apply.
//!
//! Single phase: walk `body.events` in proposer-supplied order, exercising
//! each entry's Transact target (RW σ). No separate validation /
//! finalization phases — header-equivalent gating (slot, seal) and
//! finalization-equivalent gating (state-root) are chain-author conventions
//! placed at body.events[0] and body.events[len-1] by the proposer.
//!
//! Structural backstop (kernel-enforced): parent linkage + global
//! attestation/result trace exhaustion.

use jar_types::{Block, BlockHash, Command, KResult, MerkleProof, State};

use crate::attest::AttestCursor;
use crate::runtime::Hardware;
use crate::state_root;
use crate::transact;

/// Outcome of apply_block.
#[derive(Debug)]
pub struct ApplyBlockOutcome<H: Hardware> {
    pub state_next: State<H>,
    pub block: Block<H>,
    pub commands: Vec<Command<H>>,
    pub block_outcome: BlockOutcome,
    pub state_root: H::Hash,
    pub merkle_traces: Vec<MerkleProof<H>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockOutcome {
    Accepted,
    Panicked(String),
}

/// Apply a finalized block. Pure: same inputs produce same outputs.
///
/// `block.body` is mutable: in proposer mode (no traces yet), the kernel
/// populates attestation/result/reach traces. In verifier mode, the kernel
/// consumes the populated traces and fails on divergence.
pub fn apply_block<H: Hardware>(
    state_in: &State<H>,
    prior_block_hash: BlockHash<H>,
    block_in: &Block<H>,
    hw: &H,
) -> KResult<ApplyBlockOutcome<H>> {
    let mut state = state_in.clone();
    let mut block = block_in.clone();
    let mut cursor = AttestCursor::default();
    let merkle_traces: Vec<MerkleProof<H>> = Vec::new();

    // Structural backstop: parent linkage. Checked early — a block with the
    // wrong parent can't transition σ regardless of body contents.
    if block.parent != prior_block_hash {
        return Ok(ApplyBlockOutcome {
            state_next: state_in.clone(),
            block,
            commands: Vec::new(),
            block_outcome: BlockOutcome::Panicked(format!(
                "parent hash mismatch: header={:?} expected={:?}",
                block_in.parent, prior_block_hash
            )),
            state_root: state_root::state_root(state_in, hw),
            merkle_traces,
        });
    }

    // Transact phase: iterate body.events in list order.
    let commands = transact::run_phase(&mut state, &mut block.body, &mut cursor, hw, true)?;

    // Structural backstop: global trace exhaustion.
    if cursor.attestation_pos != block.body.attestation_trace.len() {
        return Ok(ApplyBlockOutcome {
            state_next: state_in.clone(),
            block,
            commands: Vec::new(),
            block_outcome: BlockOutcome::Panicked(format!(
                "attestation_trace exhaustion mismatch: cursor={} len={}",
                cursor.attestation_pos,
                block_in.body.attestation_trace.len()
            )),
            state_root: state_root::state_root(state_in, hw),
            merkle_traces,
        });
    }
    if cursor.result_pos != block.body.result_trace.len() {
        return Ok(ApplyBlockOutcome {
            state_next: state_in.clone(),
            block,
            commands: Vec::new(),
            block_outcome: BlockOutcome::Panicked(format!(
                "result_trace exhaustion mismatch: cursor={} len={}",
                cursor.result_pos,
                block_in.body.result_trace.len()
            )),
            state_root: state_root::state_root(state_in, hw),
            merkle_traces,
        });
    }

    let post_root = state_root::state_root(&state, hw);

    Ok(ApplyBlockOutcome {
        state_next: state,
        block,
        commands,
        block_outcome: BlockOutcome::Accepted,
        state_root: post_root,
        merkle_traces,
    })
}
