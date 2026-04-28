//! `apply_block` — the kernel's pure-function block-apply.
//!
//! Three phases: block_validation_cap (RO), transact (RW per-event),
//! block_finalization_cap (RO). Plus the structural backstop (parent hash,
//! slot monotonicity, trace exhaustion).

use jar_types::{
    Body, Command, Hash, Header, KResult, KernelRole, MerkleProof, State,
};

use crate::attest::AttestCursor;
use crate::runtime::Hardware;
use crate::state_root;
use crate::transact;

/// Outcome of apply_block.
#[derive(Debug)]
pub struct ApplyBlockOutcome {
    pub state_next: State,
    pub body: Body,
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

/// Apply a finalized block. Pure: same inputs produce same outputs.
///
/// `body` is mutable: in proposer mode (no traces yet), the kernel populates
/// attestation/result/reach traces. In verifier mode, the kernel consumes
/// the populated traces and fails on divergence.
pub fn apply_block<H: Hardware>(
    state_in: &State,
    prior_block_hash: jar_types::BlockHash,
    header: &Header,
    body_in: &Body,
    hw: &H,
) -> KResult<ApplyBlockOutcome> {
    let mut state = state_in.clone();
    let mut body = body_in.clone();
    let mut cursor = AttestCursor::default();
    let mut commands: Vec<Command> = Vec::new();
    let merkle_traces: Vec<MerkleProof> = Vec::new();

    let block_validation_cap = state.block_validation_cap;
    let block_finalization_cap = state.block_finalization_cap;

    // Phase 1: block_validation_cap (RO).
    if let Err(reason) = run_policy_phase(
        &mut state,
        block_validation_cap,
        KernelRole::BlockValidation,
        header,
        &mut body,
        &mut cursor,
        hw,
    ) {
        return Ok(ApplyBlockOutcome {
            state_next: state_in.clone(),
            body,
            commands: Vec::new(),
            block_outcome: BlockOutcome::Panicked(format!(
                "block_validation_cap fault: {}",
                reason
            )),
            state_root: state_root::state_root(state_in),
            merkle_traces,
        });
    }

    // Phase 2: transact phase.
    let mut transact_commands = transact::run_phase(&mut state, &mut body, &mut cursor, hw, true)?;
    commands.append(&mut transact_commands);

    // Phase 3: block_finalization_cap (RO).
    if let Err(reason) = run_policy_phase(
        &mut state,
        block_finalization_cap,
        KernelRole::BlockFinalization,
        header,
        &mut body,
        &mut cursor,
        hw,
    ) {
        return Ok(ApplyBlockOutcome {
            state_next: state_in.clone(),
            body,
            commands: Vec::new(),
            block_outcome: BlockOutcome::Panicked(format!(
                "block_finalization_cap fault: {}",
                reason
            )),
            state_root: state_root::state_root(state_in),
            merkle_traces,
        });
    }

    // Structural backstop.
    if header.parent != prior_block_hash {
        return Ok(ApplyBlockOutcome {
            state_next: state_in.clone(),
            body,
            commands: Vec::new(),
            block_outcome: BlockOutcome::Panicked(format!(
                "parent hash mismatch: header={:?} expected={:?}",
                header.parent, prior_block_hash
            )),
            state_root: state_root::state_root(state_in),
            merkle_traces,
        });
    }
    if header.slot <= state.bookkeeping.slot {
        return Ok(ApplyBlockOutcome {
            state_next: state_in.clone(),
            body,
            commands: Vec::new(),
            block_outcome: BlockOutcome::Panicked(format!(
                "slot non-monotone: header={} σ.bookkeeping.slot={}",
                header.slot.0, state.bookkeeping.slot.0
            )),
            state_root: state_root::state_root(state_in),
            merkle_traces,
        });
    }
    if cursor.attestation_pos != body.attestation_trace.len() {
        let reason = format!(
            "attestation_trace exhaustion mismatch: cursor={} len={}",
            cursor.attestation_pos,
            body.attestation_trace.len()
        );
        return Ok(ApplyBlockOutcome {
            state_next: state_in.clone(),
            body,
            commands: Vec::new(),
            block_outcome: BlockOutcome::Panicked(reason),
            state_root: state_root::state_root(state_in),
            merkle_traces,
        });
    }
    if cursor.result_pos != body.result_trace.len() {
        let reason = format!(
            "result_trace exhaustion mismatch: cursor={} len={}",
            cursor.result_pos,
            body.result_trace.len()
        );
        return Ok(ApplyBlockOutcome {
            state_next: state_in.clone(),
            body,
            commands: Vec::new(),
            block_outcome: BlockOutcome::Panicked(reason),
            state_root: state_root::state_root(state_in),
            merkle_traces,
        });
    }

    state.bookkeeping.slot = header.slot;
    let post_root = state_root::state_root(&state);
    state
        .bookkeeping
        .recent_headers
        .push_back((Hash::ZERO, post_root));
    while state.bookkeeping.recent_headers.len() > 256 {
        state.bookkeeping.recent_headers.pop_front();
    }

    Ok(ApplyBlockOutcome {
        state_next: state,
        body,
        commands,
        block_outcome: BlockOutcome::Accepted,
        state_root: post_root,
        merkle_traces,
    })
}

/// Run a block-policy phase (validation or finalization). RO σ. Faults
/// propagate up as errors.
fn run_policy_phase<H: Hardware>(
    state: &mut State,
    policy_cap: jar_types::CapId,
    role: KernelRole,
    _header: &Header,
    _body: &mut Body,
    _cursor: &mut AttestCursor,
    _hw: &H,
) -> Result<(), String> {
    // Smoke implementation: verify the policy_cap is a VaultRef into a Vault.
    // Real impl spawns a VM, runs vault.initialize(), CALLs the manager with
    // (header, body), and consumes traces. Until guest blobs land, we accept
    // any valid VaultRef as "the policy passed".
    let record = match state.cap_registry.get(&policy_cap) {
        Some(r) => r,
        None => return Err(format!("policy cap {:?} missing", policy_cap)),
    };
    match &record.cap {
        jar_types::Capability::VaultRef { vault_id, .. } => {
            if !state.vaults.contains_key(vault_id) {
                return Err(format!("policy vault {:?} missing", vault_id));
            }
            // Mark a tracing event so behaviour is observable; a real run
            // would consume attestation/result trace cursor positions.
            let _ = role;
            Ok(())
        }
        _ => Err(format!(
            "policy cap {:?} is not a VaultRef (cap={:?})",
            policy_cap, record.cap
        )),
    }
}

