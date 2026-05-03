//! `apply_block`: walk `σ.transact_endpoints` in slot order and run
//! per-slot interleaved verify-then-process for the event-redesign.
//!
//! For each slot:
//!
//! - Look up the `EventEndpointCap` that occupies the slot.
//! - For every body event whose `target_path` resolves to this slot,
//!   run a fresh `Vault.initialize` in `KernelRole::Verify` against a
//!   clone of σ (ro-σ semantics; verify may panic, in which case the
//!   block panics with it).
//! - For Schedule slots (no events but a matching
//!   `body.schedule_attestation_traces` entry), run a single verify
//!   pass that consumes the kernel-fed traces.
//! - After all verifies, run one `KernelRole::Process` invocation
//!   against the live σ (rw-σ). Mutations persist.
//!
//! Trace consumption (mint_attest_cap, emit_event, setScore) routes
//! through host calls and the per-invocation context. Today the host
//! calls are stubbed, so verify/process for the genesis halt blobs
//! just halts cleanly. Real consumption lands in Stage D.
//!
//! Trace exhaustion: every body event must resolve to a slot, and every
//! `schedule_attestation_traces` entry must reference a known slot. Any
//! unresolved item panics the block (post-walk validation).
//!
//! `target_path` v1 wire format: 4-byte little-endian u32 of the slot
//! index in `σ.transact_endpoints`. Path-based name resolution lands
//! in a follow-up.

use std::collections::BTreeMap;

use crate::runtime::Hardware;
use crate::state::state_root;
use crate::transact;
use crate::types::{
    AttestationEntry, Block, BlockHash, Command, Hash, KResult, MerkleProof, State,
};

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

/// Resolve a `target_path` to a slot index in `σ.transact_endpoints`.
/// v1 wire format: little-endian u32 (4 bytes).
fn resolve_target_path(path: &[u8]) -> Option<usize> {
    if path.len() != 4 {
        return None;
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(path);
    Some(u32::from_le_bytes(buf) as usize)
}

pub fn apply_block<H: Hardware>(
    state_in: &State,
    prior_block_hash: BlockHash,
    block_in: &Block,
    pool: &mut crate::pool::CyclePool,
    hw: &H,
) -> KResult<ApplyBlockOutcome> {
    let block = block_in.clone();
    let prior_state_root = state_root::state_root(state_in);

    // Parent linkage check.
    if block.parent != prior_block_hash {
        return Ok(panicked(
            state_in,
            block,
            format!(
                "parent hash mismatch: header={:?} expected={:?}",
                block_in.parent, prior_block_hash
            ),
            prior_state_root,
        ));
    }

    let mut state = state_in.clone();
    let mut commands: Vec<Command> = Vec::new();

    // Group body events by slot index resolved from target_path.
    let mut events_by_slot: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (i, ev) in block.body.events.iter().enumerate() {
        match resolve_target_path(&ev.target_path) {
            Some(slot) => events_by_slot.entry(slot).or_default().push(i),
            None => {
                return Ok(panicked(
                    state_in,
                    block,
                    format!("event {i} has malformed target_path"),
                    prior_state_root,
                ));
            }
        }
    }

    // Index schedule_attestation_traces by slot index. Duplicate entries
    // for a single slot are a malformed body.
    let mut schedule_traces: BTreeMap<usize, &[AttestationEntry]> = BTreeMap::new();
    for sat in &block.body.schedule_attestation_traces {
        let slot = sat.slot_index as usize;
        if schedule_traces
            .insert(slot, sat.traces.as_slice())
            .is_some()
        {
            return Ok(panicked(
                state_in,
                block,
                format!("duplicate schedule_attestation_traces entry for slot {slot}"),
                prior_state_root,
            ));
        }
    }

    // Walk transact endpoints in slot order.
    let n = state.transact_endpoints.len();
    for slot_idx in 0..n {
        let endpoint = state.transact_endpoints[slot_idx];

        let ev_indices = events_by_slot.remove(&slot_idx).unwrap_or_default();
        let sched_slice = schedule_traces.remove(&slot_idx);

        if !ev_indices.is_empty() {
            // Per-event verify: fresh Vault.initialize against a clone of σ.
            for &ev_idx in &ev_indices {
                let ev = &block.body.events[ev_idx];
                let result = transact::run_verify(
                    &state,
                    &endpoint,
                    slot_idx,
                    /* dispatch_context */ false,
                    &ev.blob,
                    &ev.attestation_traces,
                    pool,
                    &mut commands,
                    hw,
                )?;
                if let Some(reason) = result.fault {
                    return Ok(panicked(
                        state_in,
                        block,
                        format!("verify slot {slot_idx} event {ev_idx}: {reason}"),
                        prior_state_root,
                    ));
                }
            }
        } else if let Some(traces) = sched_slice {
            // Schedule slot verify: single fresh Vault.initialize that
            // consumes the kernel-fed schedule_attestation_traces slice.
            let result = transact::run_verify(
                &state,
                &endpoint,
                slot_idx,
                /* dispatch_context */ false,
                &[],
                traces,
                pool,
                &mut commands,
                hw,
            )?;
            if let Some(reason) = result.fault {
                return Ok(panicked(
                    state_in,
                    block,
                    format!("schedule verify slot {slot_idx}: {reason}"),
                    prior_state_root,
                ));
            }
        }

        // Process: one Vault.initialize against live σ. Always fires.
        let result = transact::run_process(
            &mut state,
            &endpoint,
            slot_idx,
            /* dispatch_context */ false,
            pool,
            &mut commands,
            hw,
        )?;
        if let Some(reason) = result.fault {
            return Ok(panicked(
                state_in,
                block,
                format!("process slot {slot_idx}: {reason}"),
                prior_state_root,
            ));
        }
    }

    // Trace exhaustion: every event / schedule trace must have matched a slot.
    if !events_by_slot.is_empty() {
        let stray: Vec<usize> = events_by_slot.keys().copied().collect();
        return Ok(panicked(
            state_in,
            block,
            format!("body events targeting unknown slots: {stray:?}"),
            prior_state_root,
        ));
    }
    if !schedule_traces.is_empty() {
        let stray: Vec<usize> = schedule_traces.keys().copied().collect();
        return Ok(panicked(
            state_in,
            block,
            format!("schedule_attestation_traces for unknown slots: {stray:?}"),
            prior_state_root,
        ));
    }

    let new_root = state_root::state_root(&state);
    Ok(ApplyBlockOutcome {
        state_next: state,
        block,
        commands,
        block_outcome: BlockOutcome::Accepted,
        state_root: new_root,
        merkle_traces: Vec::new(),
    })
}

fn panicked(
    state_in: &State,
    block: Block,
    reason: String,
    prior_state_root: Hash,
) -> ApplyBlockOutcome {
    ApplyBlockOutcome {
        state_next: state_in.clone(),
        block,
        commands: Vec::new(),
        block_outcome: BlockOutcome::Panicked(reason),
        state_root: prior_state_root,
        merkle_traces: Vec::new(),
    }
}
