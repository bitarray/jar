//! Transact-phase per-event execution.
//!
//! Walks σ.transact_space_cnode in slot order. Each slot holds either a
//! `Transact` cap (consumes events from `body.events[vault_id]` and runs
//! each in list order, RW σ) or a `Schedule` cap (kernel-fired once with
//! no body input, RW σ). Per-invocation ephemeral; faults are
//! invocation-local (σ rolls back, block stays valid).
//!
//! Body well-formedness:
//! - body.events VaultIds appear in the same relative order as the Transact
//!   slots in transact_space_cnode (subset, no out-of-order entries).
//! - No body.events entry references a Schedule slot's vault_id.
//! - No trailing unmatched body entries at end of walk.

use crate::types::{
    AttestationEntry, Body, Caller, Capability, Command, KResult, KernelError, KernelRole,
    ReachEntry, ResultEntry, State, VaultId,
};

use crate::attest::AttestCursor;
use crate::cap_registry;
use crate::code_blobs;
use crate::frame::Frame;
use crate::invocation::{INVOCATION_GAS_BUDGET, InvocationCtx, drive_invocation};
use crate::reach::ReachSet;
use crate::runtime::Hardware;
use crate::snapshot::StateSnapshot;

/// What kind of slot we're running for. Affects whether body events are
/// consumed and how reach is recorded.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum SlotKind {
    Transact,
    Schedule,
}

/// Iterate Transact entrypoints in canonical order over σ.transact_space_cnode.
/// (Schedule slots are not returned.)
pub fn transact_entrypoints(state: &State) -> KResult<Vec<VaultId>> {
    let cnode_id = match &cap_registry::lookup(state, state.transact_space_cnode)?.cap {
        Capability::CNode { cnode_id } => *cnode_id,
        _ => {
            return Err(KernelError::Internal(
                "transact_space_cnode is not a CNode cap".into(),
            ));
        }
    };
    let cnode = state.cnode(cnode_id)?;
    let mut entrypoints = Vec::new();
    for (_slot, cap_id) in cnode.iter() {
        if let Capability::Transact { vault_id, .. } = cap_registry::lookup(state, cap_id)?.cap {
            entrypoints.push(vault_id);
        }
    }
    Ok(entrypoints)
}

/// Iterate the entrypoint schedule in canonical slot order. Returns
/// `(slot_idx, kind, vault_id)` tuples.
pub fn schedule_walk(state: &State) -> KResult<Vec<(u8, SlotKind, VaultId)>> {
    let cnode_id = match &cap_registry::lookup(state, state.transact_space_cnode)?.cap {
        Capability::CNode { cnode_id } => *cnode_id,
        _ => {
            return Err(KernelError::Internal(
                "transact_space_cnode is not a CNode cap".into(),
            ));
        }
    };
    let cnode = state.cnode(cnode_id)?;
    let mut walk = Vec::new();
    for (slot_idx, cap_id) in cnode.iter() {
        match cap_registry::lookup(state, cap_id)?.cap {
            Capability::Transact { vault_id, .. } => {
                walk.push((slot_idx, SlotKind::Transact, vault_id));
            }
            Capability::Schedule { vault_id, .. } => {
                walk.push((slot_idx, SlotKind::Schedule, vault_id));
            }
            _ => {
                return Err(KernelError::Internal(format!(
                    "transact_space_cnode slot {} holds non-Transact/Schedule cap",
                    slot_idx
                )));
            }
        }
    }
    Ok(walk)
}

/// Run one invocation (Transact event or Schedule firing). Returns the
/// produced reach + commands. On invocation fault, σ is restored and the
/// produced reach is empty.
///
/// Trace routing is the caller's concern: for Transact events,
/// `attestation_trace` / `result_trace` are the event's own per-event
/// traces and `cursor` starts at 0 (the caller is expected to also
/// enforce per-invocation boundary check on return). For Schedule
/// invocations, they're the block-level traces and the cursor continues
/// across slots.
#[allow(clippy::too_many_arguments)]
pub fn run_one_invocation<H: Hardware>(
    state: &mut State,
    target: VaultId,
    kind: SlotKind,
    reach_idx: u32,
    payload: &[u8],
    attestation_trace: &mut Vec<AttestationEntry>,
    result_trace: &mut Vec<ResultEntry>,
    cursor: &mut AttestCursor,
    hw: &H,
) -> KResult<(ReachEntry, Vec<Command>)> {
    let snapshot = StateSnapshot::take(state);
    // Resolve the entrypoint blob from σ.code_vault before we hand `state`
    // to the InvocationCtx as `&mut`.
    let code_hash = state.vault(target)?.code_hash;
    let blob = code_blobs::resolve_code_blob(state, &code_hash)?.to_vec();
    let mut vm = javm::kernel::InvocationKernel::new(&blob, payload, INVOCATION_GAS_BUDGET)
        .map_err(|e| KernelError::Internal(format!("javm init: {:?}", e)))?;
    let mut commands: Vec<Command> = Vec::new();
    let mut reach = ReachSet::default();
    reach.note(target);
    let mut slot_emission = None;
    let frame = build_invocation_frame(state, target)?;

    let mut ctx = InvocationCtx {
        state,
        role: KernelRole::TransactEntry,
        current_vault: target,
        frame,
        caller: Caller::Kernel(KernelRole::TransactEntry),
        commands: &mut commands,
        reach: &mut reach,
        attest_cursor: cursor,
        attestation_trace,
        result_trace,
        slot_emission: &mut slot_emission,
        prev_slot: None,
        hw,
    };

    let outcome = drive_invocation(&mut vm, &mut ctx)?;

    let _ = kind; // currently unused — both kinds run the same way at
    // the VM level. Kept on the signature for future use.

    if outcome.is_ok() {
        Ok((
            ReachEntry {
                entrypoint: target,
                event_idx: reach_idx,
                vaults: reach.vaults.into_iter().collect(),
            },
            commands,
        ))
    } else {
        snapshot.restore(state);
        Ok((
            ReachEntry {
                entrypoint: target,
                event_idx: reach_idx,
                vaults: Vec::new(),
            },
            Vec::new(),
        ))
    }
}

/// Build the Frame for a Transact / Schedule invocation. Slot 0 holds an
/// RW Storage cap to the entrypoint Vault's overlay. Real chain authors
/// decide their own Frame layout via VaultRef.Initialize args.
fn build_invocation_frame(state: &mut State, vault_id: VaultId) -> KResult<Frame> {
    use crate::types::{KeyRange, StorageRights};

    let mut frame = Frame::new();
    let storage_cap = cap_registry::alloc(
        state,
        crate::types::CapRecord {
            cap: Capability::Storage {
                vault_id,
                key_range: KeyRange::all(),
                rights: StorageRights::RW,
            },
            issuer: None,
            narrowing: Vec::new(),
        },
    );
    frame.set(0, storage_cap);
    Ok(frame)
}

/// Run the entire transact phase. Walks σ.transact_space_cnode in slot
/// order. For Transact slots, consumes the matching body.events entry and
/// runs each event in list order against its per-event traces. For
/// Schedule slots, kernel-fires the target Vault once with no body input
/// against the block-level body.attestation_trace / body.result_trace.
/// Body well-formedness is enforced in-line.
pub fn run_phase<H: Hardware>(
    state: &mut State,
    body: &mut Body,
    block_cursor: &mut AttestCursor,
    hw: &H,
    is_proposer: bool,
) -> KResult<Vec<Command>> {
    let _ = is_proposer; // determinism: same code path either way
    let mut all_commands: Vec<Command> = Vec::new();
    let walk = schedule_walk(state)?;

    // Pointer into body.events — advanced by Transact slots that find
    // their VaultId at the head of the iterator.
    let mut body_event_idx: usize = 0;
    let mut reach_idx: u32 = 0;

    for (slot_idx, kind, target) in walk {
        match kind {
            SlotKind::Schedule => {
                if let Some((vid, _)) = body.events.get(body_event_idx)
                    && *vid == target
                {
                    return Err(KernelError::Internal(format!(
                        "body.events references Schedule slot {} (vault {:?})",
                        slot_idx, target
                    )));
                }
                let (reach_entry, mut commands) = run_one_invocation(
                    state,
                    target,
                    SlotKind::Schedule,
                    reach_idx,
                    &[],
                    &mut body.attestation_trace,
                    &mut body.result_trace,
                    block_cursor,
                    hw,
                )?;
                check_or_record_reach(body, reach_idx as usize, &reach_entry)?;
                reach_idx += 1;
                all_commands.append(&mut commands);
            }
            SlotKind::Transact => {
                let group_matches = body
                    .events
                    .get(body_event_idx)
                    .map(|(vid, _)| *vid == target)
                    .unwrap_or(false);
                if !group_matches {
                    continue;
                }
                let group_len = body.events[body_event_idx].1.len();
                for event_idx in 0..group_len {
                    let mut event_cursor = AttestCursor::default();
                    let (reach_entry, mut commands) = {
                        let (_target, ref mut events) = body.events[body_event_idx];
                        let mut event = std::mem::take(&mut events[event_idx]);
                        let payload = event.payload.clone();
                        let result = run_one_invocation(
                            state,
                            target,
                            SlotKind::Transact,
                            reach_idx,
                            &payload,
                            &mut event.attestation_trace,
                            &mut event.result_trace,
                            &mut event_cursor,
                            hw,
                        );
                        let attestation_len = event.attestation_trace.len();
                        let result_len = event.result_trace.len();
                        events[event_idx] = event;
                        let inner = result?;
                        if event_cursor.attestation_pos != attestation_len
                            || event_cursor.result_pos != result_len
                        {
                            return Err(KernelError::TraceDivergence(format!(
                                "transact event #{} (vault {:?}) trace exhaustion mismatch: \
                                 attestation {}/{}, result {}/{}",
                                event_idx,
                                target,
                                event_cursor.attestation_pos,
                                attestation_len,
                                event_cursor.result_pos,
                                result_len,
                            )));
                        }
                        inner
                    };
                    check_or_record_reach(body, reach_idx as usize, &reach_entry)?;
                    reach_idx += 1;
                    all_commands.append(&mut commands);
                }
                body_event_idx += 1;
            }
        }
    }

    if body_event_idx < body.events.len() {
        return Err(KernelError::Internal(
            "body.events has trailing/out-of-order entry".into(),
        ));
    }

    Ok(all_commands)
}

/// On verifier side, compare against recorded reach; on proposer side,
/// append.
fn check_or_record_reach(
    body: &mut Body,
    reach_idx: usize,
    reach_entry: &ReachEntry,
) -> KResult<()> {
    if let Some(recorded) = body.reach_trace.get(reach_idx) {
        if recorded.vaults != reach_entry.vaults {
            return Err(KernelError::TraceDivergence(format!(
                "reach mismatch at reach_idx {}: actual {:?}, recorded {:?}",
                reach_idx, reach_entry.vaults, recorded.vaults
            )));
        }
    } else {
        body.reach_trace.push(reach_entry.clone());
    }
    Ok(())
}
