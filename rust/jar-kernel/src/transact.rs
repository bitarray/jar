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

use std::sync::Arc;

use jar_types::{
    AttestationEntry, Body, Caller, Capability, Command, Event, KResult, KernelError, KernelRole,
    ReachEntry, ResultEntry, State, StorageMode, VaultId,
};

use crate::attest::AttestCursor;
use crate::cap_registry;
use crate::frame::Frame;
use crate::invocation::{InvocationCtx, ScriptStep, VmExec, drive_invocation};
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
#[allow(clippy::too_many_arguments)]
pub fn run_one_invocation<H: Hardware>(
    state: &mut State,
    target: VaultId,
    kind: SlotKind,
    reach_idx: u32,
    event: Option<&Event>,
    attestation_trace: &mut Vec<AttestationEntry>,
    result_trace: &mut Vec<ResultEntry>,
    cursor: &mut AttestCursor,
    hw: &H,
) -> KResult<(ReachEntry, Vec<Command>)> {
    let snapshot = StateSnapshot::take(state);
    let mut commands: Vec<Command> = Vec::new();
    let mut reach = ReachSet::default();
    reach.note(target);
    let mut slot_emission = None;
    let frame = build_invocation_frame(state, target)?;

    let mut ctx = InvocationCtx {
        state,
        role: KernelRole::TransactEntry,
        storage_mode: StorageMode::Rw,
        current_vault: target,
        frame,
        caller: Caller::Kernel(KernelRole::TransactEntry),
        commands: &mut commands,
        reach: &mut reach,
        attest_cursor: cursor,
        attestation_trace,
        result_trace,
        slot_emission: &mut slot_emission,
        hw,
    };

    // Smoke VM: halts immediately. Real PVM execution lands when guest
    // blobs join. Schedule and Transact-event invocations both run the
    // same way — caller=TransactEntry, RW σ, fresh ephemeral VM. They
    // differ only in whether `event` is `Some` (Transact) or `None`
    // (Schedule).
    let mut vm = build_smoke_vm(event);
    let outcome = drive_invocation(&mut vm, &mut ctx)?;

    let _ = kind; // Currently unused — both kinds run identically at the
    // VM level. Kept on the signature for future use (e.g. distinguishing
    // in caller(), or applying different gas budgets).

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
/// RW Storage cap to the entrypoint Vault's own storage. Real chain
/// authors decide their own Frame layout via VaultRef.Initialize args.
fn build_invocation_frame(state: &mut State, vault_id: VaultId) -> KResult<Frame> {
    use jar_types::{KeyRange, StorageRights};

    let mut frame = Frame::new();
    let storage_cap = cap_registry::alloc(
        state,
        jar_types::CapRecord {
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

/// Smoke VM: halts immediately. Replaced with a real PVM blob driver once
/// guest services land.
fn build_smoke_vm(_event: Option<&Event>) -> impl VmExec {
    crate::invocation::ScriptVm::new(vec![ScriptStep::Halt { rv: 0 }])
}

/// Run the entire transact phase. Walks σ.transact_space_cnode in slot
/// order. For Transact slots, consumes the matching body.events entry and
/// runs each event in list order. For Schedule slots, kernel-fires the
/// target Vault once with no body input. Body well-formedness is enforced
/// in-line.
pub fn run_phase<H: Hardware>(
    state: &mut State,
    body: &mut Body,
    cursor: &mut AttestCursor,
    hw: &H,
    is_proposer: bool,
) -> KResult<Vec<Command>> {
    let _ = is_proposer; // determinism: same code path either way
    let _ = Arc::new(()); // keep Arc import alive
    let mut all_commands: Vec<Command> = Vec::new();
    let walk = schedule_walk(state)?;

    let events_owned: Vec<(VaultId, Vec<Event>)> = body.events.clone();
    let mut body_iter = events_owned.into_iter().peekable();
    let mut reach_idx: u32 = 0;

    for (slot_idx, kind, target) in walk {
        match kind {
            SlotKind::Schedule => {
                // body.events must NOT contain any entry for a Schedule slot.
                if let Some((vid, _)) = body_iter.peek()
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
                    None,
                    &mut body.attestation_trace,
                    &mut body.result_trace,
                    cursor,
                    hw,
                )?;
                check_or_record_reach(body, reach_idx as usize, &reach_entry)?;
                reach_idx += 1;
                all_commands.append(&mut commands);
            }
            SlotKind::Transact => {
                // Consume the next body.events entry only if it matches.
                let events = if let Some((vid, _)) = body_iter.peek() {
                    if *vid == target {
                        let (_, evs) = body_iter.next().expect("peeked");
                        evs
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                };
                for event in events {
                    let (reach_entry, mut commands) = run_one_invocation(
                        state,
                        target,
                        SlotKind::Transact,
                        reach_idx,
                        Some(&event),
                        &mut body.attestation_trace,
                        &mut body.result_trace,
                        cursor,
                        hw,
                    )?;
                    check_or_record_reach(body, reach_idx as usize, &reach_entry)?;
                    reach_idx += 1;
                    all_commands.append(&mut commands);
                }
            }
        }
    }

    if body_iter.peek().is_some() {
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
