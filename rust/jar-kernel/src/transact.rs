//! Transact-phase per-event execution.
//!
//! For each Transact entrypoint (in canonical order of σ.transact_space_cnode)
//! and for each event in `body.events[entrypoint]`:
//! - Snapshot σ.
//! - Spawn a fresh VM for the entrypoint Vault, run its initialize() then
//!   CALL the manager with the event payload (RW σ).
//! - On success: commit σ, append reach to body.reach_trace.
//! - On fault: restore snapshot, charge gas, append empty reach.

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

/// Iterate Transact entrypoints in canonical order over σ.transact_space_cnode.
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
        let record = cap_registry::lookup(state, cap_id)?;
        if let Capability::Transact { vault_id, .. } = record.cap {
            entrypoints.push(vault_id);
        }
    }
    Ok(entrypoints)
}

/// Run one event through one Transact entrypoint Vault. Returns the produced
/// reach + commands. On invocation fault, σ is restored and the produced
/// reach is empty.
#[allow(clippy::too_many_arguments)]
pub fn run_transact_event<H: Hardware>(
    state: &mut State,
    entrypoint: VaultId,
    event_idx: u32,
    event: &Event,
    attestation_trace: &mut Vec<AttestationEntry>,
    result_trace: &mut Vec<ResultEntry>,
    cursor: &mut AttestCursor,
    hw: &H,
) -> KResult<(ReachEntry, Vec<Command>)> {
    let snapshot = StateSnapshot::take(state);
    let mut commands: Vec<Command> = Vec::new();
    let mut reach = ReachSet::default();
    reach.note(entrypoint);
    let mut slot_emission = None;
    let frame = build_transact_frame(state, entrypoint)?;

    let mut ctx = InvocationCtx {
        state,
        role: KernelRole::TransactEntry,
        storage_mode: StorageMode::Rw,
        current_vault: entrypoint,
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

    // For now, transact entrypoints run via a script-driven smoke VM that
    // immediately halts. Real PVM execution lands when guest blobs join.
    let mut vm = build_smoke_vm(event);
    let outcome = drive_invocation(&mut vm, &mut ctx)?;

    if outcome.is_ok() {
        Ok((reach.into_entry(entrypoint, event_idx), commands))
    } else {
        snapshot.restore(state);
        let _ = outcome.fault.unwrap_or_default();
        Ok((
            ReachEntry {
                entrypoint,
                event_idx,
                vaults: Vec::new(),
            },
            Vec::new(),
        ))
    }
}

/// Build the Frame for a Transact entrypoint invocation. Slot 0 holds the
/// Vault's own slots-CNode reference; slot 1 holds an RW Storage cap. (Real
/// chain authors decide their own Frame layout via VaultRef.Initialize args.)
fn build_transact_frame(state: &mut State, vault_id: VaultId) -> KResult<Frame> {
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
fn build_smoke_vm(_event: &Event) -> impl VmExec {
    crate::invocation::ScriptVm::new(vec![ScriptStep::Halt { rv: 0 }])
}

/// Run the entire transact phase. Iterates entrypoints in canonical order,
/// runs each event through its entrypoint Vault, and accumulates traces +
/// commands.
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
    let entrypoints = transact_entrypoints(state)?;
    for ep in entrypoints {
        let events = body.events.get(&ep).cloned().unwrap_or_default();
        for (i, event) in events.into_iter().enumerate() {
            let event_idx = i as u32;
            let (reach_entry, mut commands) = run_transact_event(
                state,
                ep,
                event_idx,
                &event,
                &mut body.attestation_trace,
                &mut body.result_trace,
                cursor,
                hw,
            )?;
            // Strict-equality check on verifier side.
            if let Some(recorded) = body
                .reach_trace
                .iter()
                .find(|r| r.entrypoint == ep && r.event_idx == event_idx)
            {
                if recorded.vaults != reach_entry.vaults {
                    return Err(KernelError::TraceDivergence(format!(
                        "reach mismatch on {:?}#{}: actual {:?}, recorded {:?}",
                        ep, event_idx, reach_entry.vaults, recorded.vaults
                    )));
                }
            } else {
                body.reach_trace.push(reach_entry);
            }
            all_commands.append(&mut commands);
        }
    }
    Ok(all_commands)
}

