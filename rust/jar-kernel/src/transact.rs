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

use crate::cap::attest::AttestCursor;
use crate::cap::{KERNEL_CAP_SLOT, KernelCap};
use crate::reach::ReachSet;
use crate::runtime::Hardware;
use crate::state::cap_registry;
use crate::state::code_blobs;
use crate::state::snapshot::StateSnapshot;
use crate::vm::{INVOCATION_GAS_BUDGET, InvocationCtx, Vm, drive_invocation};

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
        Capability::CNode(c) => c.cnode_id,
        _ => {
            return Err(KernelError::Internal(
                "transact_space_cnode is not a CNode cap".into(),
            ));
        }
    };
    let cnode = state.cnode(cnode_id)?;
    let mut entrypoints = Vec::new();
    for (_slot, cap_id) in cnode.iter() {
        if let Capability::Transact(c) = cap_registry::lookup(state, cap_id)?.cap {
            entrypoints.push(c.vault_id);
        }
    }
    Ok(entrypoints)
}

/// Iterate the entrypoint schedule in canonical slot order. Returns
/// `(slot_idx, kind, vault_id)` tuples.
pub fn schedule_walk(state: &State) -> KResult<Vec<(u8, SlotKind, VaultId)>> {
    let cnode_id = match &cap_registry::lookup(state, state.transact_space_cnode)?.cap {
        Capability::CNode(c) => c.cnode_id,
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
            Capability::Transact(c) => {
                walk.push((slot_idx, SlotKind::Transact, c.vault_id));
            }
            Capability::Schedule(c) => {
                walk.push((slot_idx, SlotKind::Schedule, c.vault_id));
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
    // Resolve the entrypoint blob from the Vault's CodeCap slot before we
    // hand `state` to the InvocationCtx as `&mut`.
    let blob = code_blobs::resolve_init_blob(state, target)?;
    // TODO: when transact guests start reading payload bytes, wire them
    // through `vm.write_data_cap_init(slot, payload)` against a manifest-
    // reserved DATA cap (and place at ephemeral sub-slot 4 per the new
    // cap-arg convention). Today's halt-immediate fixtures don't need it.
    let _ = payload;
    let mut vm: Vm = Vm::new(&blob, INVOCATION_GAS_BUDGET)
        .map_err(|e| KernelError::Internal(format!("javm init: {:?}", e)))?;
    populate_host_call_slots(&mut vm);
    populate_home_vault_ref(&mut vm, target);
    populate_storage_slot(
        &mut vm, target, /* writable */ true, /* snapshot */ None,
    );
    populate_ephemeral_kernel_caps(
        &mut vm,
        target,
        crate::types::Caller::Kernel(crate::types::KernelRole::TransactEntry),
        INVOCATION_GAS_BUDGET,
    );

    let mut commands: Vec<Command> = Vec::new();
    let mut reach = ReachSet::default();
    reach.note(target);
    let mut slot_emission = None;

    let mut ctx = InvocationCtx {
        state,
        role: KernelRole::TransactEntry,
        current_vault: target,
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

/// Populate the kernel's host-call selectors at the live slots in the
/// running VM's cap-table. Each live slot `N` holds
/// `KernelCap::HostCall(N)`, so the guest's `ecalli N` yields
/// `KernelResult::ProtocolCall { slot: N }` to the host loop.
///
/// The walk skips retired slots — slots 1/2/3 (Gas/SelfId/Caller) now
/// live as `Capability::*` caps in the ephemeral table, and the other
/// retired-gap ranges are documented in `host_abi::HostCall`.
pub(crate) fn populate_host_call_slots(vm: &mut Vm) {
    use crate::vm::host_abi::HostCall;
    for id in (HostCall::StorageRead as u8)..=(HostCall::SlotRead as u8) {
        if HostCall::from_slot(id).is_err() {
            continue;
        }
        vm.cap_table_set_original(id, javm::cap::Cap::Protocol(KernelCap::HostCall(id)));
    }
}

/// Populate the per-invocation kernel caps in the ephemeral table:
/// sub-slot 1 = Caller, sub-slot 2 = SelfId, sub-slot 3 = Gas. Called
/// at the start of every kernel-driven invocation (transact / dispatch
/// step-2 / step-3). Sub-slots 0 (Reply) is left empty — root has no
/// userspace caller; the kernel rewrites it on every internal CALL.
pub(crate) fn populate_ephemeral_kernel_caps(
    vm: &mut Vm,
    self_vault: VaultId,
    caller: crate::types::Caller,
    invocation_gas: u64,
) {
    use crate::types::{CallerKernelCap, CallerVaultCap, GasCap, SelfCap};
    let id = match vm
        .vm_arena
        .vm(0)
        .cap_table
        .get(javm::cap::EPHEMERAL_TABLE_SLOT)
    {
        Some(javm::cap::Cap::EphemeralTable(c)) => c.table_id,
        _ => return,
    };
    let table = match vm.ephemeral_arena.get_mut(id) {
        Some(t) => t,
        None => return,
    };

    // Sub-slot 1: Caller cap. Ephemeral — kernel-injected per-frame.
    let caller_cap = match caller {
        crate::types::Caller::Vault(vid) => {
            Capability::CallerVault(CallerVaultCap { vault_id: vid })
        }
        crate::types::Caller::Kernel(role) => Capability::CallerKernel(CallerKernelCap { role }),
    };
    table.set(
        1,
        javm::cap::Cap::Protocol(KernelCap::Ephemeral(caller_cap)),
    );

    // Sub-slot 2: Self cap. Ephemeral.
    table.set(
        2,
        javm::cap::Cap::Protocol(KernelCap::Ephemeral(Capability::SelfId(SelfCap {
            vault_id: self_vault,
        }))),
    );

    // Sub-slot 3: Gas cap. Ephemeral.
    table.set(
        3,
        javm::cap::Cap::Protocol(KernelCap::Ephemeral(Capability::Gas(GasCap {
            remaining: invocation_gas,
        }))),
    );
}

/// Place the per-invocation home `VaultRef` at slot 1 of the active
/// VM's persistent Frame. javm's resolve walk crosses through this
/// cap (its `as_foreign_frame()` reports the home Vault's id) so a
/// guest cap-ref like `0x000100AA` reaches `home_vault.slots[0xAA]`.
///
/// Stored as `KernelCap::Ephemeral` — the cap has no σ presence; it
/// vanishes at invocation teardown when the Frame is discarded.
/// Sub-VaultRefs reachable from the home Vault's slots are real
/// `Registered` caps (held in σ.cap_registry).
pub(crate) fn populate_home_vault_ref(vm: &mut Vm, home: VaultId) {
    use crate::cap::{Capability, KernelCap, VaultRefCap, VaultRights};
    vm.cap_table_set(
        1,
        javm::cap::Cap::Protocol(KernelCap::Ephemeral(Capability::VaultRef(VaultRefCap {
            vault_id: home,
            rights: VaultRights::ALL,
        }))),
    );
}

/// Populate the running VM's cap-table at `KERNEL_CAP_SLOT` with the
/// per-invocation storage cap. Pass `snapshot = Some(root)` for
/// SnapshotStorage (read-only at a prior root); `None` + `writable`
/// for an in-progress overlay Storage cap.
pub(crate) fn populate_storage_slot(
    vm: &mut Vm,
    vault_id: VaultId,
    writable: bool,
    snapshot: Option<crate::types::Hash>,
) {
    use crate::types::{KeyRange, SnapshotStorageCap, StorageCap, StorageRights};
    let cap = if let Some(root) = snapshot {
        Capability::SnapshotStorage(SnapshotStorageCap {
            vault_id,
            key_range: KeyRange::all(),
            root,
        })
    } else {
        Capability::Storage(StorageCap {
            vault_id,
            key_range: KeyRange::all(),
            rights: if writable {
                StorageRights::RW
            } else {
                StorageRights::RO
            },
        })
    };
    // The per-invocation Storage / SnapshotStorage cap is Ephemeral —
    // it's kernel-injected for the duration of the invocation and not
    // tracked in σ.cap_registry. Vault-side derived Storage caps
    // granted explicitly will be Registered.
    vm.cap_table_set(
        KERNEL_CAP_SLOT,
        javm::cap::Cap::Protocol(KernelCap::Ephemeral(cap)),
    );
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
