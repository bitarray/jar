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

use crate::cap::KernelCap;
use crate::cap::attest::AttestCursor;
use crate::reach::ReachSet;
use crate::runtime::Hardware;
use crate::state::cap_registry;
use crate::vm::{InvocationCtx, Vm, drive_invocation};

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

/// One entrypoint slot's metadata as walked from σ.transact_space_cnode.
/// Carries the budgets the kernel must use when firing this entrypoint
/// (the entrypoint is trusted-gateway code; user-supplied per-event
/// budgets don't reach it directly).
#[derive(Copy, Clone, Debug)]
pub struct WalkEntry {
    pub slot_idx: u8,
    pub kind: SlotKind,
    pub vault_id: VaultId,
    pub gas_budget: u64,
    pub memory_budget: u32,
}

/// Iterate the entrypoint schedule in canonical slot order.
pub fn schedule_walk(state: &State) -> KResult<Vec<WalkEntry>> {
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
                walk.push(WalkEntry {
                    slot_idx,
                    kind: SlotKind::Transact,
                    vault_id: c.vault_id,
                    gas_budget: c.gas_budget,
                    memory_budget: c.memory_budget,
                });
            }
            Capability::Schedule(c) => {
                walk.push(WalkEntry {
                    slot_idx,
                    kind: SlotKind::Schedule,
                    vault_id: c.vault_id,
                    gas_budget: c.gas_budget,
                    memory_budget: c.memory_budget,
                });
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
    gas_budget: u64,
    memory_budget: u32,
    attestation_trace: &mut Vec<AttestationEntry>,
    result_trace: &mut Vec<ResultEntry>,
    cursor: &mut AttestCursor,
    hw: &H,
) -> KResult<(ReachEntry, Vec<Command>)> {
    // No StateSnapshot: faults discard the Frame; persistent caps in
    // Vaults are unchanged because reads are COPY (not MOVE) and
    // managers explicitly stage commits via MGMT_MOVE Frame → Vault.
    // See discussions/persistence-via-caps.md.
    //
    // Build VM 0 from the Vault's persistent CapTable (CNode-driven
    // init replaces the legacy "fetch JAR blob, re-parse manifest"
    // path). vault_init walks vault.slots and translates persistent
    // caps to ephemeral counterparts at the same slot index.
    let mut vm: Vm = crate::vm::new_vm_from_vault(state, target, gas_budget, memory_budget, None)?;
    populate_host_call_slots(&mut vm);
    populate_home_vault_ref(&mut vm, target);
    populate_ephemeral_kernel_caps(
        &mut vm,
        target,
        crate::types::Caller::Kernel(crate::types::KernelRole::TransactEntry),
    );
    // Pass the event payload to the guest via the new args ABI:
    // `set_args` allocates a fresh DATA cap, writes the payload bytes
    // into its backing pages, places it at bare-Frame slot 4, and
    // sets `φ[7] = payload.len()`. The guest opts into reading the
    // bytes by calling `javm_builtins::map_args(args_len)`. Skip
    // when the payload is empty — slot 4 stays unoccupied and
    // `map_args(0)` returns `&[]`.
    if !payload.is_empty() {
        vm.set_args(payload)
            .map_err(|e| KernelError::Internal(format!("vm.set_args: {:?}", e)))?;
    }

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
        // Frame is already discarded by drive_invocation's javm
        // teardown; cap moves the manager committed before the fault
        // remain in σ. Reach is empty because we don't trust the
        // Frame's record once it faulted.
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
/// The walk skips kernel-pinned slots — slot 1 (home VaultRef), slot 2
/// (`SELF_SLOT`), slot 3 (per-VM Gas) — and other retired-gap ranges
/// are documented in `host_abi::HostCall`.
pub(crate) fn populate_host_call_slots(vm: &mut Vm) {
    use crate::vm::host_abi::HostCall;
    // Walk the full slot space; HostCall::from_slot identifies the live
    // selectors (Attest=15, AttestationKey=16, ResultEqual=18, SlotClear=19,
    // SlotRead=21). Retired ranges (storage 4-6, etc.) are skipped.
    for id in 0u8..=31 {
        if HostCall::from_slot(id).is_err() {
            continue;
        }
        vm.cap_table_set_original(id, javm::cap::Cap::Protocol(KernelCap::HostCall(id)));
        // HostCall selectors are kernel infrastructure: pinning blocks
        // guests from MOVing/COPYing them and accidentally bricking the
        // host-call dispatch path.
        vm.vm_arena.vm_mut(0).cap_table.pin(id);
    }
}

/// Populate the per-invocation kernel caps:
/// - BareFrame slot 1 = Caller (cross-frame channel)
/// - BareFrame slot 3 = Gas (cross-frame channel)
/// - BareFrame `FAULT_HANDLER_SLOT` (10) = FaultHandler authority
///   (default location; a guest can claim exclusive recovery via
///   `MGMT_FH_MOVE`)
/// - MainFrame `SELF_SLOT` (2) = Self (per-VM identity)
///
/// Called at the start of every kernel-driven invocation (transact /
/// dispatch step-2 / step-3). BareFrame sub-slot 0 (Reply) is left
/// empty — root has no userspace caller; the kernel rewrites it on
/// every internal CALL.
pub(crate) fn populate_ephemeral_kernel_caps(
    vm: &mut Vm,
    self_vault: VaultId,
    caller: crate::types::Caller,
) {
    use crate::types::{CallerKernelCap, CallerVaultCap, SelfCap};
    use javm::cap::{FaultHandlerCap, FaultHandlerRights};

    // BareFrame sub-slots 1, 3, and FAULT_HANDLER_SLOT.
    let bare_idx = vm.bare_frame_id.index();
    let table = &mut vm.vm_arena.vm_mut(bare_idx).cap_table;

    // BareFrame `BARE_CALLER_SLOT` (= 1): Caller cap. Ephemeral —
    // kernel-injected per top-level invocation. javm refreshes this
    // on every internal CALL/REPLY transition via the
    // `ProtocolCapT::caller_cap_for` hook.
    let caller_cap = match caller {
        crate::types::Caller::Vault(vid) => {
            Capability::CallerVault(CallerVaultCap { vault_id: vid })
        }
        crate::types::Caller::Kernel(role) => Capability::CallerKernel(CallerKernelCap { role }),
    };
    table.set(
        javm::kernel::BARE_CALLER_SLOT,
        javm::cap::Cap::Protocol(KernelCap::Ephemeral(caller_cap)),
    );
    table.pin(javm::kernel::BARE_CALLER_SLOT);

    // BareFrame `B_GAS = GAS_SLOT` (= 3): the slot is pinned but
    // physically empty. The kernel treats it as a *view* onto
    // `active.vm.gas()` — `MGMT_GAS_DERIVE` and `MGMT_GAS_MERGE`
    // special-case the B_GAS access path to read/write the active
    // VM's runtime counter directly. There's no separate cap-level
    // `remaining` to drift out of sync. The invocation budget is
    // already in `vm.gas()` (set at `VmInstance::new` and charged
    // for init by `finalize_kernel`).
    table.pin(javm::kernel::GAS_SLOT);

    // FAULT_HANDLER_SLOT (= 10): per-invocation FaultHandler. Default
    // is `B_FH`; a frame can claim exclusive recovery by MOVE-ing the
    // cap to its own `M_FH` via the generic `MGMT_MOVE` op (which the
    // kernel allows under a narrow whitelist for this mirror move).
    // The walk in javm's handle_vm_fault consults both locations.
    table.set(
        javm::kernel::FAULT_HANDLER_SLOT,
        javm::cap::Cap::FaultHandler(FaultHandlerCap {
            rights: FaultHandlerRights::ALL,
        }),
    );
    table.pin(javm::kernel::FAULT_HANDLER_SLOT);

    // MainFrame slot 2 (`SELF_SLOT`): Self cap. Per-VM identity.
    vm.cap_table_set(
        crate::vm::SELF_SLOT,
        javm::cap::Cap::Protocol(KernelCap::Ephemeral(Capability::SelfId(SelfCap {
            vault_id: self_vault,
        }))),
    );
    // Pin the active VM's MainFrame kernel slots. M_GAS and M_FH are
    // empty by default but pinned so guests can't squat them; the
    // kernel writes through `set` directly (via MGMT_GAS_DERIVE for
    // M_GAS, MGMT_FH_MOVE for M_FH), bypassing the guest mgmt-op
    // pinning checks.
    let main_table = &mut vm.vm_arena.vm_mut(0).cap_table;
    main_table.pin(crate::vm::SELF_SLOT);
    main_table.pin(javm::kernel::GAS_SLOT);
    main_table.pin(javm::kernel::FAULT_HANDLER_SLOT);
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
    // Pin slot 1 so the home VaultRef can't be MOVED/DROPPED by guest
    // mgmt ops. javm's resolve walk crosses this cap on every Vault
    // cap-ref; mutating it would let the guest hijack its own home.
    vm.vm_arena.vm_mut(0).cap_table.pin(1);
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

    for entry in walk {
        let WalkEntry {
            slot_idx,
            kind,
            vault_id: target,
            gas_budget,
            memory_budget,
        } = entry;
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
                    gas_budget,
                    memory_budget,
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
                            gas_budget,
                            memory_budget,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::GenesisBuilder;
    use crate::types::Caller;
    use javm::cap::Cap;

    /// `populate_ephemeral_kernel_caps` places the per-invocation
    /// FaultHandler at BareFrame `FAULT_HANDLER_SLOT` (= 10) by
    /// default. A subsequent `MGMT_FH_MOVE` would shift it to a
    /// frame's `M_FH`; without that, the cap stays at B_FH.
    #[test]
    fn populate_places_fault_handler_at_b_fh() {
        let g = GenesisBuilder::default().build().expect("genesis ok");
        let mut vm =
            crate::vm::new_vm_from_vault(&g.state, g.transact_vault, 100_000_000, 256, None)
                .expect("new_vm_from_vault");
        populate_ephemeral_kernel_caps(
            &mut vm,
            g.transact_vault,
            Caller::Kernel(crate::types::KernelRole::TransactEntry),
        );
        let bare_idx = vm.bare_frame_id.index();
        match vm
            .vm_arena
            .vm(bare_idx)
            .cap_table
            .get(javm::kernel::FAULT_HANDLER_SLOT)
        {
            Some(Cap::FaultHandler(fh)) => {
                assert_eq!(fh.rights, javm::cap::FaultHandlerRights::ALL);
            }
            other => panic!("expected FaultHandler at B_FH, got {:?}", other.is_some()),
        }
    }

    /// SelfCap is pinned at the active VM's `MainFrame[SELF_SLOT]`
    /// (= 2), not at BareFrame slot 2 (which is empty after the
    /// pre-FaultHandler reorg).
    #[test]
    fn populate_pins_self_at_main_frame() {
        let g = GenesisBuilder::default().build().expect("genesis ok");
        let mut vm =
            crate::vm::new_vm_from_vault(&g.state, g.transact_vault, 100_000_000, 256, None)
                .expect("new_vm_from_vault");
        populate_ephemeral_kernel_caps(
            &mut vm,
            g.transact_vault,
            Caller::Kernel(crate::types::KernelRole::TransactEntry),
        );
        // Active VM = VM 0: MainFrame slot SELF_SLOT holds SelfId.
        match vm.vm_arena.vm(0).cap_table.get(crate::vm::SELF_SLOT) {
            Some(Cap::Protocol(KernelCap::Ephemeral(Capability::SelfId(s)))) => {
                assert_eq!(s.vault_id, g.transact_vault);
            }
            other => panic!(
                "expected SelfCap at MainFrame SELF_SLOT, got {:?}",
                other.is_some()
            ),
        }
        // BareFrame slot 2 is empty (Self moved to MainFrame).
        let bare_idx = vm.bare_frame_id.index();
        assert!(vm.vm_arena.vm(bare_idx).cap_table.is_empty(2));
    }

    /// After `populate_*`, the kernel-managed slots in MainFrame and
    /// BareFrame are marked pinned. Generic mgmt ops should refuse
    /// to mutate them; this test asserts the bitmap state directly.
    #[test]
    fn kernel_managed_slots_are_pinned() {
        let g = GenesisBuilder::default().build().expect("genesis ok");
        let mut vm =
            crate::vm::new_vm_from_vault(&g.state, g.transact_vault, 100_000_000, 256, None)
                .expect("new_vm_from_vault");
        populate_host_call_slots(&mut vm);
        populate_home_vault_ref(&mut vm, g.transact_vault);
        populate_ephemeral_kernel_caps(
            &mut vm,
            g.transact_vault,
            Caller::Kernel(crate::types::KernelRole::TransactEntry),
        );
        // MainFrame: 0 (BARE_FRAME ref), 1 (home VaultRef), 2 (Self),
        // 3 (M_GAS), 10 (M_FH), HostCalls 15/16/18/19/21.
        let main = &vm.vm_arena.vm(0).cap_table;
        for &s in &[0u8, 1, 2, 3, 10, 15, 16, 18, 19, 21] {
            assert!(main.is_pinned(s), "MainFrame slot {} not pinned", s);
        }
        // BareFrame: 1 (Caller), 3 (B_GAS), 9 (Untyped), 10 (B_FH).
        let bare_idx = vm.bare_frame_id.index();
        let bare = &vm.vm_arena.vm(bare_idx).cap_table;
        for &s in &[1u8, 3, 9, 10] {
            assert!(bare.is_pinned(s), "BareFrame slot {} not pinned", s);
        }
        // Slot 4 (BARE_ARG_SLOT) is intentionally NOT pinned — guests
        // legitimately MOVE the args DATA cap out into their own
        // MainFrame before MGMT_MAP-ing it.
        assert!(!bare.is_pinned(javm::kernel::BARE_ARG_SLOT));
    }
}
