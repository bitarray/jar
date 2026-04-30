//! Off-chain Dispatch step-2 / step-3 driver.
//!
//! For each arriving Dispatch event at a subscribed entrypoint:
//! 1. `vault_initialize(entrypoint, RO)` — fresh VM, run `initialize()`.
//! 2. **Step 2** (`caller=Kernel(AggregateStandalone)`): per-event verification
//!    on the standalone event. May cap_call downward Dispatches. May not
//!    touch the slot. Entered with φ[7]=0.
//! 3. **Step 3** (`caller=Kernel(AggregateMerge)`): args = current slot bytes,
//!    surfaced via the `slot_read` host call. Folds verified-event data with
//!    current slot. Emits exactly one slot replacement via `cap_call` on self
//!    / Transact / `slot_clear()`. Entered with φ[7]=1.
//! 4. Slot is updated; if changed, `BroadcastLite` command emitted.
//!
//! Step-2/3 frames carry a `SnapshotStorage` cap rooted at the prior block's
//! state — RO by construction. The kernel enforces RO via the cap variant;
//! there is no `StorageMode` flag.
//!
//! Note: a single VM instance per phase. The spec docstring's "same VM
//! (memory persists)" ideal needs javm cooperative-yield support to be
//! truly literal; today step-2 and step-3 are separate `InvocationKernel`s
//! built from the same blob, distinguished by the φ[7] phase tag.

use crate::types::{
    AttestationEntry, Caller, Capability, Command, Event, KResult, KernelError, KernelRole,
    ResultEntry, SlotContent, State, VaultId,
};

use crate::cap::attest::AttestCursor;
use crate::reach::ReachSet;
use crate::runtime::{Hardware, NodeOffchain};
use crate::state::cap_registry;
use crate::transact::{populate_home_vault_ref, populate_host_call_slots};
use crate::vm::{INVOCATION_GAS_BUDGET, InvocationCtx, Vm, drive_invocation};

#[derive(Debug, Default)]
pub struct InboundOutcome {
    pub commands: Vec<Command>,
    pub slot_changed: bool,
}

/// Process one inbound Dispatch event for `entrypoint`. Updates `node.slots`
/// and produces the resulting commands (downward dispatches + lite-stream
/// broadcast, if changed).
pub fn handle_inbound_dispatch<H: Hardware>(
    node: &mut NodeOffchain,
    state: &State,
    entrypoint: VaultId,
    event: &Event,
    hw: &H,
) -> KResult<InboundOutcome> {
    // Validate entrypoint is reachable via dispatch_space_cnode (top-level).
    let cnode_id = match &cap_registry::lookup(state, state.dispatch_space_cnode)?.cap {
        Capability::CNode(c) => c.cnode_id,
        _ => {
            return Err(KernelError::Internal(
                "dispatch_space_cnode is not a CNode cap".into(),
            ));
        }
    };
    let cn = state.cnode(cnode_id)?;
    let mut found = false;
    for (_, cap_id) in cn.iter() {
        if let Capability::Dispatch(d) = cap_registry::lookup(state, cap_id)?.cap
            && d.vault_id == entrypoint
        {
            found = true;
            break;
        }
    }
    if !found {
        return Err(KernelError::Internal(format!(
            "entrypoint {:?} not in dispatch_space_cnode",
            entrypoint
        )));
    }

    let mut commands: Vec<Command> = Vec::new();
    let mut reach = ReachSet::default();
    reach.note(entrypoint);

    // The dispatch pipeline runs against a kernel-side clone of σ — RO
    // by chain-author convention; the running VM's slot-1 home VaultRef
    // would normally carry only `read_cap_indirection` rights. Today
    // that narrowing is not yet implemented (slot-1 is full-rights);
    // RO discipline is achieved by chain-author cap distribution within
    // dispatch entrypoint Vaults.
    let mut state_clone = state.clone();
    let mut attestation_trace: Vec<AttestationEntry> = event.attestation_trace.clone();
    let mut result_trace: Vec<ResultEntry> = event.result_trace.clone();
    let mut cursor = AttestCursor::default();

    // Build VM 0 from the dispatch entrypoint Vault's CapTable on each
    // phase. The kernel's `node.code_cache` reuses compilations across
    // step-2 and step-3 (and across blocks) since persistent CodeCaps
    // store identical sub-blob bytes.

    // Step 2.
    let attestation_target = attestation_trace.len();
    let result_target = result_trace.len();
    {
        // Build VM 0 from `state_clone` first (immutable borrow), then
        // hand `&mut state_clone` to the InvocationCtx. Walking
        // vault.slots only reads σ, so the borrow nests cleanly.
        // TODO: payload bytes (event.payload) need to be written into a
        // persistent DATA cap and placed at bare-Frame sub-slot 4 when
        // dispatch guests start reading them. Today's fixtures halt.
        let mut vm: Vm = crate::vm::new_vm_from_vault(
            &state_clone,
            entrypoint,
            INVOCATION_GAS_BUDGET,
            Some(&mut node.code_cache),
        )?;
        let mut slot_emission: Option<SlotContent> = None;
        let mut ctx = InvocationCtx {
            state: &mut state_clone,
            role: KernelRole::AggregateStandalone,
            current_vault: entrypoint,
            caller: Caller::Kernel(KernelRole::AggregateStandalone),
            commands: &mut commands,
            reach: &mut reach,
            attest_cursor: &mut cursor,
            attestation_trace: &mut attestation_trace,
            result_trace: &mut result_trace,
            slot_emission: &mut slot_emission,
            prev_slot: None,
            hw,
        };
        populate_host_call_slots(&mut vm);
        populate_home_vault_ref(&mut vm, entrypoint);
        crate::transact::populate_ephemeral_kernel_caps(
            &mut vm,
            entrypoint,
            Caller::Kernel(KernelRole::AggregateStandalone),
            INVOCATION_GAS_BUDGET,
        );
        vm.set_active_reg(7, 0);
        let _ = drive_invocation(&mut vm, &mut ctx)?;
    }
    if cursor.attestation_pos != attestation_target || cursor.result_pos != result_target {
        return Err(KernelError::TraceDivergence(format!(
            "step-2 trace exhaustion mismatch: attestation {}/{}, result {}/{}",
            cursor.attestation_pos, attestation_target, cursor.result_pos, result_target
        )));
    }

    // Step 3.
    let prev_slot_owned = node.slot(entrypoint).clone();
    let mut slot_emission: Option<SlotContent> = None;
    {
        let mut vm: Vm = crate::vm::new_vm_from_vault(
            &state_clone,
            entrypoint,
            INVOCATION_GAS_BUDGET,
            Some(&mut node.code_cache),
        )?;
        let mut ctx = InvocationCtx {
            state: &mut state_clone,
            role: KernelRole::AggregateMerge,
            current_vault: entrypoint,
            caller: Caller::Kernel(KernelRole::AggregateMerge),
            commands: &mut commands,
            reach: &mut reach,
            attest_cursor: &mut cursor,
            attestation_trace: &mut attestation_trace,
            result_trace: &mut result_trace,
            slot_emission: &mut slot_emission,
            prev_slot: Some(&prev_slot_owned),
            hw,
        };
        populate_host_call_slots(&mut vm);
        populate_home_vault_ref(&mut vm, entrypoint);
        crate::transact::populate_ephemeral_kernel_caps(
            &mut vm,
            entrypoint,
            Caller::Kernel(KernelRole::AggregateMerge),
            INVOCATION_GAS_BUDGET,
        );
        vm.set_active_reg(7, 1);
        let _ = drive_invocation(&mut vm, &mut ctx)?;
    }
    if cursor.attestation_pos != attestation_trace.len() || cursor.result_pos != result_trace.len()
    {
        return Err(KernelError::TraceDivergence(format!(
            "step-3 trace exhaustion mismatch: attestation {}/{}, result {}/{}",
            cursor.attestation_pos,
            attestation_trace.len(),
            cursor.result_pos,
            result_trace.len()
        )));
    }

    let prev_slot = prev_slot_owned;
    let new_slot = slot_emission.unwrap_or(SlotContent::Empty);
    let changed = new_slot != prev_slot;
    node.set_slot(entrypoint, new_slot.clone());
    if changed {
        commands.push(Command::BroadcastLite {
            entrypoint,
            content: new_slot,
        });
    }
    Ok(InboundOutcome {
        commands,
        slot_changed: changed,
    })
}
