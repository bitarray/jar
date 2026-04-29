//! Off-chain Dispatch step-2 / step-3 driver.
//!
//! For each arriving Dispatch event at a subscribed entrypoint:
//! 1. `vault_initialize(entrypoint, RO)` — fresh VM, run `initialize()`.
//! 2. **Step 2** (`caller=Kernel(AggregateStandalone)`): per-event verification
//!    on the standalone event. May cap_call downward Dispatches. May not
//!    touch the slot.
//! 3. **Step 3** (`caller=Kernel(AggregateMerge)`): same VM (memory persists),
//!    args = current slot bytes. Folds verified-event data with current slot.
//!    Emits exactly one slot replacement via `cap_call` on self / Transact /
//!    `slot_clear()`.
//! 4. Slot is updated; if changed, `BroadcastLite` command emitted.

use jar_types::{
    AttestationEntry, Caller, Capability, Command, Crypto, Event, KResult, KernelError, KernelRole,
    ResultEntry, SlotContent, State, StorageMode, VaultId,
};

use crate::attest::AttestCursor;
use crate::cap_registry;
use crate::frame::Frame;
use crate::invocation::{InvocationCtx, ScriptStep, VmExec, drive_invocation};
use crate::reach::ReachSet;
use crate::runtime::{Hardware, NodeOffchain};

#[derive(Debug)]
pub struct InboundOutcome<H: Hardware> {
    pub commands: Vec<Command<H>>,
    pub slot_changed: bool,
}

impl<H: Hardware> Default for InboundOutcome<H> {
    fn default() -> Self {
        Self {
            commands: Vec::new(),
            slot_changed: false,
        }
    }
}

/// Process one inbound Dispatch event for `entrypoint`. Updates `node.slots`
/// and produces the resulting commands (downward dispatches + lite-stream
/// broadcast, if changed).
pub fn handle_inbound_dispatch<H: Hardware>(
    node: &mut NodeOffchain<H>,
    state: &State<H>,
    entrypoint: VaultId,
    event: &Event<H>,
    hw: &H,
) -> KResult<InboundOutcome<H>> {
    // Validate entrypoint is reachable via dispatch_space_cnode (top-level).
    let cnode_id = match &cap_registry::lookup(state, state.dispatch_space_cnode)?.cap {
        Capability::CNode { cnode_id } => *cnode_id,
        _ => {
            return Err(KernelError::Internal(
                "dispatch_space_cnode is not a CNode cap".into(),
            ));
        }
    };
    let cn = state.cnode(cnode_id)?;
    let mut found = false;
    for (_, cap_id) in cn.iter() {
        if let Capability::Dispatch { vault_id, .. } = cap_registry::lookup(state, cap_id)?.cap
            && vault_id == entrypoint
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

    let mut commands: Vec<Command<H>> = Vec::new();
    let mut reach = ReachSet::default();
    reach.note(entrypoint);

    // Build a verifier-side mutable copy of the event traces (the dispatch
    // pipeline runs RO σ; traces flow within this invocation only).
    let mut attestation_trace: Vec<AttestationEntry<H>> = event.attestation_trace.clone();
    let mut result_trace: Vec<ResultEntry> = event.result_trace.clone();
    let mut cursor = AttestCursor::default();
    let mut state_clone = state.clone(); // RO σ, never returned to caller
    let frame = build_dispatch_frame(&mut state_clone, entrypoint, &event.caps)?;

    // Step 2. Kernel asserts cursor == |trace| at HALT; mismatch faults
    // the invocation. (Spec: per-invocation trace-exhaustion boundary.)
    let attestation_target = attestation_trace.len();
    let result_target = result_trace.len();
    {
        let mut slot_emission: Option<SlotContent<H>> = None;
        let mut ctx = InvocationCtx {
            state: &mut state_clone,
            role: KernelRole::AggregateStandalone,
            storage_mode: StorageMode::Ro,
            current_vault: entrypoint,
            frame: frame.clone(),
            caller: Caller::Kernel(KernelRole::AggregateStandalone),
            commands: &mut commands,
            reach: &mut reach,
            attest_cursor: &mut cursor,
            attestation_trace: &mut attestation_trace,
            result_trace: &mut result_trace,
            slot_emission: &mut slot_emission,
            hw,
        };
        let _ = drive_invocation(&mut build_smoke_step2(event), &mut ctx)?;
    }
    if cursor.attestation_pos != attestation_target || cursor.result_pos != result_target {
        return Err(KernelError::TraceDivergence(format!(
            "step-2 trace exhaustion mismatch: attestation {}/{}, result {}/{}",
            cursor.attestation_pos, attestation_target, cursor.result_pos, result_target
        )));
    }

    // Step 3.
    let prev_slot = node.slot(entrypoint).clone();
    let mut slot_emission: Option<SlotContent<H>> = None;
    {
        let mut ctx = InvocationCtx {
            state: &mut state_clone,
            role: KernelRole::AggregateMerge,
            storage_mode: StorageMode::Ro,
            current_vault: entrypoint,
            frame: frame.clone(),
            caller: Caller::Kernel(KernelRole::AggregateMerge),
            commands: &mut commands,
            reach: &mut reach,
            attest_cursor: &mut cursor,
            attestation_trace: &mut attestation_trace,
            result_trace: &mut result_trace,
            slot_emission: &mut slot_emission,
            hw,
        };
        let _ = drive_invocation(&mut build_smoke_step3(event, &prev_slot), &mut ctx)?;
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

/// Frame for a Dispatch invocation. Slot 0: an RO Storage cap to the entry
/// vault. Slot 1+: opaque caps from the inbound event (placeholder — wire-side
/// caps are not yet de-serialized in this milestone).
fn build_dispatch_frame<C: Crypto>(
    state: &mut State<C>,
    vault_id: VaultId,
    _caps: &[u8],
) -> KResult<Frame> {
    use jar_types::{KeyRange, StorageRights};
    let mut frame = Frame::new();
    let storage_cap = cap_registry::alloc(
        state,
        jar_types::CapRecord {
            cap: Capability::Storage {
                vault_id,
                key_range: KeyRange::all(),
                rights: StorageRights::RO,
            },
            issuer: None,
            narrowing: Vec::new(),
        },
    );
    frame.set(0, storage_cap);
    Ok(frame)
}

/// Smoke step-2 VM: halts immediately, emits no downward dispatches.
fn build_smoke_step2<C: Crypto>(_event: &Event<C>) -> impl VmExec {
    crate::invocation::ScriptVm::new(vec![ScriptStep::Halt { rv: 0 }])
}

/// Smoke step-3 VM: emits `slot_clear()` then halts. Real step-3 chains call
/// the appropriate cap_call to set AggregatedDispatch / AggregatedTransact.
fn build_smoke_step3<C: Crypto>(_event: &Event<C>, _prev: &SlotContent<C>) -> impl VmExec {
    let mut regs = [0u64; 13];
    let _ = &mut regs;
    crate::invocation::ScriptVm::new(vec![
        ScriptStep::ProtocolCall {
            slot: crate::host_abi::HostCall::SlotClear as u8,
            regs: [0u64; 13],
        },
        ScriptStep::Halt { rv: 0 },
    ])
}
