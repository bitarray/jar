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
//!
//! Step-2/3 frames carry a `SnapshotStorage` cap rooted at the prior block's
//! state — RO by construction. The kernel enforces RO via the cap variant;
//! there is no `StorageMode` flag.

use jar_types::{
    AttestationEntry, Caller, Capability, Command, Event, KResult, KernelError, KernelRole,
    ResultEntry, SlotContent, State, VaultId,
};

use crate::attest::AttestCursor;
use crate::cap_registry;
use crate::frame::Frame;
use crate::invocation::{InvocationCtx, ScriptStep, VmExec, drive_invocation};
use crate::reach::ReachSet;
use crate::runtime::{Hardware, NodeOffchain};

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

    let mut commands: Vec<Command> = Vec::new();
    let mut reach = ReachSet::default();
    reach.note(entrypoint);

    // The dispatch pipeline runs against a kernel-side clone of σ — RO at
    // the protocol level; mutations are discarded after step-3. The frame's
    // cap is `SnapshotStorage` rooted at the kernel's current state-root.
    let mut state_clone = state.clone();
    let prior_root = crate::state_root::state_root(state);
    let mut attestation_trace: Vec<AttestationEntry> = event.attestation_trace.clone();
    let mut result_trace: Vec<ResultEntry> = event.result_trace.clone();
    let mut cursor = AttestCursor::default();
    let frame = build_dispatch_frame(&mut state_clone, entrypoint, &event.caps, prior_root)?;

    // Step 2.
    let attestation_target = attestation_trace.len();
    let result_target = result_trace.len();
    {
        let mut slot_emission: Option<SlotContent> = None;
        let mut ctx = InvocationCtx {
            state: &mut state_clone,
            role: KernelRole::AggregateStandalone,
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
    let mut slot_emission: Option<SlotContent> = None;
    {
        let mut ctx = InvocationCtx {
            state: &mut state_clone,
            role: KernelRole::AggregateMerge,
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

/// Frame for a Dispatch invocation. Slot 0: a SnapshotStorage cap rooted at
/// `prior_root`, RO by construction. Slot 1+: opaque caps from the inbound
/// event (placeholder — wire-side caps aren't yet de-serialized).
fn build_dispatch_frame(
    state: &mut State,
    vault_id: VaultId,
    _caps: &[u8],
    prior_root: jar_types::Hash,
) -> KResult<Frame> {
    use jar_types::KeyRange;
    let mut frame = Frame::new();
    let storage_cap = cap_registry::alloc(
        state,
        jar_types::CapRecord {
            cap: Capability::SnapshotStorage {
                vault_id,
                key_range: KeyRange::all(),
                root: prior_root,
            },
            issuer: None,
            narrowing: Vec::new(),
        },
    );
    frame.set(0, storage_cap);
    Ok(frame)
}

/// Smoke step-2 VM: halts immediately, emits no downward dispatches.
fn build_smoke_step2(_event: &Event) -> impl VmExec {
    crate::invocation::ScriptVm::new(vec![ScriptStep::Halt { rv: 0 }])
}

/// Smoke step-3 VM: emits `slot_clear()` then halts. Real step-3 chains call
/// the appropriate cap_call to set AggregatedDispatch / AggregatedTransact.
fn build_smoke_step3(_event: &Event, _prev: &SlotContent) -> impl VmExec {
    crate::invocation::ScriptVm::new(vec![
        ScriptStep::ProtocolCall {
            slot: crate::host_abi::HostCall::SlotClear as u8,
            regs: [0u64; 13],
        },
        ScriptStep::Halt { rv: 0 },
    ])
}
