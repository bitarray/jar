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

use jar_types::{
    AttestationEntry, Caller, Capability, Command, Event, KResult, KernelError, KernelRole,
    ResultEntry, SlotContent, State, VaultId,
};

use crate::attest::AttestCursor;
use crate::cap_registry;
use crate::code_blobs;
use crate::frame::Frame;
use crate::invocation::{INVOCATION_GAS_BUDGET, InvocationCtx, drive_invocation};
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

    // Resolve the entrypoint blob (same blob runs both phases). Use
    // `code_cache` so the second phase reuses the first phase's compile.
    let code_hash = state_clone.vault(entrypoint)?.code_hash;
    let blob = code_blobs::resolve_code_blob(&state_clone, &code_hash)?.to_vec();

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
            prev_slot: None,
            hw,
        };
        let mut vm = javm::kernel::InvocationKernel::new_cached(
            &blob,
            &event.payload,
            INVOCATION_GAS_BUDGET,
            &mut node.code_cache,
        )
        .map_err(|e| KernelError::Internal(format!("javm init step-2: {:?}", e)))?;
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
            prev_slot: Some(&prev_slot_owned),
            hw,
        };
        let mut vm = javm::kernel::InvocationKernel::new_cached(
            &blob,
            &event.payload,
            INVOCATION_GAS_BUDGET,
            &mut node.code_cache,
        )
        .map_err(|e| KernelError::Internal(format!("javm init step-3: {:?}", e)))?;
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
