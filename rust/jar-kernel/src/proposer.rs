//! Proposer-side body assembly: drain off-chain slots into `body.events`.

use std::collections::BTreeMap;

use jar_types::{
    Body, Capability, Crypto, Event, KResult, KernelError, SlotContent, State, VaultId,
};

use crate::cap_registry;
use crate::runtime::NodeOffchain;

/// Walk every top-level Dispatch entrypoint registered in σ.dispatch_space_cnode;
/// for each whose slot is `AggregatedTransact{...}`, append a
/// `(target, event)` to a per-target list. Order target groups by the
/// matching Transact slot's position in σ.transact_space_cnode (kernel
/// will enforce this on apply_block).
///
/// Per-event traces stay on each Event (authoritative for Transact
/// invocations). Block-level traces (body.attestation_trace /
/// body.result_trace) start empty here — they're populated only by
/// Schedule invocations during apply_block (and by the block-seal
/// reservation in proposer mode).
pub fn drain_for_body<C: Crypto>(
    node: &NodeOffchain<C>,
    state: &State<C>,
) -> KResult<Body<C>> {
    // Index Transact slots in transact_space_cnode by VaultId for ordering.
    let transact_cnode_id = match &cap_registry::lookup(state, state.transact_space_cnode)?.cap {
        Capability::CNode { cnode_id } => *cnode_id,
        _ => {
            return Err(KernelError::Internal(
                "transact_space_cnode is not a CNode cap".into(),
            ));
        }
    };
    let tcnode = state.cnode(transact_cnode_id)?;
    let mut transact_slot_index: BTreeMap<VaultId, u8> = BTreeMap::new();
    for (slot_idx, cap_id) in tcnode.iter() {
        if let Capability::Transact { vault_id, .. } = cap_registry::lookup(state, cap_id)?.cap {
            transact_slot_index.insert(vault_id, slot_idx);
        }
    }

    // Walk dispatch_space_cnode; collect per-target event groups.
    let dispatch_cnode_id = match &cap_registry::lookup(state, state.dispatch_space_cnode)?.cap {
        Capability::CNode { cnode_id } => *cnode_id,
        _ => {
            return Err(KernelError::Internal(
                "dispatch_space_cnode is not a CNode cap".into(),
            ));
        }
    };
    let dcnode = state.cnode(dispatch_cnode_id)?;
    let mut groups: BTreeMap<u8, Vec<Event<C>>> = BTreeMap::new();
    let mut targets_in_slot_order: BTreeMap<u8, VaultId> = BTreeMap::new();

    for (_slot, cap_id) in dcnode.iter() {
        if let Capability::Dispatch { vault_id, .. } = cap_registry::lookup(state, cap_id)?.cap
            && let Some(SlotContent::AggregatedTransact {
                target,
                payload,
                caps,
                attestation_trace,
                result_trace,
            }) = node.slots.get(&vault_id)
        {
            let slot_idx = match transact_slot_index.get(target) {
                Some(idx) => *idx,
                None => {
                    return Err(KernelError::Internal(format!(
                        "drained AggregatedTransact targets {:?}, which is not a Transact slot",
                        target
                    )));
                }
            };
            // Body-side Event keeps the AggregatedTransact's bundled
            // traces — they're per-event authoritative for the on-chain
            // Transact handler (NOT spliced into body-level traces).
            groups.entry(slot_idx).or_default().push(Event {
                payload: payload.clone(),
                caps: caps.clone(),
                attestation_trace: attestation_trace.clone(),
                result_trace: result_trace.clone(),
            });
            targets_in_slot_order.insert(slot_idx, *target);
        }
    }

    // Build body.events in slot-index order.
    let mut events: Vec<(VaultId, Vec<Event<C>>)> = Vec::new();
    for (slot_idx, target) in &targets_in_slot_order {
        if let Some(group_events) = groups.remove(slot_idx) {
            events.push((*target, group_events));
        }
    }

    // Body-level traces start empty; Schedule invocations will populate
    // them during apply_block (and proposer-side block-seal reservation).
    Ok(Body {
        events,
        attestation_trace: Vec::new(),
        result_trace: Vec::new(),
        reach_trace: Vec::new(),
        merkle_traces: Vec::new(),
    })
}
