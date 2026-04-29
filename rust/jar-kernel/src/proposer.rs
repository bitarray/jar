//! Proposer-side body assembly: drain off-chain slots into `body.events`.

use jar_types::{Body, Capability, Event, KResult, KernelError, SlotContent, State, VaultId};

use crate::cap_registry;
use crate::runtime::NodeOffchain;

/// Walk every top-level Dispatch entrypoint registered in σ.dispatch_space_cnode;
/// for each whose slot is `AggregatedTransact{...}`, append a `(target, event)`
/// entry to a fresh `body.events` list.
///
/// The proposer is responsible for prepending event[0] (header-equivalent
/// gating) and appending event[-1] (finalization-equivalent gating); this
/// helper only drains the slot contents, which sit between those two.
pub fn drain_for_body(node: &NodeOffchain, state: &State) -> KResult<Body> {
    let cnode_id = match &cap_registry::lookup(state, state.dispatch_space_cnode)?.cap {
        Capability::CNode { cnode_id } => *cnode_id,
        _ => {
            return Err(KernelError::Internal(
                "dispatch_space_cnode is not a CNode cap".into(),
            ));
        }
    };
    let cn = state.cnode(cnode_id)?;
    let mut events: Vec<(VaultId, Event)> = Vec::new();
    for (_slot, cap_id) in cn.iter() {
        if let Capability::Dispatch { vault_id, .. } = cap_registry::lookup(state, cap_id)?.cap
            && let Some(SlotContent::AggregatedTransact {
                target,
                payload,
                caps,
                attestation_trace,
                result_trace,
            }) = node.slots.get(&vault_id)
        {
            events.push((
                *target,
                Event {
                    payload: payload.clone(),
                    caps: caps.clone(),
                    attestation_trace: attestation_trace.clone(),
                    result_trace: result_trace.clone(),
                },
            ));
        }
    }
    Ok(Body {
        events,
        ..Body::default()
    })
}
