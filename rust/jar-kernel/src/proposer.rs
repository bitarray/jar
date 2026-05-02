//! Proposer-side body assembly.
//!
//! At each `Kernel::advance` the kernel calls `node.pool.roll_cycle()`
//! — that drains the cycle's winners (per-(endpoint, cycle) max-register
//! entries) and lifts any collision-deferred entries into the next
//! cycle's fresh pool. In proposer mode the kernel hands the rolled
//! winners to `assemble_body`, which walks `σ.transact_endpoints` in
//! slot order and emits one `BodyEvent` per winner with
//! `target_path = u32::to_le_bytes(slot_idx)`.
//!
//! Schedule slots have no body events; their kernel-fed traces live in
//! `body.schedule_attestation_traces` and are populated by the kernel
//! at apply time (Stage D), not by the proposer.

use crate::pool::CycleRoll;
use crate::types::{Body, BodyEvent, KResult, State};

/// Assemble a `Body` from a rolled pool. Walks `σ.transact_endpoints`
/// in slot order; for each endpoint cap-id with rolled winners, emits
/// one `BodyEvent` per winner. `target_path` encodes the slot index as
/// 4-byte little-endian u32 (matches `apply_block::resolve_target_path`).
pub fn assemble_body(state: &State, roll: &CycleRoll) -> KResult<Body> {
    let mut events: Vec<BodyEvent> = Vec::new();
    for (slot_idx, cap_id) in state.transact_endpoints.iter().enumerate() {
        if let Some(entries) = roll.winners.get(cap_id) {
            let path = (slot_idx as u32).to_le_bytes().to_vec();
            for entry in entries {
                events.push(BodyEvent {
                    target_path: path.clone(),
                    blob: entry.blob.clone(),
                    attestation_traces: entry.attestation_traces.clone(),
                });
            }
        }
    }
    Ok(Body {
        events,
        ..Body::default()
    })
}
