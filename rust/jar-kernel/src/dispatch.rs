//! Off-chain dispatch processing for the event-redesign.
//!
//! Dispatch endpoints live in `σ.dispatch_endpoints` (flat
//! `Vec<EventEndpointCap>`, inline values). Off-chain events arriving
//! at the node go through `Kernel::dispatch`, which routes them here.
//!
//! Per arriving event:
//!
//! - Verify (fresh `Vault.initialize`, ro-σ): may panic. A panicking
//!   verify drops the event silently.
//! - Process (one `Vault.initialize` per cycle, ro-σ for dispatch):
//!   for v1 we run a fresh process VM per arriving event. The
//!   "persistent state across calls within a cycle" optimization is
//!   a chain-author concern that lands when long-lived dispatch VMs
//!   are introduced.
//!
//! Dispatch is ro-σ throughout: verify and process both run against
//! cloned σ; emitted commands (Emit / setScore / authority records)
//! are routed back to hardware. σ mutations during dispatch process
//! (if any) are discarded.
//!
//! `target_path` v1 wire format: 4-byte little-endian u32 of the slot
//! index in `σ.dispatch_endpoints`. Mirrors apply_block's transact
//! addressing.

use crate::runtime::{Hardware, NodeOffchain};
use crate::transact;
use crate::types::{AttestationEntry, Command, KResult, KernelError, State};

fn resolve_dispatch_path(path: &[u8]) -> Option<usize> {
    if path.len() != 4 {
        return None;
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(path);
    Some(u32::from_le_bytes(buf) as usize)
}

/// Handle one inbound event arriving at a dispatch endpoint. Returns
/// the commands the verify/process invocations produced (e.g.
/// emit_event self-broadcasts for the DA pattern).
pub fn handle_inbound<H: Hardware>(
    state: &State,
    node: &mut NodeOffchain,
    target_path: &[u8],
    blob: &[u8],
    attestation_traces: &[AttestationEntry],
    hw: &H,
) -> KResult<Vec<Command>> {
    let mut commands: Vec<Command> = Vec::new();

    let slot_idx = resolve_dispatch_path(target_path).ok_or_else(|| {
        KernelError::Internal(format!(
            "dispatch target_path malformed: {} bytes",
            target_path.len()
        ))
    })?;
    let endpoint = state
        .dispatch_endpoints
        .get(slot_idx)
        .copied()
        .ok_or_else(|| {
            KernelError::Internal(format!(
                "dispatch target_path slot {} out of range ({} endpoints)",
                slot_idx,
                state.dispatch_endpoints.len()
            ))
        })?;

    // Verify: fresh, ro-σ. Faulting verify drops the event silently.
    let verify = transact::run_verify(
        state,
        &endpoint,
        slot_idx,
        /* dispatch_context */ true,
        blob,
        attestation_traces,
        &mut node.pool,
        &mut commands,
        hw,
    )?;
    if verify.fault.is_some() {
        return Ok(commands);
    }

    // Process: ro-σ for dispatch. Run on a discarded clone so any
    // mutations the chain-author attempts go nowhere.
    let mut state_ro = state.clone();
    let process = transact::run_process(
        &mut state_ro,
        &endpoint,
        slot_idx,
        /* dispatch_context */ true,
        blob,
        &mut node.pool,
        &mut commands,
        hw,
    )?;
    if process.fault.is_some() {
        // Dispatch process fault is informational only.
        return Ok(commands);
    }
    Ok(commands)
}
