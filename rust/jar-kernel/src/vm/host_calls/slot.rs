//! Slot host calls — retired in the event-redesign.
//!
//! `slot_clear` and `slot_read` are gone. The slot model itself
//! (per-(node, endpoint) SlotContent) is replaced by setScore-buffered
//! max-register on per-cycle pools. New host calls (`emit_event`,
//! `mint_attest_cap`, `setScore`) live in their own modules.
//!
//! This file is preserved as a stub during the migration; callers that
//! still reference these symbols will be updated in Stage C/D.

use crate::runtime::Hardware;
use crate::types::KResult;
use crate::vm::{HostCallOutcome, InvocationCtx, Vm};

/// Stub: slot_clear is gone. Always faults.
pub fn host_slot_clear<H: Hardware>(
    _vm: &mut Vm,
    _ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    Ok(HostCallOutcome::Fault(
        "slot_clear is retired in event-redesign".into(),
    ))
}

/// Stub: slot_read is gone. Always faults.
pub fn host_slot_read<H: Hardware>(
    _vm: &mut Vm,
    _ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    Ok(HostCallOutcome::Fault(
        "slot_read is retired in event-redesign".into(),
    ))
}
