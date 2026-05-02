//! Attestation host calls — stub for the event-redesign migration.
//!
//! In the event-redesign:
//! - `attest(cap, blob)` is retired (cap-as-proof; no exercise).
//! - `attestation_key(cap)` is retired (key field public on the cap).
//! - `result_equal(cap, blob)` is retired (ResultCap collapses into
//!   AttestationCap with IDENTITY_KEY).
//!
//! Replacements (`mint_attest_cap`, `setScore`, `emit_event`) live in
//! their own modules; concrete implementations land in Stage C/D.

use crate::runtime::Hardware;
use crate::types::KResult;
use crate::vm::{HostCallOutcome, InvocationCtx, Vm};

/// Stub: attest is retired. Always faults.
pub fn host_attest<H: Hardware>(
    _vm: &mut Vm,
    _ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    Ok(HostCallOutcome::Fault(
        "attest is retired in event-redesign; use mint_attest_cap inside verify".into(),
    ))
}

/// Stub: attestation_key is retired (cap.key is public). Always faults.
pub fn host_attestation_key<H: Hardware>(
    _vm: &mut Vm,
    _ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    Ok(HostCallOutcome::Fault(
        "attestation_key is retired in event-redesign; cap.key is directly accessible".into(),
    ))
}

/// Stub: result_equal is retired. Always faults.
pub fn host_result_equal<H: Hardware>(
    _vm: &mut Vm,
    _ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    Ok(HostCallOutcome::Fault(
        "result_equal is retired in event-redesign; use mint_attest_cap with IDENTITY_KEY".into(),
    ))
}
