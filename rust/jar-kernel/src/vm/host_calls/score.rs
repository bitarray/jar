//! `setScore(identifier, score)` host call (verify-only).
//!
//! Reads `(identifier_ptr, identifier_len, score)` from φ[7..10] and
//! buffers a `PoolEntry` into the per-(endpoint, cycle) max-register
//! owned by `NodeOffchain.pool`. Same identifier + same blob keeps the
//! higher-scoring witness; same identifier + different blob is a
//! collision and defers to the next cycle's pool.
//!
//! Process context: `setScore` returns `RC_READONLY` (verify-only).
//!
//! Concrete handler lands in Stage D once parameter decoding plus the
//! `InvocationCtx → NodeOffchain.pool` plumbing is in place.

use crate::runtime::Hardware;
use crate::types::KResult;
use crate::vm::{HostCallOutcome, InvocationCtx, Vm};

/// Stub: setScore not yet wired. Always faults.
pub fn host_set_score<H: Hardware>(
    _vm: &mut Vm,
    _ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    Ok(HostCallOutcome::Fault(
        "setScore is stubbed; concrete handler lands in Stage D".into(),
    ))
}
