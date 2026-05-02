//! Transact-phase per-event execution — stub for the event-redesign migration.
//!
//! In the new design, apply_block walks `σ.transact_endpoints` in slot
//! order, running per-slot interleaved verify-then-process. Concrete
//! implementation lands in Stage C.

use crate::cap::attest::AttestCursor;
use crate::runtime::Hardware;
use crate::types::{Body, Command, KResult, State};

/// Stub: returns empty commands. Concrete implementation in Stage C.
pub fn run_phase<H: Hardware>(
    _state: &mut State,
    _body: &mut Body,
    _cursor: &mut AttestCursor,
    _hw: &H,
    _record_reach: bool,
) -> KResult<Vec<Command>> {
    Ok(Vec::new())
}
