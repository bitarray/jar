//! Legacy slot module — retired in the event-redesign.
//!
//! The prior `SlotContent` union (AggregatedDispatch / AggregatedTransact /
//! Empty) and per-(node, endpoint) slot persistence is gone. Aggregation
//! is now via setScore + max-register on the per-cycle pool; cycle = block
//! window, state torn down at boundaries.
//!
//! `Event` is preserved here as a minimal struct used in legacy code
//! paths during the migration; new code uses `BodyEvent` from `block.rs`.

use super::ResultEntry;
use crate::cap::AttestationEntry;

/// Legacy Event shape. Retained for in-process tests / fixtures during
/// the migration. New code: see `BodyEvent` in `types/block.rs`.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct Event {
    pub payload: Vec<u8>,
    pub caps: Vec<u8>,
    pub attestation_trace: Vec<AttestationEntry>,
    pub result_trace: Vec<ResultEntry>,
}
