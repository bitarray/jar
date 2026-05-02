//! Pinning rules — vestigial in the event-redesign.
//!
//! The prior `Dispatch` / `Transact` / `Schedule` cap variants with
//! `born_in` CNode parents and the associated pinning rules (no cross-
//! CNode placement, no cross-invocation arg-passing) are gone. The
//! `EventEndpointCap` is a flat cap; placement is governed by which σ
//! list it's in (transact_endpoints vs dispatch_endpoints), not by
//! structural pinning. The remaining stub keeps `cap_registry::derive`'s
//! signature; future cleanups may inline the no-op away.

use crate::cap::Capability;
use crate::types::{CapId, KResult, State};

/// Vestigial — always Ok in the new design.
pub fn check_derive(
    _state: &State,
    _source: CapId,
    _new_cap: &Capability,
    _dest_persistent: bool,
) -> KResult<()> {
    Ok(())
}

/// Vestigial — always Ok in the new design (no pinned cap variants).
pub fn arg_scan(_state: &State, _arg_caps: &[CapId]) -> KResult<()> {
    Ok(())
}
