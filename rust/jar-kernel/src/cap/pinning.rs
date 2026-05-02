//! Pinning rules — retired in the event-redesign.
//!
//! The prior `Dispatch` / `Transact` / `Schedule` cap variants with
//! `born_in` CNodeIds and the associated pinning rules (no cross-CNode
//! placement, no cross-invocation arg-passing) are gone. The new
//! `EventEndpointCap` is a flat cap with no born_in field; placement
//! is governed by which σ list it's in (transact_endpoints vs
//! dispatch_endpoints), not by structural pinning.
//!
//! This module is preserved as a stub for any callers still importing
//! it; it will be removed entirely in a follow-up commit.

use crate::cap::Capability;
use crate::types::{CNodeId, CapId, KResult, State};

/// Vestigial — always Ok in the new design.
pub fn check_grant_or_move(_cap: &Capability, _target_cnode: CNodeId) -> KResult<()> {
    Ok(())
}

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
