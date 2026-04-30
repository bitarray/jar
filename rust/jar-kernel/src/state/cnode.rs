//! Operations on CNodes — grant, move, revoke, derive.
//!
//! All slot mutations on persistent CNodes go through these. Pinning checks
//! happen here.

use crate::types::{CNodeId, CapId, Capability, KResult, KernelError, State};

use crate::cap::pinning;
use crate::state::cap_registry;

/// Grant `source_cap` into `(dest_cnode, dest_slot)`. The cap is COPIED — the
/// source still references it (this is the kernel-level "grant a copy").
/// Returns the granted CapId (the same as `source_cap` since granting doesn't
/// re-allocate).
pub fn cnode_grant(
    state: &mut State,
    source_cap: CapId,
    dest_cnode: CNodeId,
    dest_slot: u8,
) -> KResult<CapId> {
    let src_record = cap_registry::lookup(state, source_cap)?.clone();
    pinning::check_grant_or_move(&src_record.cap, dest_cnode)?;
    let cnode = state
        .cnodes
        .get_mut(&dest_cnode)
        .ok_or(KernelError::CNodeNotFound(dest_cnode))?;
    if cnode.get(dest_slot).is_some() {
        return Err(KernelError::Internal(format!(
            "cnode_grant: slot {} of {:?} already occupied",
            dest_slot, dest_cnode
        )));
    }
    cnode.set(dest_slot, Some(source_cap));
    cap_registry::note_holder(state, source_cap, dest_cnode, dest_slot);
    Ok(source_cap)
}

/// Move a cap from `(src_cnode, src_slot)` to `(dest_cnode, dest_slot)`.
/// Pinning rule: Dispatch/Transact may only be moved within their `born_in`.
pub fn cnode_move(
    state: &mut State,
    src_cnode: CNodeId,
    src_slot: u8,
    dest_cnode: CNodeId,
    dest_slot: u8,
) -> KResult<CapId> {
    let cap = state
        .cnodes
        .get(&src_cnode)
        .ok_or(KernelError::CNodeNotFound(src_cnode))?
        .get(src_slot)
        .ok_or(KernelError::CNodeSlotEmpty {
            cnode: src_cnode,
            slot: src_slot,
        })?;
    let record = cap_registry::lookup(state, cap)?.clone();
    pinning::check_grant_or_move(&record.cap, dest_cnode)?;
    if state
        .cnodes
        .get(&dest_cnode)
        .ok_or(KernelError::CNodeNotFound(dest_cnode))?
        .get(dest_slot)
        .is_some()
    {
        return Err(KernelError::Internal(format!(
            "cnode_move: dest slot {} of {:?} already occupied",
            dest_slot, dest_cnode
        )));
    }
    // Clear source.
    if let Some(src) = state.cnodes.get_mut(&src_cnode) {
        src.set(src_slot, None);
    }
    cap_registry::unnote_holder(state, cap, src_cnode, src_slot);
    // Set destination.
    if let Some(dest) = state.cnodes.get_mut(&dest_cnode) {
        dest.set(dest_slot, Some(cap));
    }
    cap_registry::note_holder(state, cap, dest_cnode, dest_slot);
    Ok(cap)
}

/// Revoke whatever lives in `(cnode, slot)` (if anything). Cascade-revokes
/// all caps derived from it.
pub fn cnode_revoke(state: &mut State, cnode: CNodeId, slot: u8) -> KResult<()> {
    let Some(cn) = state.cnodes.get(&cnode) else {
        return Err(KernelError::CNodeNotFound(cnode));
    };
    let Some(cap_id) = cn.get(slot) else {
        return Ok(());
    };
    cap_registry::revoke_cascade(state, cap_id);
    Ok(())
}

/// Allocate a fresh empty CNode in σ; returns its id.
pub fn cnode_create(state: &mut State) -> CNodeId {
    let id = state.next_cnode_id();
    state.cnodes.insert(id, crate::types::CNode::new());
    id
}

/// Place an already-allocated CapId at a CNode slot directly (used during
/// genesis construction). Skips pinning checks — caller's responsibility.
pub fn cnode_place_raw(state: &mut State, cnode: CNodeId, slot: u8, cap: CapId) -> KResult<()> {
    let cn = state
        .cnodes
        .get_mut(&cnode)
        .ok_or(KernelError::CNodeNotFound(cnode))?;
    cn.set(slot, Some(cap));
    cap_registry::note_holder(state, cap, cnode, slot);
    Ok(())
}

/// Mint a fresh CapRecord ex nihilo (issuer = None) and place at `(cnode, slot)`.
/// Used during genesis construction. Skips pinning checks.
pub fn mint_and_place(
    state: &mut State,
    cap: Capability,
    narrowing: Vec<u8>,
    cnode: CNodeId,
    slot: u8,
) -> KResult<CapId> {
    let id = cap_registry::alloc(
        state,
        crate::types::CapRecord {
            cap,
            issuer: None,
            narrowing,
        },
    );
    cnode_place_raw(state, cnode, slot, id)?;
    Ok(id)
}
