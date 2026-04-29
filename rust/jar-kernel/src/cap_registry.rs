//! Capability registry: alloc, lookup, derive, revoke (cascade).

use std::collections::BTreeSet;

use jar_types::{
    CNodeId, CapId, CapRecord, Capability, Crypto, KResult, KernelError, State, VaultId,
};

use crate::pinning;

/// Allocate a fresh CapRecord and place it in σ. Returns the new CapId.
pub fn alloc<C: Crypto>(state: &mut State<C>, record: CapRecord<C>) -> CapId {
    let id = state.next_cap_id();
    if let Some(parent) = record.issuer {
        state.cap_children.entry(parent).or_default().insert(id);
    }
    state.cap_registry.insert(id, record);
    id
}

/// Look up a CapRecord. Errors if missing.
pub fn lookup<C: Crypto>(state: &State<C>, id: CapId) -> KResult<&CapRecord<C>> {
    state.cap_record(id)
}

/// Cascade-revoke `id` and all caps derived from it. Clears every CNode slot
/// that referenced any of them. Returns the number of caps revoked.
pub fn revoke_cascade<C: Crypto>(state: &mut State<C>, root: CapId) -> usize {
    let mut to_visit = vec![root];
    let mut revoked = 0usize;
    while let Some(id) = to_visit.pop() {
        if let Some(children) = state.cap_children.remove(&id) {
            to_visit.extend(children);
        }
        if state.cap_registry.remove(&id).is_some() {
            revoked += 1;
        }
        if let Some(holders) = state.cap_holders.remove(&id) {
            for (cn, slot) in holders {
                if let Some(cnode) = state.cnodes.get_mut(&cn) {
                    cnode.set(slot, None);
                }
            }
        }
    }
    revoked
}

/// Record that `cap` is held in `(cnode, slot)`.
pub fn note_holder<C: Crypto>(state: &mut State<C>, cap: CapId, cnode: CNodeId, slot: u8) {
    state
        .cap_holders
        .entry(cap)
        .or_default()
        .insert((cnode, slot));
}

/// Forget that `cap` is held in `(cnode, slot)`.
pub fn unnote_holder<C: Crypto>(state: &mut State<C>, cap: CapId, cnode: CNodeId, slot: u8) {
    if let Some(set) = state.cap_holders.get_mut(&cap) {
        set.remove(&(cnode, slot));
        if set.is_empty() {
            state.cap_holders.remove(&cap);
        }
    }
}

/// Derive a new CapRecord from `source` with kernel-provided narrowing data.
/// `dest_persistent`: true iff destination is a persistent CNode (not a Frame).
/// Pinning rules are enforced.
pub fn derive<C: Crypto>(
    state: &mut State<C>,
    source: CapId,
    new_cap: Capability<C>,
    narrowing: Vec<u8>,
    dest_persistent: bool,
) -> KResult<CapId> {
    let _ = lookup(state, source)?;
    pinning::check_derive(state, source, &new_cap, dest_persistent)?;
    let record = CapRecord {
        cap: new_cap,
        issuer: Some(source),
        narrowing,
    };
    Ok(alloc(state, record))
}

/// Iterate all top-level cap-ids known to the registry. Helpful for tests.
pub fn all_cap_ids<C: Crypto>(state: &State<C>) -> BTreeSet<CapId> {
    state.cap_registry.keys().copied().collect()
}

/// Look up the VaultId mapped by a callable cap (Vault, VaultRef, Dispatch,
/// Transact, DispatchRef, TransactRef, Storage). Errors if `id` is none of those.
pub fn cap_vault_id<C: Crypto>(state: &State<C>, id: CapId) -> KResult<VaultId> {
    let cap = &lookup(state, id)?.cap;
    cap.vault_id()
        .ok_or_else(|| KernelError::Internal(format!("cap {:?} has no vault id", id)))
}
