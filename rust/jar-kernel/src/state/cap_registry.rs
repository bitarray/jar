//! RegCap registry: alloc, lookup, derive, revoke (cascade).

use std::collections::BTreeSet;

use crate::types::{CapId, CapRecord, KResult, KernelError, RegCap, State, VaultId};

use crate::cap::pinning;

/// Allocate a fresh CapRecord and place it in σ. Returns the new CapId.
pub fn alloc(state: &mut State, record: CapRecord) -> CapId {
    let id = state.next_cap_id();
    if let Some(parent) = record.issuer {
        state.cap_children.entry(parent).or_default().insert(id);
    }
    state.cap_registry.insert(id, record);
    id
}

/// Look up a CapRecord. Errors if missing.
pub fn lookup(state: &State, id: CapId) -> KResult<&CapRecord> {
    state.cap_record(id)
}

/// Cascade-revoke `id` and all caps derived from it. Returns the number
/// of caps revoked.
///
/// The kernel does NOT track "which slots hold this cap-id" — Vault.slots
/// is the only cap-bearing surface and isn't mirrored in σ.cap_holders
/// (that index was retired alongside `state.cnodes`). Vault slots that
/// reference a revoked cap surface the revocation lazily on next access.
pub fn revoke_cascade(state: &mut State, root: CapId) -> usize {
    let mut to_visit = vec![root];
    let mut revoked = 0usize;
    while let Some(id) = to_visit.pop() {
        if let Some(children) = state.cap_children.remove(&id) {
            to_visit.extend(children);
        }
        if state.cap_registry.remove(&id).is_some() {
            revoked += 1;
        }
    }
    revoked
}

/// Derive a new CapRecord from `source` with kernel-provided narrowing data.
/// `dest_persistent`: true iff destination is a persistent surface (Vault.slots
/// vs Frame). Pinning rules are enforced.
pub fn derive(
    state: &mut State,
    source: CapId,
    new_cap: RegCap,
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
pub fn all_cap_ids(state: &State) -> BTreeSet<CapId> {
    state.cap_registry.keys().copied().collect()
}

/// Look up the VaultId mapped by a callable cap (VaultRef, EventEndpoint).
/// Errors if `id` doesn't reference a Vault.
pub fn cap_vault_id(state: &State, id: CapId) -> KResult<VaultId> {
    let cap = &lookup(state, id)?.cap;
    cap.vault_id()
        .ok_or_else(|| KernelError::Internal(format!("cap {id:?} has no vault id")))
}
