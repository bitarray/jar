//! Cap-table host adapter helpers — `vault.slots` ↔ Frame `Cap`
//! translation and rights-checked slot operations.
//!
//! `vault.slots[N]` holds `RegCap` values (small references). Each
//! reference projection is paired with refcount maintenance on the
//! σ-side registry entry (data_blobs / code_blobs / storage_quotas):
//!
//! - `RegCap::VaultRef(vr)` ↔ `Cap::Protocol(ProtocolCap::VaultRef(vr))`.
//! - `RegCap::Resource(r)`  ↔ `Cap::Protocol(ProtocolCap::Resource(r))`.
//! - `RegCap::ImageRef(ir)` ↔ `Cap::Protocol(ProtocolCap::ImageRef(ir))`.
//! - `RegCap::File(f)`      ↔ `Cap::Protocol(ProtocolCap::File(f))`.
//!   `clone` bumps `data_blobs[file_id].refcount`; `drop`/`take`
//!   decrement (and free + refund-to-origin at refcount → 0).
//! - `RegCap::StorageQuota(q)` ↔ `Cap::Protocol(ProtocolCap::StorageQuota(q))`.
//!   Same refcount discipline against `storage_quotas`.
//! - `RegCap::Code(_)` is container-bound — `clone` / `take` return
//!   `None`; the persistent code reference doesn't get a Frame
//!   projection in v1 (Frame `Cap::Code` is the *compiled* artifact,
//!   produced by `vault_init`'s compile path; the σ↔Frame conversion
//!   path for Code is deferred).
//!
//! Bytes-side conversion across the persistence boundary lives in
//! the dedicated `host_open` / `host_save` host calls (Stage 3) —
//! `set`/`clone` here are pure reference-shape projections with
//! refcount maintenance; they do NOT materialise pages.

use std::sync::Arc;

use crate::cap::{Cap, ProtocolCap, RegCap, VaultRights};
use crate::types::{State, VaultId};
use crate::vm::Vm;

// =============================================================================
// Slot accessors (low-level, no rights checks)
// =============================================================================

/// Read the `RegCap` at `(vault, slot)`, if any.
pub(crate) fn slot_cap(state: &State, vault: VaultId, slot: u8) -> Option<RegCap> {
    state.vaults.get(&vault)?.slots.get(slot).cloned()
}

/// Mutably set the slot to `value`, copy-on-write the Vault Arc.
pub(crate) fn slot_set(state: &mut State, vault: VaultId, slot: u8, value: Option<RegCap>) {
    let arc = match state.vaults.get(&vault) {
        Some(a) => a.clone(),
        None => return,
    };
    let mut v: crate::types::Vault = (*arc).clone();
    v.slots.set(slot, value);
    state.vaults.insert(vault, Arc::new(v));
}

// =============================================================================
// Cap-shape projection
// =============================================================================

/// Translate a `RegCap` into the Frame cap-table representation.
/// Returns `None` for `RegCap::Code`, which is container-bound (Frame
/// `Cap::Code` is the compiled artifact, not a reference; the
/// vault_init compile path is the only σ→Frame transition for Code).
pub fn vault_cap_to_frame(cap: &RegCap) -> Option<Cap> {
    match cap {
        RegCap::VaultRef(vr) => Some(Cap::Protocol(ProtocolCap::VaultRef(*vr))),
        RegCap::Resource(r) => Some(Cap::Protocol(ProtocolCap::Resource(r.clone()))),
        RegCap::ImageRef(ir) => Some(Cap::Protocol(ProtocolCap::ImageRef(*ir))),
        RegCap::File(f) => Some(Cap::Protocol(ProtocolCap::File(*f))),
        RegCap::StorageQuota(q) => Some(Cap::Protocol(ProtocolCap::StorageQuota(*q))),
        RegCap::Code(_) => None,
    }
}

/// Translate a Frame cap back to a `RegCap` for placement into
/// `vault.slots`. Returns `None` if the cap can't legally live in σ.
pub fn frame_to_vault_cap(cap: &Cap) -> Option<RegCap> {
    match cap {
        Cap::Protocol(ProtocolCap::VaultRef(vr)) => Some(RegCap::VaultRef(*vr)),
        Cap::Protocol(ProtocolCap::Resource(r)) => Some(RegCap::Resource(r.clone())),
        Cap::Protocol(ProtocolCap::ImageRef(ir)) => Some(RegCap::ImageRef(*ir)),
        Cap::Protocol(ProtocolCap::File(f)) => Some(RegCap::File(*f)),
        Cap::Protocol(ProtocolCap::StorageQuota(q)) => Some(RegCap::StorageQuota(*q)),
        _ => None,
    }
}

// =============================================================================
// Rights-checked slot operations
// =============================================================================

/// `ProtocolCapHost::get` — read-only fetch.
pub fn get(state: &State, vault: VaultId, slot: u8) -> Option<Cap> {
    slot_cap(state, vault, slot)
        .as_ref()
        .and_then(vault_cap_to_frame)
}

/// `ProtocolCapHost::take` — fetch and clear, gated by `rights.revoke`.
///
/// Bans `RegCap::File`, `RegCap::Code`, and `RegCap::StorageQuota`:
/// these are reference caps with refcount discipline, and the
/// take-then-set ordering used by `MGMT_MOVE` cannot maintain
/// refcount correctness when both endpoints would touch the same
/// entry. Programs use `clone` + `drop` (i.e. MGMT_COPY then
/// MGMT_DROP) for move semantics. This mirrors the prior ban on
/// `RegCap::Data` MOVE-across-boundary.
pub fn take(state: &mut State, vault: VaultId, slot: u8, rights: VaultRights) -> Option<Cap> {
    if !rights.revoke {
        return None;
    }
    let cap = slot_cap(state, vault, slot)?;
    if matches!(
        cap,
        RegCap::File(_) | RegCap::Code(_) | RegCap::StorageQuota(_)
    ) {
        return None;
    }
    let frame_cap = vault_cap_to_frame(&cap)?;
    slot_set(state, vault, slot, None);
    Some(frame_cap)
}

/// `ProtocolCapHost::set` — place into an empty slot, gated by
/// `rights.grant`. Returns `Err(cap)` if the host rejects placement.
///
/// For reference-shaped caps (File / StorageQuota / VaultRef /
/// ImageRef / Resource), set bumps the appropriate registry refcount.
/// `Cap::Data` is rejected — bytes cross the persistence boundary
/// only via the explicit `host_save` op.
pub fn set(
    state: &mut State,
    vault: VaultId,
    slot: u8,
    rights: VaultRights,
    cap: Cap,
    _vm: Option<&Vm>,
) -> Result<(), Cap> {
    if !rights.grant {
        return Err(cap);
    }
    match state.vaults.get(&vault) {
        Some(v) if v.slots.get(slot).is_none() => {}
        _ => return Err(cap),
    }
    let vc = match &cap {
        Cap::Protocol(ProtocolCap::VaultRef(vr)) => RegCap::VaultRef(*vr),
        Cap::Protocol(ProtocolCap::Resource(r)) => RegCap::Resource(r.clone()),
        Cap::Protocol(ProtocolCap::ImageRef(ir)) => RegCap::ImageRef(*ir),
        Cap::Protocol(ProtocolCap::File(f)) => RegCap::File(*f),
        Cap::Protocol(ProtocolCap::StorageQuota(q)) => RegCap::StorageQuota(*q),
        _ => return Err(cap),
    };
    // Bump σ-side refcount on registry entries (File/Code/Quota).
    // Other RegCap kinds have no registry entry and need no bookkeeping.
    bump_refcount_for(state, &vc);
    slot_set(state, vault, slot, Some(vc));
    Ok(())
}

/// `ProtocolCapHost::clone` — read-only copy, gated by `rights.derive`.
///
/// For reference-shaped caps, returns the Frame projection with the
/// same registry id; **does not** bump σ-side refcount. The Frame
/// cap is a "lookup handle" — operations on it (host_open, host_save)
/// validate the registry entry at use time. If the entry is freed
/// before the Frame cap is used, ops fail cleanly.
pub fn clone(
    state: &State,
    vault: VaultId,
    slot: u8,
    rights: VaultRights,
    _vm: Option<&mut Vm>,
) -> Option<Cap> {
    if !rights.derive {
        return None;
    }
    let cap = slot_cap(state, vault, slot)?;
    vault_cap_to_frame(&cap)
}

/// `ProtocolCapHost::drop` — clear the slot, gated by `rights.revoke`.
/// Decrements the σ-side refcount on the registry entry (free + refund
/// at refcount → 0).
pub fn drop(state: &mut State, vault: VaultId, slot: u8, rights: VaultRights) -> bool {
    if !rights.revoke {
        return false;
    }
    let cap = match slot_cap(state, vault, slot) {
        Some(c) => c,
        None => return false,
    };
    drop_refcount_for(state, &cap);
    slot_set(state, vault, slot, None);
    true
}

// =============================================================================
// Refcount maintenance helpers
// =============================================================================

/// Bump the registry-entry refcount that backs `cap`, if any.
/// VaultRef / Resource / ImageRef have no registry entry — no-op.
pub(crate) fn bump_refcount_for(state: &mut State, cap: &RegCap) {
    match cap {
        RegCap::File(f) => state.bump_file_refcount(f.file_id),
        RegCap::Code(c) => state.bump_code_refcount(c.code_id),
        RegCap::StorageQuota(q) => state.bump_quota_refcount(q.quota_id),
        RegCap::VaultRef(_) | RegCap::Resource(_) | RegCap::ImageRef(_) => {}
    }
}

/// Drop the registry-entry refcount that backs `cap`, if any.
/// Frees the entry and refunds bytes (for File/Code) at refcount → 0.
pub(crate) fn drop_refcount_for(state: &mut State, cap: &RegCap) {
    match cap {
        RegCap::File(f) => state.drop_file_refcount(f.file_id),
        RegCap::Code(c) => state.drop_code_refcount(c.code_id),
        RegCap::StorageQuota(q) => state.drop_quota_refcount(q.quota_id),
        RegCap::VaultRef(_) | RegCap::Resource(_) | RegCap::ImageRef(_) => {}
    }
}

/// `ProtocolCapHost::is_empty` — predicate.
pub fn is_empty(state: &State, vault: VaultId, slot: u8) -> bool {
    match state.vaults.get(&vault) {
        Some(v) => v.slots.get(slot).is_none(),
        None => true,
    }
}
