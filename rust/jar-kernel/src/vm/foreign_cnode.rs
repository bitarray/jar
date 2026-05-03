//! Cap-table host adapter helpers — `vault.slots` ↔ Frame `Cap`
//! translation and rights-checked slot operations.
//!
//! After CapId removal, `vault.slots[N]` holds `RegCap` values
//! directly. Translation between `RegCap` and the Frame's `Cap`
//! representation:
//!
//! - `RegCap::VaultRef(vr)` ↔ `Cap::Protocol(ProtocolCap::VaultRef(vr))`.
//! - `RegCap::Resource(r)`  ↔ `Cap::Protocol(ProtocolCap::Resource(r))`.
//! - `RegCap::Code(_)` / `RegCap::Data(_)` are container-bound:
//!   they're compiled / mapped at `vault_init` only, never moved
//!   between Vault and Frame mid-VM. `take` / `clone` on those return
//!   `None`.
//!
//! The rights-checked ops (`take` / `set` / `clone` / `drop` /
//! `is_empty` / `get`) are exposed as free functions. The production
//! `ProtocolCapHost` impl on [`crate::vm::InvocationHost`] delegates
//! to them; tests that exercise cap-table semantics in isolation can
//! call them directly without constructing a full host.

use std::sync::Arc;

use crate::cap::{Cap, ProtocolCap, RegCap, VaultRights};
use crate::types::{State, VaultId};

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
/// Returns `None` for kinds that don't have a `ProtocolCap` variant
/// (Code / Data are container-bound; Stage 6 lifts the Data
/// restriction by routing through `InvocationHost::clone`'s vm
/// access for ephemeral allocation).
pub fn vault_cap_to_frame(cap: &RegCap) -> Option<Cap> {
    match cap {
        RegCap::VaultRef(vr) => Some(Cap::Protocol(ProtocolCap::VaultRef(*vr))),
        RegCap::Resource(r) => Some(Cap::Protocol(ProtocolCap::Resource(r.clone()))),
        RegCap::ImageRef(ir) => Some(Cap::Protocol(ProtocolCap::ImageRef(*ir))),
        RegCap::Code(_) | RegCap::Data(_) => None,
    }
}

/// Translate a Frame cap back to a `RegCap` for placement into
/// `vault.slots`. Returns `None` if the cap can't legally live in σ.
pub fn frame_to_vault_cap(cap: &Cap) -> Option<RegCap> {
    match cap {
        Cap::Protocol(ProtocolCap::VaultRef(vr)) => Some(RegCap::VaultRef(*vr)),
        Cap::Protocol(ProtocolCap::Resource(r)) => Some(RegCap::Resource(r.clone())),
        Cap::Protocol(ProtocolCap::ImageRef(ir)) => Some(RegCap::ImageRef(*ir)),
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
pub fn take(state: &mut State, vault: VaultId, slot: u8, rights: VaultRights) -> Option<Cap> {
    if !rights.revoke {
        return None;
    }
    let cap = slot_cap(state, vault, slot)?;
    let frame_cap = vault_cap_to_frame(&cap)?;
    slot_set(state, vault, slot, None);
    Some(frame_cap)
}

/// `ProtocolCapHost::set` — place into an empty slot, gated by
/// `rights.grant`. Returns `Err(cap)` if the host rejects placement.
pub fn set(
    state: &mut State,
    vault: VaultId,
    slot: u8,
    rights: VaultRights,
    cap: Cap,
) -> Result<(), Cap> {
    if !rights.grant {
        return Err(cap);
    }
    match state.vaults.get(&vault) {
        Some(v) if v.slots.get(slot).is_none() => {}
        _ => return Err(cap),
    }
    let vc = match frame_to_vault_cap(&cap) {
        Some(v) => v,
        None => return Err(cap),
    };
    slot_set(state, vault, slot, Some(vc));
    Ok(())
}

/// `ProtocolCapHost::clone` — read-only copy, gated by `rights.derive`.
pub fn clone(state: &State, vault: VaultId, slot: u8, rights: VaultRights) -> Option<Cap> {
    if !rights.derive {
        return None;
    }
    let cap = slot_cap(state, vault, slot)?;
    vault_cap_to_frame(&cap)
}

/// `ProtocolCapHost::drop` — clear the slot, gated by `rights.revoke`.
pub fn drop(state: &mut State, vault: VaultId, slot: u8, rights: VaultRights) -> bool {
    if !rights.revoke {
        return false;
    }
    if slot_cap(state, vault, slot).is_none() {
        return false;
    }
    slot_set(state, vault, slot, None);
    true
}

/// `ProtocolCapHost::is_empty` — predicate.
pub fn is_empty(state: &State, vault: VaultId, slot: u8) -> bool {
    match state.vaults.get(&vault) {
        Some(v) => v.slots.get(slot).is_none(),
        None => true,
    }
}
