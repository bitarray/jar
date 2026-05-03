//! Cap-table host adapter helpers — `vault.slots` ↔ Frame `Cap`
//! translation and rights-checked slot operations.
//!
//! `vault.slots[N]` holds `RegCap` values directly. Translation
//! between `RegCap` and the Frame's `Cap` representation:
//!
//! - `RegCap::VaultRef(vr)` ↔ `Cap::Protocol(ProtocolCap::VaultRef(vr))`.
//! - `RegCap::Resource(r)`  ↔ `Cap::Protocol(ProtocolCap::Resource(r))`.
//! - `RegCap::ImageRef(ir)` ↔ `Cap::Protocol(ProtocolCap::ImageRef(ir))`.
//! - `RegCap::Code(_)` is container-bound — `clone` / `take` return
//!   `None`; code never moves between Vault and Frame.
//! - `RegCap::Data(_)`: `clone` allocates a fresh ephemeral
//!   `Cap::Data` from the active VM's `untyped` + `backing`,
//!   byte-copying σ content. `set` reads the post-execution pages
//!   of an ephemeral `Cap::Data` and persists them into σ.
//!   `take` is BANNED for Data — MGMT_MOVE across the
//!   persistent/ephemeral boundary returns `None`. Guests use
//!   COPY + DROP instead.
//!
//! The rights-checked ops (`take` / `set` / `clone` / `drop` /
//! `is_empty` / `get`) are exposed as free functions. The
//! production `ProtocolCapHost` impl on
//! [`crate::vm::InvocationHost`] delegates to them.

use std::sync::Arc;

use crate::cap::{Cap, ProtocolCap, RegCap, VaultRights};
use crate::types::{DataCap, State, VaultId};
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
/// `RegCap::Data` is rejected (returns `None`): MGMT_MOVE across
/// the persistent/ephemeral boundary is banned. Guests use COPY +
/// DROP for move-like semantics.
pub fn take(state: &mut State, vault: VaultId, slot: u8, rights: VaultRights) -> Option<Cap> {
    if !rights.revoke {
        return None;
    }
    let cap = slot_cap(state, vault, slot)?;
    if matches!(cap, RegCap::Data(_)) {
        // Data crossings must use clone+drop, not move. The
        // persistent and ephemeral memory pools are tracked
        // separately; in-place move would entangle them.
        return None;
    }
    let frame_cap = vault_cap_to_frame(&cap)?;
    slot_set(state, vault, slot, None);
    Some(frame_cap)
}

/// `ProtocolCapHost::set` — place into an empty slot, gated by
/// `rights.grant`. Returns `Err(cap)` if the host rejects placement.
///
/// For `Cap::Data`, the kernel reads the cap's post-execution
/// pages from `vm.backing` and persists them as a fresh
/// `RegCap::Data` σ entry. The ephemeral source slot is left
/// untouched (Data MOVE-across-boundary is banned; semantically
/// this is the COPY-into-σ path).
pub fn set(
    state: &mut State,
    vault: VaultId,
    slot: u8,
    rights: VaultRights,
    cap: Cap,
    vm: Option<&Vm>,
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
        Cap::Data(d) => {
            // Read post-execution pages directly from the
            // BackingStore — works whether or not the cap is
            // currently mapped in the active VM.
            let vm = match vm {
                Some(v) => v,
                None => return Err(cap),
            };
            let bytes = match vm.backing.read_pages(d.backing_offset, d.page_count) {
                Some(b) => b,
                None => return Err(cap),
            };
            RegCap::Data(DataCap {
                content: Arc::new(bytes),
                page_count: d.page_count,
            })
        }
        _ => return Err(cap),
    };
    slot_set(state, vault, slot, Some(vc));
    Ok(())
}

/// `ProtocolCapHost::clone` — read-only copy, gated by `rights.derive`.
///
/// For `RegCap::Data`, allocates a fresh ephemeral `Cap::Data`
/// from the active VM's `untyped` (BareFrame slot
/// `BARE_FRAME_UNTYPED_SLOT`) + `backing`, byte-copying the σ
/// content. The σ slot is left intact.
pub fn clone(
    state: &State,
    vault: VaultId,
    slot: u8,
    rights: VaultRights,
    vm: Option<&mut Vm>,
) -> Option<Cap> {
    if !rights.derive {
        return None;
    }
    let cap = slot_cap(state, vault, slot)?;
    match cap {
        RegCap::VaultRef(vr) => Some(Cap::Protocol(ProtocolCap::VaultRef(vr))),
        RegCap::Resource(r) => Some(Cap::Protocol(ProtocolCap::Resource(r))),
        RegCap::ImageRef(ir) => Some(Cap::Protocol(ProtocolCap::ImageRef(ir))),
        RegCap::Code(_) => None,
        RegCap::Data(d) => {
            // Allocate a fresh ephemeral DataCap from the active
            // invocation's BareFrame Untyped + BackingStore.
            let vm = vm?;
            let bare_idx = vm.bare_frame_id.index();
            let bare_table = &mut vm.vm_arena.vm_mut(bare_idx).cap_table;
            let untyped = match bare_table.get_mut(javm::kernel::BARE_FRAME_UNTYPED_SLOT) {
                Some(javm::cap::Cap::Untyped(u)) => u,
                _ => return None,
            };
            let data_cap =
                javm::kernel::allocate_data_cap(&d.content, d.page_count, untyped, &mut vm.backing)
                    .ok()?;
            Some(Cap::Data(data_cap))
        }
    }
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
