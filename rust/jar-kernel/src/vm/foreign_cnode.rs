//! Host adapter that lets javm's resolve walk address jar-kernel's
//! σ-resident Vault CNodes as a third frame kind.
//!
//! When a cap-ref crossing lands on a `Cap::Protocol(_)` whose
//! `as_foreign_frame()` returns `Some(VaultId)`, javm packages that as
//! `FrameId::Foreign(VaultId)` and routes subsequent slot operations
//! (`take` / `set` / `clone` / `drop` / `is_empty`)
//! through this adapter.
//!
//! After CapId removal, `vault.slots[N]` holds `RegCap` values
//! directly. Translation between `RegCap` and the Frame's `Cap`
//! representation:
//!
//! - `RegCap::VaultRef(vr)` ↔ `Cap::Protocol(ProtocolCap::VaultRef(vr))`.
//! - `RegCap::Resource(r)` ↔ `Cap::Protocol(ProtocolCap::Resource(r))`.
//! - `RegCap::Code(_)` / `RegCap::Data(_)` are container-bound:
//!   they're compiled / mapped at `vault_init` only, never moved between
//!   Vault and Frame mid-VM. `take` / `clone` on those return
//!   `None`.
//!
//! No cap_registry, no cascade revocation. `drop` is just "clear the
//! slot"; granting a copy via `set` after `clone` produces an
//! independent owner of the value.

use std::sync::Arc;

use javm::cap::ProtocolCapHost;

use crate::cap::{Cap, ProtocolCap, RegCap, VaultRights};
use crate::types::{State, VaultId};

/// Adapter implementing [`ProtocolCapHost<ProtocolCap>`] over `&mut State`.
/// Rebuilt cheaply each iteration of `drive_invocation`'s run loop
/// because it just wraps a borrow.
pub struct VaultCnodeView<'a> {
    pub state: &'a mut State,
}

impl<'a> VaultCnodeView<'a> {
    pub fn new(state: &'a mut State) -> Self {
        Self { state }
    }
}

/// Read the `RegCap` at `(vault, slot)`, if any.
fn slot_cap(state: &State, vault: VaultId, slot: u8) -> Option<RegCap> {
    state.vaults.get(&vault)?.slots.get(slot).cloned()
}

/// Mutably set the slot to `value`, copy-on-write the Vault Arc.
fn slot_set(state: &mut State, vault: VaultId, slot: u8, value: Option<RegCap>) {
    let arc = match state.vaults.get(&vault) {
        Some(a) => a.clone(),
        None => return,
    };
    let mut v: crate::types::Vault = (*arc).clone();
    v.slots.set(slot, value);
    state.vaults.insert(vault, Arc::new(v));
}

impl ProtocolCapHost<ProtocolCap> for VaultCnodeView<'_> {
    fn get(&self, vault: VaultId, slot: u8) -> Option<Cap> {
        let vc = slot_cap(self.state, vault, slot)?;
        vault_cap_to_frame(&vc)
    }

    fn take(&mut self, vault: VaultId, slot: u8, rights: VaultRights) -> Option<Cap> {
        if !rights.revoke {
            return None;
        }
        let cap = slot_cap(self.state, vault, slot)?;
        let frame_cap = vault_cap_to_frame(&cap)?;
        slot_set(self.state, vault, slot, None);
        Some(frame_cap)
    }

    fn set(&mut self, vault: VaultId, slot: u8, rights: VaultRights, cap: Cap) -> Result<(), Cap> {
        if !rights.grant {
            return Err(cap);
        }
        // Slot must be empty.
        match self.state.vaults.get(&vault) {
            Some(v) if v.slots.get(slot).is_none() => {}
            _ => return Err(cap),
        }
        let vc = match frame_to_vault_cap(&cap) {
            Some(v) => v,
            None => return Err(cap),
        };
        slot_set(self.state, vault, slot, Some(vc));
        Ok(())
    }

    fn clone(&mut self, vault: VaultId, slot: u8, rights: VaultRights) -> Option<Cap> {
        if !rights.derive {
            return None;
        }
        let cap = slot_cap(self.state, vault, slot)?;
        // Cloning is a pure-value operation: produce another Frame cap
        // of the same shape. No cap_registry interaction.
        vault_cap_to_frame(&cap)
    }

    fn drop(&mut self, vault: VaultId, slot: u8, rights: VaultRights) -> bool {
        if !rights.revoke {
            return false;
        }
        if slot_cap(self.state, vault, slot).is_none() {
            return false;
        }
        slot_set(self.state, vault, slot, None);
        true
    }

    fn is_empty(&self, vault: VaultId, slot: u8) -> bool {
        match self.state.vaults.get(&vault) {
            Some(v) => v.slots.get(slot).is_none(),
            None => true,
        }
    }
}

/// Translate a `RegCap` into the Frame cap-table representation.
/// Returns `None` for kinds that don't have a `ProtocolCap` variant
/// (Code / Data are container-bound).
fn vault_cap_to_frame(cap: &RegCap) -> Option<Cap> {
    match cap {
        RegCap::VaultRef(vr) => Some(Cap::Protocol(ProtocolCap::VaultRef(*vr))),
        RegCap::Resource(r) => Some(Cap::Protocol(ProtocolCap::Resource(r.clone()))),
        RegCap::Code(_) | RegCap::Data(_) => None,
    }
}

/// Translate a Frame cap back to a `RegCap` for placement into
/// `vault.slots`. Returns `None` if the cap can't legally live in σ.
fn frame_to_vault_cap(cap: &Cap) -> Option<RegCap> {
    match cap {
        Cap::Protocol(ProtocolCap::VaultRef(vr)) => Some(RegCap::VaultRef(*vr)),
        Cap::Protocol(ProtocolCap::Resource(r)) => Some(RegCap::Resource(r.clone())),
        // HostCall, Frame-only kinds (SelfId / Caller* / AttestationScope /
        // Attestation / AttestationAggregate), and javm-side first-class
        // arms (Cap::Code, Cap::Data, Cap::FrameRef, Cap::Empty) all
        // refuse persistence to vault.slots.
        _ => None,
    }
}
