//! Host adapter that lets javm's resolve walk address jar-kernel's
//! σ-resident Vault CNodes as a third frame kind.
//!
//! When a cap-ref crossing lands on a `Cap::Protocol(_)` whose
//! `as_foreign_frame()` returns `Some(VaultId)`, javm packages that as
//! `FrameId::Foreign(VaultId)` and routes subsequent slot operations
//! (`fc_take` / `fc_set` / `fc_clone` / `fc_drop` / `fc_is_empty`)
//! through this adapter.
//!
//! Each method maps a `vault.slots[N]: SlotEntry` to/from a Frame cap:
//!
//! - `SlotEntry::VaultRef(vr)` round-trips with
//!   `Cap::Protocol(ProtocolCap::VaultRef(vr))` — pure value, no σ identity.
//!
//! - `SlotEntry::Cap(id)` with a `RegCap::Resource(_)` record round-trips
//!   with `Cap::Protocol(ProtocolCap::Resource { id, cap })`. The CapId
//!   is preserved so derive-tree bookkeeping survives the bounce.
//!
//! - `SlotEntry::Cap(id)` with a `RegCap::Code(_)` / `RegCap::Data(_)`
//!   record is rejected by `fc_take` / `fc_clone` — bulk caps don't
//!   relocate mid-VM (they're compiled / mapped at vault_init only).
//!
//! - `SlotEntry::Cap(id)` with a `RegCap::EventEndpoint(_)` record is
//!   rejected. EventEndpoints belong in `σ.{transact,dispatch}_endpoints`,
//!   not `vault.slots`; finding one here is a kernel bug.
//!
//! - `fc_drop` on a `SlotEntry::Cap(id)` invokes
//!   `cap_registry::revoke_cascade(id)` then clears the slot.
//!   `fc_drop` on a `SlotEntry::VaultRef(_)` just clears the slot
//!   (no registry to update).

use std::sync::Arc;

use javm::cap::ForeignCnode;

use crate::cap::{Cap, ProtocolCap, RegCap, VaultRights};
use crate::state::cap_registry;
use crate::types::{CapId, SlotEntry, State, VaultId};

/// Adapter implementing [`ForeignCnode<ProtocolCap>`] over `&mut State`.
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

/// Read the `SlotEntry` at `(vault, slot)`, if any.
fn slot_entry(state: &State, vault: VaultId, slot: u8) -> Option<SlotEntry> {
    state.vaults.get(&vault)?.slots.get(slot).cloned()
}

/// Mutably set the slot to `value`, copy-on-write the Vault Arc.
fn slot_set(state: &mut State, vault: VaultId, slot: u8, value: Option<SlotEntry>) {
    let arc = match state.vaults.get(&vault) {
        Some(a) => a.clone(),
        None => return,
    };
    let mut v: crate::types::Vault = (*arc).clone();
    v.slots.set(slot, value);
    state.vaults.insert(vault, Arc::new(v));
}

impl ForeignCnode<ProtocolCap> for VaultCnodeView<'_> {
    fn fc_take(&mut self, vault: VaultId, slot: u8, rights: VaultRights) -> Option<Cap> {
        if !rights.revoke {
            return None;
        }
        let entry = slot_entry(self.state, vault, slot)?;
        let cap = entry_to_frame_cap(self.state, &entry)?;
        slot_set(self.state, vault, slot, None);
        Some(cap)
    }

    fn fc_set(
        &mut self,
        vault: VaultId,
        slot: u8,
        rights: VaultRights,
        cap: Cap,
    ) -> Result<(), Cap> {
        if !rights.grant {
            return Err(cap);
        }
        // Slot must be empty.
        match self.state.vaults.get(&vault) {
            Some(v) if v.slots.get(slot).is_none() => {}
            _ => return Err(cap),
        }
        let entry = match cap_to_slot_entry(&cap) {
            Some(e) => e,
            None => return Err(cap),
        };
        slot_set(self.state, vault, slot, Some(entry));
        Ok(())
    }

    fn fc_clone(&mut self, vault: VaultId, slot: u8, rights: VaultRights) -> Option<Cap> {
        if !rights.derive {
            return None;
        }
        match slot_entry(self.state, vault, slot)? {
            // VaultRefs are values: clone the value (with rights honored).
            // Narrowing rights belongs to a separate MGMT_DOWNGRADE op;
            // here we just produce an identical VaultRef.
            SlotEntry::VaultRef(vr) => Some(Cap::Protocol(ProtocolCap::VaultRef(vr))),
            SlotEntry::Cap(parent_id) => clone_registered_cap(self.state, parent_id),
        }
    }

    fn fc_drop(&mut self, vault: VaultId, slot: u8, rights: VaultRights) -> bool {
        if !rights.revoke {
            return false;
        }
        let entry = match slot_entry(self.state, vault, slot) {
            Some(e) => e,
            None => return false,
        };
        if let SlotEntry::Cap(cap_id) = &entry {
            cap_registry::revoke_cascade(self.state, *cap_id);
        }
        slot_set(self.state, vault, slot, None);
        true
    }

    fn fc_is_empty(&self, vault: VaultId, slot: u8) -> bool {
        match self.state.vaults.get(&vault) {
            Some(v) => v.slots.get(slot).is_none(),
            None => true,
        }
    }
}

/// Translate a `SlotEntry` into the Frame cap-table representation.
/// Returns `None` for entries that can't be moved into a Frame as
/// guest-visible caps (Code / Data are bulk and stay container-bound;
/// EventEndpoint is malformed in vault.slots).
fn entry_to_frame_cap(state: &State, entry: &SlotEntry) -> Option<Cap> {
    match entry {
        SlotEntry::VaultRef(vr) => Some(Cap::Protocol(ProtocolCap::VaultRef(*vr))),
        SlotEntry::Cap(cap_id) => {
            let record = cap_registry::lookup(state, *cap_id).ok()?;
            match &record.cap {
                RegCap::Resource(r) => Some(Cap::Protocol(ProtocolCap::Resource {
                    id: *cap_id,
                    cap: r.clone(),
                })),
                // Code / Data don't move mid-VM. EventEndpoint shouldn't be
                // in vault.slots at all. Guests asking for these get None.
                RegCap::Code(_) | RegCap::Data(_) | RegCap::EventEndpoint(_) => None,
            }
        }
    }
}

/// Translate a Frame cap back to a `SlotEntry` for placement into
/// `vault.slots`. Returns `None` if the cap can't legally live in σ.
fn cap_to_slot_entry(cap: &Cap) -> Option<SlotEntry> {
    match cap {
        Cap::Protocol(ProtocolCap::VaultRef(vr)) => Some(SlotEntry::VaultRef(*vr)),
        Cap::Protocol(ProtocolCap::Resource { id, .. }) => Some(SlotEntry::Cap(*id)),
        // HostCall, Frame-only kinds (SelfId / Caller* / AttestationScope /
        // Attestation / AttestationAggregate), and javm-side first-class
        // arms (Cap::Code, Cap::Data, Cap::FrameRef, Cap::Empty) all
        // refuse persistence to vault.slots.
        _ => None,
    }
}

/// Clone a registered cap (for `MGMT_COPY` via `fc_clone`). Allocates a
/// child cap_registry record with parent = source. Code / Data /
/// EventEndpoint don't expose Frame projections, so cloning into a
/// Frame is rejected.
fn clone_registered_cap(state: &mut State, parent_id: CapId) -> Option<Cap> {
    let record = cap_registry::lookup(state, parent_id).ok()?.clone();
    let RegCap::Resource(r) = &record.cap else {
        return None;
    };
    let child_cap = RegCap::Resource(r.clone());
    let child_id =
        cap_registry::derive(state, parent_id, child_cap.clone(), Vec::new(), false).ok()?;
    let RegCap::Resource(r2) = child_cap else {
        unreachable!()
    };
    Some(Cap::Protocol(ProtocolCap::Resource {
        id: child_id,
        cap: r2,
    }))
}
