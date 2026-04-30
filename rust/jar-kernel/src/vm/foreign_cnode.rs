//! Host adapter that lets javm's resolve walk address jar-kernel's
//! σ-resident Vault CNodes as a third frame kind.
//!
//! When a cap-ref crossing lands on a `Cap::Protocol(KernelCap)` whose
//! `as_foreign_frame()` returns `Some(VaultId)`, javm packages that as
//! `FrameId::Foreign(VaultId)` and routes subsequent slot operations
//! (`fc_take` / `fc_set` / `fc_clone` / `fc_drop` / `fc_is_empty`)
//! through this adapter.
//!
//! Each method maps to existing σ helpers:
//!
//! - `fc_take` reads the `CapId` at `vault.slots[slot]`, looks up the
//!   `CapRecord`, returns the cap as `KernelCap::Registered { id, cap }`,
//!   and clears the slot. Bookkeeping: no `cap_holders` update because
//!   `Vault.slots` is currently NOT mirrored in `state.cnodes` — caps
//!   in Vault slots are tracked by VaultId, not CNodeId. (See the
//!   note in `state/cnode.rs` — this is a pre-existing layout choice.)
//!
//! - `fc_set` accepts only `KernelCap::Registered { id, cap }` (caps
//!   without persistent identity cannot live in σ). It runs the
//!   pinning rule (`pinning::check_grant_or_move`) and the
//!   final-step VaultRights gate, then writes `id` into the slot.
//!
//! - `fc_clone` looks up the source CapId, calls
//!   `cap_registry::derive` to allocate a child record, and returns
//!   the child wrapped as `KernelCap::Registered`. Used by
//!   `MGMT_COPY` Vault → anywhere.
//!
//! - `fc_drop` invokes `cap_registry::revoke_cascade`, which removes
//!   the cap from `cap_registry`, walks `cap_children`, and clears
//!   every slot in `state.cnodes` that referenced it. The Vault
//!   slot itself is cleared explicitly here (cascade only walks
//!   `state.cnodes`, not Vault.slots).

use std::sync::Arc;

use javm::cap::{Cap, ForeignCnode};

use crate::cap::{Capability, KernelCap, VaultRights};
use crate::state::cap_registry;
use crate::types::{State, VaultId};

/// Adapter implementing [`ForeignCnode<KernelCap>`] over `&mut State`.
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

/// Read the `CapId` at `(vault, slot)`, if any.
fn slot_cap_id(state: &State, vault: VaultId, slot: u8) -> Option<crate::types::CapId> {
    state.vaults.get(&vault)?.slots.get(slot)
}

/// Mutably set the slot to `value`, copy-on-write the Vault Arc.
fn slot_set(state: &mut State, vault: VaultId, slot: u8, value: Option<crate::types::CapId>) {
    let arc = match state.vaults.get(&vault) {
        Some(a) => a.clone(),
        None => return,
    };
    let mut v: crate::types::Vault = (*arc).clone();
    v.slots.set(slot, value);
    state.vaults.insert(vault, Arc::new(v));
}

impl ForeignCnode<KernelCap> for VaultCnodeView<'_> {
    fn fc_take(&mut self, vault: VaultId, slot: u8, rights: VaultRights) -> Option<Cap<KernelCap>> {
        if !rights.revoke {
            return None;
        }
        let cap_id = slot_cap_id(self.state, vault, slot)?;
        let record = cap_registry::lookup(self.state, cap_id).ok()?.clone();
        // Clear the slot. (Vault.slots is not mirrored in state.cnodes,
        // so no cap_holders update needed today.)
        slot_set(self.state, vault, slot, None);
        Some(Cap::Protocol(KernelCap::Registered {
            id: cap_id,
            cap: record.cap,
        }))
    }

    fn fc_set(
        &mut self,
        vault: VaultId,
        slot: u8,
        rights: VaultRights,
        cap: Cap<KernelCap>,
    ) -> Result<(), Cap<KernelCap>> {
        if !rights.grant {
            return Err(cap);
        }
        // Slot must be empty.
        match self.state.vaults.get(&vault) {
            Some(v) if v.slots.get(slot).is_none() => {}
            _ => return Err(cap),
        }
        // Only Registered caps can persist (Ephemeral / HostCall have no
        // CapId / no σ presence).
        let (id, capability) = match cap {
            Cap::Protocol(KernelCap::Registered { id, ref cap }) => (id, cap.clone()),
            _ => return Err(cap),
        };
        // Pinning: Vault.slots are not σ-rooted CNodes, but Dispatch /
        // Transact / Schedule pinning is a global rule independent of
        // the CNode kind. We check pinning against the Vault's id by
        // synthesising a CNodeId-shaped guard: pinned variants should
        // not migrate to Frame, and from Frame they should only return
        // to their born_in CNode (not a Vault). The conservative read:
        // reject any pinned-or-ref placement to a Vault slot.
        if matches!(
            &capability,
            Capability::Dispatch(_)
                | Capability::Transact(_)
                | Capability::Schedule(_)
                | Capability::DispatchRef(_)
                | Capability::TransactRef(_)
        ) {
            return Err(cap);
        }
        slot_set(self.state, vault, slot, Some(id));
        Ok(())
    }

    fn fc_clone(
        &mut self,
        vault: VaultId,
        slot: u8,
        rights: VaultRights,
    ) -> Option<Cap<KernelCap>> {
        if !rights.derive {
            return None;
        }
        let cap_id = slot_cap_id(self.state, vault, slot)?;
        let record = cap_registry::lookup(self.state, cap_id).ok()?.clone();
        if !is_clone_eligible(&record.cap) {
            return None;
        }
        // Allocate a child CapRecord. dest_persistent=false because the
        // destination is a Frame — pinning rules treat Frames as
        // ephemeral.
        let child_cap = record.cap.clone();
        let child_id =
            cap_registry::derive(self.state, cap_id, child_cap.clone(), Vec::new(), false).ok()?;
        Some(Cap::Protocol(KernelCap::Registered {
            id: child_id,
            cap: child_cap,
        }))
    }

    fn fc_drop(&mut self, vault: VaultId, slot: u8, rights: VaultRights) -> bool {
        if !rights.revoke {
            return false;
        }
        let cap_id = match slot_cap_id(self.state, vault, slot) {
            Some(id) => id,
            None => return false,
        };
        // Cascade-revoke removes the cap and any descendants from
        // cap_registry / cap_children / cap_holders. It clears slots
        // in state.cnodes that reference the cap, but does NOT touch
        // Vault.slots, so we clear the source slot here.
        cap_registry::revoke_cascade(self.state, cap_id);
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

/// A cap is "clone-eligible" (allowed to be `MGMT_COPY`'d via
/// `fc_clone`) iff it is not pinned and not an ephemeral Frame-only
/// variant. Pinning is enforced separately on `fc_set`; this is a
/// pre-flight check on the source.
fn is_clone_eligible(cap: &Capability) -> bool {
    !cap.is_pinned_or_ref()
}
