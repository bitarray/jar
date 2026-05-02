//! Cap-table host adapter — `vault.slots` ↔ Frame `Cap` translation
//! and ProtocolCapHost slot ops.
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
//! Two `ProtocolCapHost` implementors live in this crate:
//!
//! - [`VaultCnodeView`] — the slim adapter; just `&mut State`. Used
//!   by tests that exercise cap-table mutation in isolation. Its
//!   `call` returns Fault (no kernel ctx).
//! - [`crate::vm::InvocationHost`] — the production adapter; carries
//!   the full per-invocation context (commands, role, traces, hw,
//!   etc) and dispatches CALL into the host-call handlers.
//!
//! Both share the slot helpers (`slot_cap` / `slot_set`) and the
//! cap-shape projection helpers (`vault_cap_to_frame` /
//! `frame_to_vault_cap`).

use std::sync::Arc;

use javm::cap::ProtocolCapHost;

use crate::cap::{Cap, ProtocolCap, RegCap, VaultRights};
use crate::types::{State, VaultId};

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

/// Translate a `RegCap` into the Frame cap-table representation.
/// Returns `None` for kinds that don't have a `ProtocolCap` variant
/// (Code / Data are container-bound).
pub(crate) fn vault_cap_to_frame(cap: &RegCap) -> Option<Cap> {
    match cap {
        RegCap::VaultRef(vr) => Some(Cap::Protocol(ProtocolCap::VaultRef(*vr))),
        RegCap::Resource(r) => Some(Cap::Protocol(ProtocolCap::Resource(r.clone()))),
        RegCap::Code(_) | RegCap::Data(_) => None,
    }
}

/// Translate a Frame cap back to a `RegCap` for placement into
/// `vault.slots`. Returns `None` if the cap can't legally live in σ.
pub(crate) fn frame_to_vault_cap(cap: &Cap) -> Option<RegCap> {
    match cap {
        Cap::Protocol(ProtocolCap::VaultRef(vr)) => Some(RegCap::VaultRef(*vr)),
        Cap::Protocol(ProtocolCap::Resource(r)) => Some(RegCap::Resource(r.clone())),
        _ => None,
    }
}

// =============================================================================
// VaultCnodeView — slim test-only adapter
// =============================================================================

/// Test-only adapter: just `&mut State`, no kernel context. CALL on a
/// protocol cap reached through this view returns `Fault` because there
/// is no place to dispatch host-call work.
pub struct VaultCnodeView<'a> {
    pub state: &'a mut State,
}

impl<'a> VaultCnodeView<'a> {
    pub fn new(state: &'a mut State) -> Self {
        Self { state }
    }
}

impl ProtocolCapHost<ProtocolCap> for VaultCnodeView<'_> {
    fn call(
        &mut self,
        cap: ProtocolCap,
        _vm: &mut javm::kernel::InvocationKernel<ProtocolCap>,
    ) -> javm::cap::CallOutcome {
        javm::cap::CallOutcome::Fault(format!("CALL via VaultCnodeView (no kernel ctx): {cap:?}"))
    }

    fn get(&self, vault: VaultId, slot: u8) -> Option<Cap> {
        slot_cap(self.state, vault, slot)
            .as_ref()
            .and_then(vault_cap_to_frame)
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
