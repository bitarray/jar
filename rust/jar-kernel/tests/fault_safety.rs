//! Fault-safety in the value-cap model.
//!
//! Vault.slots holds caps inline; granting a copy via clone produces
//! an independent value. A manager that fc_clones a cap into a Frame
//! and then faults leaves the source slot intact — the clone is just
//! discarded.

use std::sync::Arc;

use javm::cap::ProtocolCapHost;

use jar_kernel::cap::Cap;
use jar_kernel::vm::foreign_cnode::VaultCnodeView;
use jar_kernel::{RegCap, ResourceCap, ResourceKind, State, Vault, VaultId, VaultRights};

fn place_resource(state: &mut State, vault: VaultId, slot: u8) -> ResourceCap {
    let r = ResourceCap(ResourceKind::CreateVault { quota_pages: 16 });
    let arc = state.vaults.get(&vault).unwrap().clone();
    let mut v: Vault = (*arc).clone();
    v.slots.set(slot, Some(RegCap::Resource(r.clone())));
    state.vaults.insert(vault, Arc::new(v));
    r
}

#[test]
fn fc_clone_leaves_source_intact_so_drop_is_safe() {
    let mut state = State::empty();
    let vault_id = state.next_vault_id();
    state.vaults.insert(vault_id, Arc::new(Vault::new()));
    let r = place_resource(&mut state, vault_id, 7);

    let _ephemeral = {
        let mut view = VaultCnodeView::new(&mut state);
        view.clone(vault_id, 7, VaultRights::ALL).expect("clone")
    };
    drop(_ephemeral);

    assert_eq!(
        state.vaults.get(&vault_id).unwrap().slots.get(7),
        Some(&RegCap::Resource(r))
    );
}

#[test]
fn manager_pattern_no_commit_no_change() {
    let mut state = State::empty();
    let vault_id = state.next_vault_id();
    state.vaults.insert(vault_id, Arc::new(Vault::new()));
    let r = place_resource(&mut state, vault_id, 0);

    let _ = {
        let mut view = VaultCnodeView::new(&mut state);
        view.clone(vault_id, 0, VaultRights::ALL).unwrap()
    };
    assert_eq!(
        state.vaults.get(&vault_id).unwrap().slots.get(0),
        Some(&RegCap::Resource(r))
    );
}

#[test]
fn fc_take_then_no_replace_leaves_slot_empty() {
    // Manager takes a cap and faults before moving it back: slot empty.
    // For fault safety, managers use COPY (clone) for reads.
    let mut state = State::empty();
    let vault_id = state.next_vault_id();
    state.vaults.insert(vault_id, Arc::new(Vault::new()));
    let _ = place_resource(&mut state, vault_id, 0);

    let _taken: Cap = {
        let mut view = VaultCnodeView::new(&mut state);
        view.take(vault_id, 0, VaultRights::ALL).unwrap()
    };
    assert!(state.vaults.get(&vault_id).unwrap().slots.get(0).is_none());
}
