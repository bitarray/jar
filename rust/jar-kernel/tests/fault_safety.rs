//! Fault-safety in the post-StateSnapshot model.
//!
//! With reads-are-COPY persistent caps and no automatic σ rollback,
//! fault safety is a property of the cap surface: a manager that hasn't
//! committed via MGMT_MOVE Frame → Vault leaves the Vault unchanged
//! when its Frame faults. This test exercises the property at the
//! adapter level — fc_clone (Vault → Frame) leaves the source slot
//! intact, and a "discarded ephemeral cap" results in no change to σ.
//!
//! Resource caps are used for these checks because, in the post-
//! RegCap-narrowing model, they're the canonical registered cap that
//! round-trips through Frame as `ProtocolCap::Resource`.

use std::sync::Arc;

use javm::cap::ForeignCnode;

use jar_kernel::cap::Cap;
use jar_kernel::state::cap_registry;
use jar_kernel::vm::foreign_cnode::VaultCnodeView;
use jar_kernel::{
    CapRecord, RegCap, ResourceCap, ResourceKind, SlotEntry, State, Vault, VaultRights,
};

fn place_resource(state: &mut State, vault: jar_kernel::VaultId, slot: u8) -> jar_kernel::CapId {
    let cap_id = cap_registry::alloc(
        state,
        CapRecord {
            cap: RegCap::Resource(ResourceCap(ResourceKind::CreateVault { quota_pages: 16 })),
            issuer: None,
            narrowing: vec![],
        },
    );
    let arc = state.vaults.get(&vault).unwrap().clone();
    let mut v: Vault = (*arc).clone();
    v.slots.set(slot, Some(SlotEntry::Cap(cap_id)));
    state.vaults.insert(vault, Arc::new(v));
    cap_id
}

#[test]
fn fc_clone_leaves_source_intact_so_drop_is_safe() {
    let mut state = State::empty();
    let vault_id = state.next_vault_id();
    state.vaults.insert(vault_id, Arc::new(Vault::new()));
    let parent_id = place_resource(&mut state, vault_id, 7);

    // Manager-style "read" via fc_clone. The original remains.
    let _ephemeral = {
        let mut view = VaultCnodeView::new(&mut state);
        view.fc_clone(vault_id, 7, VaultRights::ALL)
            .expect("fc_clone")
    };

    // Simulate fault: manager-Frame discarded.
    drop(_ephemeral);

    assert_eq!(
        state.vaults.get(&vault_id).unwrap().slots.get(7),
        Some(&SlotEntry::Cap(parent_id))
    );
    assert!(matches!(
        state.cap_registry.get(&parent_id).unwrap().cap,
        RegCap::Resource(_)
    ));
}

#[test]
fn manager_pattern_no_commit_no_change() {
    // Pure read, no MOVE-back: the Vault is unchanged. Baseline
    // atomicity guarantee.
    let mut state = State::empty();
    let vault_id = state.next_vault_id();
    state.vaults.insert(vault_id, Arc::new(Vault::new()));
    let cap_id = place_resource(&mut state, vault_id, 0);

    let _ = {
        let mut view = VaultCnodeView::new(&mut state);
        view.fc_clone(vault_id, 0, VaultRights::ALL).unwrap()
    };
    assert_eq!(
        state.vaults.get(&vault_id).unwrap().slots.get(0),
        Some(&SlotEntry::Cap(cap_id))
    );
}

#[test]
fn fc_take_then_no_replace_leaves_slot_empty() {
    // If a manager takes a cap out of a Vault and faults before
    // moving it back, the Vault slot is left empty. By design;
    // managers wanting fault safety use COPY (fc_clone) for reads.
    let mut state = State::empty();
    let vault_id = state.next_vault_id();
    state.vaults.insert(vault_id, Arc::new(Vault::new()));
    let cap_id = place_resource(&mut state, vault_id, 0);

    let _taken: Cap = {
        let mut view = VaultCnodeView::new(&mut state);
        view.fc_take(vault_id, 0, VaultRights::ALL).unwrap()
    };
    // Slot is now empty. Cap is still in registry (held by `_taken`).
    assert!(state.vaults.get(&vault_id).unwrap().slots.get(0).is_none());
    assert!(state.cap_registry.contains_key(&cap_id));
}
