//! Tests for the host adapter that lets javm's MGMT_MOVE / COPY / DROP
//! ecallis address Vault CNodes through cap-ref indirection.
//!
//! The post-RegCap-narrowing model means:
//!
//! - VaultRef is a value cap stored inline as `SlotEntry::VaultRef(vr)`
//!   and projected to `ProtocolCap::VaultRef(vr)` in a Frame. Round-trip
//!   never touches `cap_registry`.
//! - Resource caps round-trip through `cap_registry` with CapId
//!   preservation, projecting to `ProtocolCap::Resource { id, cap }`.
//! - Code / Data caps are container-bound: they're compiled / mapped at
//!   `vault_init` only, never moved between Vault and Frame mid-VM.
//!   `fc_take` / `fc_clone` on such slots return `None`.
//! - EventEndpointCap doesn't legally live in vault.slots.

use std::sync::Arc;

use javm::cap::ForeignCnode;

use jar_kernel::cap::{Cap, ProtocolCap};
use jar_kernel::state::cap_registry;
use jar_kernel::vm::foreign_cnode::VaultCnodeView;
use jar_kernel::{
    CapRecord, DataCap, RegCap, ResourceCap, ResourceKind, SlotEntry, State, Vault, VaultId,
    VaultRefCap, VaultRights,
};

fn empty_vault() -> (State, VaultId) {
    let mut state = State::empty();
    let vault_id = state.next_vault_id();
    state.vaults.insert(vault_id, Arc::new(Vault::new()));
    (state, vault_id)
}

fn place_resource(state: &mut State, vault: VaultId, slot: u8) -> jar_kernel::CapId {
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

fn place_vault_ref(state: &mut State, vault: VaultId, slot: u8, vr: VaultRefCap) {
    let arc = state.vaults.get(&vault).unwrap().clone();
    let mut v: Vault = (*arc).clone();
    v.slots.set(slot, Some(SlotEntry::VaultRef(vr)));
    state.vaults.insert(vault, Arc::new(v));
}

#[test]
fn fc_take_resource_returns_protocol_resource_and_clears_slot() {
    let (mut state, vault_id) = empty_vault();
    let cap_id = place_resource(&mut state, vault_id, 7);
    let mut view = VaultCnodeView::new(&mut state);
    let cap = view
        .fc_take(vault_id, 7, VaultRights::ALL)
        .expect("fc_take with full rights");
    match cap {
        Cap::Protocol(ProtocolCap::Resource { id, .. }) => assert_eq!(id, cap_id),
        _ => panic!("expected ProtocolCap::Resource"),
    }
    assert!(state.vaults.get(&vault_id).unwrap().slots.get(7).is_none());
}

#[test]
fn fc_take_vault_ref_returns_protocol_vault_ref() {
    let (mut state, vault_id) = empty_vault();
    let vr = VaultRefCap {
        vault_id: VaultId(99),
        rights: VaultRights::ALL,
    };
    place_vault_ref(&mut state, vault_id, 5, vr);
    let mut view = VaultCnodeView::new(&mut state);
    let cap = view
        .fc_take(vault_id, 5, VaultRights::ALL)
        .expect("fc_take vault_ref");
    match cap {
        Cap::Protocol(ProtocolCap::VaultRef(out)) => {
            assert_eq!(out.vault_id, VaultId(99));
            assert_eq!(out.rights, VaultRights::ALL);
        }
        _ => panic!("expected ProtocolCap::VaultRef"),
    }
}

#[test]
fn fc_take_requires_revoke_right() {
    let (mut state, vault_id) = empty_vault();
    let _ = place_resource(&mut state, vault_id, 7);
    let mut view = VaultCnodeView::new(&mut state);
    assert!(view.fc_take(vault_id, 7, VaultRights::READ).is_none());
    assert!(state.vaults.get(&vault_id).unwrap().slots.get(7).is_some());
}

#[test]
fn fc_take_data_cap_returns_none() {
    // Data caps are container-bound; fc_take on a Data slot is a no-op.
    let (mut state, vault_id) = empty_vault();
    let cap_id = cap_registry::alloc(
        &mut state,
        CapRecord {
            cap: RegCap::Data(DataCap {
                content: Arc::new(b"sample".to_vec()),
                page_count: 1,
            }),
            issuer: None,
            narrowing: vec![],
        },
    );
    let arc = state.vaults.get(&vault_id).unwrap().clone();
    let mut v: Vault = (*arc).clone();
    v.slots.set(7, Some(SlotEntry::Cap(cap_id)));
    state.vaults.insert(vault_id, Arc::new(v));

    let mut view = VaultCnodeView::new(&mut state);
    assert!(view.fc_take(vault_id, 7, VaultRights::ALL).is_none());
}

#[test]
fn fc_set_places_resource_into_empty_slot() {
    let (mut state, vault_id) = empty_vault();
    let cap_id = place_resource(&mut state, vault_id, 7);
    // Take it.
    {
        let mut view = VaultCnodeView::new(&mut state);
        let _ = view.fc_take(vault_id, 7, VaultRights::ALL).unwrap();
    }
    // Place into slot 8.
    let cap = Cap::Protocol(ProtocolCap::Resource {
        id: cap_id,
        cap: ResourceCap(ResourceKind::CreateVault { quota_pages: 16 }),
    });
    let mut view = VaultCnodeView::new(&mut state);
    view.fc_set(vault_id, 8, VaultRights::ALL, cap)
        .expect("fc_set into empty slot 8");
    let v = state.vaults.get(&vault_id).unwrap();
    assert_eq!(v.slots.get(8), Some(&SlotEntry::Cap(cap_id)));
}

#[test]
fn fc_set_places_vault_ref_inline() {
    let (mut state, vault_id) = empty_vault();
    let vr = VaultRefCap {
        vault_id: VaultId(7),
        rights: VaultRights::READ,
    };
    let cap = Cap::Protocol(ProtocolCap::VaultRef(vr));
    let mut view = VaultCnodeView::new(&mut state);
    view.fc_set(vault_id, 0, VaultRights::ALL, cap)
        .expect("fc_set vault_ref");
    let v = state.vaults.get(&vault_id).unwrap();
    assert_eq!(v.slots.get(0), Some(&SlotEntry::VaultRef(vr)));
}

#[test]
fn fc_set_rejects_frame_only_caps() {
    let (mut state, vault_id) = empty_vault();
    let mut view = VaultCnodeView::new(&mut state);
    let ephemeral = Cap::Protocol(ProtocolCap::SelfId(jar_kernel::cap::SelfCap {
        vault_id: VaultId(0),
    }));
    assert!(
        view.fc_set(vault_id, 0, VaultRights::ALL, ephemeral)
            .is_err()
    );
}

#[test]
fn fc_set_requires_grant_right() {
    let (mut state, vault_id) = empty_vault();
    let cap_id = place_resource(&mut state, vault_id, 7);
    // Take it.
    {
        let mut view = VaultCnodeView::new(&mut state);
        let _ = view.fc_take(vault_id, 7, VaultRights::ALL).unwrap();
    }
    let cap = Cap::Protocol(ProtocolCap::Resource {
        id: cap_id,
        cap: ResourceCap(ResourceKind::CreateVault { quota_pages: 16 }),
    });
    let mut view = VaultCnodeView::new(&mut state);
    assert!(view.fc_set(vault_id, 0, VaultRights::READ, cap).is_err());
}

#[test]
fn fc_clone_resource_allocates_child_capid() {
    let (mut state, vault_id) = empty_vault();
    let parent_id = place_resource(&mut state, vault_id, 7);
    let pre_count = state.cap_registry.len();
    let mut view = VaultCnodeView::new(&mut state);
    let cap = view
        .fc_clone(vault_id, 7, VaultRights::ALL)
        .expect("fc_clone with derive right");
    assert_eq!(state.cap_registry.len(), pre_count + 1);
    let child_id = match cap {
        Cap::Protocol(ProtocolCap::Resource { id, .. }) => id,
        _ => panic!("expected ProtocolCap::Resource"),
    };
    assert_ne!(child_id, parent_id);
    // Source slot still occupied.
    assert_eq!(
        state.vaults.get(&vault_id).unwrap().slots.get(7),
        Some(&SlotEntry::Cap(parent_id))
    );
    // cap_children records lineage.
    assert!(
        state
            .cap_children
            .get(&parent_id)
            .map(|s| s.contains(&child_id))
            .unwrap_or(false)
    );
}

#[test]
fn fc_clone_vault_ref_returns_inline_value() {
    let (mut state, vault_id) = empty_vault();
    let vr = VaultRefCap {
        vault_id: VaultId(42),
        rights: VaultRights::ALL,
    };
    place_vault_ref(&mut state, vault_id, 3, vr);
    let pre_count = state.cap_registry.len();
    let mut view = VaultCnodeView::new(&mut state);
    let cap = view
        .fc_clone(vault_id, 3, VaultRights::ALL)
        .expect("fc_clone vault_ref");
    // VaultRef cloning doesn't touch cap_registry.
    assert_eq!(state.cap_registry.len(), pre_count);
    match cap {
        Cap::Protocol(ProtocolCap::VaultRef(out)) => assert_eq!(out, vr),
        _ => panic!("expected ProtocolCap::VaultRef"),
    }
    // Source slot still occupied with the same VaultRef.
    assert_eq!(
        state.vaults.get(&vault_id).unwrap().slots.get(3),
        Some(&SlotEntry::VaultRef(vr))
    );
}

#[test]
fn fc_clone_requires_derive_right() {
    let (mut state, vault_id) = empty_vault();
    let _ = place_resource(&mut state, vault_id, 7);
    let mut view = VaultCnodeView::new(&mut state);
    assert!(view.fc_clone(vault_id, 7, VaultRights::READ).is_none());
}

#[test]
fn fc_drop_resource_revokes_cap_and_clears_slot() {
    let (mut state, vault_id) = empty_vault();
    let cap_id = place_resource(&mut state, vault_id, 7);
    let mut view = VaultCnodeView::new(&mut state);
    assert!(view.fc_drop(vault_id, 7, VaultRights::ALL));
    assert!(!state.cap_registry.contains_key(&cap_id));
    assert!(state.vaults.get(&vault_id).unwrap().slots.get(7).is_none());
}

#[test]
fn fc_drop_vault_ref_just_clears_slot() {
    let (mut state, vault_id) = empty_vault();
    let vr = VaultRefCap {
        vault_id: VaultId(42),
        rights: VaultRights::READ,
    };
    place_vault_ref(&mut state, vault_id, 3, vr);
    let pre_registry = state.cap_registry.len();
    let mut view = VaultCnodeView::new(&mut state);
    assert!(view.fc_drop(vault_id, 3, VaultRights::ALL));
    // Slot cleared; cap_registry untouched (VaultRef has no σ entry).
    assert!(state.vaults.get(&vault_id).unwrap().slots.get(3).is_none());
    assert_eq!(state.cap_registry.len(), pre_registry);
}

#[test]
fn fc_drop_resource_cascade_removes_children() {
    let (mut state, vault_id) = empty_vault();
    let parent_id = place_resource(&mut state, vault_id, 7);
    // Clone first → child registered.
    let _ = {
        let mut view = VaultCnodeView::new(&mut state);
        view.fc_clone(vault_id, 7, VaultRights::ALL)
    }
    .expect("clone");
    let pre = state.cap_registry.len();
    assert!(pre >= 2);
    let mut view = VaultCnodeView::new(&mut state);
    assert!(view.fc_drop(vault_id, 7, VaultRights::ALL));
    assert!(!state.cap_registry.contains_key(&parent_id));
    // Both parent and the derived child are revoked.
    assert!(state.cap_registry.len() <= pre - 2);
}

#[test]
fn fc_is_empty_reports_slot_state() {
    let (mut state, vault_id) = empty_vault();
    let _ = place_resource(&mut state, vault_id, 7);
    let view = VaultCnodeView::new(&mut state);
    assert!(!view.fc_is_empty(vault_id, 7));
    assert!(view.fc_is_empty(vault_id, 8));
    assert!(view.fc_is_empty(VaultId(99_999), 0));
}

#[test]
fn vault_ref_with_read_announces_foreign_frame() {
    use javm::cap::ProtocolCap as _;
    let cap = ProtocolCap::VaultRef(VaultRefCap {
        vault_id: VaultId(42),
        rights: VaultRights::ALL,
    });
    let (id, rights) = cap.as_foreign_frame().expect("VaultRef → foreign frame");
    assert_eq!(id, VaultId(42));
    assert_eq!(rights, VaultRights::ALL);
}

#[test]
fn vault_ref_without_read_does_not_announce_foreign_frame() {
    use javm::cap::ProtocolCap as _;
    let cap = ProtocolCap::VaultRef(VaultRefCap {
        vault_id: VaultId(42),
        rights: VaultRights::INITIALIZE, // no `read`
    });
    assert!(cap.as_foreign_frame().is_none());
}
