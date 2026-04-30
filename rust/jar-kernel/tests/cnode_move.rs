//! Tests for the host adapter that lets javm's MGMT_MOVE / COPY / DROP
//! ecallis address Vault CNodes through cap-ref indirection.
//!
//! These tests drive the [`jar_kernel::vm::foreign_cnode::VaultCnodeView`]
//! adapter directly. They cover the four operations (take, set, clone,
//! drop), pinning rejection, and rights enforcement. A guest-driven
//! end-to-end test (where a PVM blob does `MGMT_MOVE` against a cap-ref
//! that crosses through the slot-1 home VaultRef) is deferred to a
//! separate harness once the transpiler exposes ergonomic dynamic-ecall
//! emission.

use std::sync::Arc;

use javm::cap::{Cap, ForeignCnode};

use jar_kernel::cap::KernelCap;
use jar_kernel::state::cap_registry;
use jar_kernel::vm::foreign_cnode::VaultCnodeView;
use jar_kernel::{
    CapRecord, Capability, DataCap, DispatchCap, State, Vault, VaultId, VaultRefCap, VaultRights,
};

/// Build a State with one Vault and a Data cap registered + placed at
/// `vault.slots[slot]`. Returns `(state, vault_id, data_cap_id)`.
fn state_with_one_data_cap(slot: u8) -> (State, VaultId, jar_kernel::CapId) {
    let mut state = State::empty();
    let vault_id = state.next_vault_id();
    state.vaults.insert(vault_id, Arc::new(Vault::new()));
    let cap_id = cap_registry::alloc(
        &mut state,
        CapRecord {
            cap: Capability::Data(DataCap {
                content: Arc::new(b"sample data".to_vec()),
                page_count: 1,
            }),
            issuer: None,
            narrowing: vec![],
        },
    );
    let arc = state.vaults.get(&vault_id).unwrap().clone();
    let mut v: Vault = (*arc).clone();
    v.slots.set(slot, Some(cap_id));
    state.vaults.insert(vault_id, Arc::new(v));
    (state, vault_id, cap_id)
}

#[test]
fn fc_take_returns_registered_and_clears_slot() {
    let (mut state, vault_id, cap_id) = state_with_one_data_cap(7);
    let mut view = VaultCnodeView::new(&mut state);
    let cap = view
        .fc_take(vault_id, 7, VaultRights::ALL)
        .expect("fc_take should succeed with full rights");
    match cap {
        Cap::Protocol(KernelCap::Registered { id, cap: c }) => {
            assert_eq!(id, cap_id);
            assert!(matches!(c, Capability::Data(_)));
        }
        _ => panic!("expected Cap::Protocol(KernelCap::Registered{{..}})"),
    }
    // Slot must now be empty.
    assert!(state.vaults.get(&vault_id).unwrap().slots.get(7).is_none());
}

#[test]
fn fc_take_requires_revoke_right() {
    let (mut state, vault_id, _cap_id) = state_with_one_data_cap(7);
    let mut view = VaultCnodeView::new(&mut state);
    // Read-only rights → fc_take refuses.
    assert!(view.fc_take(vault_id, 7, VaultRights::READ).is_none());
    // Slot still occupied.
    assert!(state.vaults.get(&vault_id).unwrap().slots.get(7).is_some());
}

#[test]
fn fc_set_places_registered_into_empty_slot() {
    let (mut state, vault_id, cap_id) = state_with_one_data_cap(7);
    // Take it.
    {
        let mut view = VaultCnodeView::new(&mut state);
        let _ = view.fc_take(vault_id, 7, VaultRights::ALL).unwrap();
    }
    // Place it back at slot 8.
    let cap = Cap::Protocol(KernelCap::Registered {
        id: cap_id,
        cap: Capability::Data(DataCap {
            content: Arc::new(b"sample data".to_vec()),
            page_count: 1,
        }),
    });
    let mut view = VaultCnodeView::new(&mut state);
    view.fc_set(vault_id, 8, VaultRights::ALL, cap)
        .expect("fc_set into empty slot 8");
    let v = state.vaults.get(&vault_id).unwrap();
    assert_eq!(v.slots.get(8), Some(cap_id));
}

#[test]
fn fc_set_rejects_non_registered() {
    let mut state = State::empty();
    let vault_id = state.next_vault_id();
    state.vaults.insert(vault_id, Arc::new(Vault::new()));
    let mut view = VaultCnodeView::new(&mut state);

    // Ephemeral cap (kernel-injected per-frame, no σ identity) cannot
    // be placed into a Vault slot.
    // An Ephemeral persistent-shaped Capability — Data here, but any
    // would do — must be rejected by fc_set since only Registered caps
    // can persist in σ.
    let ephemeral = Cap::Protocol(KernelCap::Ephemeral(Capability::Data(DataCap {
        content: Arc::new(b"sample data".to_vec()),
        page_count: 1,
    })));
    let result = view.fc_set(vault_id, 0, VaultRights::ALL, ephemeral);
    assert!(result.is_err());
}

#[test]
fn fc_set_requires_grant_right() {
    let mut state = State::empty();
    let vault_id = state.next_vault_id();
    state.vaults.insert(vault_id, Arc::new(Vault::new()));
    let cap_id = cap_registry::alloc(
        &mut state,
        CapRecord {
            cap: Capability::Data(DataCap {
                content: Arc::new(b"sample data".to_vec()),
                page_count: 1,
            }),
            issuer: None,
            narrowing: vec![],
        },
    );
    let cap = Cap::Protocol(KernelCap::Registered {
        id: cap_id,
        cap: Capability::Data(DataCap {
            content: Arc::new(b"sample data".to_vec()),
            page_count: 1,
        }),
    });
    let mut view = VaultCnodeView::new(&mut state);
    // Read-only — no grant. Must reject.
    let result = view.fc_set(vault_id, 0, VaultRights::READ, cap);
    assert!(result.is_err());
}

#[test]
fn fc_set_rejects_pinned_cap() {
    let mut state = State::empty();
    let vault_id = state.next_vault_id();
    state.vaults.insert(vault_id, Arc::new(Vault::new()));
    let born_in = jar_kernel::state::cnode::cnode_create(&mut state);
    let cap_id = cap_registry::alloc(
        &mut state,
        CapRecord {
            cap: Capability::Dispatch(DispatchCap { vault_id, born_in }),
            issuer: None,
            narrowing: vec![],
        },
    );
    let cap = Cap::Protocol(KernelCap::Registered {
        id: cap_id,
        cap: Capability::Dispatch(DispatchCap { vault_id, born_in }),
    });
    let mut view = VaultCnodeView::new(&mut state);
    let result = view.fc_set(vault_id, 0, VaultRights::ALL, cap);
    assert!(
        result.is_err(),
        "Dispatch caps are pinned; fc_set must reject"
    );
}

#[test]
fn fc_clone_allocates_child_capid() {
    let (mut state, vault_id, parent_id) = state_with_one_data_cap(7);
    let pre_count = state.cap_registry.len();
    let mut view = VaultCnodeView::new(&mut state);
    let cap = view
        .fc_clone(vault_id, 7, VaultRights::ALL)
        .expect("fc_clone with derive right");
    let post_count = state.cap_registry.len();
    assert_eq!(post_count, pre_count + 1, "fc_clone must allocate a child");
    let (child_id, kind) = match cap {
        Cap::Protocol(KernelCap::Registered { id, cap }) => (id, cap),
        _ => panic!("expected Registered cap"),
    };
    assert_ne!(child_id, parent_id);
    assert!(matches!(kind, Capability::Data(_)));
    // Source slot still occupied (clone doesn't take).
    assert_eq!(
        state.vaults.get(&vault_id).unwrap().slots.get(7),
        Some(parent_id)
    );
    // Children index records the linkage.
    assert!(
        state
            .cap_children
            .get(&parent_id)
            .map(|s| s.contains(&child_id))
            .unwrap_or(false),
        "cap_children should record parent → child"
    );
}

#[test]
fn fc_clone_requires_derive_right() {
    let (mut state, vault_id, _) = state_with_one_data_cap(7);
    let mut view = VaultCnodeView::new(&mut state);
    // Read-only rights — derive bit absent.
    assert!(view.fc_clone(vault_id, 7, VaultRights::READ).is_none());
}

#[test]
fn fc_drop_revokes_cap_and_clears_slot() {
    let (mut state, vault_id, cap_id) = state_with_one_data_cap(7);
    let mut view = VaultCnodeView::new(&mut state);
    assert!(view.fc_drop(vault_id, 7, VaultRights::ALL));
    // Cap removed from registry.
    assert!(!state.cap_registry.contains_key(&cap_id));
    // Slot cleared.
    assert!(state.vaults.get(&vault_id).unwrap().slots.get(7).is_none());
}

#[test]
fn fc_drop_cascade_removes_children() {
    let (mut state, vault_id, parent_id) = state_with_one_data_cap(7);
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
    // Both parent and the derived child are revoked by the cascade.
    assert!(!state.cap_registry.contains_key(&parent_id));
    // The derived child Storage was also issued from parent_id.
    // (Don't bind to its specific id — just assert the registry shrunk
    // by at least 2.)
    assert!(state.cap_registry.len() <= pre - 2);
}

#[test]
fn fc_is_empty_reports_slot_state() {
    let (mut state, vault_id, _) = state_with_one_data_cap(7);
    let view = VaultCnodeView::new(&mut state);
    assert!(!view.fc_is_empty(vault_id, 7));
    assert!(view.fc_is_empty(vault_id, 8));
    // Unknown vault → treat as empty.
    assert!(view.fc_is_empty(VaultId(99_999), 0));
}

#[test]
fn vault_ref_with_read_announces_foreign_frame() {
    use javm::cap::ProtocolCapT;
    let cap = KernelCap::Ephemeral(Capability::VaultRef(VaultRefCap {
        vault_id: VaultId(42),
        rights: VaultRights::ALL,
    }));
    let (id, rights) = cap.as_foreign_frame().expect("VaultRef → foreign frame");
    assert_eq!(id, VaultId(42));
    assert_eq!(rights, VaultRights::ALL);
}

#[test]
fn vault_ref_without_read_does_not_announce_foreign_frame() {
    use javm::cap::ProtocolCapT;
    let cap = KernelCap::Ephemeral(Capability::VaultRef(VaultRefCap {
        vault_id: VaultId(42),
        rights: VaultRights::INITIALIZE, // no `read`
    }));
    assert!(cap.as_foreign_frame().is_none());
}

// ---------------------------------------------------------------------------
// Persistent DataCap (Step 2): the cnode-cross machinery moves CapIds across
// Vaults; persistent → ephemeral content materialization is deferred to
// Step 8 (the Vault.initialize protocol). These tests cover ID-level
// movement and refcount-shared content.
// ---------------------------------------------------------------------------

fn place_data_cap(
    state: &mut State,
    vault: VaultId,
    slot: u8,
    content: Vec<u8>,
    page_count: u32,
) -> jar_kernel::CapId {
    use jar_kernel::DataCap;
    let cap_id = cap_registry::alloc(
        state,
        CapRecord {
            cap: Capability::Data(DataCap {
                content: Arc::new(content),
                page_count,
            }),
            issuer: None,
            narrowing: vec![],
        },
    );
    let arc = state.vaults.get(&vault).unwrap().clone();
    let mut v: Vault = (*arc).clone();
    v.slots.set(slot, Some(cap_id));
    state.vaults.insert(vault, Arc::new(v));
    cap_id
}

#[test]
fn data_cap_round_trips_via_vault_slot() {
    let mut state = State::empty();
    let vault_id = state.next_vault_id();
    state.vaults.insert(vault_id, Arc::new(Vault::new()));
    let cap_id = place_data_cap(&mut state, vault_id, 5, b"hello".to_vec(), 1);

    // fc_take of a persistent DataCap returns the Registered cap.
    let mut view = VaultCnodeView::new(&mut state);
    let cap = view
        .fc_take(vault_id, 5, VaultRights::ALL)
        .expect("fc_take");
    let (returned_id, returned_cap) = match cap {
        Cap::Protocol(KernelCap::Registered { id, cap }) => (id, cap),
        _ => panic!("expected Registered cap"),
    };
    assert_eq!(returned_id, cap_id);
    match &returned_cap {
        Capability::Data(d) => {
            assert_eq!(d.page_count, 1);
            assert_eq!(d.content.as_slice(), b"hello");
        }
        _ => panic!("expected Data variant"),
    }
    // Slot now empty.
    assert!(state.vaults.get(&vault_id).unwrap().slots.get(5).is_none());
    // Place it back at a different slot.
    let mut view = VaultCnodeView::new(&mut state);
    view.fc_set(
        vault_id,
        9,
        VaultRights::ALL,
        Cap::Protocol(KernelCap::Registered {
            id: returned_id,
            cap: returned_cap,
        }),
    )
    .expect("fc_set should accept persistent DataCap");
    assert_eq!(
        state.vaults.get(&vault_id).unwrap().slots.get(9),
        Some(cap_id)
    );
}

#[test]
fn data_cap_clones_share_arc_content() {
    let mut state = State::empty();
    let vault_id = state.next_vault_id();
    state.vaults.insert(vault_id, Arc::new(Vault::new()));
    let _parent_id = place_data_cap(&mut state, vault_id, 3, b"abc".to_vec(), 1);

    // fc_clone produces a child with derive-shared content (same Arc).
    let mut view = VaultCnodeView::new(&mut state);
    let cap = view
        .fc_clone(vault_id, 3, VaultRights::ALL)
        .expect("fc_clone");
    let (parent_arc, child_arc) = match cap {
        Cap::Protocol(KernelCap::Registered {
            cap: Capability::Data(d),
            ..
        }) => {
            let parent = match &state.cap_registry.get(&_parent_id).unwrap().cap {
                Capability::Data(p) => Arc::clone(&p.content),
                _ => unreachable!(),
            };
            (parent, d.content)
        }
        _ => panic!("expected Registered Data cap"),
    };
    assert!(
        Arc::ptr_eq(&parent_arc, &child_arc),
        "derived DataCap shares Arc<Vec<u8>> content"
    );
}

#[test]
fn data_cap_moves_between_vaults() {
    // Vault A has a DataCap at slot 0; we MOVE it to Vault B's slot 1
    // via fc_take + fc_set.
    let mut state = State::empty();
    let vault_a = state.next_vault_id();
    state.vaults.insert(vault_a, Arc::new(Vault::new()));
    let cap_id = place_data_cap(&mut state, vault_a, 0, b"shared".to_vec(), 2);
    let vault_b = state.next_vault_id();
    state.vaults.insert(vault_b, Arc::new(Vault::new()));

    let cap = {
        let mut view = VaultCnodeView::new(&mut state);
        view.fc_take(vault_a, 0, VaultRights::ALL)
            .expect("take from A")
    };

    {
        let mut view = VaultCnodeView::new(&mut state);
        view.fc_set(vault_b, 1, VaultRights::ALL, cap)
            .expect("set into B");
    }

    assert!(state.vaults.get(&vault_a).unwrap().slots.get(0).is_none());
    assert_eq!(
        state.vaults.get(&vault_b).unwrap().slots.get(1),
        Some(cap_id)
    );
}
