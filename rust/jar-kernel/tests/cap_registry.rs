//! Cap-registry tests: alloc, derive, revoke (cascade), pinning.

use jar_crypto::Ed25519Blake;
use jar_kernel::cap_registry;
use jar_kernel::cnode_ops;
use jar_kernel::pinning;
use jar_types::{CapRecord, Capability, KernelError, State, StorageRights, VaultId, VaultRights};

fn empty_state() -> State<Ed25519Blake> {
    State::<Ed25519Blake>::empty()
}

#[test]
fn alloc_assigns_monotonic_ids() {
    let mut s = empty_state();
    let a = cap_registry::alloc(
        &mut s,
        CapRecord {
            cap: Capability::Vault {
                vault_id: VaultId(0),
            },
            issuer: None,
            narrowing: vec![],
        },
    );
    let b = cap_registry::alloc(
        &mut s,
        CapRecord {
            cap: Capability::Vault {
                vault_id: VaultId(1),
            },
            issuer: None,
            narrowing: vec![],
        },
    );
    assert_eq!(a.0, 0);
    assert_eq!(b.0, 1);
}

#[test]
fn revoke_cascades_to_derived() {
    let mut s = empty_state();
    let parent_cnode = cnode_ops::cnode_create(&mut s);
    let parent = cap_registry::alloc(
        &mut s,
        CapRecord {
            cap: Capability::Dispatch {
                vault_id: VaultId(0),
                born_in: parent_cnode,
            },
            issuer: None,
            narrowing: vec![],
        },
    );
    let dispatch_ref = cap_registry::derive(
        &mut s,
        parent,
        Capability::DispatchRef {
            vault_id: VaultId(0),
        },
        vec![],
        false,
    )
    .expect("derive DispatchRef ok");

    assert!(s.cap_registry.contains_key(&parent));
    assert!(s.cap_registry.contains_key(&dispatch_ref));

    cap_registry::revoke_cascade(&mut s, parent);
    assert!(!s.cap_registry.contains_key(&parent));
    assert!(!s.cap_registry.contains_key(&dispatch_ref));
}

#[test]
fn pinning_rejects_dispatch_into_wrong_cnode() {
    let mut s = empty_state();
    let cn_a = cnode_ops::cnode_create(&mut s);
    let cn_b = cnode_ops::cnode_create(&mut s);
    let dispatch_cap = cnode_ops::mint_and_place(
        &mut s,
        Capability::Dispatch {
            vault_id: VaultId(7),
            born_in: cn_a,
        },
        vec![],
        cn_a,
        0,
    )
    .unwrap();

    // Granting into cn_a is fine.
    cnode_ops::cnode_grant(&mut s, dispatch_cap, cn_a, 1).unwrap();

    // Granting into cn_b must fail with Pinning.
    match cnode_ops::cnode_grant(&mut s, dispatch_cap, cn_b, 0) {
        Err(KernelError::Pinning(_)) => {}
        other => panic!("expected Pinning error, got {:?}", other),
    }
}

#[test]
fn pinning_rejects_dispatchref_to_persistent_cnode() {
    let mut s = empty_state();
    let cn = cnode_ops::cnode_create(&mut s);
    let dispatch = cnode_ops::mint_and_place(
        &mut s,
        Capability::Dispatch {
            vault_id: VaultId(0),
            born_in: cn,
        },
        vec![],
        cn,
        0,
    )
    .unwrap();
    // Deriving a DispatchRef and trying to make it persistent must fail.
    match cap_registry::derive(
        &mut s,
        dispatch,
        Capability::DispatchRef {
            vault_id: VaultId(0),
        },
        vec![],
        true,
    ) {
        Err(KernelError::Pinning(_)) => {}
        other => panic!("expected Pinning, got {:?}", other),
    }
}

#[test]
fn arg_scan_rejects_pinned_caps() {
    let mut s = empty_state();
    let cn = cnode_ops::cnode_create(&mut s);
    let pinned_dispatch = cap_registry::alloc(
        &mut s,
        CapRecord {
            cap: Capability::Dispatch {
                vault_id: VaultId(0),
                born_in: cn,
            },
            issuer: None,
            narrowing: vec![],
        },
    );
    let dispatch_ref = cap_registry::alloc(
        &mut s,
        CapRecord {
            cap: Capability::DispatchRef {
                vault_id: VaultId(0),
            },
            issuer: None,
            narrowing: vec![],
        },
    );
    let plain = cap_registry::alloc(
        &mut s,
        CapRecord {
            cap: Capability::VaultRef {
                vault_id: VaultId(1),
                rights: VaultRights::ALL,
            },
            issuer: None,
            narrowing: vec![],
        },
    );
    // Plain VaultRef in args is fine.
    pinning::arg_scan(&s, &[plain]).unwrap();
    // Pinned Dispatch in args is rejected.
    match pinning::arg_scan(&s, &[plain, pinned_dispatch]) {
        Err(KernelError::Pinning(_)) => {}
        other => panic!("expected Pinning, got {:?}", other),
    }
    // Ephemeral DispatchRef in args is also rejected.
    match pinning::arg_scan(&s, &[dispatch_ref]) {
        Err(KernelError::Pinning(_)) => {}
        other => panic!("expected Pinning, got {:?}", other),
    }
}

#[test]
fn vaultref_derive_into_frame_or_persistent_works() {
    let mut s = empty_state();
    let parent = cap_registry::alloc(
        &mut s,
        CapRecord {
            cap: Capability::VaultRef {
                vault_id: VaultId(0),
                rights: VaultRights::ALL,
            },
            issuer: None,
            narrowing: vec![],
        },
    );
    // Frame.
    cap_registry::derive(
        &mut s,
        parent,
        Capability::VaultRef {
            vault_id: VaultId(0),
            rights: VaultRights::INITIALIZE,
        },
        vec![],
        false,
    )
    .unwrap();
    // Persistent.
    cap_registry::derive(
        &mut s,
        parent,
        Capability::VaultRef {
            vault_id: VaultId(0),
            rights: VaultRights::INITIALIZE,
        },
        vec![],
        true,
    )
    .unwrap();
}

#[test]
fn storage_rights_constants_are_self_consistent() {
    // Smoke check on the StorageRights constants used in tests.
    let rw = StorageRights::RW;
    let ro = StorageRights::RO;
    assert!(rw.read && rw.write);
    assert!(ro.read && !ro.write);
}
