//! Tests for the cap-table host operations: take / set / clone / drop /
//! is_empty against `vault.slots`. After CapId removal, caps live inline
//! as `RegCap` values and project to/from Frame `Cap` representations:
//!
//! - VaultRef ↔ `ProtocolCap::VaultRef(_)`.
//! - Resource ↔ `ProtocolCap::Resource(_)`.
//! - Code / Data are container-bound (`take` / `clone` return `None`).
//!
//! No cap_registry, no cascade revocation. `drop` just clears the slot.

use std::sync::Arc;

use jar_kernel::cap::{Cap, ProtocolCap};
use jar_kernel::vm::foreign_cnode;
use jar_kernel::{
    DataCap, ImageId, RegCap, ResourceCap, ResourceKind, State, Vault, VaultId, VaultRefCap,
    VaultRights,
};

fn empty_vault() -> (State, VaultId) {
    let mut state = State::empty();
    let vault_id = state.next_vault_id();
    // Tests in this file exercise foreign_cnode operations; they
    // never invoke vault.initialize, so a placeholder image_id is
    // fine.
    state
        .vaults
        .insert(vault_id, Arc::new(Vault::new(ImageId(0))));
    (state, vault_id)
}

fn place(state: &mut State, vault: VaultId, slot: u8, cap: RegCap) {
    let arc = state.vaults.get(&vault).unwrap().clone();
    let mut v: Vault = (*arc).clone();
    v.slots.set(slot, Some(cap));
    state.vaults.insert(vault, Arc::new(v));
}

fn place_resource(state: &mut State, vault: VaultId, slot: u8) -> ResourceCap {
    let r = ResourceCap(ResourceKind::CreateVault { quota_pages: 16 });
    place(state, vault, slot, RegCap::Resource(r.clone()));
    r
}

#[test]
fn take_resource_returns_protocol_resource_and_clears_slot() {
    let (mut state, vault_id) = empty_vault();
    let r = place_resource(&mut state, vault_id, 7);
    let cap = foreign_cnode::take(&mut state, vault_id, 7, VaultRights::ALL)
        .expect("take with full rights");
    match cap {
        Cap::Protocol(ProtocolCap::Resource(out)) => assert_eq!(out, r),
        _ => panic!("expected ProtocolCap::Resource"),
    }
    assert!(state.vaults.get(&vault_id).unwrap().slots.get(7).is_none());
}

#[test]
fn take_vault_ref_returns_protocol_vault_ref() {
    let (mut state, vault_id) = empty_vault();
    let vr = VaultRefCap {
        vault_id: VaultId(99),
        rights: VaultRights::ALL,
    };
    place(&mut state, vault_id, 5, RegCap::VaultRef(vr));
    let cap =
        foreign_cnode::take(&mut state, vault_id, 5, VaultRights::ALL).expect("take vault_ref");
    match cap {
        Cap::Protocol(ProtocolCap::VaultRef(out)) => assert_eq!(out, vr),
        _ => panic!("expected ProtocolCap::VaultRef"),
    }
}

#[test]
fn take_requires_revoke_right() {
    let (mut state, vault_id) = empty_vault();
    let _ = place_resource(&mut state, vault_id, 7);
    assert!(foreign_cnode::take(&mut state, vault_id, 7, VaultRights::READ).is_none());
    assert!(state.vaults.get(&vault_id).unwrap().slots.get(7).is_some());
}

#[test]
fn take_data_cap_returns_none() {
    let (mut state, vault_id) = empty_vault();
    place(
        &mut state,
        vault_id,
        7,
        RegCap::Data(DataCap {
            content: Arc::new(b"sample".to_vec()),
            page_count: 1,
        }),
    );
    assert!(foreign_cnode::take(&mut state, vault_id, 7, VaultRights::ALL).is_none());
}

#[test]
fn set_places_resource_into_empty_slot() {
    let (mut state, vault_id) = empty_vault();
    let r = ResourceCap(ResourceKind::CreateVault { quota_pages: 16 });
    let cap = Cap::Protocol(ProtocolCap::Resource(r.clone()));
    foreign_cnode::set(&mut state, vault_id, 8, VaultRights::ALL, cap, None)
        .expect("set into empty slot 8");
    assert_eq!(
        state.vaults.get(&vault_id).unwrap().slots.get(8),
        Some(&RegCap::Resource(r))
    );
}

#[test]
fn set_places_vault_ref_inline() {
    let (mut state, vault_id) = empty_vault();
    let vr = VaultRefCap {
        vault_id: VaultId(7),
        rights: VaultRights::READ,
    };
    let cap = Cap::Protocol(ProtocolCap::VaultRef(vr));
    foreign_cnode::set(&mut state, vault_id, 0, VaultRights::ALL, cap, None)
        .expect("set vault_ref");
    assert_eq!(
        state.vaults.get(&vault_id).unwrap().slots.get(0),
        Some(&RegCap::VaultRef(vr))
    );
}

#[test]
fn set_rejects_frame_only_caps() {
    let (mut state, vault_id) = empty_vault();
    let ephemeral = Cap::Protocol(ProtocolCap::SelfId(jar_kernel::cap::SelfCap {
        vault_id: VaultId(0),
    }));
    assert!(
        foreign_cnode::set(&mut state, vault_id, 0, VaultRights::ALL, ephemeral, None).is_err()
    );
}

#[test]
fn set_requires_grant_right() {
    let (mut state, vault_id) = empty_vault();
    let r = ResourceCap(ResourceKind::CreateVault { quota_pages: 16 });
    let cap = Cap::Protocol(ProtocolCap::Resource(r));
    assert!(foreign_cnode::set(&mut state, vault_id, 0, VaultRights::READ, cap, None).is_err());
}

#[test]
fn clone_resource_produces_independent_copy() {
    let (mut state, vault_id) = empty_vault();
    let r = place_resource(&mut state, vault_id, 7);
    let cap = foreign_cnode::clone(&state, vault_id, 7, VaultRights::ALL, None)
        .expect("clone with derive right");
    match cap {
        Cap::Protocol(ProtocolCap::Resource(out)) => assert_eq!(out, r),
        _ => panic!("expected ProtocolCap::Resource"),
    }
    assert_eq!(
        state.vaults.get(&vault_id).unwrap().slots.get(7),
        Some(&RegCap::Resource(r))
    );
}

#[test]
fn clone_vault_ref_produces_inline_value() {
    let (mut state, vault_id) = empty_vault();
    let vr = VaultRefCap {
        vault_id: VaultId(42),
        rights: VaultRights::ALL,
    };
    place(&mut state, vault_id, 3, RegCap::VaultRef(vr));
    let cap =
        foreign_cnode::clone(&state, vault_id, 3, VaultRights::ALL, None).expect("clone vault_ref");
    match cap {
        Cap::Protocol(ProtocolCap::VaultRef(out)) => assert_eq!(out, vr),
        _ => panic!("expected ProtocolCap::VaultRef"),
    }
    assert_eq!(
        state.vaults.get(&vault_id).unwrap().slots.get(3),
        Some(&RegCap::VaultRef(vr))
    );
}

#[test]
fn clone_requires_derive_right() {
    let (mut state, vault_id) = empty_vault();
    let _ = place_resource(&mut state, vault_id, 7);
    assert!(foreign_cnode::clone(&state, vault_id, 7, VaultRights::READ, None).is_none());
}

#[test]
fn clone_code_cap_returns_none() {
    use jar_kernel::CodeCap;
    let (mut state, vault_id) = empty_vault();
    place(
        &mut state,
        vault_id,
        7,
        RegCap::Code(CodeCap {
            blob: Arc::new(vec![0; 64]),
        }),
    );
    assert!(foreign_cnode::clone(&state, vault_id, 7, VaultRights::ALL, None).is_none());
}

#[test]
fn drop_clears_slot() {
    let (mut state, vault_id) = empty_vault();
    let _ = place_resource(&mut state, vault_id, 7);
    assert!(foreign_cnode::drop(
        &mut state,
        vault_id,
        7,
        VaultRights::ALL
    ));
    assert!(state.vaults.get(&vault_id).unwrap().slots.get(7).is_none());
}

#[test]
fn drop_empty_slot_is_noop() {
    let (mut state, vault_id) = empty_vault();
    assert!(!foreign_cnode::drop(
        &mut state,
        vault_id,
        7,
        VaultRights::ALL
    ));
}

#[test]
fn is_empty_reports_slot_state() {
    let (mut state, vault_id) = empty_vault();
    let _ = place_resource(&mut state, vault_id, 7);
    assert!(!foreign_cnode::is_empty(&state, vault_id, 7));
    assert!(foreign_cnode::is_empty(&state, vault_id, 8));
    assert!(foreign_cnode::is_empty(&state, VaultId(99_999), 0));
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
        rights: VaultRights::INITIALIZE,
    });
    assert!(cap.as_foreign_frame().is_none());
}
