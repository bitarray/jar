//! Cap-registry tests: alloc, derive, revoke (cascade).
//!
//! Trimmed during the event-redesign migration. Pinning-related tests
//! that used `DispatchCap` / `DispatchRefCap` are removed because those
//! cap variants no longer exist (replaced by the flat
//! `EventEndpointCap`). Stage E (E1) restores broader integration
//! coverage for the new model.

use jar_kernel::state::cap_registry;
use jar_kernel::{CapRecord, Capability, State, VaultId, VaultRefCap, VaultRights};

fn empty_state() -> State {
    State::empty()
}

#[test]
fn alloc_assigns_monotonic_ids() {
    let mut s = empty_state();
    let a = cap_registry::alloc(
        &mut s,
        CapRecord {
            cap: Capability::VaultRef(VaultRefCap {
                vault_id: VaultId(0),
                rights: VaultRights::ALL,
            }),
            issuer: None,
            narrowing: vec![],
        },
    );
    let b = cap_registry::alloc(
        &mut s,
        CapRecord {
            cap: Capability::VaultRef(VaultRefCap {
                vault_id: VaultId(1),
                rights: VaultRights::ALL,
            }),
            issuer: None,
            narrowing: vec![],
        },
    );
    assert_eq!(a.0, 0);
    assert_eq!(b.0, 1);
}

#[test]
fn derive_creates_child_record() {
    let mut s = empty_state();
    let parent = cap_registry::alloc(
        &mut s,
        CapRecord {
            cap: Capability::VaultRef(VaultRefCap {
                vault_id: VaultId(7),
                rights: VaultRights::ALL,
            }),
            issuer: None,
            narrowing: vec![],
        },
    );
    let child = cap_registry::derive(
        &mut s,
        parent,
        Capability::VaultRef(VaultRefCap {
            vault_id: VaultId(7),
            rights: VaultRights::READ,
        }),
        Vec::new(),
        false,
    )
    .expect("derive ok");
    assert_ne!(parent.0, child.0);
    let rec = cap_registry::lookup(&s, child).expect("child record present");
    assert_eq!(rec.issuer, Some(parent));
}
