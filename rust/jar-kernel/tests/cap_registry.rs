//! Cap-registry tests: alloc, derive, revoke (cascade).
//!
//! With VaultRef no longer in RegCap (it's an inline value cap with
//! `(vault_id, rights)` identity), the cap_registry tests use
//! `RegCap::Resource` as the canonical registered-cap example.

use jar_kernel::state::cap_registry;
use jar_kernel::{CapRecord, RegCap, ResourceCap, ResourceKind, State, VaultId};

fn empty_state() -> State {
    State::empty()
}

fn create_vault_resource(quota: u64) -> RegCap {
    RegCap::Resource(ResourceCap(ResourceKind::CreateVault {
        quota_pages: quota,
    }))
}

#[test]
fn alloc_assigns_monotonic_ids() {
    let mut s = empty_state();
    let a = cap_registry::alloc(
        &mut s,
        CapRecord {
            cap: create_vault_resource(64),
            issuer: None,
            narrowing: vec![],
        },
    );
    let b = cap_registry::alloc(
        &mut s,
        CapRecord {
            cap: create_vault_resource(128),
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
            cap: RegCap::Resource(ResourceCap(ResourceKind::SetQuota { target: VaultId(7) })),
            issuer: None,
            narrowing: vec![],
        },
    );
    let child = cap_registry::derive(
        &mut s,
        parent,
        RegCap::Resource(ResourceCap(ResourceKind::SetQuota { target: VaultId(7) })),
        Vec::new(),
        false,
    )
    .expect("derive ok");
    assert_ne!(parent.0, child.0);
    let rec = cap_registry::lookup(&s, child).expect("child record present");
    assert_eq!(rec.issuer, Some(parent));
}
