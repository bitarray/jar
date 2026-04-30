//! Snapshot/rollback semantics for σ.
//!
//! The snapshot mechanism is being retired in Step 3 of the
//! unified-persistence refactor; in the meantime these tests cover the
//! Arc-CoW guarantee that makes σ.clone() cheap.

use std::sync::Arc;

use jar_kernel::state::snapshot::StateSnapshot;
use jar_kernel::{CapRecord, Capability, DataCap, State, Vault, VaultId};

fn state_with_one_vault() -> (State, VaultId) {
    let mut s = State::empty();
    let v = Vault::new();
    let id = s.next_vault_id();
    s.vaults.insert(id, Arc::new(v));
    (s, id)
}

#[test]
fn snapshot_round_trip_restores_cap_registry() {
    let (mut s, _id) = state_with_one_vault();
    let snap = StateSnapshot::take(&s);

    // Mutate: register a fresh cap.
    let cap_id = jar_kernel::state::cap_registry::alloc(
        &mut s,
        CapRecord {
            cap: Capability::Data(DataCap {
                content: Arc::new(b"x".to_vec()),
                page_count: 1,
            }),
            issuer: None,
            narrowing: vec![],
        },
    );
    assert!(s.cap_registry.contains_key(&cap_id));

    // Restore: registry should look like before.
    snap.restore(&mut s);
    assert!(!s.cap_registry.contains_key(&cap_id));
}

#[test]
fn arc_cow_keeps_unmutated_vaults_shared() {
    let (s, id) = state_with_one_vault();
    let s2 = s.clone();
    // The Arcs point to the same allocation.
    assert!(Arc::ptr_eq(&s.vaults[&id], &s2.vaults[&id]));
}
