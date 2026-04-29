//! Snapshot/rollback semantics for σ.

use std::sync::Arc;

use jar_kernel::snapshot::StateSnapshot;
use jar_types::{Hash, State, Vault, VaultId};

fn state_with_one_vault() -> (State, VaultId) {
    let mut s = State::empty();
    let mut v = Vault::new(Hash::ZERO);
    v.quota_items = 16;
    v.quota_bytes = 4096;
    let id = s.next_vault_id();
    s.vaults.insert(id, Arc::new(v));
    (s, id)
}

#[test]
fn snapshot_round_trip_restores_state() {
    let (mut s, id) = state_with_one_vault();
    let snap = StateSnapshot::take(&s);

    // Mutate: clone vault, write a key, replace.
    let mut v = (*s.vaults[&id]).clone();
    v.storage.insert(b"k".to_vec(), b"v".to_vec());
    v.total_footprint = 2;
    s.vaults.insert(id, Arc::new(v));
    assert_eq!(
        s.vaults[&id].storage.get(b"k".as_slice()),
        Some(&b"v".to_vec())
    );

    // Restore: vault should look like before.
    snap.restore(&mut s);
    assert!(!s.vaults[&id].storage.contains_key(b"k".as_slice()));
    assert_eq!(s.vaults[&id].total_footprint, 0);
}

#[test]
fn arc_cow_keeps_unmutated_vaults_shared() {
    let (s, id) = state_with_one_vault();
    let s2 = s.clone();
    // The Arcs point to the same allocation.
    assert!(Arc::ptr_eq(&s.vaults[&id], &s2.vaults[&id]));
}
