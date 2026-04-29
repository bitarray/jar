//! Storage host-call + quota enforcement.
//!
//! Exercises the cap-based storage authority: `Storage` cap allows reads
//! and (with rights.write) writes/deletes; `SnapshotStorage` rejects writes.

use std::sync::Arc;

use jar_kernel::storage;
use jar_kernel::{
    CapRecord, Capability, Hash, KernelError, KeyRange, State, StorageRights, Vault, VaultId,
};

fn setup() -> (State, VaultId, jar_kernel::CapId) {
    let mut s = State::empty();
    let mut v = Vault::new(Hash::ZERO);
    v.quota_items = 4;
    v.quota_bytes = 64;
    let id = s.next_vault_id();
    s.vaults.insert(id, Arc::new(v));
    let cap = jar_kernel::cap_registry::alloc(
        &mut s,
        CapRecord {
            cap: Capability::Storage {
                vault_id: id,
                key_range: KeyRange::all(),
                rights: StorageRights::RW,
            },
            issuer: None,
            narrowing: vec![],
        },
    );
    (s, id, cap)
}

#[test]
fn storage_read_write_round_trip() {
    let (mut s, _id, cap) = setup();
    storage::storage_write(&mut s, cap, b"hello", b"world").unwrap();
    let r = storage::storage_read(&s, cap, b"hello").unwrap();
    assert_eq!(r.as_deref(), Some(&b"world"[..]));
}

#[test]
fn snapshot_storage_blocks_writes() {
    let mut s = State::empty();
    let mut v = Vault::new(Hash::ZERO);
    v.quota_items = 4;
    v.quota_bytes = 64;
    let id = s.next_vault_id();
    s.vaults.insert(id, Arc::new(v));
    let cap = jar_kernel::cap_registry::alloc(
        &mut s,
        CapRecord {
            cap: Capability::SnapshotStorage {
                vault_id: id,
                key_range: KeyRange::all(),
                root: Hash::ZERO,
            },
            issuer: None,
            narrowing: vec![],
        },
    );
    let r = storage::storage_write(&mut s, cap, b"x", b"y");
    match r {
        Err(KernelError::ReadOnly(_)) => {}
        other => panic!(
            "expected ReadOnly on SnapshotStorage write, got {:?}",
            other
        ),
    }
}

#[test]
fn read_only_storage_cap_blocks_writes() {
    let mut s = State::empty();
    let mut v = Vault::new(Hash::ZERO);
    v.quota_items = 4;
    v.quota_bytes = 64;
    let id = s.next_vault_id();
    s.vaults.insert(id, Arc::new(v));
    let cap = jar_kernel::cap_registry::alloc(
        &mut s,
        CapRecord {
            cap: Capability::Storage {
                vault_id: id,
                key_range: KeyRange::all(),
                rights: StorageRights::RO,
            },
            issuer: None,
            narrowing: vec![],
        },
    );
    let r = storage::storage_write(&mut s, cap, b"x", b"y");
    match r {
        Err(KernelError::Internal(msg)) if msg.contains("Write") => {}
        other => panic!("expected lacks-Write Internal error, got {:?}", other),
    }
}

#[test]
fn quota_bytes_is_enforced() {
    let (mut s, _id, cap) = setup();
    for i in 0..12 {
        let key = format!("k{}", i);
        let val = format!("aaaaaaaa{}", i);
        let _ = storage::storage_write(&mut s, cap, key.as_bytes(), val.as_bytes());
    }
    let footprint = s.vaults[&_id].total_footprint;
    assert!(footprint <= 64, "footprint {} > quota_bytes 64", footprint);
}

#[test]
fn quota_items_is_enforced() {
    let (mut s, _id, cap) = setup();
    storage::storage_write(&mut s, cap, b"a", b"1").unwrap();
    storage::storage_write(&mut s, cap, b"b", b"2").unwrap();
    storage::storage_write(&mut s, cap, b"c", b"3").unwrap();
    storage::storage_write(&mut s, cap, b"d", b"4").unwrap();
    let r = storage::storage_write(&mut s, cap, b"e", b"5");
    match r {
        Err(KernelError::QuotaExceeded {
            what: "quota_items",
        }) => {}
        other => panic!("expected QuotaExceeded(items), got {:?}", other),
    }
}
