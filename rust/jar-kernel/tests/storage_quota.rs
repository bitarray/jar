//! Storage host-call + quota enforcement.

use std::sync::Arc;

use jar_crypto::Ed25519Blake;
use jar_kernel::storage;
use jar_types::{
    CapRecord, Capability, KernelError, KeyRange, State, StorageMode, StorageRights, Vault, VaultId,
};

fn setup() -> (State<Ed25519Blake>, VaultId, jar_types::CapId) {
    let mut s = State::<Ed25519Blake>::empty();
    let mut v = Vault::<Ed25519Blake>::new(jar_types::Hash::ZERO);
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
    storage::storage_write(&mut s, StorageMode::Rw, cap, b"hello", b"world").unwrap();
    let r = storage::storage_read(&s, cap, b"hello").unwrap();
    assert_eq!(r.as_deref(), Some(&b"world"[..]));
}

#[test]
fn read_only_blocks_writes() {
    let (mut s, _id, cap) = setup();
    let r = storage::storage_write(&mut s, StorageMode::Ro, cap, b"x", b"y");
    match r {
        Err(KernelError::ReadOnly(_)) => {}
        other => panic!("expected ReadOnly, got {:?}", other),
    }
}

#[test]
fn quota_bytes_is_enforced() {
    let (mut s, _id, cap) = setup();
    // 64-byte budget: each "k0=val0" pair is ~6 bytes; 12 entries should bust.
    for i in 0..12 {
        let key = format!("k{}", i);
        let val = format!("aaaaaaaa{}", i);
        let _ =
            storage::storage_write(&mut s, StorageMode::Rw, cap, key.as_bytes(), val.as_bytes());
    }
    // Final write should have bounced once we exceeded quota_bytes.
    let footprint = s.vaults[&_id].total_footprint;
    assert!(footprint <= 64, "footprint {} > quota_bytes 64", footprint);
}

#[test]
fn quota_items_is_enforced() {
    let (mut s, _id, cap) = setup();
    // quota_items = 4, so the 5th distinct key should be rejected.
    storage::storage_write(&mut s, StorageMode::Rw, cap, b"a", b"1").unwrap();
    storage::storage_write(&mut s, StorageMode::Rw, cap, b"b", b"2").unwrap();
    storage::storage_write(&mut s, StorageMode::Rw, cap, b"c", b"3").unwrap();
    storage::storage_write(&mut s, StorageMode::Rw, cap, b"d", b"4").unwrap();
    let r = storage::storage_write(&mut s, StorageMode::Rw, cap, b"e", b"5");
    match r {
        Err(KernelError::QuotaExceeded {
            what: "quota_items",
        }) => {}
        other => panic!("expected QuotaExceeded(items), got {:?}", other),
    }
}
