//! Round-trip tests for the rkyv pipeline on `Cap`.
//!
//! Encode: `rkyv::to_bytes(&cap)` — errors on unsettled `Ref` targets.
//! Decode: `rkyv::access::<Archived<Cap>>` (zero-copy validation) →
//!         `rkyv::deserialize::<Cap, _>(archived)` (materialise owned).
//!
//! Verifies content-hash preservation across the full I/O boundary,
//! covers the V1 wire features (paged data, sparse cnodes), and asserts
//! that `Ref`-bearing caps surface a typed encode error (no panic).

use javm_cap::cache::CapHashOrRef;
use javm_cap::cap::page::{PageBytes, PageSlot};
use javm_cap::image::EndpointDef;
use javm_cap::{
    CNodeCap, Cap, DataCap, GROUP_SIZE, Key, NUM_REGS, PAGE_SIZE, PageSlab, image::Image,
};
use std::collections::BTreeMap;
use std::sync::Arc;

fn round_trip(cap: Cap) {
    let original = cap.cap_hash();
    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&cap).expect("rkyv encode");
    let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
    aligned.extend_from_slice(&bytes);
    let archived = rkyv::access::<rkyv::Archived<Cap>, rkyv::rancor::Error>(aligned.as_slice())
        .expect("rkyv access");
    let recovered: Cap =
        rkyv::deserialize::<Cap, rkyv::rancor::Error>(archived).expect("rkyv deserialize");
    assert_eq!(original, recovered.cap_hash());
}

#[test]
fn empty_cnode_roundtrip_preserves_hash() {
    round_trip(Cap::CNode(CNodeCap::new()));
}

#[test]
fn inline_data_roundtrip_preserves_hash() {
    round_trip(Cap::data_inline(b"hello-rkyv"));
}

#[test]
fn rkyv_archive_roundtrip_data_cap() {
    round_trip(Cap::data_inline(b"archive me"));
}

#[test]
fn image_cap_roundtrip_preserves_hash() {
    let mut img = Image::with_code(vec![0u8, 10u8, 42]);
    let mut endpoints = BTreeMap::new();
    endpoints.insert(
        Key::from(0u8),
        EndpointDef {
            entry_pc: 1,
            arg_registers: 0,
            arg_cnode_size: 0,
            initial_regs: BTreeMap::new(),
        },
    );
    img.endpoints = endpoints;
    round_trip(Cap::image_with_slots(&img, &[], &[]).expect("image_with_slots"));
}

#[test]
fn instance_cap_roundtrip_preserves_hash() {
    round_trip(Cap::instance_with_mem(
        [0u8; 32],
        [0xAA; 32],
        [0xBB; 32],
        DataCap::from_bytes_sized(&[], 4096),
        [0u64; NUM_REGS],
        0,
        0,
    ));
}

#[test]
fn paged_data_roundtrip_preserves_hash() {
    let page = PageBytes {
        hash: [0xCC; 32],
        bytes: vec![1u8; 4096],
    };
    let pages = vec![
        PageSlot::Empty,
        PageSlot::Loaded(Arc::new(page)),
        PageSlot::Missing([0xDD; 32]),
    ];
    round_trip(Cap::Data(DataCap {
        backing: Arc::new(PageSlab {
            size: GROUP_SIZE as u64,
            pages,
        }),
        overlay: BTreeMap::new(),
    }));
}

#[test]
fn data_overlay_roundtrip_preserves_effective_bytes() {
    // A cap with a live CoW overlay is *not* hashable (it must be flushed
    // first), but the rkyv wire form must still survive the round trip — this
    // is the path the zero-copy slot return rides. Compare effective bytes.
    let mut cap = DataCap::from_bytes_sized(b"backing-page-0", 2 * PAGE_SIZE as u64);
    let mut content = vec![0u8; PAGE_SIZE];
    content[..3].copy_from_slice(b"ovl");
    cap.write_page(0, &content);
    assert!(cap.is_dirty(0));

    let bytes =
        rkyv::to_bytes::<rkyv::rancor::Error>(&Cap::Data(cap.clone())).expect("rkyv encode");
    let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
    aligned.extend_from_slice(&bytes);
    let archived = rkyv::access::<rkyv::Archived<Cap>, rkyv::rancor::Error>(aligned.as_slice())
        .expect("rkyv access");
    let recovered: Cap =
        rkyv::deserialize::<Cap, rkyv::rancor::Error>(archived).expect("rkyv deserialize");
    let Cap::Data(rec) = recovered else {
        panic!("expected Cap::Data")
    };
    assert!(rec.is_dirty(0), "overlay page survives the round trip");
    let (mut a, mut b) = (vec![0u8; 2 * PAGE_SIZE], vec![0u8; 2 * PAGE_SIZE]);
    cap.copy_into(0, &mut a);
    rec.copy_into(0, &mut b);
    assert_eq!(
        a, b,
        "effective (overlay+backing) bytes preserved across rkyv"
    );
}

#[test]
fn cnode_with_populated_slot_roundtrips() {
    let mut cn = CNodeCap::new();
    cn.set(&Key::from(2u8), Some(CapHashOrRef::Hash([0xEE; 32])))
        .expect("set slot 2");
    cn.set(&Key::from(7u8), Some(CapHashOrRef::Hash([0xFF; 32])))
        .expect("set slot 7");
    round_trip(Cap::CNode(cn));
}

#[test]
fn owned_in_cap_errors_on_encode() {
    // An in-flight `Owned(Box<Cap>)` slot is runtime-only — it has no wire
    // form and rkyv encode must surface a typed error (no panic).
    let mut cn = CNodeCap::new();
    cn.set(
        &Key::from(0u8),
        Some(CapHashOrRef::Owned(Box::new(Cap::data_inline(b"payload")))),
    )
    .expect("set owned");
    let cap = Cap::CNode(cn);
    let err = rkyv::to_bytes::<rkyv::rancor::Error>(&cap).expect_err("must reject Owned");
    if cfg!(debug_assertions) {
        let msg = format!("{err}");
        assert!(
            msg.contains("Owned") || msg.contains("settle"),
            "expected CapHasRefError in chain, got: {msg}"
        );
    }
}
