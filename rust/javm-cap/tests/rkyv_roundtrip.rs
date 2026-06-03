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
use javm_cap::cap::data::DataCap;
use javm_cap::cap::page::{PageBytes, PageSlot};
use javm_cap::image::EndpointDef;
use javm_cap::{CNodeCap, Cap, DataGroup, DataGroups, GROUP_SIZE, NUM_REGS, TypeCap, image::Image};
use ssz::MissingOr;
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
fn type_cap_roundtrip_preserves_hash() {
    round_trip(Cap::Type(TypeCap {
        image_hash_chain: [0xAB; 32],
    }));
}

#[test]
fn empty_cnode_roundtrip_preserves_hash() {
    round_trip(Cap::CNode(CNodeCap::new(0).expect("cnode")));
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
    let mut img = Image::empty();
    img.code = vec![0u8, 10u8, 42];
    let mut endpoints = BTreeMap::new();
    endpoints.insert(
        0u8,
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
    round_trip(Cap::instance_with_overlays(
        [0u8; 32],
        [0xAA; 32],
        [0xBB; 32],
        &[],
        4096,
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
    let mut groups: DataGroups = DataGroups::new();
    groups.insert(
        DataCap::group_key(0),
        MissingOr::Materialized(DataGroup { pages }),
    );
    round_trip(Cap::Data(DataCap {
        size: GROUP_SIZE as u64,
        groups,
    }));
}

#[test]
fn cnode_with_populated_slot_roundtrips() {
    let mut cn = CNodeCap::new(4).expect("cnode");
    cn.set(2u16.into(), Some(CapHashOrRef::Hash([0xEE; 32])))
        .expect("set slot 2");
    cn.set(7u16.into(), Some(CapHashOrRef::Hash([0xFF; 32])))
        .expect("set slot 7");
    round_trip(Cap::CNode(cn));
}

#[test]
fn ref_in_cap_errors_on_encode() {
    use javm_cap::CacheDirectory;
    let cache = CacheDirectory::new();
    let blob = Cap::Type(TypeCap {
        image_hash_chain: [0x11; 32],
    });
    let h = cache.put_cap(&blob).expect("put_cap");
    let capref = cache.promote_blob_to_instance(&h).expect("promote");
    let mut cn = CNodeCap::new(0).expect("cnode");
    cn.set(0u16.into(), Some(CapHashOrRef::Ref(capref)))
        .expect("set ref");
    let cap = Cap::CNode(cn);
    let err = rkyv::to_bytes::<rkyv::rancor::Error>(&cap).expect_err("must reject Ref");
    // Release builds strip rancor's source-chain detail (it requires
    // both debug assertions and rancor's `alloc` feature), so we only
    // assert on the message contents when debug assertions are on.
    if cfg!(debug_assertions) {
        let msg = format!("{err}");
        assert!(
            msg.contains("CapHashOrRef::Ref") || msg.contains("CapRef") || msg.contains("settle"),
            "expected CapHasRefError in chain, got: {msg}"
        );
    }
}
