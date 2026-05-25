use javm_cap::image::EndpointDef;
use javm_cap::wire::WireCap;
use javm_cap::{CNodeCap, Cap, NUM_REGS, TypeCap, cap_hash, image::Image};
use std::collections::BTreeMap;

#[test]
fn type_cap_roundtrip_preserves_hash() {
    let cap = Cap::Type(TypeCap {
        image_hash_chain: [0xAB; 32],
    });
    let wire = WireCap::from_cap(&cap).expect("from_cap");
    let recovered = wire.into_cap().expect("into_cap");
    assert_eq!(cap_hash(&cap), cap_hash(&recovered));
}

#[test]
fn empty_cnode_roundtrip_preserves_hash() {
    let cap = Cap::CNode(CNodeCap::new(0).expect("cnode"));
    let wire = WireCap::from_cap(&cap).expect("from_cap");
    let recovered = wire.into_cap().expect("into_cap");
    assert_eq!(cap_hash(&cap), cap_hash(&recovered));
}

#[test]
fn inline_data_roundtrip_preserves_hash() {
    let cap = Cap::data_inline(b"hello-rkyv");
    let wire = WireCap::from_cap(&cap).expect("from_cap");
    let recovered = wire.into_cap().expect("into_cap");
    assert_eq!(cap_hash(&cap), cap_hash(&recovered));
}

#[test]
fn rkyv_archive_roundtrip_data_cap() {
    let cap = Cap::data_inline(b"archive me");
    let wire = WireCap::from_cap(&cap).expect("from_cap");
    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&wire).expect("rkyv encode");
    let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
    aligned.extend_from_slice(&bytes);
    let decoded: WireCap =
        rkyv::from_bytes::<WireCap, rkyv::rancor::Error>(&aligned).expect("rkyv decode");
    let recovered = decoded.into_cap().expect("into_cap");
    assert_eq!(cap_hash(&cap), cap_hash(&recovered));
}

#[test]
fn image_cap_roundtrip_preserves_hash() {
    // Mirror what the smoke test publishes: a minimal Image with
    // one endpoint and no slot references.
    let mut img = Image::empty();
    img.code = vec![0u8, 10u8, 42];
    img.packed_bitmask = vec![0b011u8];
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
    let cap = Cap::image_with_slots(&img, &[], &[]).expect("image_with_slots");
    let wire = WireCap::from_cap(&cap).expect("from_cap");
    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&wire).expect("rkyv encode");
    let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
    aligned.extend_from_slice(&bytes);
    let decoded: WireCap =
        rkyv::from_bytes::<WireCap, rkyv::rancor::Error>(&aligned).expect("rkyv decode");
    let recovered = decoded.into_cap().expect("into_cap");
    assert_eq!(cap_hash(&cap), cap_hash(&recovered));
}

#[test]
fn instance_cap_roundtrip_preserves_hash() {
    let cap = Cap::instance_with_overlays(
        [0u8; 32],
        [0xAA; 32],
        [0xBB; 32],
        &[],
        4096,
        [0u64; NUM_REGS],
        0,
        0,
    );
    let wire = WireCap::from_cap(&cap).expect("from_cap");
    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&wire).expect("rkyv encode");
    let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
    aligned.extend_from_slice(&bytes);
    let decoded: WireCap =
        rkyv::from_bytes::<WireCap, rkyv::rancor::Error>(&aligned).expect("rkyv decode");
    let recovered = decoded.into_cap().expect("into_cap");
    assert_eq!(cap_hash(&cap), cap_hash(&recovered));
}
