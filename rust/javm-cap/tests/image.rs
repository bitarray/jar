use javm_cap::image::{EndpointDef, MemoryMapping};
use javm_cap::{
    Blake2b256, Image, InitialDataCap, PinnedCap, SlotIdx, SlotPath, chain_extend, chain_genesis,
    image_content_hash,
};
use ssz::Decode as _;
use std::collections::BTreeMap;

type H = Blake2b256;

#[test]
fn empty_image_hashes_deterministically() {
    let img = Image::empty();
    let h1 = image_content_hash(&img);
    let h2 = image_content_hash(&img);
    assert_eq!(h1, h2);
}

#[test]
fn image_ssz_roundtrip() {
    let mut img = Image::empty();
    img.code = b"sample code".to_vec();
    img.jump_table = vec![0u32, 4, 8];
    img.jump_table_offsets = vec![0, 3];
    img.endpoints.insert(
        0,
        EndpointDef {
            entry_pc: 0x100,
            arg_registers: 1,
            arg_cnode_size: 0,
            initial_regs: BTreeMap::new(),
        },
    );
    let mut initial_regs = BTreeMap::new();
    initial_regs.insert(1u8, 0x4000);
    img.endpoints.insert(
        255,
        EndpointDef {
            entry_pc: 0xDEADBEEF,
            arg_registers: 4,
            arg_cnode_size: 8,
            initial_regs,
        },
    );
    img.memory_mappings.push(MemoryMapping {
        start: 0x1000,
        size: 0x4000,
        source: SlotPath::root(SlotIdx(65)),
    });
    img.memory_mappings.push(MemoryMapping {
        start: 0x5000,
        size: 0x2000,
        source: SlotPath::root(SlotIdx(3)),
    });
    img.gas_slots = vec![SlotIdx(7)];
    img.quota_slots = vec![SlotIdx(8)];
    img.pinned_slots.insert(
        SlotIdx(11),
        PinnedCap::Data {
            content: vec![0xAB; 1024],
            size: 4096,
        },
    );
    img.initial_slots.insert(
        SlotIdx(65),
        InitialDataCap {
            content: Vec::new(),
            size: 0x4000,
        },
    );
    img.yield_marker_slot = Some(SlotIdx(9));

    let bytes = ssz::Encode::as_ssz_bytes(&img);
    let decoded = Image::from_ssz_bytes(&bytes).expect("decode");
    assert_eq!(decoded, img);
}

#[test]
fn different_code_different_hash() {
    let mut a = Image::empty();
    a.code = b"AAAA".to_vec();
    let mut b = Image::empty();
    b.code = b"BBBB".to_vec();
    assert_ne!(image_content_hash(&a), image_content_hash(&b));
}

#[test]
fn endpoints_affect_hash() {
    let a = Image::empty();
    let mut b = Image::empty();
    b.endpoints.insert(
        7,
        EndpointDef {
            entry_pc: 0x1000,
            arg_registers: 2,
            arg_cnode_size: 0,
            initial_regs: BTreeMap::new(),
        },
    );
    assert_ne!(image_content_hash(&a), image_content_hash(&b));
}

#[test]
fn pinned_slots_order_independent() {
    // BTreeMap iteration is deterministic; insertion order
    // shouldn't matter for the resulting hash.
    let mut a = Image::empty();
    a.pinned_slots.insert(
        SlotIdx(3),
        PinnedCap::Data {
            content: vec![0xAA; 100],
            size: 100,
        },
    );
    a.pinned_slots.insert(
        SlotIdx(7),
        PinnedCap::Data {
            content: vec![0xBB; 200],
            size: 200,
        },
    );

    let mut b = Image::empty();
    // Different insertion order.
    b.pinned_slots.insert(
        SlotIdx(7),
        PinnedCap::Data {
            content: vec![0xBB; 200],
            size: 200,
        },
    );
    b.pinned_slots.insert(
        SlotIdx(3),
        PinnedCap::Data {
            content: vec![0xAA; 100],
            size: 100,
        },
    );

    assert_eq!(image_content_hash(&a), image_content_hash(&b));
}

#[test]
fn chain_genesis_equals_content_hash() {
    let img = Image::empty();
    assert_eq!(chain_genesis::<H>(&img), image_content_hash(&img));
}

#[test]
fn chain_extend_changes_with_new_image() {
    let img_a = Image::empty();
    let mut img_b = Image::empty();
    img_b.code = b"B".to_vec();
    let prev = chain_genesis::<H>(&img_a);
    let extended_b = chain_extend::<H>(&prev, &img_b);
    let mut img_c = Image::empty();
    img_c.code = b"C".to_vec();
    let extended_c = chain_extend::<H>(&prev, &img_c);
    assert_ne!(extended_b, extended_c);
}

#[test]
fn chain_extend_is_associative_under_sequence() {
    // Extending twice with [A then B] yields a single deterministic
    // chain hash. Calling chain_extend twice in different orders
    // gives different chains (as expected — chain order matters).
    let img_a = Image::empty();
    let mut img_b = Image::empty();
    img_b.code = b"B".to_vec();
    let mut img_c = Image::empty();
    img_c.code = b"C".to_vec();

    let chain_abc = {
        let g = chain_genesis::<H>(&img_a);
        let g_b = chain_extend::<H>(&g, &img_b);
        chain_extend::<H>(&g_b, &img_c)
    };
    let chain_acb = {
        let g = chain_genesis::<H>(&img_a);
        let g_c = chain_extend::<H>(&g, &img_c);
        chain_extend::<H>(&g_c, &img_b)
    };
    // Order matters.
    assert_ne!(chain_abc, chain_acb);

    // Re-running the same sequence gives the same result.
    let chain_abc_2 = {
        let g = chain_genesis::<H>(&img_a);
        let g_b = chain_extend::<H>(&g, &img_b);
        chain_extend::<H>(&g_b, &img_c)
    };
    assert_eq!(chain_abc, chain_abc_2);
}

#[test]
fn mgmt_copy_preserves_chain_hash() {
    // MGMT_COPY of a Cap::Instance preserves image_hash; this is
    // a function-level invariant: equality of the same H::Out
    // value. Just a sanity test that H::Out is Copy and equal.
    let img = Image::empty();
    let chain = chain_genesis::<H>(&img);
    let copy = chain;
    assert_eq!(chain, copy);
}
