use javm_cap::{
    CNodeCap, Cap, CapHashOrRef, DataCap, ImageCap, InstanceCap, Key, NUM_REGS, PAGE_SIZE,
    PageBytes, PageRef, PageSlab, PageSlot,
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// A `Cap::Data` whose dense backing holds `pages` at absolute pages `0..`,
/// sized to 2 MiB (clean — empty overlay).
fn data_cap_with_pages(pages: Vec<PageSlot>) -> Cap {
    Cap::Data(DataCap {
        backing: Arc::new(PageSlab {
            size: javm_cap::GROUP_SIZE as u64,
            pages,
        }),
        overlay: BTreeMap::new(),
    })
}

#[test]
fn cap_variants_have_distinct_hashes() {
    // The Union mix_in_selector ensures two caps whose payloads
    // happen to merkleize to the same root still differ at the
    // outer hash. Use the simplest distinguishable payloads.
    let d: Cap = Cap::Data(DataCap::empty());
    let cn: Cap = Cap::CNode(CNodeCap::new());
    assert_ne!(d.cap_hash(), cn.cap_hash());
}

#[test]
fn data_inline_hash_includes_size() {
    // Two caps with the same prefix but different logical sizes hash
    // differently — `size` is committed in the cap hash.
    let a: Cap = Cap::Data(DataCap::from_bytes_sized(b"abc", PAGE_SIZE as u64));
    let b: Cap = Cap::Data(DataCap::from_bytes_sized(b"abc", (PAGE_SIZE * 2) as u64));
    assert_ne!(a.cap_hash(), b.cap_hash());
}

#[test]
fn cnode_empty_vs_one_populated_differ() {
    let empty: CNodeCap = CNodeCap::new();
    let mut populated: CNodeCap = CNodeCap::new();
    populated
        .set(&Key::from(0u8), Some(CapHashOrRef::Hash([0xEE; 32])))
        .unwrap();
    let a: Cap = Cap::CNode(empty);
    let b: Cap = Cap::CNode(populated);
    assert_ne!(a.cap_hash(), b.cap_hash());
}

#[test]
fn cnode_with_owned_target_panics() {
    // An in-flight `Owned` slot has no wire/hash form — hashing a graph that
    // still holds one panics (callers settle first).
    let mut cn: CNodeCap = CNodeCap::new();
    cn.set(
        &Key::from(0u8),
        Some(CapHashOrRef::Owned(Box::new(Cap::data_inline(b"x")))),
    )
    .unwrap();
    let cap: Cap = Cap::CNode(cn);
    let result = std::panic::catch_unwind(|| cap.cap_hash());
    assert!(result.is_err());
}

#[test]
fn image_hash_depends_on_code() {
    let mut img_a = empty_image();
    let mut img_b = empty_image();
    img_a.code = b"foo".to_vec();
    img_b.code = b"bar".to_vec();
    let a: Cap = Cap::Image(img_a);
    let b: Cap = Cap::Image(img_b);
    assert_ne!(a.cap_hash(), b.cap_hash());
}

fn empty_image() -> ImageCap {
    ImageCap {
        code: Vec::new(),
        endpoints: Vec::new(),
        mappings: Vec::new(),
        pinned: Vec::new(),
        initial: Vec::new(),
        yield_receiver_slot: None,
        gas_slots: Vec::new(),
        quota_slots: Vec::new(),
    }
}

#[test]
fn instance_hash_depends_on_pc() {
    let mut inst_a = empty_instance();
    let mut inst_b = empty_instance();
    inst_a.pc = 0x100;
    inst_b.pc = 0x200;
    let a: Cap = Cap::Instance(inst_a);
    let b: Cap = Cap::Instance(inst_b);
    assert_ne!(a.cap_hash(), b.cap_hash());
}

fn empty_instance() -> InstanceCap {
    InstanceCap {
        image_hash_chain: [0; 32],
        image_hash: [0; 32],
        root_cnode: CapHashOrRef::Hash([0; 32]),
        mem: DataCap::empty(),
        regs: [0; NUM_REGS],
        pc: 0,
        gas_remaining: 0,
    }
}

#[test]
fn data_paged_hash_uses_loaded_page_hashes() {
    let pb = PageBytes {
        hash: [0xA1; 32],
        bytes: vec![1, 2, 3],
    };
    let cap = data_cap_with_pages(vec![PageSlot::Loaded(PageRef::new(pb))]);
    let h = cap.cap_hash();
    // Sanity: identical shape with a different page hash differs.
    let pb2 = PageBytes {
        hash: [0xB2; 32],
        bytes: vec![1, 2, 3],
    };
    let cap2 = data_cap_with_pages(vec![PageSlot::Loaded(PageRef::new(pb2))]);
    assert_ne!(h, cap2.cap_hash());
}

#[test]
fn loaded_page_substitutes_for_missing_with_same_hash() {
    // Substitution invariant: Loaded(p) and Missing(p.hash) must
    // produce the same enclosing-cap hash.
    let page_hash = [0xCD; 32];
    let pb = PageBytes {
        hash: page_hash,
        bytes: vec![0xAA; 16],
    };
    let cap_loaded = data_cap_with_pages(vec![PageSlot::Loaded(PageRef::new(pb))]);
    let cap_missing = data_cap_with_pages(vec![PageSlot::Missing(page_hash)]);
    assert_eq!(cap_loaded.cap_hash(), cap_missing.cap_hash());
}
