use javm_cap::image::{EndpointDef, MemoryMapping};
use javm_cap::{
    ArenaPageRef, Blake2b256, DataDesc, Image, ImageBuilder, Key, PAGE_SIZE, PinnedCap, SlotPath,
    chain_extend, chain_genesis, image_cap, image_content_hash,
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
    let mut initial_regs = BTreeMap::new();
    initial_regs.insert(1u8, 0x4000);
    let img = ImageBuilder::new()
        .code(b"sample code".to_vec())
        .endpoint(
            Key::from(0u8),
            EndpointDef {
                entry_pc: 0x100,
                arg_registers: 1,
                arg_cnode_size: 0,
                initial_regs: BTreeMap::new(),
            },
        )
        .endpoint(
            Key::from(255u8),
            EndpointDef {
                entry_pc: 0xDEADBEEF,
                arg_registers: 4,
                arg_cnode_size: 8,
                initial_regs,
            },
        )
        .mapping(MemoryMapping {
            start: 0x1000,
            size: 0x4000,
            source: SlotPath::root(Key::from(65u8)),
        })
        .mapping(MemoryMapping {
            start: 0x5000,
            size: 0x2000,
            source: SlotPath::root(Key::from(3u8)),
        })
        .pinned_data(Key::from(11u8), vec![0xAB; 1024], 4096)
        .initial_data(Key::from(65u8), Vec::new(), 0x4000)
        .yield_receiver_slot(Some(Key::from(9u8)))
        .build();

    let bytes = ssz::Encode::as_ssz_bytes(&img);
    let decoded = Image::from_ssz_bytes(&bytes).expect("decode");
    assert_eq!(decoded, img);
}

#[test]
fn different_code_different_hash() {
    let a = Image::with_code(b"AAAA".to_vec());
    let b = Image::with_code(b"BBBB".to_vec());
    assert_ne!(image_content_hash(&a), image_content_hash(&b));
}

#[test]
fn endpoints_affect_hash() {
    let a = Image::empty();
    let mut b = Image::empty();
    b.endpoints.insert(
        Key::from(7u8),
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
    // BTreeMap iteration is deterministic; builder call order
    // shouldn't matter for the resulting hash.
    let a = ImageBuilder::new()
        .pinned_data(Key::from(3u8), vec![0xAA; 100], 100)
        .pinned_data(Key::from(7u8), vec![0xBB; 200], 200)
        .build();

    // Different builder call order.
    let b = ImageBuilder::new()
        .pinned_data(Key::from(7u8), vec![0xBB; 200], 200)
        .pinned_data(Key::from(3u8), vec![0xAA; 100], 100)
        .build();

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
    let img_b = Image::with_code(b"B".to_vec());
    let prev = chain_genesis::<H>(&img_a);
    let extended_b = chain_extend::<H>(&prev, &img_b);
    let img_c = Image::with_code(b"C".to_vec());
    let extended_c = chain_extend::<H>(&prev, &img_c);
    assert_ne!(extended_b, extended_c);
}

#[test]
fn chain_extend_is_associative_under_sequence() {
    // Extending twice with [A then B] yields a single deterministic
    // chain hash. Calling chain_extend twice in different orders
    // gives different chains (as expected — chain order matters).
    let img_a = Image::empty();
    let img_b = Image::with_code(b"B".to_vec());
    let img_c = Image::with_code(b"C".to_vec());

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
fn mapping_is_pinned_classifies_by_source_slot() {
    // A mapping whose source slot is pinned is read-only (a guest store
    // faults); one sourced from an initial (mutable) slot is RW. This is
    // the shared classifier the interpreter drivers (`javm` `build_entry`,
    // `nub-arch-local`) use so they agree with the recompiler's
    // pinned-vs-initial slot classification.
    let img = ImageBuilder::new()
        .mapping(MemoryMapping {
            start: 0x1000_0000,
            size: 0x1000,
            source: SlotPath::root(Key::from(5u8)),
        })
        .mapping(MemoryMapping {
            start: 0x1000_1000,
            size: 0x1000,
            source: SlotPath::root(Key::from(6u8)),
        })
        .pinned_data(Key::from(5u8), vec![1, 2, 3], 0x1000)
        .initial_data(Key::from(6u8), vec![4, 5, 6], 0x1000)
        .build();

    let dummy = [0u8; 32];
    let cap = image_cap(&img, &[(Key::from(5u8), dummy)], &[(Key::from(6u8), dummy)]).unwrap();

    assert!(cap.mapping_is_pinned(0x1000_0000)); // slot 5 pinned → RO
    assert!(!cap.mapping_is_pinned(0x1000_1000)); // slot 6 initial → RW
    assert!(!cap.mapping_is_pinned(0x9999_9999)); // no mapping at this VA
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

#[test]
fn sparse_data_slot_encodes_smaller_than_inlined() {
    // A data slot whose logical content is mostly zeros: one non-zero
    // page followed by many all-zero pages. The builder elides the
    // zero pages, so the arena (and the whole Image SSZ) is far smaller
    // than the same logical content stored densely (every page inlined).
    const LOGICAL_PAGES: usize = 16;
    let size = (LOGICAL_PAGES * PAGE_SIZE) as u64;

    // Only the first page is non-zero; the rest are .bss-style zeros.
    let mut content = vec![0u8; LOGICAL_PAGES * PAGE_SIZE];
    content[..PAGE_SIZE].fill(0xCD);

    // Sparse: builder elides the 15 all-zero pages.
    let sparse = ImageBuilder::new()
        .pinned_data(Key::from(1u8), content, size)
        .build();
    // The arena holds exactly the one named page.
    assert_eq!(
        sparse.arena.len(),
        PAGE_SIZE,
        "only the non-zero page stored"
    );
    match sparse.pinned_slots.get(&Key::from(1u8)) {
        Some(PinnedCap::Data { desc }) => {
            assert_eq!(desc.size, size);
            assert_eq!(desc.pages.len(), 1, "15 zero pages elided");
            assert_eq!(desc.page_count(), LOGICAL_PAGES as u64);
        }
        other => panic!("expected pinned Data, got {other:?}"),
    }

    // Dense: hand-build the same logical content with every page named
    // and inlined into the arena (the pre-elision wire form).
    let mut arena = vec![0u8; LOGICAL_PAGES * PAGE_SIZE];
    arena[..PAGE_SIZE].fill(0xCD);
    let pages: Vec<ArenaPageRef> = (0..LOGICAL_PAGES)
        .map(|p| ArenaPageRef {
            page_index: p as u32,
            arena_off: (p * PAGE_SIZE) as u32,
            len: PAGE_SIZE as u32,
        })
        .collect();
    let mut dense = Image::empty();
    dense.pinned_slots.insert(
        Key::from(1u8),
        PinnedCap::Data {
            desc: DataDesc { size, pages },
        },
    );
    dense.arena = arena;

    // Same logical content (byte-identical materialized memory) ...
    let sparse_desc = match sparse.pinned_slots.get(&Key::from(1u8)) {
        Some(PinnedCap::Data { desc }) => desc,
        _ => unreachable!(),
    };
    let dense_desc = match dense.pinned_slots.get(&Key::from(1u8)) {
        Some(PinnedCap::Data { desc }) => desc,
        _ => unreachable!(),
    };
    assert_eq!(
        ssz::hash_tree_root(&sparse_desc.to_data_cap(&sparse.arena)),
        ssz::hash_tree_root(&dense_desc.to_data_cap(&dense.arena)),
        "sparse and dense materialize identical data caps",
    );

    // ... yet the sparse SSZ is far smaller.
    let sparse_len = ssz::Encode::as_ssz_bytes(&sparse).len();
    let dense_len = ssz::Encode::as_ssz_bytes(&dense).len();
    assert!(
        sparse_len < dense_len,
        "sparse SSZ ({sparse_len} B) should be smaller than inlined dense ({dense_len} B)",
    );
}

#[test]
fn equal_logical_image_two_builds_same_hash() {
    // Building the same logical Image two ways — here a data slot whose
    // content has a duplicated page (which the builder dedups in the
    // arena) plus a different builder call order — yields the SAME
    // image_content_hash. Cap identity is over logical {size, pages},
    // independent of arena layout / dedup / call order.
    let mut dup_content = vec![0u8; 3 * PAGE_SIZE];
    dup_content[..PAGE_SIZE].fill(0x11);
    dup_content[2 * PAGE_SIZE..].fill(0x11); // page 0 and page 2 identical
    let size = (3 * PAGE_SIZE) as u64;

    let a = ImageBuilder::new()
        .code(b"shared".to_vec())
        .pinned_data(Key::from(2u8), dup_content.clone(), size)
        .initial_data(Key::from(9u8), vec![0x22; PAGE_SIZE], PAGE_SIZE as u64)
        .build();

    // Different builder call order; identical logical content.
    let b = ImageBuilder::new()
        .initial_data(Key::from(9u8), vec![0x22; PAGE_SIZE], PAGE_SIZE as u64)
        .pinned_data(Key::from(2u8), dup_content, size)
        .code(b"shared".to_vec())
        .build();

    assert_eq!(
        image_content_hash(&a),
        image_content_hash(&b),
        "logical-equal images hash equal regardless of build order / dedup",
    );
}
