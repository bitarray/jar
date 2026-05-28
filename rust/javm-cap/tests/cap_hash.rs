use javm_cap::{
    CNodeCap, CacheDirectory, Cap, CapHashOrRef, DataCap, DataContent, ImageCap, InstanceCap,
    NUM_REGS, PAGE_SIZE, PageBytes, PageRef, PageSlot, SlotIdx, TypeCap,
};

#[test]
fn type_cap_hash_deterministic() {
    let chain = [0xAA; 32];
    let a: Cap = Cap::Type(TypeCap {
        image_hash_chain: chain,
    });
    let b: Cap = Cap::Type(TypeCap {
        image_hash_chain: chain,
    });
    assert_eq!(a.cap_hash(), b.cap_hash());
    // Different chain → different hash.
    let c: Cap = Cap::Type(TypeCap {
        image_hash_chain: [0xBB; 32],
    });
    assert_ne!(a.cap_hash(), c.cap_hash());
}

#[test]
fn cap_variants_have_distinct_hashes() {
    // The Union mix_in_selector ensures two caps whose payloads
    // happen to merkleize to the same root still differ at the
    // outer hash. Use the simplest distinguishable payloads.
    let t: Cap = Cap::Type(TypeCap {
        image_hash_chain: [0; 32],
    });
    let cn: Cap = Cap::CNode(CNodeCap::new(0).unwrap());
    assert_ne!(t.cap_hash(), cn.cap_hash());
}

#[test]
fn data_inline_hash_includes_size() {
    let bytes_a: Vec<u8> = b"abc".to_vec();
    let bytes_b: Vec<u8> = b"abc".to_vec();
    // Two caps with different inline byte lengths (same prefix)
    // hash differently because content storage IS the identifier.
    // Pad to distinct page-multiple sizes.
    let mut bytes_a_padded: Vec<u8> = vec![0u8; PAGE_SIZE];
    bytes_a_padded[..bytes_a.len()].copy_from_slice(bytes_a.as_slice());
    let mut bytes_b_padded: Vec<u8> = vec![0u8; PAGE_SIZE * 2];
    bytes_b_padded[..bytes_b.len()].copy_from_slice(bytes_b.as_slice());
    let a: Cap = Cap::Data(DataCap {
        content: DataContent::Inline(bytes_a_padded),
    });
    let b: Cap = Cap::Data(DataCap {
        content: DataContent::Inline(bytes_b_padded),
    });
    assert_ne!(a.cap_hash(), b.cap_hash());
}

#[test]
fn cnode_empty_vs_one_populated_differ() {
    let empty: CNodeCap = CNodeCap::new(2).unwrap();
    let mut populated: CNodeCap = CNodeCap::new(2).unwrap();
    populated
        .set(SlotIdx(0), Some(CapHashOrRef::Hash([0xEE; 32])))
        .unwrap();
    let a: Cap = Cap::CNode(empty);
    let b: Cap = Cap::CNode(populated);
    assert_ne!(a.cap_hash(), b.cap_hash());
}

#[test]
fn cnode_with_ref_target_panics() {
    let cache = CacheDirectory::new();
    let r = cache.put_instance(Cap::CNode(CNodeCap::new(0).unwrap()));
    let mut cn: CNodeCap = CNodeCap::new(2).unwrap();
    cn.set(SlotIdx(0), Some(CapHashOrRef::Ref(r))).unwrap();
    let cap: Cap = Cap::CNode(cn);
    let result = std::panic::catch_unwind(|| cap.cap_hash());
    assert!(result.is_err());
}

#[test]
fn image_hash_depends_on_code() {
    let mut img_a = empty_image();
    let mut img_b = empty_image();
    img_a.code.extend_from_slice(b"foo");
    img_b.code.extend_from_slice(b"bar");
    let a: Cap = Cap::Image(img_a);
    let b: Cap = Cap::Image(img_b);
    assert_ne!(a.cap_hash(), b.cap_hash());
}

fn empty_image() -> ImageCap {
    ImageCap {
        code: Vec::new(),
        jump_table: Vec::new(),
        jump_table_offsets: Vec::new(),
        endpoints: Vec::new(),
        mappings: Vec::new(),
        pinned: Vec::new(),
        initial: Vec::new(),
        yield_marker_slot: None,
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
        rw_overlays: Vec::new(),
        mem_size: 0,
        regs: [0; NUM_REGS],
        pc: 0,
        gas_remaining: 0,
    }
}

#[test]
fn data_paged_hash_uses_loaded_page_hashes() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[1, 2, 3]);
    let pb_hash = [0xA1; 32];
    let pb = PageBytes {
        hash: pb_hash,
        bytes,
    };
    let pr: PageRef = PageRef::new(pb);
    let pages: Vec<PageSlot> = vec![PageSlot::Loaded(pr)];
    let cap: Cap = Cap::Data(DataCap {
        content: DataContent::Paged {
            page_size: 4096,
            pages,
        },
    });
    let h = cap.cap_hash();
    // Sanity: identical Cap shape with a different page hash differs.
    let bytes2: Vec<u8> = vec![1, 2, 3];
    let pb2 = PageBytes {
        hash: [0xB2; 32],
        bytes: bytes2,
    };
    let pr2: PageRef = PageRef::new(pb2);
    let pages2: Vec<PageSlot> = vec![PageSlot::Loaded(pr2)];
    let cap2: Cap = Cap::Data(DataCap {
        content: DataContent::Paged {
            page_size: 4096,
            pages: pages2,
        },
    });
    assert_ne!(h, cap2.cap_hash());
}

#[test]
fn loaded_page_substitutes_for_missing_with_same_hash() {
    // Substitution invariant: Loaded(p) and Missing(p.hash) must
    // produce the same enclosing-cap hash.
    let page_hash = [0xCD; 32];
    let bytes: Vec<u8> = vec![0xAA; 16];
    let pb = PageBytes {
        hash: page_hash,
        bytes,
    };
    let pr: PageRef = PageRef::new(pb);

    let pages_loaded: Vec<PageSlot> = vec![PageSlot::Loaded(pr)];
    let cap_loaded: Cap = Cap::Data(DataCap {
        content: DataContent::Paged {
            page_size: 16,
            pages: pages_loaded,
        },
    });

    let pages_missing: Vec<PageSlot> = vec![PageSlot::Missing(page_hash)];
    let cap_missing: Cap = Cap::Data(DataCap {
        content: DataContent::Paged {
            page_size: 16,
            pages: pages_missing,
        },
    });

    assert_eq!(cap_loaded.cap_hash(), cap_missing.cap_hash());
}
