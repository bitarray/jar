//! Smoke tests for the cap types and `CacheDirectory`. Black-box
//! tests against the crate's public API — kept out of `src/` to keep
//! the source tree free of `_tests.rs` sidecars.

use javm_cap::{
    CNodeCap, CacheDirectory, Cap, CapHashOrRef, DataCap, EndpointDef, ImageCap, ImageSlotEntry,
    InstanceCap, MAX_SOURCE_DEPTH, MemoryMapping, NUM_REGS, PAGE_SIZE, PageBytes, PageRef,
    PageSlot, RwOverlay, SlotIdx,
};
use std::sync::Arc;

fn make_image_cap() -> ImageCap {
    ImageCap {
        code: vec![0xAB, 0xCD],
        endpoints: Vec::new(),
        mappings: Vec::new(),
        pinned: Vec::new(),
        initial: Vec::new(),
        yield_marker_slot: None,
    }
}

#[test]
fn cap_image_constructor() {
    let _img: Cap = Cap::Image(make_image_cap());
    let cnode: CNodeCap = CNodeCap::new();
    assert!(cnode.slots.is_empty());
}

#[test]
fn cap_image_payload_preserved() {
    let img: Cap = Cap::Image(make_image_cap());
    match img {
        Cap::Image(i) => assert_eq!(i.code.as_slice(), &[0xAB, 0xCD]),
        _ => panic!("expected Image"),
    }
}

#[test]
fn data_inline_constructor() {
    let cap = Cap::data_inline(b"hello");
    match cap {
        Cap::Data(d) => {
            // DataCap is page-padded to the next 4 KiB boundary.
            assert_eq!(d.content_len(), PAGE_SIZE as u64);
            let mut out = vec![0u8; PAGE_SIZE];
            d.copy_into(0, &mut out);
            assert_eq!(&out[..5], b"hello");
            assert!(out[5..].iter().all(|b| *b == 0));
        }
        _ => panic!("expected Cap::Data"),
    }
}

#[test]
fn empty_cnode_constructor() {
    let cap = Cap::empty_cnode();
    match cap {
        Cap::CNode(c) => {
            assert!(c.slots.is_empty());
        }
        _ => panic!("expected Cap::CNode"),
    }
}

#[test]
fn cnode_set_get_take_semantics() {
    let mut cnode: CNodeCap = CNodeCap::new();
    assert_eq!(cnode.get(SlotIdx(0)), None);

    // First insert reports no prior binding.
    let prior = cnode
        .set(SlotIdx(7), Some(CapHashOrRef::Hash([0x77; 32])))
        .unwrap();
    assert_eq!(prior, None);
    cnode
        .set(SlotIdx(2), Some(CapHashOrRef::Hash([0x22; 32])))
        .unwrap();
    cnode
        .set(SlotIdx(11), Some(CapHashOrRef::Hash([0xBB; 32])))
        .unwrap();
    assert_eq!(cnode.slots.len(), 3);
    assert_eq!(cnode.get(SlotIdx(2)), Some(CapHashOrRef::Hash([0x22; 32])));
    assert_eq!(cnode.get(SlotIdx(11)), Some(CapHashOrRef::Hash([0xBB; 32])));

    // Overwrite returns prior target.
    let prior = cnode
        .set(SlotIdx(7), Some(CapHashOrRef::Hash([0xFF; 32])))
        .unwrap();
    assert_eq!(prior, Some(CapHashOrRef::Hash([0x77; 32])));
    assert_eq!(cnode.get(SlotIdx(7)), Some(CapHashOrRef::Hash([0xFF; 32])));

    // Take removes and returns the prior target.
    let taken = cnode.take(SlotIdx(2)).unwrap();
    assert_eq!(taken, Some(CapHashOrRef::Hash([0x22; 32])));
    assert_eq!(cnode.get(SlotIdx(2)), None);
    assert_eq!(cnode.slots.len(), 2);
}

#[test]
fn cnode_lookup_after_set() {
    let mut cnode: CNodeCap = CNodeCap::new();
    cnode
        .set(SlotIdx(7), Some(CapHashOrRef::Hash([0x11; 32])))
        .unwrap();
    // Mint a real CapRef via the cache so the bookkeeping test
    // doesn't depend on the crate-internal `CapRef::new`.
    let cache = CacheDirectory::new();
    let r = cache.put_instance(Cap::CNode(CNodeCap::new()));
    cnode
        .set(SlotIdx(42), Some(CapHashOrRef::Ref(r.clone())))
        .unwrap();

    assert_eq!(cnode.get(SlotIdx(7)), Some(CapHashOrRef::Hash([0x11; 32])));
    assert_eq!(cnode.get(SlotIdx(42)), Some(CapHashOrRef::Ref(r)));
    assert_eq!(cnode.get(SlotIdx(100)), None);
}

#[test]
fn data_inline_round_trip() {
    let data = DataCap::from_bytes_sized(b"hello", PAGE_SIZE as u64);
    assert_eq!(data.content_len(), PAGE_SIZE as u64);
    let mut out = vec![0u8; PAGE_SIZE];
    data.copy_into(0, &mut out);
    assert_eq!(&out[..5], b"hello");
}

#[test]
fn page_ref_shares_then_releases() {
    let bytes: Vec<u8> = vec![1, 2, 3, 4];
    let pb = PageBytes {
        hash: [0; 32],
        bytes,
    };
    let pr: PageRef = PageRef::new(pb);
    assert_eq!(Arc::strong_count(&pr), 1);

    let pages: Vec<PageSlot> = vec![PageSlot::Loaded(pr.clone()), PageSlot::Loaded(pr.clone())];
    assert_eq!(Arc::strong_count(&pr), 3);

    drop(pages);
    assert_eq!(Arc::strong_count(&pr), 1);
    drop(pr);
}

#[test]
fn instance_with_rw_overlay() {
    let overlay_bytes: Vec<u8> = vec![0xDE, 0xAD];

    let overlays = vec![RwOverlay {
        start: 0x1000,
        bytes: overlay_bytes,
    }];

    let inst: InstanceCap = InstanceCap {
        image_hash_chain: [0xAA; 32],
        image_hash: [0xBB; 32],
        root_cnode: CapHashOrRef::Hash([0xCC; 32]),
        rw_overlays: overlays,
        mem_size: 0x10000,
        regs: [0u64; NUM_REGS],
        pc: 0,
        gas_remaining: 1_000_000,
    };
    assert_eq!(inst.image_hash, [0xBB; 32]);
    assert_eq!(inst.rw_overlays[0].start, 0x1000);
    assert_eq!(inst.rw_overlays[0].bytes.as_slice(), &[0xDE, 0xAD]);
}

#[test]
fn endpoint_def_empty_sentinel() {
    let e = EndpointDef::empty();
    assert_eq!(e.entry_pc, 0);
    for r in &e.initial_regs {
        assert_eq!(*r, 0);
    }
}

#[test]
fn memory_mapping_path_slice() {
    let mut path = [SlotIdx(0); MAX_SOURCE_DEPTH];
    path[0] = SlotIdx(3);
    path[1] = SlotIdx(7);
    let m = MemoryMapping {
        start: 0x4000,
        size: 0x2000,
        source_path: path,
        source_path_len: 2,
    };
    assert_eq!(m.path(), &[SlotIdx(3), SlotIdx(7)]);
}

#[test]
fn image_slot_entry_compact() {
    let e = ImageSlotEntry {
        slot: SlotIdx(5),
        cap_hash: [0xEE; 32],
    };
    assert_eq!(e.slot, SlotIdx(5));
    assert_eq!(e.cap_hash, [0xEE; 32]);
}

#[test]
fn capref_strong_count_tracks_holders() {
    let cache = CacheDirectory::new();
    // put_instance returns the caller's CapRef; the directory holds
    // its own clone as the entry's self-ref, so strong_count starts at 2.
    let r = cache.put_instance(Cap::CNode(CNodeCap::new()));
    assert_eq!(r.strong_count(), 2);
    let r2 = r.clone();
    assert_eq!(r.strong_count(), 3);
    assert_eq!(r2.strong_count(), 3);
    drop(r2);
    assert_eq!(r.strong_count(), 2);
}

#[test]
fn cache_round_trips_full_publish_chain() {
    let cache = CacheDirectory::new();

    // 1. Publish a Data blob. Blobs are pure content-addressed
    //    storage — re-publishing the same content is a no-op.
    let data_h = cache
        .put_cap(&Cap::data_inline(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ]))
        .expect("put data");
    assert!(cache.contains_blob(&data_h));

    // 2. Publish a CNode referencing the Data blob by hash.
    let cnode_h = {
        let mut cn: CNodeCap = CNodeCap::new();
        cn.set(SlotIdx(0), Some(CapHashOrRef::Hash(data_h)))
            .unwrap();
        cache.put_cap(&Cap::CNode(cn)).expect("put cnode")
    };
    assert!(cache.contains_blob(&cnode_h));

    // 3. Publish a minimal Image referencing the same Data blob as a
    //    pinned slot.
    let mut img = make_image_cap();
    img.pinned.push(ImageSlotEntry {
        slot: SlotIdx(7),
        cap_hash: data_h,
    });
    let image_h = cache.put_cap(&Cap::Image(img)).expect("put image");
    assert!(cache.contains_blob(&image_h));

    // 4. Publish an Instance binding image + cnode.
    let regs = [0u64; NUM_REGS];
    let inst_h = cache
        .put_cap(&Cap::instance_with_overlays(
            [0u8; 32],
            image_h,
            cnode_h,
            &[],
            4096,
            regs,
            0x1000,
            1_000_000,
        ))
        .expect("put instance");
    assert!(cache.contains_blob(&inst_h));

    // 5. Promote the cnode to a mutable instance via Arc::clone +
    //    settle. With Arc storage the blob entry stays put; the
    //    instances tier shares the same Arc until mutation.
    let new_ref = cache
        .promote_blob_to_instance(&cnode_h)
        .expect("promote cnode");
    let settled_h = cache
        .settle(CapHashOrRef::Ref(new_ref))
        .expect("settle resolves the ref");
    // Settling an unchanged cnode-clone produces the same content
    // hash as the original blob.
    assert_eq!(settled_h, cnode_h);
}

#[test]
fn capref_sweep_reclaims_orphaned_instance() {
    let cache = CacheDirectory::new();

    let r = cache.put_instance(Cap::CNode(CNodeCap::new()));
    assert_eq!(cache.instance_count(), 1);
    // Two holders: caller's CapRef + directory's self-ref.
    assert_eq!(r.strong_count(), 2);

    // Sweep with the external holder still alive — nothing reclaimed.
    cache.sweep_instances();
    assert_eq!(cache.instance_count(), 1);

    // Drop the external holder; sweep reclaims.
    drop(r);
    cache.sweep_instances();
    assert_eq!(cache.instance_count(), 0);
}

#[test]
fn capref_sweep_cascades_through_cnode_ref_chain() {
    let cache = CacheDirectory::new();

    // Leaf instance with no nested Refs.
    let leaf = cache.put_instance(Cap::CNode(CNodeCap::new()));

    // Parent cnode holding the leaf via Ref. Cap::Clone bumps the
    // leaf's strong count when we clone the CNodeCap into the cap.
    let mut parent_cn: CNodeCap = CNodeCap::new();
    parent_cn
        .set(SlotIdx(0), Some(CapHashOrRef::Ref(leaf.clone())))
        .unwrap();
    let parent = cache.put_instance(Cap::CNode(parent_cn));

    // Counts: leaf has 3 strong refs (our local + parent's cnode slot
    // + directory's self-ref); parent has 2 (our local + directory).
    assert_eq!(leaf.strong_count(), 3);
    assert_eq!(parent.strong_count(), 2);

    drop(leaf);
    drop(parent);
    // Leaf still alive in parent's cnode; parent still alive in
    // directory's self-ref. Sweep reclaims parent first (its
    // self-ref count is 1 after we dropped our local). Reclaiming
    // parent drops its Cap which drops its `Ref(leaf)` slot which
    // drops leaf's last external clone — next pass reclaims leaf.
    cache.sweep_instances();
    assert_eq!(cache.instance_count(), 0);
}
