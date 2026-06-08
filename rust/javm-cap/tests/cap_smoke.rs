//! Smoke tests for the cap types and `CacheDirectory`. Black-box
//! tests against the crate's public API — kept out of `src/` to keep
//! the source tree free of `_tests.rs` sidecars.

use javm_cap::{
    CNodeCap, CacheDirectory, Cap, CapHashOrRef, DataCap, ImageCap, ImageSlotEntry, InstanceCap,
    Key, MemoryMapping, NUM_REGS, PAGE_SIZE, PageBytes, PageRef, PageSlot, ResidentCap, SlotPath,
};
use std::sync::Arc;

fn make_image_cap() -> ImageCap {
    ImageCap {
        code: vec![0xAB, 0xCD],
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
    assert_eq!(cnode.get(&Key::from(0u8)), None);

    // First insert reports no prior binding.
    let prior = cnode
        .set(&Key::from(7u8), Some(CapHashOrRef::Hash([0x77; 32])))
        .unwrap();
    assert_eq!(prior, None);
    cnode
        .set(&Key::from(2u8), Some(CapHashOrRef::Hash([0x22; 32])))
        .unwrap();
    cnode
        .set(&Key::from(11u8), Some(CapHashOrRef::Hash([0xBB; 32])))
        .unwrap();
    assert_eq!(cnode.slots.len(), 3);
    assert_eq!(
        cnode.get(&Key::from(2u8)),
        Some(CapHashOrRef::Hash([0x22; 32]))
    );
    assert_eq!(
        cnode.get(&Key::from(11u8)),
        Some(CapHashOrRef::Hash([0xBB; 32]))
    );

    // Overwrite returns prior target.
    let prior = cnode
        .set(&Key::from(7u8), Some(CapHashOrRef::Hash([0xFF; 32])))
        .unwrap();
    assert_eq!(prior, Some(CapHashOrRef::Hash([0x77; 32])));
    assert_eq!(
        cnode.get(&Key::from(7u8)),
        Some(CapHashOrRef::Hash([0xFF; 32]))
    );

    // Take removes and returns the prior target.
    let taken = cnode.take(&Key::from(2u8)).unwrap();
    assert_eq!(taken, Some(CapHashOrRef::Hash([0x22; 32])));
    assert_eq!(cnode.get(&Key::from(2u8)), None);
    assert_eq!(cnode.slots.len(), 2);
}

#[test]
fn cnode_owned_move_is_zero_copy() {
    // `Owned(Box<Cap>)` must move through `set`/`take` with no deep clone of
    // the boxed cap — the zero-copy DataCap hand-off. We assert the heap
    // address of the boxed `Cap` survives the round trip unchanged.
    let mut cnode: CNodeCap = CNodeCap::new();
    let boxed = Box::new(Cap::data_inline(b"payload"));
    let ptr_before = boxed.as_ref() as *const Cap;

    let prior = cnode
        .set(&Key::from(5u8), Some(CapHashOrRef::Owned(boxed)))
        .unwrap();
    assert_eq!(prior, None);

    let taken = cnode.take(&Key::from(5u8)).unwrap();
    match taken {
        Some(CapHashOrRef::Owned(b)) => {
            assert_eq!(
                b.as_ref() as *const Cap,
                ptr_before,
                "Owned slot must move, not clone, through the cnode",
            );
        }
        other => panic!("expected moved Owned, got {other:?}"),
    }
    assert_eq!(cnode.get(&Key::from(5u8)), None);
    assert!(cnode.slots.is_empty());
}

#[test]
fn cache_get_owned_is_none() {
    // `Owned` lives inline on the kernel frame, never in the directory; the
    // polymorphic `get` reports it absent (the holder derefs the Box directly).
    let cache = CacheDirectory::new();
    let owned = CapHashOrRef::Owned(Box::new(Cap::data_inline(b"x")));
    assert!(cache.get(owned).is_none());
}

#[derive(Clone)]
struct TestResidentCap {
    cap: Cap,
    resident_wrapped: bool,
}

impl ResidentCap for TestResidentCap {
    fn from_cap(cap: Cap) -> Self {
        Self {
            cap,
            resident_wrapped: true,
        }
    }

    fn as_cap(&self) -> &Cap {
        &self.cap
    }

    fn into_cap(self) -> Cap {
        self.cap
    }
}

#[test]
fn cache_directory_can_store_resident_payload() {
    let cache: CacheDirectory<_, TestResidentCap> =
        CacheDirectory::with_hasher(hashbrown::DefaultHashBuilder::default());
    let cap = Cap::data_inline(b"resident");
    let h = cache.put_cap(&cap).expect("put resident cap");

    let blob = cache.get_blob(&h).expect("resident blob");
    assert!(blob.resident_wrapped);
    assert!(matches!(blob.as_cap(), Cap::Data(_)));

    let r = cache.put_instance(Cap::empty_cnode());
    let inst = cache.get_instance(&r).expect("resident instance entry");
    assert!(inst.resident_wrapped);
    assert!(matches!(inst.as_cap(), Cap::CNode(_)));
}

#[test]
fn cnode_lookup_after_set() {
    let mut cnode: CNodeCap = CNodeCap::new();
    cnode
        .set(&Key::from(7u8), Some(CapHashOrRef::Hash([0x11; 32])))
        .unwrap();
    cnode
        .set(
            &Key::from(42u8),
            Some(CapHashOrRef::Owned(Box::new(Cap::data_inline(b"x")))),
        )
        .unwrap();

    assert_eq!(
        cnode.get(&Key::from(7u8)),
        Some(CapHashOrRef::Hash([0x11; 32]))
    );
    // `Owned` clones out by value (a fresh Box), so `get` reports presence;
    // pointer identity makes value equality unsuitable here.
    assert!(matches!(
        cnode.get(&Key::from(42u8)),
        Some(CapHashOrRef::Owned(_))
    ));
    assert_eq!(cnode.get(&Key::from(100u8)), None);
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
fn instance_with_mem_image() {
    // The Instance's RW memory is a dense DataCap; write 0xDEAD into the page
    // at offset 0x1000 of a 64 KiB image.
    let mut mem = DataCap::from_bytes_sized(&[], 0x10000);
    let mut page = vec![0u8; PAGE_SIZE];
    page[..2].copy_from_slice(&[0xDE, 0xAD]);
    mem.put_page(0x1000, &page);

    let inst: InstanceCap = InstanceCap {
        image_hash_chain: [0xAA; 32],
        image_hash: [0xBB; 32],
        root_cnode: CapHashOrRef::Hash([0xCC; 32]),
        mem,
        regs: [0u64; NUM_REGS],
        pc: 0,
        gas_remaining: 1_000_000,
    };
    assert_eq!(inst.image_hash, [0xBB; 32]);
    assert_eq!(inst.mem_extent(), 0x10000);
    let mut out = vec![0u8; PAGE_SIZE];
    inst.mem.copy_into(0x1000, &mut out);
    assert_eq!(&out[..2], &[0xDE, 0xAD]);
}

#[test]
fn memory_mapping_path_slice() {
    let m = MemoryMapping {
        start: 0x4000,
        size: 0x2000,
        source: SlotPath::new([Key::from(3u8), Key::from(7u8)]).unwrap(),
    };
    assert_eq!(m.path(), &[Key::from(3u8), Key::from(7u8)]);
}

#[test]
fn image_slot_entry_compact() {
    let e = ImageSlotEntry {
        slot: Key::from(5u8),
        cap_hash: [0xEE; 32],
    };
    assert_eq!(e.slot, Key::from(5u8));
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
        cn.set(&Key::from(0u8), Some(CapHashOrRef::Hash(data_h)))
            .unwrap();
        cache.put_cap(&Cap::CNode(cn)).expect("put cnode")
    };
    assert!(cache.contains_blob(&cnode_h));

    // 3. Publish a minimal Image referencing the same Data blob as a
    //    pinned slot.
    let mut img = make_image_cap();
    img.pinned.push(ImageSlotEntry {
        slot: Key::from(7u8),
        cap_hash: data_h,
    });
    let image_h = cache.put_cap(&Cap::Image(img)).expect("put image");
    assert!(cache.contains_blob(&image_h));

    // 4. Publish an Instance binding image + cnode.
    let regs = [0u64; NUM_REGS];
    let inst_h = cache
        .put_cap(&Cap::instance_with_mem(
            [0u8; 32],
            image_h,
            cnode_h,
            DataCap::from_bytes_sized(&[], 4096),
            regs,
            0x1000,
            1_000_000,
        ))
        .expect("put instance");
    assert!(cache.contains_blob(&inst_h));

    // 5. Settle an inline `Owned` cnode (the deferred-persist path): a
    //    freshly-built CNode referencing the same Data blob by hash settles
    //    to the same content hash as the published cnode blob.
    let mut owned_cn: CNodeCap = CNodeCap::new();
    owned_cn
        .set(&Key::from(0u8), Some(CapHashOrRef::Hash(data_h)))
        .unwrap();
    let settled_h = cache
        .settle(CapHashOrRef::Owned(Box::new(Cap::CNode(owned_cn))))
        .expect("settle owned cnode");
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
