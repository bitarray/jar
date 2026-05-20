//! Refcount maintenance + CoW tests for `Cache<A>`.
//!
//! Validates the `Arc::make_mut`-style protocol: blob entries start
//! at refcount=1; binding into additional slots bumps via `incref`;
//! unbinding via `decref`; sole-owner mutations move-promote without
//! a copy, shared mutations shallow-clone. See plan
//! `distributed-puzzling-tower.md` for the full design.

use allocator_api2::alloc::Global;
use allocator_api2::vec::Vec as AVec;
use core::sync::atomic::AtomicU32;

use crate::slot::SlotIdx;

use super::cache::Cache;
use super::cap::{Cap, CapHashOrRef};
use super::cnode::{CNodeCap, CNodeSlotEntry};
use super::data::{DataCap, DataContent};
use super::page::{PageBytes, PageRef, PageSlot};

fn make_data_inline(bytes: &[u8]) -> Cap<Global> {
    let mut v = AVec::new_in(Global);
    v.extend_from_slice(bytes);
    Cap::Data(DataCap {
        size: bytes.len() as u64,
        content: DataContent::Inline(v),
    })
}

fn make_cnode_with(entries: &[(SlotIdx, CapHashOrRef)]) -> Cap<Global> {
    let mut slots = AVec::new_in(Global);
    for &(slot, target) in entries {
        slots.push(CNodeSlotEntry { slot, target });
    }
    slots.sort_by_key(|e| e.slot);
    Cap::CNode(CNodeCap {
        size_log: 8,
        slots,
    })
}

#[test]
fn put_blob_initial_refcount_one() {
    let mut cache = Cache::new_in(Global);
    let h = [0x11u8; 32];
    let rc = cache.put_blob(h, make_data_inline(b"hello")).unwrap();
    assert_eq!(rc, 1);
    assert_eq!(cache.refcount(CapHashOrRef::Hash(h)), Some(1));
}

#[test]
fn put_blob_same_hash_increments_refcount() {
    let mut cache = Cache::new_in(Global);
    let h = [0x22u8; 32];
    let rc1 = cache.put_blob(h, make_data_inline(b"abc")).unwrap();
    let rc2 = cache.put_blob(h, make_data_inline(b"abc")).unwrap();
    assert_eq!(rc1, 1);
    assert_eq!(rc2, 2);
}

#[test]
fn incref_decref_track() {
    let mut cache = Cache::new_in(Global);
    let h = [0x33u8; 32];
    cache.put_blob(h, make_data_inline(b"x")).unwrap();
    cache.incref(CapHashOrRef::Hash(h)).unwrap();
    assert_eq!(cache.refcount(CapHashOrRef::Hash(h)), Some(2));
    let n = cache.decref(CapHashOrRef::Hash(h)).unwrap();
    assert_eq!(n, 1);
    let n = cache.decref(CapHashOrRef::Hash(h)).unwrap();
    assert_eq!(n, 0);
    // Removed from the map.
    assert!(cache.refcount(CapHashOrRef::Hash(h)).is_none());
}

#[test]
fn sole_owner_get_mut_move_promotes() {
    // Setup: one blob B with refcount=1.
    let mut cache = Cache::new_in(Global);
    let h = [0x44u8; 32];
    cache.put_blob(h, make_data_inline(b"sole")).unwrap();
    assert_eq!(cache.blob_count(), 1);
    assert_eq!(cache.instance_count(), 0);

    // get_mut: sole owner path — moves into instances.
    let r = cache.get_mut(CapHashOrRef::Hash(h)).unwrap();

    // blob is gone, instance is present.
    assert_eq!(cache.blob_count(), 0);
    assert_eq!(cache.instance_count(), 1);
    // New instance entry's refcount starts at 1.
    assert_eq!(cache.refcount(CapHashOrRef::Ref(r)), Some(1));

    // Content preserved.
    match cache.get(CapHashOrRef::Ref(r)).unwrap() {
        Cap::Data(d) => {
            assert_eq!(d.size, 4);
            match &d.content {
                DataContent::Inline(bs) => assert_eq!(bs.as_slice(), b"sole"),
                _ => panic!("expected Inline"),
            }
        }
        _ => panic!("expected Data"),
    }
}

#[test]
fn shared_blob_get_mut_clones() {
    // Setup: blob B with two references (refcount=2).
    let mut cache = Cache::new_in(Global);
    let h = [0x55u8; 32];
    cache.put_blob(h, make_data_inline(b"shared")).unwrap();
    cache.incref(CapHashOrRef::Hash(h)).unwrap();
    assert_eq!(cache.refcount(CapHashOrRef::Hash(h)), Some(2));

    // get_mut: shared path — clones into instances.
    let r = cache.get_mut(CapHashOrRef::Hash(h)).unwrap();

    // Original blob stays (refcount decremented to 1; other holder
    // still references it).
    assert_eq!(cache.blob_count(), 1);
    assert_eq!(cache.refcount(CapHashOrRef::Hash(h)), Some(1));
    // New instance entry has its own copy at refcount=1.
    assert_eq!(cache.refcount(CapHashOrRef::Ref(r)), Some(1));

    // Mutating the instance copy doesn't disturb the original.
    if let Cap::Data(d) = cache.instance_mut(r).unwrap()
        && let DataContent::Inline(bs) = &mut d.content
    {
        bs[0] = b'!';
    }
    if let Cap::Data(d) = cache.get(CapHashOrRef::Hash(h)).unwrap()
        && let DataContent::Inline(bs) = &d.content
    {
        assert_eq!(bs.as_slice(), b"shared");
    }
}

#[test]
fn cnode_clone_bumps_target_refcounts() {
    // Setup: a Data blob D and a CNode C with one slot pointing at D.
    let mut cache = Cache::new_in(Global);
    let d_hash = [0xD1u8; 32];
    let c_hash = [0xC1u8; 32];
    cache.put_blob(d_hash, make_data_inline(b"target")).unwrap();
    let cnode = make_cnode_with(&[(SlotIdx(0), CapHashOrRef::Hash(d_hash))]);
    cache.put_blob(c_hash, cnode).unwrap();
    // Bind D explicitly (the cnode references D, so we incref D to
    // reflect that. Cache::put_blob doesn't walk cap content; the
    // caller is responsible for refcount bookkeeping on referenced
    // targets.)
    cache.incref(CapHashOrRef::Hash(d_hash)).unwrap();

    assert_eq!(cache.refcount(CapHashOrRef::Hash(d_hash)), Some(2));

    // Make C shared by incref'ing it.
    cache.incref(CapHashOrRef::Hash(c_hash)).unwrap();
    assert_eq!(cache.refcount(CapHashOrRef::Hash(c_hash)), Some(2));

    // Promote C to an instance via get_mut. Because C is shared
    // (refcount > 1), the cache shallow-clones it and bumps D's
    // refcount to reflect the new referencing instance entry.
    let _r = cache.get_mut(CapHashOrRef::Hash(c_hash)).unwrap();

    // D is now referenced by the original C blob (still in blobs at
    // refcount=1 after make_mut decrement) AND the new instance copy.
    assert_eq!(cache.refcount(CapHashOrRef::Hash(d_hash)), Some(3));
}

#[test]
fn datacap_paged_pages_shared_via_pageref() {
    // Validate per-page sharing within DataCap clones via PageRef
    // (Aarc<PageBytes>). This is the in-DataCap refcount, distinct
    // from the entry-level refcount.
    let mut bytes = AVec::new_in(Global);
    bytes.extend_from_slice(&[1, 2, 3, 4]);
    let pb = PageBytes {
        refcount: AtomicU32::new(1),
        hash: [0; 32],
        bytes,
    };
    let pr: PageRef<Global> = PageRef::new_in(pb, Global).expect("alloc");
    assert_eq!(pr.refcount(), 1);

    let mut pages_a: AVec<PageSlot<Global>, Global> = AVec::new_in(Global);
    pages_a.push(PageSlot::Loaded(pr.clone()));
    let mut pages_b: AVec<PageSlot<Global>, Global> = AVec::new_in(Global);
    pages_b.push(PageSlot::Loaded(pr.clone()));

    // Three holders: pr itself, pages_a's slot, pages_b's slot.
    assert_eq!(pr.refcount(), 3);

    drop(pages_a);
    assert_eq!(pr.refcount(), 2);
    drop(pages_b);
    assert_eq!(pr.refcount(), 1);
    drop(pr);
    // PageBytes freed; nothing left to assert.
}

#[test]
fn get_mut_already_ref_is_idempotent() {
    let mut cache = Cache::new_in(Global);
    let cap = make_data_inline(b"inst");
    let r = cache.put_instance(cap).unwrap();
    assert_eq!(cache.refcount(CapHashOrRef::Ref(r)), Some(1));
    let r2 = cache.get_mut(CapHashOrRef::Ref(r)).unwrap();
    assert_eq!(r, r2);
    // Refcount unchanged (no promote work needed).
    assert_eq!(cache.refcount(CapHashOrRef::Ref(r)), Some(1));
}

#[test]
fn get_mut_image_or_type_errors() {
    let mut cache = Cache::new_in(Global);
    // Image: requires owned content; we set up a minimal one.
    let mut code = AVec::new_in(Global);
    code.push(0xAB);
    let img_cap = Cap::Image(crate::talc::image::ImageCap {
        code,
        bitmask: AVec::new_in(Global),
        jump_table: AVec::new_in(Global),
        endpoints: AVec::new_in(Global),
        mappings: AVec::new_in(Global),
        pinned: AVec::new_in(Global),
        initial: AVec::new_in(Global),
        yield_marker_slot: None,
    });
    let h = [0x77u8; 32];
    cache.put_blob(h, img_cap).unwrap();
    // get_mut on Image is invalid in V1 (Images are immutable).
    let err = cache.get_mut(CapHashOrRef::Hash(h));
    assert!(matches!(
        err,
        Err(super::cache::CacheError::NonMutableKind)
    ));
}
