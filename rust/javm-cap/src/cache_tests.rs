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
    Cap::CNode(CNodeCap { size_log: 8, slots })
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
fn publish_image_increfs_pinned_and_initial() {
    let mut cache = Cache::new_in(Global);
    let d_pinned = cache.publish_data_inline(b"pinned").unwrap();
    let d_initial = cache.publish_data_inline(b"initial").unwrap();
    assert_eq!(cache.refcount(CapHashOrRef::Hash(d_pinned)), Some(1));
    assert_eq!(cache.refcount(CapHashOrRef::Hash(d_initial)), Some(1));

    let mut pinned = AVec::new_in(Global);
    pinned.push(crate::image_cap::ImageSlotEntry {
        slot: SlotIdx(3),
        cap_hash: d_pinned,
    });
    let mut initial = AVec::new_in(Global);
    initial.push(crate::image_cap::ImageSlotEntry {
        slot: SlotIdx(7),
        cap_hash: d_initial,
    });
    let img = crate::image_cap::ImageCap {
        code: AVec::new_in(Global),
        bitmask: AVec::new_in(Global),
        jump_table: AVec::new_in(Global),
        endpoints: AVec::new_in(Global),
        mappings: AVec::new_in(Global),
        pinned,
        initial,
        yield_marker_slot: None,
    };
    let img_hash = cache.publish_image_from_cap(img).unwrap();

    assert_eq!(cache.refcount(CapHashOrRef::Hash(img_hash)), Some(1));
    // Pinned + initial blobs both bumped.
    assert_eq!(cache.refcount(CapHashOrRef::Hash(d_pinned)), Some(2));
    assert_eq!(cache.refcount(CapHashOrRef::Hash(d_initial)), Some(2));
}

#[test]
fn publish_image_missing_target_errors() {
    let mut cache = Cache::new_in(Global);
    let mut pinned = AVec::new_in(Global);
    pinned.push(crate::image_cap::ImageSlotEntry {
        slot: SlotIdx(0),
        cap_hash: [0xFE; 32],
    });
    let img = crate::image_cap::ImageCap {
        code: AVec::new_in(Global),
        bitmask: AVec::new_in(Global),
        jump_table: AVec::new_in(Global),
        endpoints: AVec::new_in(Global),
        mappings: AVec::new_in(Global),
        pinned,
        initial: AVec::new_in(Global),
        yield_marker_slot: None,
    };
    let err = cache.publish_image_from_cap(img);
    assert!(matches!(err, Err(super::cache::CacheError::BlobMissing)));
}

#[test]
fn publish_data_inline_hashes_and_stores() {
    let mut cache = Cache::new_in(Global);
    let h = cache.publish_data_inline(b"hello").unwrap();
    // Stored as a blob keyed by its content hash.
    assert_eq!(cache.refcount(CapHashOrRef::Hash(h)), Some(1));
    assert_eq!(cache.blob_count(), 1);
    // Same bytes => same hash, refcount bumps.
    let h2 = cache.publish_data_inline(b"hello").unwrap();
    assert_eq!(h, h2);
    assert_eq!(cache.refcount(CapHashOrRef::Hash(h)), Some(2));
    assert_eq!(cache.blob_count(), 1);
}

#[test]
fn publish_cnode_increfs_targets() {
    let mut cache = Cache::new_in(Global);
    let d = cache.publish_data_inline(b"target").unwrap();
    assert_eq!(cache.refcount(CapHashOrRef::Hash(d)), Some(1));

    let c = cache
        .publish_cnode(4, &[(SlotIdx(0), CapHashOrRef::Hash(d))])
        .unwrap();
    // Target's refcount bumped because cnode references it.
    assert_eq!(cache.refcount(CapHashOrRef::Hash(d)), Some(2));
    assert_eq!(cache.refcount(CapHashOrRef::Hash(c)), Some(1));
}

#[test]
fn publish_cnode_missing_target_errors() {
    let mut cache = Cache::new_in(Global);
    let err = cache.publish_cnode(4, &[(SlotIdx(0), CapHashOrRef::Hash([0xFE; 32]))]);
    assert!(matches!(err, Err(super::cache::CacheError::BlobMissing)));
}

#[test]
fn publish_instance_blob_increfs_image_and_cnode() {
    let mut cache = Cache::new_in(Global);
    // Image is content-addressed; stash a synthetic one for refcount
    // observation (publish_instance_blob only checks blob presence).
    let mut code = AVec::new_in(Global);
    code.push(0x00);
    let img = Cap::Image(crate::image_cap::ImageCap {
        code,
        bitmask: AVec::new_in(Global),
        jump_table: AVec::new_in(Global),
        endpoints: AVec::new_in(Global),
        mappings: AVec::new_in(Global),
        pinned: AVec::new_in(Global),
        initial: AVec::new_in(Global),
        yield_marker_slot: None,
    });
    let img_hash = super::cap_hash::cap_hash(&img);
    cache.put_blob(img_hash, img).unwrap();
    let c = cache.publish_cnode(4, &[]).unwrap();

    assert_eq!(cache.refcount(CapHashOrRef::Hash(img_hash)), Some(1));
    assert_eq!(cache.refcount(CapHashOrRef::Hash(c)), Some(1));

    let inst_hash = cache
        .publish_instance_blob(
            [0xAA; 32],
            img_hash,
            c,
            &[(0x1000, &[0xDE, 0xAD][..])],
            0x10000,
            [0u64; super::cap::NUM_REGS],
            0,
            1_000_000,
        )
        .unwrap();

    assert_eq!(cache.refcount(CapHashOrRef::Hash(inst_hash)), Some(1));
    // Image + cnode both bumped because the instance references them.
    assert_eq!(cache.refcount(CapHashOrRef::Hash(img_hash)), Some(2));
    assert_eq!(cache.refcount(CapHashOrRef::Hash(c)), Some(2));
}

#[test]
fn settle_hash_is_identity() {
    let mut cache = Cache::new_in(Global);
    let h = cache.publish_data_inline(b"x").unwrap();
    let settled = cache.settle(CapHashOrRef::Hash(h)).unwrap();
    assert_eq!(h, settled);
}

#[test]
fn settle_promotes_cnode_to_blob() {
    // Setup: a Data blob D and a CNode blob C referencing D. Then we
    // get_mut C (sole-owner move-promote) and settle the result.
    let mut cache = Cache::new_in(Global);
    let d = cache.publish_data_inline(b"target").unwrap();
    let c = cache
        .publish_cnode(2, &[(SlotIdx(0), CapHashOrRef::Hash(d))])
        .unwrap();
    let c_ref = cache.get_mut(CapHashOrRef::Hash(c)).unwrap();
    assert_eq!(cache.blob_count(), 1); // d only
    assert_eq!(cache.instance_count(), 1); // c (promoted)

    let new_c_hash = cache.settle(CapHashOrRef::Ref(c_ref)).unwrap();
    // Settled cnode is now a blob. The cnode wasn't mutated, so its
    // hash equals the original `c`.
    assert_eq!(new_c_hash, c);
    assert_eq!(cache.blob_count(), 2);
    assert_eq!(cache.instance_count(), 0);
    assert_eq!(cache.refcount(CapHashOrRef::Hash(new_c_hash)), Some(1));
}

#[test]
fn settle_instance_resolves_root_cnode_ref() {
    // Setup: Data D, CNode C → D, Instance I → C. Get_mut C to promote
    // it, rebind I.root_cnode to Ref(c_r), then settle the instance.
    let mut cache = Cache::new_in(Global);
    let d = cache.publish_data_inline(b"d").unwrap();
    let c = cache
        .publish_cnode(2, &[(SlotIdx(0), CapHashOrRef::Hash(d))])
        .unwrap();

    // Build a minimal image to satisfy publish_instance_blob's
    // existence check.
    let img = Cap::Image(crate::image_cap::ImageCap {
        code: AVec::new_in(Global),
        bitmask: AVec::new_in(Global),
        jump_table: AVec::new_in(Global),
        endpoints: AVec::new_in(Global),
        mappings: AVec::new_in(Global),
        pinned: AVec::new_in(Global),
        initial: AVec::new_in(Global),
        yield_marker_slot: None,
    });
    let img_hash = super::cap_hash::cap_hash(&img);
    cache.put_blob(img_hash, img).unwrap();

    let inst_hash = cache
        .publish_instance_blob(
            [0; 32],
            img_hash,
            c,
            &[],
            0,
            [0u64; super::cap::NUM_REGS],
            0,
            0,
        )
        .unwrap();

    // Promote I and C to instances; rebind I.root_cnode to Ref(c_r).
    let i_ref = cache.get_mut(CapHashOrRef::Hash(inst_hash)).unwrap();
    let c_ref = cache.get_mut(CapHashOrRef::Hash(c)).unwrap();
    if let Cap::Instance(inst) = cache.instance_mut(i_ref).unwrap() {
        inst.root_cnode = CapHashOrRef::Ref(c_ref);
    } else {
        panic!("expected Instance");
    }

    let snapshot = cache.settle(CapHashOrRef::Ref(i_ref)).unwrap();
    // Instance stays in instances; the cnode has graduated back to a
    // blob with the same hash as before (no mutation occurred).
    assert!(cache.refcount(CapHashOrRef::Ref(i_ref)).is_some());
    // c_blob has 2 holders: the publisher (test scope still "owns"
    // the originally-published hash) and the instance (its Hash(c)
    // reference after the Ref→Hash rewrite). The earlier get_mut
    // shared-clone path balanced its own bookkeeping.
    assert_eq!(cache.refcount(CapHashOrRef::Hash(c)), Some(2));
    // root_cnode is now Hash again.
    if let Some(Cap::Instance(inst)) = cache.get(CapHashOrRef::Ref(i_ref)) {
        assert_eq!(inst.root_cnode, CapHashOrRef::Hash(c));
    } else {
        panic!("expected Instance still live");
    }
    // Settling again must be idempotent and return the same hash.
    let again = cache.settle(CapHashOrRef::Ref(i_ref)).unwrap();
    assert_eq!(snapshot, again);
}

// ---- publish_image (SCALE Image -> ImageCap bridge) ----

fn make_scale_image_with_pinned_data(
    slots: &[(crate::slot::SlotIdx, &[u8], u64)],
) -> crate::image::Image {
    use crate::image::PinnedCap;
    let mut img = crate::image::Image::empty();
    for (slot, content, size) in slots {
        img.pinned_slots.insert(
            *slot,
            PinnedCap::Data {
                content: content.to_vec(),
                size: *size,
            },
        );
    }
    img
}

#[test]
fn publish_image_inlines_pinned_data_blobs() {
    // Each pinned Data slot becomes a DataCap blob in `blobs`; the
    // image references it by hash. The image's refcount is 1
    // (publisher's hold), and each pinned blob's refcount is 1
    // (image's per-slot hold).
    let mut cache = Cache::new_in(Global);
    let bytes_a = b"slot_a_content";
    let bytes_b = b"slot_b_content";
    let img = make_scale_image_with_pinned_data(&[
        (SlotIdx(1), bytes_a, bytes_a.len() as u64),
        (SlotIdx(2), bytes_b, bytes_b.len() as u64),
    ]);
    let image_hash = cache.publish_image(&img).unwrap();
    assert_eq!(
        cache.refcount(CapHashOrRef::Hash(image_hash)),
        Some(1),
        "image's own refcount"
    );

    // Each pinned data should be a separate blob with refcount=1
    // (held by the image's one slot reference).
    let data_a_hash = cache
        .publish_data_inline_with_size(bytes_a, bytes_a.len() as u64)
        .unwrap();
    // The publish_data above bumped refcount; image already held it.
    // Refcount should now be 2 (image + temp publisher).
    assert_eq!(cache.refcount(CapHashOrRef::Hash(data_a_hash)), Some(2));
    let _ = cache.decref(CapHashOrRef::Hash(data_a_hash));
    assert_eq!(cache.refcount(CapHashOrRef::Hash(data_a_hash)), Some(1));
}

#[test]
fn publish_image_duplicate_data_shared_with_per_slot_refcount() {
    // Two pinned slots referencing identical Data content share a
    // single blob; that blob's refcount equals the number of slot
    // references (2) — not 1 (shared) and not 4 (with publish/decref
    // double-counting).
    let mut cache = Cache::new_in(Global);
    let bytes = b"shared_data";
    let img = make_scale_image_with_pinned_data(&[
        (SlotIdx(1), bytes, bytes.len() as u64),
        (SlotIdx(2), bytes, bytes.len() as u64),
    ]);
    let _image_hash = cache.publish_image(&img).unwrap();

    // Recompute the data hash externally (bumps it once) so we can
    // observe the post-publish refcount, then release.
    let data_hash = cache
        .publish_data_inline_with_size(bytes, bytes.len() as u64)
        .unwrap();
    assert_eq!(
        cache.refcount(CapHashOrRef::Hash(data_hash)),
        Some(3),
        "image holds 2 + temp publisher = 3"
    );
    let _ = cache.decref(CapHashOrRef::Hash(data_hash));
    assert_eq!(
        cache.refcount(CapHashOrRef::Hash(data_hash)),
        Some(2),
        "image holds 2 references to shared blob (one per slot)"
    );
}

#[test]
fn publish_image_inlines_initial_data_blobs() {
    use crate::image::InitialDataCap;
    let mut cache = Cache::new_in(Global);
    let bytes = b"initial_content";
    let size = 4096; // larger than content; trailing zero-padding
    let mut img = crate::image::Image::empty();
    img.initial_slots.insert(
        SlotIdx(7),
        InitialDataCap {
            content: bytes.to_vec(),
            size,
        },
    );
    let image_hash = cache.publish_image(&img).unwrap();
    assert!(cache.refcount(CapHashOrRef::Hash(image_hash)).is_some());

    // The published data uses the explicit `size` (not bytes.len()).
    // Recompute its hash externally to observe.
    let data_hash = cache.publish_data_inline_with_size(bytes, size).unwrap();
    assert_eq!(
        cache.refcount(CapHashOrRef::Hash(data_hash)),
        Some(2),
        "image holds 1 + temp publisher = 2"
    );
}

#[test]
fn publish_image_pinned_image_validates_existing_hash() {
    // PinnedCap::Image { content_hash } requires the referenced
    // sub-Image blob to already exist; publish_image errors with
    // BlobMissing if it doesn't.
    let mut cache = Cache::new_in(Global);
    let mut img = crate::image::Image::empty();
    let missing_hash = [0xDEu8; 32];
    img.pinned_slots.insert(
        SlotIdx(1),
        crate::image::PinnedCap::Image {
            content_hash: missing_hash,
        },
    );
    let err = cache.publish_image(&img);
    assert!(matches!(err, Err(super::cache::CacheError::BlobMissing)));
}

#[test]
fn publish_image_pinned_image_succeeds_when_sub_image_present() {
    // Pre-publish a sub-Image, then reference it from a pinned slot
    // via PinnedCap::Image{content_hash=<that hash>}.
    let mut cache = Cache::new_in(Global);
    let sub_img = crate::image::Image::empty();
    let sub_hash = cache.publish_image(&sub_img).unwrap();

    let mut parent = crate::image::Image::empty();
    parent.pinned_slots.insert(
        SlotIdx(5),
        crate::image::PinnedCap::Image {
            content_hash: sub_hash,
        },
    );
    let parent_hash = cache.publish_image(&parent).unwrap();
    // Parent references sub by hash; sub's refcount should now be 2
    // (one for the initial publish, one for parent's pinned slot ref).
    assert_eq!(cache.refcount(CapHashOrRef::Hash(sub_hash)), Some(2));
    assert!(parent_hash != sub_hash);
}

#[test]
fn publish_image_carries_endpoint_fields() {
    // Verify the conversion preserves the endpoint mapping.
    use crate::image::EndpointDef as ScaleEp;
    use alloc::collections::BTreeMap;
    let mut img = crate::image::Image::empty();
    let mut initial_regs = BTreeMap::new();
    initial_regs.insert(1u8, 0x4000); // stack pointer (φ[1])
    initial_regs.insert(11u8, 0x42); // endpoint_idx
    img.endpoints.insert(
        7,
        ScaleEp {
            entry_pc: 0x1000,
            arg_registers: 2,
            arg_cnode_size: 4,
            initial_regs,
        },
    );

    let mut cache = Cache::new_in(Global);
    let image_hash = cache.publish_image(&img).unwrap();
    let cap = cache.get(CapHashOrRef::Hash(image_hash)).unwrap();
    let img_cap = match cap {
        Cap::Image(ic) => ic,
        _ => panic!("expected ImageCap"),
    };
    let ep = &img_cap.endpoints[7];
    assert_eq!(ep.entry_pc, 0x1000);
    assert_eq!(
        ep.stack_top, 0x4000,
        "stack_top extracted from initial_regs[1]"
    );
    assert_eq!(ep.arg_cnode_size, 4);
    assert_eq!(ep.initial_regs[1], 0x4000);
    assert_eq!(ep.initial_regs[11], 0x42);
    // Untouched endpoints stay empty.
    assert_eq!(img_cap.endpoints[0].entry_pc, 0);
}

#[test]
fn publish_image_rejects_too_deep_source_path() {
    // SlotPath with 9 steps > MAX_SOURCE_DEPTH (8).
    let mut img = crate::image::Image::empty();
    let steps: alloc::vec::Vec<SlotIdx> = (0..9u32).map(SlotIdx).collect();
    img.memory_mappings.push(crate::image::MemoryMapping {
        start: 0,
        size: 0x1000,
        source: crate::slot::SlotPath::new(steps).unwrap(),
    });
    let mut cache = Cache::new_in(Global);
    let err = cache.publish_image(&img);
    assert!(matches!(
        err,
        Err(super::cache::CacheError::ImageConvertFailed(
            crate::image_cap::ImageConvertError::SourcePathTooDeep(9)
        ))
    ));
}

#[test]
fn publish_image_rejects_out_of_range_endpoint() {
    use crate::image::EndpointDef as ScaleEp;
    use alloc::collections::BTreeMap;
    let mut img = crate::image::Image::empty();
    img.endpoints.insert(
        // MAX_ENDPOINTS = 64; index 200 is out of range.
        200,
        ScaleEp {
            entry_pc: 0x1000,
            arg_registers: 0,
            arg_cnode_size: 0,
            initial_regs: BTreeMap::new(),
        },
    );
    let mut cache = Cache::new_in(Global);
    let err = cache.publish_image(&img);
    assert!(matches!(
        err,
        Err(super::cache::CacheError::ImageConvertFailed(
            crate::image_cap::ImageConvertError::EndpointIndexOutOfRange(200)
        ))
    ));
}

#[test]
fn publish_data_paged_round_trips() {
    let mut cache = Cache::new_in(Global);
    let p0 = vec![0xAAu8; 4096];
    let p1 = vec![0xBBu8; 4096];
    let pages = [Some(p0.as_slice()), None, Some(p1.as_slice())];
    let h = cache
        .publish_data_paged(4096, &pages, 4096 * 3)
        .expect("publish");

    // Refcount of the paged blob = 1 (publisher).
    assert_eq!(cache.refcount(CapHashOrRef::Hash(h)), Some(1));
    let cap = cache.get(CapHashOrRef::Hash(h)).expect("present");
    match cap {
        Cap::Data(d) => {
            assert_eq!(d.size, 4096 * 3);
            match &d.content {
                DataContent::Paged { page_size, pages } => {
                    assert_eq!(*page_size, 4096);
                    assert_eq!(pages.len(), 3);
                    assert!(matches!(pages[0], PageSlot::Loaded(_)));
                    assert!(matches!(pages[1], PageSlot::Empty));
                    assert!(matches!(pages[2], PageSlot::Loaded(_)));
                    // Loaded pages start with refcount 1 (the page is
                    // uniquely owned by the DataCap that holds it).
                    if let PageSlot::Loaded(pr) = &pages[0] {
                        assert_eq!(pr.refcount(), 1);
                        assert_eq!(pr.get().bytes.as_slice(), &[0xAAu8; 4096][..]);
                    }
                }
                _ => panic!("expected paged content"),
            }
        }
        _ => panic!("expected Data cap"),
    }
}

#[test]
fn publish_data_paged_rejects_mismatched_page_length() {
    let mut cache = Cache::new_in(Global);
    let bad = vec![0u8; 4095]; // wrong size
    let pages = [Some(bad.as_slice())];
    let err = cache.publish_data_paged(4096, &pages, 4096);
    assert!(matches!(
        err,
        Err(super::cache::CacheError::PageSizeMismatch {
            expected: 4096,
            got: 4095,
        })
    ));
    // No partial state: cache stays empty on the failure path.
    assert_eq!(cache.blob_count(), 0);
}

#[test]
fn publish_data_paged_is_idempotent_on_identical_content() {
    let mut cache = Cache::new_in(Global);
    let p = vec![0x42u8; 4096];
    let pages = [Some(p.as_slice()), None];
    let h1 = cache.publish_data_paged(4096, &pages, 8192).unwrap();
    let h2 = cache.publish_data_paged(4096, &pages, 8192).unwrap();
    assert_eq!(h1, h2);
    // Second publish bumped the blob's refcount.
    assert_eq!(cache.refcount(CapHashOrRef::Hash(h1)), Some(2));
}

#[test]
fn get_mut_image_or_type_errors() {
    let mut cache = Cache::new_in(Global);
    // Image: requires owned content; we set up a minimal one.
    let mut code = AVec::new_in(Global);
    code.push(0xAB);
    let img_cap = Cap::Image(crate::image_cap::ImageCap {
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
    assert!(matches!(err, Err(super::cache::CacheError::NonMutableKind)));
}
