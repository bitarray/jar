//! Tests for the unified [`Cache`].

use nub_host_common::cache::{Cache, STATE_CACHE_VA};

#[test]
fn cache_new_initializes_directory_empty() {
    let cache = Cache::new().expect("alloc");
    assert_eq!(
        cache.base_va(),
        STATE_CACHE_VA,
        "cache region must be mapped at STATE_CACHE_VA (host VA == guest VA invariant)"
    );
    let dir = cache.directory();
    assert_eq!(dir.blob_count(), 0);
    assert_eq!(dir.instance_count(), 0);
}

#[test]
fn publish_data_records_blob() {
    let mut cache = Cache::new().expect("alloc");
    let h = cache
        .put_cap(&javm_cap::Cap::data_inline(&[0xAA, 0xBB, 0xCC]))
        .expect("put_cap");
    let dir = cache.directory();
    assert_eq!(dir.blob_count(), 1);
    assert!(dir.contains_blob(&h));
    // The cap's CacheEntry lives in the talc heap inside the region.
    let va = dir
        .entry_va(javm_cap::CapHashOrRef::Hash(h))
        .expect("entry_va");
    assert!(va >= STATE_CACHE_VA);
    assert!(va < STATE_CACHE_VA + cache.size() as u64);
}

#[test]
fn publish_data_is_idempotent() {
    let mut cache = Cache::new().expect("alloc");
    let h1 = cache
        .put_cap(&javm_cap::Cap::data_inline(&[1, 2, 3]))
        .expect("put_cap 1");
    let h2 = cache
        .put_cap(&javm_cap::Cap::data_inline(&[1, 2, 3]))
        .expect("put_cap 2");
    assert_eq!(h1, h2);
    let dir = cache.directory();
    // Same hash → single blob slot, refcount bumped to 2.
    assert_eq!(dir.blob_count(), 1);
    assert_eq!(
        dir.refcount(javm_cap::CapHashOrRef::Hash(h1)),
        Some(2),
        "refcount should be 2 after idempotent re-put"
    );
}

#[test]
fn publish_chain_data_cnode_image_instance() {
    use javm_cap::slot::SlotIdx;
    use javm_cap::{Cap, CapHashOrRef};

    let mut cache = Cache::new().expect("alloc");
    // Data
    let data_h = cache.put_cap(&Cap::data_inline(&[0x42; 8])).expect("data");
    // CNode referencing it (built as a Cap<Global>)
    let mut cnode = javm_cap::CNodeCap::new(4).expect("cnode new");
    cnode
        .set(SlotIdx(0), Some(CapHashOrRef::Hash(data_h)))
        .expect("cnode set");
    let cnode_h = cache.put_cap(&Cap::CNode(cnode)).expect("cnode");
    // Image with a pinned reference to the data
    let image_cap = Cap::image_with_slots(
        &javm_cap::image::Image::empty(),
        &[(SlotIdx(7), data_h)],
        &[],
    )
    .expect("image_with_slots");
    let image_h = cache.put_cap(&image_cap).expect("image");
    // Instance
    let inst_h = cache
        .put_cap(&Cap::instance_with_overlays(
            [0; 32],
            image_h,
            cnode_h,
            &[],
            4096,
            [0u64; javm_cap::NUM_REGS],
            0x1000,
            1_000_000,
        ))
        .expect("instance");
    let dir = cache.directory();
    // 4 blob entries in the directory (data, cnode, image, instance).
    assert_eq!(dir.blob_count(), 4);
    // Each hash resolves.
    for &h in &[data_h, cnode_h, image_h, inst_h] {
        assert!(dir.contains_blob(&h));
    }
}

#[test]
fn pin_unpin_roundtrip() {
    let mut cache = Cache::new().expect("alloc");
    let h = cache
        .put_cap(&javm_cap::Cap::data_inline(&[0; 4]))
        .expect("put_cap");
    cache.pin(h).expect("pin");
    assert_eq!(cache.pinned_count(), 1);
    cache.unpin(h);
    assert_eq!(cache.pinned_count(), 0);
}
