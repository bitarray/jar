//! Tests for the host-side [`Cache`].

use crate::cache::Cache;
use nub_host_common::cache::{CacheDirectory, STATE_CACHE_SIZE, STATE_CACHE_VA};

#[test]
fn cache_new_initializes_directory_zero() {
    let cache = Cache::new().expect("alloc");
    assert_eq!(
        cache.base_va(),
        STATE_CACHE_VA,
        "cache region must be mapped at STATE_CACHE_VA (host VA == guest VA invariant)"
    );
    let dir = cache.directory();
    assert_eq!(dir.blob_count.load(std::sync::atomic::Ordering::Acquire), 0);
    assert_eq!(
        dir.instance_count
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
}

#[test]
fn publish_data_records_directory_slot() {
    let mut cache = Cache::new().expect("alloc");
    let h = cache
        .put_cap(&javm_cap::Cap::data_inline(&[0xAA, 0xBB, 0xCC]))
        .expect("put_cap");
    let dir = cache.directory();
    assert_eq!(dir.blob_count.load(std::sync::atomic::Ordering::Acquire), 1);
    let dir_ptr = dir as *const CacheDirectory;
    // Slot index is the hash's natural slot (open-addressed
    // probe), not necessarily 0. Just verify the hash resolves
    // and its entry_va points into the cache region.
    let (_, slot_ptr) = unsafe { CacheDirectory::find_blob(dir_ptr, &h) }.expect("found");
    unsafe {
        assert_eq!((*slot_ptr).hash, h);
        let va = (*slot_ptr).entry_va;
        assert!(va >= STATE_CACHE_VA);
        assert!(va < STATE_CACHE_VA + STATE_CACHE_SIZE as u64);
    }
}

#[test]
fn publish_data_is_idempotent_in_directory() {
    let mut cache = Cache::new().expect("alloc");
    let h1 = cache
        .put_cap(&javm_cap::Cap::data_inline(&[1, 2, 3]))
        .expect("put_cap 1");
    let h2 = cache
        .put_cap(&javm_cap::Cap::data_inline(&[1, 2, 3]))
        .expect("put_cap 2");
    assert_eq!(h1, h2);
    let dir = cache.directory();
    // Only one directory slot consumed (touch_blob updates an
    // existing slot rather than allocating a new one).
    assert_eq!(dir.blob_count.load(std::sync::atomic::Ordering::Acquire), 1);
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
    assert_eq!(dir.blob_count.load(std::sync::atomic::Ordering::Acquire), 4);
    // Each hash resolves.
    let dir_ptr = dir as *const CacheDirectory;
    for &h in &[data_h, cnode_h, image_h, inst_h] {
        assert!(unsafe { CacheDirectory::find_blob(dir_ptr, &h) }.is_some());
    }
}

#[test]
fn pin_unpin_roundtrip() {
    let mut cache = Cache::new().expect("alloc");
    let h = cache
        .put_cap(&javm_cap::Cap::data_inline(&[0; 4]))
        .expect("put_cap");
    cache.pin(h).expect("pin");
    assert_eq!(cache.pinned.len(), 1);
    cache.unpin(h);
    assert!(cache.pinned.is_empty());
}
