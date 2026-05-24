//! Tests for [`CacheDirectory`].

use super::directory::*;
use alloc::boxed::Box;
use core::sync::atomic::Ordering;

fn fresh() -> Box<CacheDirectory> {
    // Box::new_zeroed would be cleaner but is unstable; init_at
    // zeroes a heap-allocated buffer in-place.
    let boxed: Box<CacheDirectory> = unsafe {
        let layout = core::alloc::Layout::new::<CacheDirectory>();
        let raw = alloc::alloc::alloc(layout) as *mut CacheDirectory;
        CacheDirectory::init_at(raw);
        Box::from_raw(raw)
    };
    assert_eq!(boxed.blob_count.load(Ordering::Acquire), 0);
    assert_eq!(boxed.instance_count.load(Ordering::Acquire), 0);
    assert_eq!(boxed.next_ref.load(Ordering::Acquire), 1);
    boxed
}

/// Build a hash whose natural slot is `target` by stuffing
/// `target` into the first 8 bytes (LE).
fn hash_at(target: usize, tag: u8) -> [u8; 32] {
    let mut h = [tag; 32];
    h[0..8].copy_from_slice(&(target as u64).to_le_bytes());
    h
}

#[test]
fn init_zero_sentinels_observed() {
    let dir = fresh();
    let raw = &*dir as *const CacheDirectory;
    for i in 0..MAX_BLOB_SLOTS {
        unsafe {
            assert_eq!((*raw).blob_slots[i].hash, [0u8; 32]);
            assert_eq!((*raw).blob_slots[i].entry_va, 0);
        }
    }
    for i in 0..MAX_INSTANCE_SLOTS {
        unsafe {
            assert_eq!((*raw).instance_slots[i].ref_id, 0);
            assert_eq!((*raw).instance_slots[i].entry_va, 0);
        }
    }
}

#[test]
fn insert_lands_at_natural_slot() {
    let mut dir = fresh();
    let raw = &mut *dir as *mut CacheDirectory;
    let h = hash_at(17, 0xAA);
    let idx =
        unsafe { CacheDirectory::insert_blob(raw, h, 0xDEAD_BEEF_CAFE_BABE) }.expect("insert");
    assert_eq!(idx, 17);
    assert_eq!(dir.blob_count.load(Ordering::Acquire), 1);
    let (found_idx, slot_ptr) = unsafe { CacheDirectory::find_blob(raw, &h) }.expect("found");
    assert_eq!(found_idx, 17);
    unsafe {
        assert_eq!((*slot_ptr).entry_va, 0xDEAD_BEEF_CAFE_BABE);
    }
}

#[test]
fn insert_collision_probes_forward() {
    let mut dir = fresh();
    let raw = &mut *dir as *mut CacheDirectory;
    let h1 = hash_at(5, 0x11);
    let h2 = hash_at(5, 0x22);
    let h3 = hash_at(5, 0x33);
    let i1 = unsafe { CacheDirectory::insert_blob(raw, h1, 0x100) }.expect("i1");
    let i2 = unsafe { CacheDirectory::insert_blob(raw, h2, 0x200) }.expect("i2");
    let i3 = unsafe { CacheDirectory::insert_blob(raw, h3, 0x300) }.expect("i3");
    assert_eq!(i1, 5);
    assert_eq!(i2, 6);
    assert_eq!(i3, 7);
    assert_eq!(dir.blob_count.load(Ordering::Acquire), 3);
    for (h, expected) in [(h1, 0x100u64), (h2, 0x200), (h3, 0x300)] {
        let (_, slot) = unsafe { CacheDirectory::find_blob(raw, &h) }.expect("found");
        assert_eq!(unsafe { (*slot).entry_va }, expected);
    }
}

#[test]
fn insert_idempotent_refreshes_entry_va() {
    let mut dir = fresh();
    let raw = &mut *dir as *mut CacheDirectory;
    let h = hash_at(1, 0xCC);
    let i1 = unsafe { CacheDirectory::insert_blob(raw, h, 0x100) }.expect("i1");
    let i2 = unsafe { CacheDirectory::insert_blob(raw, h, 0x200) }.expect("i2");
    assert_eq!(i1, i2);
    assert_eq!(dir.blob_count.load(Ordering::Acquire), 1, "no double-count");
    let (_, slot) = unsafe { CacheDirectory::find_blob(raw, &h) }.expect("found");
    assert_eq!(unsafe { (*slot).entry_va }, 0x200);
}

#[test]
fn remove_compacts_probe_chain() {
    let mut dir = fresh();
    let raw = &mut *dir as *mut CacheDirectory;
    let h1 = hash_at(10, 0x01);
    let h2 = hash_at(10, 0x02);
    let h3 = hash_at(10, 0x03);
    unsafe {
        CacheDirectory::insert_blob(raw, h1, 0x100).expect("i1");
        CacheDirectory::insert_blob(raw, h2, 0x200).expect("i2");
        CacheDirectory::insert_blob(raw, h3, 0x300).expect("i3");
    }
    // Remove the middle entry; backward-shift should pull h3 from
    // slot 12 into slot 11 so the chain stays unbroken.
    assert!(unsafe { CacheDirectory::remove_blob(raw, &h2) });
    assert_eq!(dir.blob_count.load(Ordering::Acquire), 2);
    // h1 still at slot 10.
    let (idx_h1, _) = unsafe { CacheDirectory::find_blob(raw, &h1) }.expect("h1");
    assert_eq!(idx_h1, 10);
    // h3 should now be at slot 11 (shifted back).
    let (idx_h3, slot_h3) = unsafe { CacheDirectory::find_blob(raw, &h3) }.expect("h3");
    assert_eq!(idx_h3, 11);
    assert_eq!(unsafe { (*slot_h3).entry_va }, 0x300);
    // Slot 12 must now be empty so future inserts can land there.
    let slot12 = unsafe { core::ptr::addr_of!((*raw).blob_slots[12]) };
    assert_eq!(unsafe { (*slot12).entry_va }, 0);
}

#[test]
fn remove_non_existent_returns_false() {
    let mut dir = fresh();
    let raw = &mut *dir as *mut CacheDirectory;
    let h = hash_at(3, 0xFF);
    assert!(!unsafe { CacheDirectory::remove_blob(raw, &h) });
    assert_eq!(dir.blob_count.load(Ordering::Acquire), 0);
}

#[test]
fn missing_blob_lookup_returns_none() {
    let dir = fresh();
    let raw = &*dir as *const CacheDirectory;
    let h = hash_at(42, 0x11);
    assert!(unsafe { CacheDirectory::find_blob(raw, &h) }.is_none());
}

#[test]
fn fill_table_then_overflow() {
    let mut dir = fresh();
    let raw = &mut *dir as *mut CacheDirectory;
    for i in 0..MAX_BLOB_SLOTS {
        let h = hash_at(i, 0xAB);
        assert!(unsafe { CacheDirectory::insert_blob(raw, h, (i as u64) + 1) }.is_some());
    }
    assert_eq!(
        dir.blob_count.load(Ordering::Acquire),
        MAX_BLOB_SLOTS as u16
    );
    // One more insert must fail.
    let h_extra = hash_at(0, 0xFE);
    assert!(unsafe { CacheDirectory::insert_blob(raw, h_extra, 0xDEAD) }.is_none());
}

#[test]
fn alloc_ref_assigns_monotonic_ids_to_natural_slots() {
    let mut dir = fresh();
    let raw = &mut *dir as *mut CacheDirectory;
    // First three allocations should yield (1, 0), (2, 1), (3, 2).
    for expected_ref in 1u64..=3 {
        let (ref_id, slot_idx) = unsafe { CacheDirectory::alloc_ref(raw).expect("alloc") };
        assert_eq!(ref_id, expected_ref);
        assert_eq!(slot_idx, (expected_ref - 1) as usize);
        // Populate the slot so subsequent allocs see it occupied.
        unsafe {
            let slot = CacheDirectory::instance_slot_ptr(raw, slot_idx);
            (*slot).ref_id = ref_id;
            (*slot).entry_va = 0x1000_0000 + ref_id;
        }
        dir.instance_count_incr();
    }
    assert_eq!(dir.instance_count.load(Ordering::Acquire), 3);
}

#[test]
fn find_instance_direct_index() {
    let mut dir = fresh();
    let raw = &mut *dir as *mut CacheDirectory;
    let (ref_id, slot_idx) = unsafe { CacheDirectory::alloc_ref(raw).expect("alloc") };
    unsafe {
        let slot = CacheDirectory::instance_slot_ptr(raw, slot_idx);
        (*slot).ref_id = ref_id;
        (*slot).entry_va = 0xCAFE_BABE;
    }
    let found = unsafe { CacheDirectory::find_instance(raw, ref_id).expect("found") };
    assert_eq!(found.0, slot_idx);
    unsafe {
        assert_eq!((*found.1).entry_va, 0xCAFE_BABE);
    }
    // Sentinel ref 0 never found.
    assert!(unsafe { CacheDirectory::find_instance(raw, 0) }.is_none());
    // A ref the directory never issued is not found.
    assert!(unsafe { CacheDirectory::find_instance(raw, 999_999) }.is_none());
}

#[test]
fn alloc_ref_retries_on_collision() {
    // Pre-fill slot 0 with a synthetic occupied entry. alloc_ref's
    // first attempt asks for ref_id=1 which maps to slot 0 (now
    // occupied), so it should retry with ref_id=2 → slot 1.
    let mut dir = fresh();
    let raw = &mut *dir as *mut CacheDirectory;
    unsafe {
        let slot = CacheDirectory::instance_slot_ptr(raw, 0);
        (*slot).ref_id = 0xDEAD_BEEF;
        (*slot).entry_va = 1;
    }
    let (ref_id, slot_idx) = unsafe { CacheDirectory::alloc_ref(raw).expect("alloc") };
    assert_eq!(ref_id, 2, "first non-colliding ref_id");
    assert_eq!(slot_idx, 1);
    // next_ref has been incremented twice (1 was consumed by the
    // collision, 2 succeeded), so the next allocation yields 3.
    assert_eq!(dir.next_ref.load(Ordering::Acquire), 3);
}

#[test]
fn free_instance_clears_slot() {
    let mut dir = fresh();
    let raw = &mut *dir as *mut CacheDirectory;
    let (ref_id, slot_idx) = unsafe { CacheDirectory::alloc_ref(raw).expect("alloc") };
    unsafe {
        let slot = CacheDirectory::instance_slot_ptr(raw, slot_idx);
        (*slot).ref_id = ref_id;
        (*slot).entry_va = 0x1234;
    }
    dir.instance_count_incr();

    assert!(unsafe { CacheDirectory::find_instance(raw, ref_id) }.is_some());
    unsafe { CacheDirectory::free_instance(raw, slot_idx) };
    dir.instance_count_decr();
    assert!(unsafe { CacheDirectory::find_instance(raw, ref_id) }.is_none());
    // The slot is reusable: a future alloc may land here if its
    // natural slot collides.
}

#[test]
fn freed_slot_reused_by_future_alloc() {
    let mut dir = fresh();
    let raw = &mut *dir as *mut CacheDirectory;
    // Alloc 1 -> slot 0; free it.
    let (r1, s1) = unsafe { CacheDirectory::alloc_ref(raw).expect("alloc") };
    assert_eq!((r1, s1), (1, 0));
    unsafe {
        (*CacheDirectory::instance_slot_ptr(raw, s1)).ref_id = r1;
    }
    unsafe { CacheDirectory::free_instance(raw, s1) };

    // Manually rewind next_ref so the next alloc maps back to slot 0.
    // (In real usage, slot 0 is reused only after next_ref wraps;
    // this test exercises the reuse mechanism directly.)
    dir.next_ref.store(1, Ordering::Release);
    let (r2, s2) = unsafe { CacheDirectory::alloc_ref(raw).expect("alloc") };
    assert_eq!((r2, s2), (1, 0));
}
