//! `CacheDirectory` — guest-readable index of cache-resident caps.
//!
//! Lives in shared memory; the host populates it when publishing caps
//! via `javm_cap::Cache`, and the guest scans it to resolve
//! `CapHashOrRef` keys into a usable virtual address for the
//! corresponding `CacheEntry`.
//!
//! Two flat arrays of fixed size, scanned linearly:
//!
//! - `blob_slots: [BlobSlot; MAX_BLOB_SLOTS]` — content-addressed
//!   caps keyed by 32-byte hash. Sentinel for empty: `hash == [0; 32]`.
//! - `instance_slots: [InstanceSlot; MAX_INSTANCE_SLOTS]` — identity-
//!   keyed mutable caps keyed by `CapRef` (a monotonic `u64`).
//!   Sentinel for empty: `ref_id == 0` (the cache reserves `CapRef(0)`
//!   so this never collides with a real ref).
//!
//! `entry_va` is the host-or-guest VA pointing at the `CacheEntry`
//! whose `cap` field holds the actual cap. Because host and guest map
//! the cache region at different VAs, *each party* writes the VA it
//! observes. The host writes its own VA when populating a slot; on
//! guest read, the directory entry's `entry_va` must be translated via
//! the cache-region offset (`entry_va - host_cache_va + guest_cache_va`).
//! In V1 host and guest share the same VA layout, so this is identity.
//!
//! **Linear scan is fine at this size.** 256 + 256 slots × ~40 bytes
//! each fits in 20 KiB; a hash compare is 4 quadword loads. We expect
//! cache hit rates well above 90% for the JIT-path Image lookups so
//! the absolute scan cost is rarely on the hot path.

use core::sync::atomic::{AtomicU16, Ordering};

/// Maximum number of content-addressed blobs the V1 directory tracks.
pub const MAX_BLOB_SLOTS: usize = 256;

/// Maximum number of identity-keyed instances the V1 directory tracks.
pub const MAX_INSTANCE_SLOTS: usize = 256;

/// One blob entry. `hash == [0; 32]` is the empty-slot sentinel; the
/// chance of a real Blake2b256 digest colliding with all-zero is
/// astronomically small and the cap-hash protocol treats the all-zero
/// hash as an invalid identity anyway (`H(0x00 || ...)` never yields
/// all-zero).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlobSlot {
    pub hash: [u8; 32],
    pub entry_va: u64,
}

impl BlobSlot {
    pub const SIZE: usize = core::mem::size_of::<BlobSlot>();
}

/// One instance entry. `ref_id == 0` is the empty-slot sentinel; the
/// cache's `next_ref` allocator starts at 1, so real refs never
/// collide with the sentinel.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InstanceSlot {
    pub ref_id: u64,
    pub entry_va: u64,
}

impl InstanceSlot {
    pub const SIZE: usize = core::mem::size_of::<InstanceSlot>();
}

/// Top-level directory. `#[repr(C, align(8))]` so the in-memory layout
/// matches between host and guest builds.
#[repr(C, align(8))]
pub struct CacheDirectory {
    /// Informational populated-blob counter. The canonical "is slot
    /// occupied" check is `hash != [0; 32]` — the count is convenient
    /// for tests and for advisory diagnostics.
    pub blob_count: AtomicU16,
    /// Informational populated-instance counter.
    pub instance_count: AtomicU16,
    _pad: [u8; 4],
    pub blob_slots: [BlobSlot; MAX_BLOB_SLOTS],
    pub instance_slots: [InstanceSlot; MAX_INSTANCE_SLOTS],
}

impl CacheDirectory {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Zero-initialise a `CacheDirectory` at `ptr`.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a writable region of at least [`Self::SIZE`]
    /// bytes, aligned to 8.
    pub unsafe fn init_at(ptr: *mut CacheDirectory) {
        unsafe {
            core::ptr::write_bytes(ptr, 0, 1);
        }
    }

    /// Linear scan for a populated blob slot with the given hash.
    /// Returns `(index, slot_ptr)` on hit.
    ///
    /// # Safety
    ///
    /// `this` must point at a live `CacheDirectory`.
    pub unsafe fn find_blob(
        this: *const CacheDirectory,
        hash: &[u8; 32],
    ) -> Option<(usize, *const BlobSlot)> {
        for idx in 0..MAX_BLOB_SLOTS {
            let slot_ptr = unsafe { core::ptr::addr_of!((*this).blob_slots[idx]) };
            let slot_hash = unsafe { &(*slot_ptr).hash };
            if slot_hash == hash {
                return Some((idx, slot_ptr));
            }
        }
        None
    }

    /// Linear scan for a populated instance slot with the given ref id.
    ///
    /// # Safety
    ///
    /// `this` must point at a live `CacheDirectory`.
    pub unsafe fn find_instance(
        this: *const CacheDirectory,
        ref_id: u64,
    ) -> Option<(usize, *const InstanceSlot)> {
        if ref_id == 0 {
            // 0 is the empty sentinel; bail out before scanning.
            return None;
        }
        for idx in 0..MAX_INSTANCE_SLOTS {
            let slot_ptr = unsafe { core::ptr::addr_of!((*this).instance_slots[idx]) };
            let slot_ref = unsafe { (*slot_ptr).ref_id };
            if slot_ref == ref_id {
                return Some((idx, slot_ptr));
            }
        }
        None
    }

    /// First slot with `hash == [0; 32]`. Used by host publish to pick
    /// an insertion site.
    ///
    /// # Safety
    ///
    /// `this` must point at a live `CacheDirectory`.
    pub unsafe fn first_empty_blob(this: *const CacheDirectory) -> Option<usize> {
        let zero = [0u8; 32];
        for idx in 0..MAX_BLOB_SLOTS {
            let slot_ptr = unsafe { core::ptr::addr_of!((*this).blob_slots[idx]) };
            if unsafe { (*slot_ptr).hash == zero } {
                return Some(idx);
            }
        }
        None
    }

    /// First slot with `ref_id == 0`.
    ///
    /// # Safety
    ///
    /// `this` must point at a live `CacheDirectory`.
    pub unsafe fn first_empty_instance(this: *const CacheDirectory) -> Option<usize> {
        for idx in 0..MAX_INSTANCE_SLOTS {
            let slot_ptr = unsafe { core::ptr::addr_of!((*this).instance_slots[idx]) };
            if unsafe { (*slot_ptr).ref_id == 0 } {
                return Some(idx);
            }
        }
        None
    }

    /// Mutable pointer to the blob slot at `idx`. Caller decides what
    /// to do (populate / clear).
    ///
    /// # Safety
    ///
    /// `this` must point at a live `CacheDirectory`; `idx < MAX_BLOB_SLOTS`.
    pub unsafe fn blob_slot_ptr(this: *mut CacheDirectory, idx: usize) -> *mut BlobSlot {
        debug_assert!(idx < MAX_BLOB_SLOTS);
        unsafe { core::ptr::addr_of_mut!((*this).blob_slots[idx]) }
    }

    /// Mutable pointer to the instance slot at `idx`.
    ///
    /// # Safety
    ///
    /// `this` must point at a live `CacheDirectory`; `idx < MAX_INSTANCE_SLOTS`.
    pub unsafe fn instance_slot_ptr(
        this: *mut CacheDirectory,
        idx: usize,
    ) -> *mut InstanceSlot {
        debug_assert!(idx < MAX_INSTANCE_SLOTS);
        unsafe { core::ptr::addr_of_mut!((*this).instance_slots[idx]) }
    }

    /// Atomically increment the populated-blob counter. Called *after*
    /// writing slot contents so the count gates a release-acquire
    /// fence on the slot data.
    #[inline]
    pub fn blob_count_incr(&self) {
        self.blob_count.fetch_add(1, Ordering::Release);
    }

    /// Atomically decrement the populated-blob counter. Called when a
    /// slot transitions back to the empty sentinel.
    #[inline]
    pub fn blob_count_decr(&self) {
        self.blob_count.fetch_sub(1, Ordering::Release);
    }

    /// Atomically increment the populated-instance counter.
    #[inline]
    pub fn instance_count_incr(&self) {
        self.instance_count.fetch_add(1, Ordering::Release);
    }

    /// Atomically decrement the populated-instance counter.
    #[inline]
    pub fn instance_count_decr(&self) {
        self.instance_count.fetch_sub(1, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        boxed
    }

    #[test]
    fn init_zero_sentinels_observed() {
        let dir = fresh();
        let raw = &*dir as *const CacheDirectory;
        // All blob and instance slots are sentinel.
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
    fn first_empty_returns_zero_on_fresh_directory() {
        let dir = fresh();
        let raw = &*dir as *const CacheDirectory;
        assert_eq!(unsafe { CacheDirectory::first_empty_blob(raw) }, Some(0));
        assert_eq!(
            unsafe { CacheDirectory::first_empty_instance(raw) },
            Some(0)
        );
    }

    #[test]
    fn populate_and_find_blob_slot() {
        let mut dir = fresh();
        let raw = &mut *dir as *mut CacheDirectory;
        let h = [0xAAu8; 32];
        unsafe {
            let slot = CacheDirectory::blob_slot_ptr(raw, 7);
            (*slot).hash = h;
            (*slot).entry_va = 0xDEAD_BEEF_CAFE_BABE;
        }
        dir.blob_count_incr();
        assert_eq!(dir.blob_count.load(Ordering::Acquire), 1);

        let found = unsafe { CacheDirectory::find_blob(raw, &h) };
        let (idx, slot_ptr) = found.expect("found");
        assert_eq!(idx, 7);
        unsafe {
            assert_eq!((*slot_ptr).entry_va, 0xDEAD_BEEF_CAFE_BABE);
        }

        // Empty slot starts at the next index since 0..6 are still empty.
        assert_eq!(unsafe { CacheDirectory::first_empty_blob(raw) }, Some(0));
        unsafe {
            // Fill 0..7
            for i in 0..7 {
                let s = CacheDirectory::blob_slot_ptr(raw, i);
                (*s).hash[0] = (i as u8) + 1;
            }
        }
        // Now 8 is the first empty.
        assert_eq!(unsafe { CacheDirectory::first_empty_blob(raw) }, Some(8));
    }

    #[test]
    fn populate_and_find_instance_slot() {
        let mut dir = fresh();
        let raw = &mut *dir as *mut CacheDirectory;
        let ref_id: u64 = 42;
        unsafe {
            let slot = CacheDirectory::instance_slot_ptr(raw, 3);
            (*slot).ref_id = ref_id;
            (*slot).entry_va = 0x1000_2000_3000_4000;
        }
        dir.instance_count_incr();

        let found = unsafe { CacheDirectory::find_instance(raw, ref_id) };
        let (idx, slot_ptr) = found.expect("found");
        assert_eq!(idx, 3);
        unsafe {
            assert_eq!((*slot_ptr).entry_va, 0x1000_2000_3000_4000);
        }

        // Sentinel ref 0 is never found.
        assert!(unsafe { CacheDirectory::find_instance(raw, 0) }.is_none());
    }

    #[test]
    fn missing_lookup_returns_none() {
        let dir = fresh();
        let raw = &*dir as *const CacheDirectory;
        assert!(unsafe { CacheDirectory::find_blob(raw, &[0x11u8; 32]) }.is_none());
        assert!(unsafe { CacheDirectory::find_instance(raw, 999) }.is_none());
    }
}
