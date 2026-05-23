//! `CacheDirectory` — guest-readable index of cache-resident caps.
//!
//! Lives in shared memory; the host populates blob slots when
//! publishing caps via `javm_cap::Cache`, and both host + guest may
//! populate instance slots (host for pre-published Instances; guest
//! for sub-VM Instances derived in-kernel). The directory is the
//! only piece of cache state the guest sees directly — it scans here
//! to resolve `CapHashOrRef` keys into a usable virtual address for
//! the corresponding `CacheEntry`.
//!
//! Two arrays of fixed size:
//!
//! - `blob_slots: [BlobSlot; MAX_BLOB_SLOTS]` — content-addressed
//!   caps keyed by 32-byte hash. Scanned linearly. Sentinel: `hash
//!   == [0; 32]`.
//! - `instance_slots: [InstanceSlot; MAX_INSTANCE_SLOTS]` — identity-
//!   keyed mutable caps keyed by `CapRef` (a monotonic `u64`).
//!   Direct-indexed by `slot_idx = (ref_id - 1) & (MAX_INSTANCE_SLOTS - 1)`.
//!   Sentinel: `ref_id == 0` (the cache reserves `CapRef(0)` so this never
//!   collides with a real ref).
//!
//! `entry_va` is the host-or-guest VA pointing at the `CacheEntry`
//! whose `cap` field holds the actual cap. Because host and guest map
//! the cache region at different VAs, *each party* writes the VA it
//! observes. In V1 host and guest share the same VA layout, so the
//! translation is identity.
//!
//! ## Instance-slot allocation
//!
//! [`alloc_ref`] atomically reads `next_ref` and increments it,
//! retrying on slot collision. Allocation is therefore O(1)
//! amortised; lookup via [`find_instance`] is O(1) deterministic
//! (compute the natural slot, validate `ref_id` matches).
//!
//! With `MAX_INSTANCE_SLOTS = 32768` and live-ref counts well below
//! that (deep recursion is bounded by `MAX_DEPTH = 32768` from the
//! call-loop), collision probability per allocation is sparse-table:
//! at 1000 live refs, ≈ 3 % chance of a single retry, average ≈
//! 1.03 attempts.
//!
//! The simpler "retry on collision" allocator replaces what would
//! otherwise be a freelist. A freelist saves the wasted ref_ids
//! consumed by collisions; at our table sparsity that waste is
//! negligible (< 3 % at 1000 live refs), and the freelist's
//! additional shared state (`freelist_head` + per-slot `next_free`)
//! isn't worth its complexity.

use core::sync::atomic::{AtomicU16, AtomicU64, Ordering};

/// Maximum number of content-addressed blobs the V1 directory tracks.
pub const MAX_BLOB_SLOTS: usize = 256;

/// Maximum number of identity-keyed instances the V1 directory tracks.
/// Power-of-2 so direct-indexing uses a cheap bitmask.
pub const MAX_INSTANCE_SLOTS: usize = 32768;

/// Mask for direct-indexing: `slot_idx = (ref_id - 1) & INSTANCE_MASK`.
pub const INSTANCE_MASK: u64 = (MAX_INSTANCE_SLOTS as u64) - 1;

const _: () = assert!(MAX_INSTANCE_SLOTS.is_power_of_two(), "must be power-of-2");

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
/// allocator's `next_ref` starts at 1, so real refs never collide
/// with the sentinel.
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
    /// Monotonic ref-id allocator, shared between host + guest. Starts
    /// at 1 (`CapRef(0)` is reserved as the empty-slot sentinel).
    /// Wraps after `2^64` allocations (effectively never).
    pub next_ref: AtomicU64,
    pub blob_slots: [BlobSlot; MAX_BLOB_SLOTS],
    pub instance_slots: [InstanceSlot; MAX_INSTANCE_SLOTS],
}

impl CacheDirectory {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Zero-initialise a `CacheDirectory` at `ptr`, then set
    /// `next_ref = 1` so the first allocation yields `CapRef(1)`.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a writable region of at least [`Self::SIZE`]
    /// bytes, aligned to 8.
    pub unsafe fn init_at(ptr: *mut CacheDirectory) {
        unsafe {
            core::ptr::write_bytes(ptr, 0, 1);
            // `write_bytes` zeroed the atomic; bump to 1 so the first
            // `fetch_add` yields `CapRef(1)` rather than `CapRef(0)`.
            (*ptr).next_ref.store(1, Ordering::Release);
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

    /// Direct-indexed lookup of an instance slot by `ref_id`.
    /// O(1): compute natural slot, validate `ref_id` matches.
    ///
    /// Returns `None` if the slot is empty OR holds a different
    /// `ref_id` (a stale entry from a prior collision-retry that has
    /// since been overwritten).
    ///
    /// # Safety
    ///
    /// `this` must point at a live `CacheDirectory`.
    pub unsafe fn find_instance(
        this: *const CacheDirectory,
        ref_id: u64,
    ) -> Option<(usize, *const InstanceSlot)> {
        if ref_id == 0 {
            return None;
        }
        let slot_idx = ((ref_id - 1) & INSTANCE_MASK) as usize;
        let slot_ptr = unsafe { core::ptr::addr_of!((*this).instance_slots[slot_idx]) };
        let slot_ref = unsafe { (*slot_ptr).ref_id };
        if slot_ref == ref_id {
            Some((slot_idx, slot_ptr))
        } else {
            None
        }
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

    /// Allocate a fresh `ref_id` + its corresponding slot index.
    /// Returns `None` if the entire instance table is occupied.
    ///
    /// Loops on collision: if the natural slot for the next
    /// `next_ref` value is already occupied, increments `next_ref`
    /// again and retries. Bounded by `MAX_INSTANCE_SLOTS` iterations
    /// — beyond that, the table is genuinely full.
    ///
    /// # Safety
    ///
    /// `this` must point at a live `CacheDirectory`.
    pub unsafe fn alloc_ref(this: *const CacheDirectory) -> Option<(u64, usize)> {
        for _attempts in 0..MAX_INSTANCE_SLOTS {
            let candidate = unsafe { (*this).next_ref.fetch_add(1, Ordering::Relaxed) };
            if candidate == 0 {
                // `next_ref` wrapped; CapRef(0) is reserved. Skip.
                continue;
            }
            let slot_idx = ((candidate - 1) & INSTANCE_MASK) as usize;
            let slot_ref = unsafe { (*this).instance_slots[slot_idx].ref_id };
            if slot_ref == 0 {
                return Some((candidate, slot_idx));
            }
            // Slot occupied — try the next ref_id.
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
    pub unsafe fn instance_slot_ptr(this: *mut CacheDirectory, idx: usize) -> *mut InstanceSlot {
        debug_assert!(idx < MAX_INSTANCE_SLOTS);
        unsafe { core::ptr::addr_of_mut!((*this).instance_slots[idx]) }
    }

    /// Free an instance slot. Sets `ref_id = 0` and `entry_va = 0`,
    /// returning the slot to the pool for reuse by a future
    /// [`alloc_ref`] whose natural slot collides here.
    ///
    /// # Safety
    ///
    /// `this` must point at a live `CacheDirectory`; the slot must
    /// not be concurrently read by another thread (Hyperlight
    /// serialises host + guest, so this is automatic in V1).
    pub unsafe fn free_instance(this: *mut CacheDirectory, slot_idx: usize) {
        debug_assert!(slot_idx < MAX_INSTANCE_SLOTS);
        unsafe {
            let slot = core::ptr::addr_of_mut!((*this).instance_slots[slot_idx]);
            (*slot).ref_id = 0;
            (*slot).entry_va = 0;
        }
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
        assert_eq!(boxed.next_ref.load(Ordering::Acquire), 1);
        boxed
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

    #[test]
    fn missing_blob_lookup_returns_none() {
        let dir = fresh();
        let raw = &*dir as *const CacheDirectory;
        assert!(unsafe { CacheDirectory::find_blob(raw, &[0x11u8; 32]) }.is_none());
    }

    #[test]
    fn first_empty_returns_zero_on_fresh_directory() {
        let dir = fresh();
        let raw = &*dir as *const CacheDirectory;
        assert_eq!(unsafe { CacheDirectory::first_empty_blob(raw) }, Some(0));
    }
}
