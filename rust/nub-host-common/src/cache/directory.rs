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
//!   caps keyed by 32-byte hash. **Open-addressed hash table** with
//!   linear probing. Natural slot for a hash is its first 8 bytes
//!   (LE) masked into `MAX_BLOB_SLOTS - 1`. Sentinel: `entry_va == 0`
//!   marks an empty slot and terminates the probe chain.
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
//! ## Blob directory: open-addressing details
//!
//! The natural slot for a hash is `LE(hash[0..8]) & (MAX_BLOB_SLOTS - 1)`.
//! `CapHash` is already a Blake2b digest, so its low bytes are
//! uniformly distributed — no secondary hash function is needed.
//!
//! Insertion: probe from natural slot, place at the first slot with
//! `entry_va == 0`. Same-hash slot is idempotent (just refresh
//! `entry_va`). Returns `None` only if every slot is occupied.
//!
//! Lookup: probe from natural slot; hit on hash match; miss on the
//! first slot with `entry_va == 0`. O(1) amortised at typical load.
//!
//! Deletion: backward-shift. Zero the target slot, then for each
//! subsequent occupied slot, check whether its natural position is at
//! or before the current hole; if yes, shift it back into the hole
//! and advance the hole. Stops at the first slot whose natural
//! position is strictly after the hole, or at the first empty slot.
//! Keeps every chain dense so lookups never need to probe past empty.
//!
//! ## Instance-slot allocation
//!
//! [`CacheDirectory::alloc_ref`] atomically reads `next_ref` and
//! increments it, retrying on slot collision. Allocation is therefore
//! O(1) amortised; lookup via [`CacheDirectory::find_instance`] is
//! O(1) deterministic (compute the natural slot, validate `ref_id`
//! matches).
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
/// Power-of-2 so the blob probe uses a cheap bitmask.
pub const MAX_BLOB_SLOTS: usize = 256;

const _: () = assert!(MAX_BLOB_SLOTS.is_power_of_two(), "must be power-of-2");

/// Mask for blob probe: `slot_idx = natural & BLOB_MASK`.
const BLOB_MASK: usize = MAX_BLOB_SLOTS - 1;

/// Maximum number of identity-keyed instances the V1 directory tracks.
/// Power-of-2 so direct-indexing uses a cheap bitmask.
pub const MAX_INSTANCE_SLOTS: usize = 32768;

/// Mask for direct-indexing: `slot_idx = (ref_id - 1) & INSTANCE_MASK`.
pub const INSTANCE_MASK: u64 = (MAX_INSTANCE_SLOTS as u64) - 1;

const _: () = assert!(MAX_INSTANCE_SLOTS.is_power_of_two(), "must be power-of-2");

/// One blob entry. `entry_va == 0` is the empty-slot sentinel —
/// zero is never a valid VA. The `hash` field is meaningful only
/// when `entry_va != 0`; an empty slot's `hash` is `[0; 32]` by
/// construction (zero-initialised by `init_at`).
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
    /// Informational populated-blob counter. Maintained by
    /// `insert_blob`/`remove_blob`. The canonical occupancy check is
    /// `entry_va != 0` on a slot; the count is convenient for tests
    /// and for advisory diagnostics.
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

/// Natural probe-start slot for a blob hash: low 8 bytes of the hash
/// (LE) masked into `MAX_BLOB_SLOTS - 1`. Distribution is uniform
/// because `CapHash` is itself a Blake2b digest.
#[inline]
fn blob_natural_slot(hash: &[u8; 32]) -> usize {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash[0..8]);
    (u64::from_le_bytes(bytes) as usize) & BLOB_MASK
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

    /// Open-addressed lookup for a populated blob slot with the given
    /// hash. Probes from the natural slot, stops at the first empty
    /// slot (`entry_va == 0`) or after `MAX_BLOB_SLOTS` attempts.
    /// Returns `(index, slot_ptr)` on hit.
    ///
    /// # Safety
    ///
    /// `this` must point at a live `CacheDirectory`.
    pub unsafe fn find_blob(
        this: *const CacheDirectory,
        hash: &[u8; 32],
    ) -> Option<(usize, *const BlobSlot)> {
        let start = blob_natural_slot(hash);
        for i in 0..MAX_BLOB_SLOTS {
            let idx = (start + i) & BLOB_MASK;
            let slot_ptr = unsafe { core::ptr::addr_of!((*this).blob_slots[idx]) };
            let entry_va = unsafe { (*slot_ptr).entry_va };
            if entry_va == 0 {
                // Chain terminates here — hash is not present.
                return None;
            }
            if unsafe { (*slot_ptr).hash } == *hash {
                return Some((idx, slot_ptr));
            }
        }
        None
    }

    /// Insert a `(hash, entry_va)` pair via open-addressed probe from
    /// the natural slot. Idempotent: if a slot already holds the same
    /// hash, its `entry_va` is refreshed and the existing index is
    /// returned (the `blob_count` is NOT bumped). Returns `None` only
    /// if every slot in the table is occupied.
    ///
    /// `entry_va` must be non-zero (zero is the empty-slot sentinel).
    ///
    /// # Safety
    ///
    /// `this` must point at a live `CacheDirectory`.
    pub unsafe fn insert_blob(
        this: *mut CacheDirectory,
        hash: [u8; 32],
        entry_va: u64,
    ) -> Option<usize> {
        debug_assert!(entry_va != 0, "entry_va == 0 is reserved for empty slots");
        let start = blob_natural_slot(&hash);
        for i in 0..MAX_BLOB_SLOTS {
            let idx = (start + i) & BLOB_MASK;
            let slot_ptr = unsafe { core::ptr::addr_of_mut!((*this).blob_slots[idx]) };
            let existing_va = unsafe { (*slot_ptr).entry_va };
            if existing_va == 0 {
                // Fresh insert.
                unsafe {
                    (*slot_ptr).hash = hash;
                    (*slot_ptr).entry_va = entry_va;
                    (*this).blob_count.fetch_add(1, Ordering::Release);
                }
                return Some(idx);
            }
            if unsafe { (*slot_ptr).hash } == hash {
                // Idempotent update — refresh entry_va, leave count.
                unsafe { (*slot_ptr).entry_va = entry_va };
                return Some(idx);
            }
        }
        None
    }

    /// Remove the slot containing `hash`, doing backward-shift on the
    /// probe chain so every remaining entry is reachable from its
    /// natural slot without crossing an empty slot. Returns `true` if
    /// removed.
    ///
    /// # Safety
    ///
    /// `this` must point at a live `CacheDirectory`.
    pub unsafe fn remove_blob(this: *mut CacheDirectory, hash: &[u8; 32]) -> bool {
        let mut hole = match unsafe { Self::find_blob(this as *const _, hash) } {
            Some((idx, _)) => idx,
            None => return false,
        };
        // Zero the target slot.
        unsafe {
            let slot = core::ptr::addr_of_mut!((*this).blob_slots[hole]);
            (*slot).hash = [0u8; 32];
            (*slot).entry_va = 0;
        }
        // Backward-shift: walk subsequent slots and pull any whose
        // natural position is at or before the current hole into it.
        loop {
            let next = (hole + 1) & BLOB_MASK;
            if next == hole {
                // 1-slot table edge case (would only hit if MAX_BLOB_SLOTS == 1).
                break;
            }
            let next_slot = unsafe { core::ptr::addr_of_mut!((*this).blob_slots[next]) };
            let next_va = unsafe { (*next_slot).entry_va };
            if next_va == 0 {
                // Chain ends.
                break;
            }
            let next_hash = unsafe { (*next_slot).hash };
            let natural = blob_natural_slot(&next_hash);
            // Distances measured forward from `natural` (mod table size).
            let dist_natural_to_next = (next + MAX_BLOB_SLOTS - natural) & BLOB_MASK;
            let dist_natural_to_hole = (hole + MAX_BLOB_SLOTS - natural) & BLOB_MASK;
            if dist_natural_to_hole < dist_natural_to_next {
                // Pulling `next` back into `hole` keeps it ≥ natural.
                unsafe {
                    let hole_slot = core::ptr::addr_of_mut!((*this).blob_slots[hole]);
                    (*hole_slot).hash = next_hash;
                    (*hole_slot).entry_va = next_va;
                    (*next_slot).hash = [0u8; 32];
                    (*next_slot).entry_va = 0;
                }
                hole = next;
            } else {
                break;
            }
        }
        unsafe {
            (*this).blob_count.fetch_sub(1, Ordering::Release);
        }
        true
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
    /// [`Self::alloc_ref`] whose natural slot collides here.
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
}
