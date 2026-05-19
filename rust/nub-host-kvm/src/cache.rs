/*
Copyright 2025  The Nub Authors.
Licensed under the Apache License, Version 2.0.
*/

//! Host-side state cache.
//!
//! Owns a shared-memory region (mmap'd anonymous on Linux) and runs a
//! `TalcLock` instance at offset 0 inside it. Allocations of code,
//! ro_data, rw_data, etc. for published Cap::Instances live inside
//! the region; the host stores their byte offsets in
//! [`nub_host_common::cache::InstanceIndex`] so the guest can resolve
//! them by `instance_hash`.
//!
//! Per-stage scope: this module sets up the host-side mmap + talc +
//! index + publish/pin API. Wiring the region into the guest's
//! address space (KVM slot install, page-table entries at
//! [`STATE_CACHE_VA`]) lands in a follow-up.

use std::collections::HashMap;
use std::ptr::NonNull;

use nub_host_common::cache::{
    CacheTalcLock, INSTANCE_INDEX_OFFSET, IndexSlot, InstanceIndex, MAX_INDEX_SLOTS,
    STATE_CACHE_SIZE, TALC_HEAP_OFFSET, TALC_HEAP_SIZE, TalcSlice,
};
use nub_arch_x86_abi::{CapHash, PublishSpec};
use talc::source::Manual;

use crate::{HyperlightError, Result, new_error};

/// RAII wrapper over the mmap'd cache region. Munmaps on Drop.
struct CacheRegion {
    base: NonNull<u8>,
    size: usize,
}

// Send/Sync: the underlying mmap is process-local, single-threaded
// access in V0; the wrapper isn't shared across threads.
unsafe impl Send for CacheRegion {}

impl CacheRegion {
    /// Allocate `size` bytes of anonymous, shared, read-write memory
    /// at any host VA the kernel picks. Caller is responsible for
    /// initialising the contents (the bytes start zeroed).
    fn allocate(size: usize) -> Result<Self> {
        // SAFETY: mmap is a kernel call; we check the result for
        // MAP_FAILED before dereferencing.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            let err = std::io::Error::last_os_error();
            return Err(new_error!("Cache mmap({} bytes) failed: {}", size, err));
        }
        // SAFETY: mmap returned a valid non-null pointer.
        let base = unsafe { NonNull::new_unchecked(ptr as *mut u8) };
        Ok(Self { base, size })
    }

    fn base_va(&self) -> u64 {
        self.base.as_ptr() as u64
    }
}

impl Drop for CacheRegion {
    fn drop(&mut self) {
        // SAFETY: pointer was returned by mmap; size matches what we
        // passed to mmap.
        unsafe {
            libc::munmap(self.base.as_ptr().cast::<libc::c_void>(), self.size);
        }
    }
}

/// Tracked metadata for one published Cap::Instance. Drop order
/// matters: the [`TalcSlice`] fields free their slabs back to the
/// talc allocator at offset 0 of the cache region, which must
/// outlive them (enforced by field order inside [`Cache`]).
struct Entry {
    #[allow(dead_code)] // surface for future debugging / metrics
    instance_hash: CapHash,
    #[allow(dead_code)]
    code: TalcSlice,
    #[allow(dead_code)]
    bitmask: TalcSlice,
    /// Lives as `[u32]` byte slab — talc-allocated `bitmask_len * 4`
    /// bytes; guest reads as `&[u32]` via the index entries field.
    #[allow(dead_code)]
    jump_table: TalcSlice,
    #[allow(dead_code)]
    ro_data: TalcSlice,
    #[allow(dead_code)]
    rw_data: TalcSlice,
    #[allow(dead_code)]
    arg_data: TalcSlice,
    /// Which `IndexSlot` in `cache.index.slots[..]` this entry
    /// occupies. Used to clear the slot on eviction (deferred to
    /// future stage).
    #[allow(dead_code)]
    index_slot: usize,
}

/// The state cache. One per `MultiUseSandbox`.
///
/// **Field order is load-bearing.** Drop order matters: `entries`
/// drops first (which calls `talc.deallocate(...)` for each Box's
/// slabs). `region` drops last (`munmap`).
pub struct Cache {
    /// Host-side index of published Caps. Maps hash → Entry.
    entries: HashMap<CapHash, Entry>,
    /// Currently pinned hashes (one slot per active call frame).
    /// Eviction passes (future stage) skip these.
    #[allow(dead_code)]
    pinned: smallvec::SmallVec<[CapHash; 8]>,
    /// Pointer to the TalcLock living at offset 0 of `region`.
    /// Used by `TalcBox`/`TalcSlice` for alloc/free.
    talc: NonNull<CacheTalcLock>,
    /// Pointer to the `InstanceIndex` living at
    /// [`INSTANCE_INDEX_OFFSET`]. Host writes; guest scans.
    index: NonNull<InstanceIndex>,
    /// Free `IndexSlot` indices. Allocated linearly until full;
    /// returned to this Vec on eviction (future).
    free_slots: Vec<usize>,
    /// The mmap'd region. Drops LAST.
    region: CacheRegion,
}

// SAFETY: the inner pointers all live inside `region` (which is
// `Send`); the host side is single-threaded in V0 anyway.
unsafe impl Send for Cache {}

impl Cache {
    /// Allocate the cache region, initialise the TalcLock at offset
    /// 0 and the InstanceIndex at [`INSTANCE_INDEX_OFFSET`]. The
    /// talc heap covers everything from [`TALC_HEAP_OFFSET`] to the
    /// end of the region.
    pub fn new() -> Result<Self> {
        let region = CacheRegion::allocate(STATE_CACHE_SIZE)?;
        let base = region.base.as_ptr();

        // Place a TalcLock at offset 0. Zero-init by the kernel
        // (anonymous mmap pages are zeroed); we explicitly write a
        // fresh TalcLock via ptr::write.
        let talc_ptr = base.cast::<CacheTalcLock>();
        // SAFETY: `talc_ptr` is at offset 0 of a `STATE_CACHE_SIZE`-
        // byte mmap; alignment is naturally satisfied (mmap returns
        // page-aligned pointers, and TalcLock's alignment is well
        // below page size).
        unsafe {
            talc_ptr.write(CacheTalcLock::new(Manual));
        }
        let talc = unsafe { NonNull::new_unchecked(talc_ptr) };

        // Initialise the index table at INSTANCE_INDEX_OFFSET.
        let index_ptr = unsafe { base.add(INSTANCE_INDEX_OFFSET).cast::<InstanceIndex>() };
        // SAFETY: index_ptr is inside the mmap'd region, aligned
        // to 8 (offset 0x1000 is page-aligned, well within align-8).
        unsafe {
            InstanceIndex::init_at(index_ptr);
        }
        let index = unsafe { NonNull::new_unchecked(index_ptr) };

        // Claim the talc heap region (everything past the index).
        let heap_base = unsafe { base.add(TALC_HEAP_OFFSET) };
        // SAFETY: `heap_base` is within the mmap'd region; `size`
        // bytes from there fit within the region. `Manual` source
        // permits manual `claim`.
        unsafe {
            let claimed = (*talc.as_ptr())
                .lock()
                .claim(heap_base, TALC_HEAP_SIZE)
                .ok_or_else(|| new_error!("Cache talc.claim failed"))?;
            let _ = claimed;
        }

        let free_slots: Vec<usize> = (0..MAX_INDEX_SLOTS).rev().collect();

        Ok(Self {
            entries: HashMap::new(),
            pinned: smallvec::SmallVec::new(),
            talc,
            index,
            free_slots,
            region,
        })
    }

    /// Host VA of the cache region's base. Used to compute
    /// offsets from talc-returned pointers (`ptr.as_u64() - base_va`).
    pub fn base_va(&self) -> u64 {
        self.region.base_va()
    }

    /// Total cache size in bytes.
    pub fn size(&self) -> usize {
        self.region.size
    }

    /// Publish a `PublishSpec` into the cache. Allocates slabs for
    /// the immutable + initial-state byte regions, populates the
    /// matching `IndexSlot`, and inserts an `Entry` keyed by
    /// `spec.instance_hash`.
    ///
    /// **Idempotent**: returns `Ok(())` immediately if `spec.instance_hash`
    /// is already published (caller-friendly for bench/test loops that
    /// publish-then-invoke many times). To replace existing state,
    /// callers should remove the entry first (future API).
    ///
    /// Returns an error if the index is full or any allocation fails.
    pub fn publish(&mut self, spec: PublishSpec) -> Result<()> {
        if self.entries.contains_key(&spec.instance_hash) {
            return Ok(());
        }

        let slot_idx = self
            .free_slots
            .pop()
            .ok_or_else(|| new_error!("cache: index full ({} slots)", MAX_INDEX_SLOTS))?;

        // Allocate slabs for the immutable + initial-state regions.
        // Trailing zero-size slabs are allocated as 1-byte stubs by
        // `TalcSlice::zeroed`; benign.
        let code = unsafe { TalcSlice::copy_from(&spec.code, self.talc) }
            .ok_or_else(|| self.failed_alloc("code"))?;
        let bitmask = unsafe { TalcSlice::copy_from(&spec.bitmask, self.talc) }
            .ok_or_else(|| self.failed_alloc("bitmask"))?;

        // jump_table is Vec<u32> on the spec; lay it out as
        // little-endian bytes so the guest can read each entry by
        // index without endianness fixup.
        let jt_bytes: Vec<u8> = spec
            .jump_table
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let jump_table = unsafe { TalcSlice::copy_from(&jt_bytes, self.talc) }
            .ok_or_else(|| self.failed_alloc("jump_table"))?;

        let ro_data = unsafe { TalcSlice::copy_from(&spec.ro_data, self.talc) }
            .ok_or_else(|| self.failed_alloc("ro_data"))?;
        let rw_data = unsafe { TalcSlice::copy_from(&spec.rw_data, self.talc) }
            .ok_or_else(|| self.failed_alloc("rw_data"))?;
        let arg_data = unsafe { TalcSlice::copy_from(&spec.arg_data, self.talc) }
            .ok_or_else(|| self.failed_alloc("arg_data"))?;

        // Compute offsets from the slabs' host VAs and the cache base.
        let base = self.region.base_va();
        let offset_of = |va: u64| -> u32 {
            // V0 cache is < 4 GiB; offset fits in u32. Safe cast.
            (va - base) as u32
        };

        let slot = IndexSlot {
            instance_hash: spec.instance_hash,
            code_off: offset_of(code.va()),
            code_len: code.len() as u32,
            bitmask_off: offset_of(bitmask.va()),
            bitmask_len: bitmask.len() as u32,
            jump_table_off: offset_of(jump_table.va()),
            jump_table_entries: spec.jump_table.len() as u32,
            mem_size: spec.mem_size,
            ro_off: offset_of(ro_data.va()),
            ro_len: ro_data.len() as u32,
            ro_start: spec.ro_start,
            rw_off: offset_of(rw_data.va()),
            rw_len: rw_data.len() as u32,
            rw_start: spec.rw_start,
            arg_off: offset_of(arg_data.va()),
            arg_len: arg_data.len() as u32,
            arg_start: spec.arg_start,
            entry_pcs: spec.entry_pcs,
            initial_regs: spec.initial_regs,
        };

        // SAFETY: slot_idx came from `free_slots` which is bounded
        // by MAX_INDEX_SLOTS.
        unsafe {
            let dst = InstanceIndex::slot_ptr(self.index.as_ptr(), slot_idx);
            dst.write(slot);
        }
        // Publish count (Release fence so the guest sees the slot's
        // bytes before observing the count).
        // SAFETY: index ptr is valid; AtomicU8 doesn't require &mut.
        unsafe {
            (*self.index.as_ptr()).count_incr();
        }

        self.entries.insert(
            spec.instance_hash,
            Entry {
                instance_hash: spec.instance_hash,
                code,
                bitmask,
                jump_table,
                ro_data,
                rw_data,
                arg_data,
                index_slot: slot_idx,
            },
        );

        Ok(())
    }

    fn failed_alloc(&self, what: &'static str) -> HyperlightError {
        new_error!("cache: talc allocation failed ({})", what)
    }

    /// Pin an entry so eviction (future) won't evict it during an
    /// active call.
    pub fn pin(&mut self, hash: CapHash) -> Result<()> {
        if !self.entries.contains_key(&hash) {
            return Err(new_error!("cache: cannot pin unpublished hash"));
        }
        self.pinned.push(hash);
        Ok(())
    }

    /// Unpin (counterpart to `pin`).
    pub fn unpin(&mut self, hash: CapHash) {
        if let Some(pos) = self.pinned.iter().rposition(|h| *h == hash) {
            self.pinned.swap_remove(pos);
        }
    }

    /// Whether `hash` is currently published.
    pub fn contains(&self, hash: &CapHash) -> bool {
        self.entries.contains_key(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_new_initializes_index_zero() {
        let cache = Cache::new().expect("alloc");
        unsafe {
            let count = (*cache.index.as_ptr())
                .count
                .load(std::sync::atomic::Ordering::Acquire);
            assert_eq!(count, 0);
            // All slots zero (empty sentinel).
            for i in 0..MAX_INDEX_SLOTS {
                let slot = InstanceIndex::slot_ptr(cache.index.as_ptr(), i);
                let hash = (*slot).instance_hash;
                assert_eq!(hash, [0u8; 32]);
            }
        }
    }

    #[test]
    fn publish_populates_slot_and_increments_count() {
        let mut cache = Cache::new().expect("alloc");
        let mut spec = PublishSpec::empty();
        spec.instance_hash = [0xAA; 32];
        spec.code = vec![1, 2, 3, 4];
        spec.bitmask = vec![0xFF];
        spec.entry_pcs[0] = 0x1234;
        cache.publish(spec).expect("publish");

        assert!(cache.contains(&[0xAA; 32]));
        unsafe {
            let count = (*cache.index.as_ptr())
                .count
                .load(std::sync::atomic::Ordering::Acquire);
            assert_eq!(count, 1);
            // `free_slots` is `(0..N).rev().collect()` → pop returns
            // 0 first, so slot 0 gets populated.
            let slot = InstanceIndex::slot_ptr(cache.index.as_ptr(), 0);
            assert_eq!((*slot).instance_hash, [0xAA; 32]);
            assert_eq!((*slot).code_len, 4);
            assert_eq!((*slot).entry_pcs[0], 0x1234);
        }
    }

    #[test]
    fn pin_unpin_roundtrip() {
        let mut cache = Cache::new().expect("alloc");
        let mut spec = PublishSpec::empty();
        spec.instance_hash = [0xBB; 32];
        cache.publish(spec).expect("publish");

        cache.pin([0xBB; 32]).expect("pin");
        assert_eq!(cache.pinned.len(), 1);
        cache.unpin([0xBB; 32]);
        assert!(cache.pinned.is_empty());
    }

    #[test]
    fn publish_rejects_full_index() {
        let mut cache = Cache::new().expect("alloc");
        for i in 0..MAX_INDEX_SLOTS {
            let mut spec = PublishSpec::empty();
            spec.instance_hash = [i as u8 + 1; 32];
            cache.publish(spec).expect("publish");
        }
        let mut spec = PublishSpec::empty();
        spec.instance_hash = [0xFF; 32];
        let err = cache.publish(spec).unwrap_err();
        assert!(err.to_string().contains("index full"));
    }

    #[test]
    fn publish_is_idempotent_on_same_hash() {
        let mut cache = Cache::new().expect("alloc");
        let mut spec = PublishSpec::empty();
        spec.instance_hash = [0xCC; 32];
        spec.code = vec![1, 2, 3];
        cache.publish(spec.clone()).expect("first publish");
        // Second publish with the same hash is a no-op success.
        cache.publish(spec).expect("idempotent publish");
        // Still exactly 1 entry, 1 free slot consumed.
        assert_eq!(cache.entries.len(), 1);
        assert_eq!(cache.free_slots.len(), MAX_INDEX_SLOTS - 1);
    }
}
