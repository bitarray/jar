/*
Copyright 2025  The Nub Authors.
Licensed under the Apache License, Version 2.0.
*/

//! Host-side state cache.
//!
//! Owns a 1 GiB shared-memory region mapped at the fixed
//! `STATE_CACHE_VA` on both host and guest. A `TalcLock` at offset 0
//! manages allocations. At offset `CACHE_DIRECTORY_OFFSET` (= 0x1000)
//! sits the guest-readable `CacheDirectory` mapping `CapHash` /
//! `CapRef` to entry VAs. The talc heap fills the rest.
//!
//! All cap content (Vec<u8, TalcAlloc>, Box<_, TalcAlloc>, …) lives in
//! the talc-managed region. Because host and guest map the region at
//! the same VA (via `MAP_FIXED_NOREPLACE`), pointers inside that
//! content are interchangeable: the guest can walk caps purely by
//! pointer dereference.
//!
//! Per-process singleton: only one cache region can be mapped per
//! process (`MAP_FIXED_NOREPLACE`). Each `Cache` holds an exclusive
//! lease (`REGION_LEASE`) over the region for its lifetime; parallel
//! tests serialise on it.

use std::ptr::NonNull;
use std::sync::{Mutex, MutexGuard, OnceLock};

use javm_cap::{Cache as TypedCache, CapHashOrRef, CapRef};
use nub_arch_x86_abi::CapHash;
use nub_host_common::cache::{
    BlobSlot, CACHE_DIRECTORY_OFFSET, CacheDirectory, CacheTalcLock, STATE_CACHE_SIZE,
    STATE_CACHE_VA, TALC_HEAP_OFFSET, TALC_HEAP_SIZE, TalcAlloc,
};
use talc::source::Manual;

use crate::{HyperlightError, Result, new_error};

// --- Process-singleton mmap'd cache region ---

static REGION_BASE: OnceLock<usize> = OnceLock::new();
static REGION_LEASE: Mutex<()> = Mutex::new(());

/// Lazily map the cache region at `STATE_CACHE_VA`. Calls into the
/// kernel exactly once across the entire process; subsequent callers
/// just read the cached address.
fn map_region_once(size: usize) -> Result<NonNull<u8>> {
    if let Some(&addr) = REGION_BASE.get() {
        return Ok(unsafe { NonNull::new_unchecked(addr as *mut u8) });
    }
    // SAFETY: mmap is a kernel call; we check the result before use.
    let ptr = unsafe {
        libc::mmap(
            STATE_CACHE_VA as *mut libc::c_void,
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        let err = std::io::Error::last_os_error();
        return Err(new_error!(
            "Cache mmap({:#x}, {} bytes, MAP_FIXED_NOREPLACE) failed: {} \
             (cache region must be reserved at STATE_CACHE_VA so host \
             VAs match guest VAs)",
            STATE_CACHE_VA,
            size,
            err
        ));
    }
    if ptr as u64 != STATE_CACHE_VA {
        // Older glibc fallback path: NOREPLACE was ignored.
        unsafe {
            libc::munmap(ptr, size);
        }
        return Err(new_error!(
            "Cache mmap returned {:#x}, expected {:#x} (MAP_FIXED_NOREPLACE \
             fallback)",
            ptr as u64,
            STATE_CACHE_VA
        ));
    }
    let _ = REGION_BASE.set(ptr as usize);
    // SAFETY: ptr is non-null (we checked MAP_FAILED).
    Ok(unsafe { NonNull::new_unchecked(ptr as *mut u8) })
}

/// RAII wrapper holding the exclusive lease over the (process-global)
/// cache region. Re-zeroes the region on construction so each fresh
/// `Cache::new()` starts from a known state.
struct CacheRegion {
    _lease: MutexGuard<'static, ()>,
    base: NonNull<u8>,
    size: usize,
}

// SAFETY: the base pointer addresses process-global memory under the
// exclusive lease; concurrent access is impossible while the lease is
// held.
unsafe impl Send for CacheRegion {}

impl CacheRegion {
    fn allocate(size: usize) -> Result<Self> {
        assert_eq!(
            size, STATE_CACHE_SIZE,
            "CacheRegion::allocate: size must be STATE_CACHE_SIZE \
             (singleton region; per-call sizing is not supported)",
        );
        let lease = REGION_LEASE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let base = map_region_once(size)?;
        // Wipe so the new Cache starts fresh.
        unsafe {
            core::ptr::write_bytes(base.as_ptr(), 0, size);
        }
        Ok(Self {
            _lease: lease,
            base,
            size,
        })
    }

    fn base_va(&self) -> u64 {
        self.base.as_ptr() as u64
    }
}

// --- The Cache itself ---

/// Errors raised by the host-side state cache.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    /// The directory's blob slot table is full and a new blob can't
    /// be recorded. V1 capacity is `MAX_BLOB_SLOTS = 256`.
    #[error("directory blob slot table full ({0} slots in use)")]
    BlobDirectoryFull(usize),
    /// The directory's instance slot table is full.
    #[error("directory instance slot table full ({0} slots in use)")]
    InstanceDirectoryFull(usize),
    /// A publish succeeded in the typed cache but the entry VA was
    /// unavailable — should never happen in practice.
    #[error("blob not found for hash {0:?}")]
    BlobMissing([u8; 32]),
    /// The inner `javm_cap::Cache` returned an error.
    #[error("typed cache error: {0}")]
    Typed(#[from] javm_cap::CacheError),
}

impl From<CacheError> for HyperlightError {
    fn from(e: CacheError) -> Self {
        new_error!("cache: {}", e)
    }
}

/// The state cache. One per `MultiUseSandbox`.
///
/// **Field order is load-bearing.** Drop order:
/// 1. `typed_cache` drops first — its TBox handles deallocate cap
///    content back into talc.
/// 2. `pinned` is a plain `SmallVec`.
/// 3. `region` drops last (releases the lease; mmap stays mapped for
///    the process lifetime).
///
/// The talc-lock pointer and `CacheDirectory` pointer aren't stored
/// directly — they're derived on demand from `region.base` (offsets 0
/// and `CACHE_DIRECTORY_OFFSET` respectively). This mirrors the guest
/// side: `Cache` is just a base pointer plus per-region state.
///
/// New fields that hold pointers into the region must go BEFORE
/// `region` in declaration order.
pub struct Cache {
    /// Two-tier cap storage. Allocations route through `TalcAlloc`
    /// over `region`.
    typed_cache: TypedCache<TalcAlloc>,
    /// Hashes currently pinned (active call frames). Eviction (future
    /// stage) skips these.
    pinned: smallvec::SmallVec<[CapHash; 8]>,
    /// The mmap'd region. Drops LAST.
    region: CacheRegion,
}

// SAFETY: all inner pointers live inside `region` (Send); host side is
// single-threaded in V0 anyway.
unsafe impl Send for Cache {}

impl Cache {
    /// Allocate the cache region, initialise the TalcLock at offset 0
    /// and the CacheDirectory at `CACHE_DIRECTORY_OFFSET`. The talc
    /// heap covers everything from `TALC_HEAP_OFFSET` to the end of
    /// the region.
    pub fn new() -> Result<Self> {
        let region = CacheRegion::allocate(STATE_CACHE_SIZE)?;
        let base = region.base.as_ptr();

        // Place a TalcLock at offset 0. SAFETY: `talc_ptr` is at
        // offset 0 of a region-byte mmap; alignment is naturally
        // satisfied (mmap returns page-aligned pointers).
        let talc_ptr = base.cast::<CacheTalcLock>();
        unsafe {
            talc_ptr.write(CacheTalcLock::new(Manual));
        }
        let talc = unsafe { NonNull::new_unchecked(talc_ptr) };

        // Place the CacheDirectory at CACHE_DIRECTORY_OFFSET. SAFETY:
        // the offset is page-aligned (0x1000); the region is large
        // enough; zero-init satisfies the sentinel-empty invariant
        // (already zeroed by `CacheRegion::allocate`, but `init_at`
        // makes the intent explicit).
        let dir_ptr = unsafe { base.add(CACHE_DIRECTORY_OFFSET).cast::<CacheDirectory>() };
        unsafe {
            CacheDirectory::init_at(dir_ptr);
        }

        // Claim the talc heap region (everything past the directory).
        // SAFETY: heap_base is within the mmap'd region; `size` bytes
        // from there fit within the region. `Manual` source permits
        // manual `claim`.
        let heap_base = unsafe { base.add(TALC_HEAP_OFFSET) };
        unsafe {
            (*talc.as_ptr())
                .lock()
                .claim(heap_base, TALC_HEAP_SIZE)
                .ok_or_else(|| new_error!("Cache talc.claim failed"))?;
        }

        // SAFETY: `talc` was just initialised and lives as long as
        // `region`, which outlives `typed_cache` (enforced by field
        // order).
        let alloc = unsafe { TalcAlloc::from_raw(talc) };
        let typed_cache = TypedCache::new_in(alloc);

        Ok(Self {
            typed_cache,
            pinned: smallvec::SmallVec::new(),
            region,
        })
    }

    /// Pointer to the talc lock at offset 0 of the cache region.
    fn talc_lock_ptr(&self) -> NonNull<CacheTalcLock> {
        self.region.base.cast()
    }

    /// Pointer to the `CacheDirectory` at `region.base + CACHE_DIRECTORY_OFFSET`.
    fn directory_ptr(&self) -> NonNull<CacheDirectory> {
        // SAFETY: `region.base` is a valid mmap region of `STATE_CACHE_SIZE`
        // bytes; `CACHE_DIRECTORY_OFFSET` is well within bounds.
        unsafe {
            NonNull::new_unchecked(
                self.region
                    .base
                    .as_ptr()
                    .add(CACHE_DIRECTORY_OFFSET)
                    .cast::<CacheDirectory>(),
            )
        }
    }

    /// Host VA of the cache region's base. Equal to [`STATE_CACHE_VA`]
    /// post-`MAP_FIXED_NOREPLACE`.
    pub fn base_va(&self) -> u64 {
        self.region.base_va()
    }

    /// Total cache size in bytes.
    pub fn size(&self) -> usize {
        self.region.size
    }

    /// Cache region's allocator handle. Useful when the caller needs
    /// to build a Cap value in talc memory and hand it off via a
    /// `*_from_cap` publish. Cheap (wraps the talc-lock pointer).
    pub fn alloc(&self) -> TalcAlloc {
        // SAFETY: `talc_lock_ptr()` points at the lock initialised in
        // `Cache::new`, which lives as long as `region`.
        unsafe { TalcAlloc::from_raw(self.talc_lock_ptr()) }
    }

    /// Shared reference to the typed cache. Read-only inspection from
    /// the host (e.g., tests, settle, walks).
    pub fn typed(&self) -> &TypedCache<TalcAlloc> {
        &self.typed_cache
    }

    /// Shared reference to the directory. Useful for tests that want
    /// to observe what the guest sees.
    pub fn directory(&self) -> &CacheDirectory {
        // SAFETY: directory is non-null and lives inside region.
        unsafe { self.directory_ptr().as_ref() }
    }

    /// Whether a cap with this hash is currently published.
    pub fn contains(&self, hash: &CapHash) -> bool {
        self.typed_cache
            .refcount(CapHashOrRef::Hash(*hash))
            .is_some()
    }

    /// Pin a cap so eviction (future) won't evict it during an active
    /// call.
    pub fn pin(&mut self, hash: CapHash) -> Result<()> {
        if !self.contains(&hash) {
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

    // --- New typed publish surface (Stage A/B of the put_cap redesign) ---

    /// Put a caller-built `Cap<Global>`. Computes the cap's content hash,
    /// deep-clones it into the cache's talc-backed allocator on first put,
    /// or bumps the existing entry's refcount on idempotent re-put.
    pub fn put_cap(
        &mut self,
        cap: &javm_cap::Cap<allocator_api2::alloc::Global>,
    ) -> Result<CapHash> {
        let h = self.typed_cache.put_cap(cap).map_err(CacheError::from)?;
        self.touch_blob(h)?;
        Ok(h)
    }

    /// Pre-hashed variant. The caller asserts `hash == cap_hash(cap)`;
    /// `put_cap_with_hash` skips the SSZ merkleize on the idempotent path
    /// (BTreeMap lookup + refcount bump). Debug-asserts the claimed hash
    /// in debug builds; trusts the caller in release.
    pub fn put_cap_with_hash(
        &mut self,
        hash: CapHash,
        cap: &javm_cap::Cap<allocator_api2::alloc::Global>,
    ) -> Result<()> {
        self.typed_cache
            .put_cap_with_hash(hash, cap)
            .map_err(CacheError::from)?;
        self.touch_blob(hash)?;
        Ok(())
    }

    // --- Directory maintenance ---

    /// Ensure the directory has a slot for `hash` pointing at the
    /// blob's CacheEntry VA. Idempotent: if a slot already exists, the
    /// VA is refreshed in case the entry moved (e.g. CoW promote).
    fn touch_blob(&mut self, hash: CapHash) -> Result<()> {
        let va = self
            .typed_cache
            .entry_va(CapHashOrRef::Hash(hash))
            .ok_or(CacheError::BlobMissing(hash))?;
        let dir_ptr = self.directory_ptr().as_ptr();
        // SAFETY: dir_ptr is valid live pointer; find_blob just
        // scans the array.
        if let Some((_, slot_ptr)) = unsafe { CacheDirectory::find_blob(dir_ptr, &hash) } {
            // Slot present — update VA (handles CoW relocations).
            unsafe {
                (*(slot_ptr as *mut BlobSlot)).entry_va = va;
            }
            return Ok(());
        }
        let idx = unsafe { CacheDirectory::first_empty_blob(dir_ptr) }.ok_or(
            CacheError::BlobDirectoryFull(nub_host_common::cache::MAX_BLOB_SLOTS),
        )?;
        let slot = unsafe { CacheDirectory::blob_slot_ptr(dir_ptr, idx) };
        unsafe {
            (*slot).hash = hash;
            (*slot).entry_va = va;
        }
        // Release fence so the guest's acquire on `blob_count` sees
        // the slot's contents.
        unsafe { (*dir_ptr).blob_count_incr() };
        Ok(())
    }

    /// Record an instance ref in the directory at its direct-indexed
    /// slot (`slot_idx = (r - 1) & INSTANCE_MASK`). Used after a
    /// `get_mut` promotes a blob to an instance entry, or after a
    /// fresh instance publish (not currently used in V1 — Instances
    /// live as blobs).
    ///
    /// `r` is expected to have come from `CacheDirectory::alloc_ref`
    /// so the natural slot is guaranteed empty (or already holds the
    /// same ref_id, in which case this acts as an entry_va update).
    #[allow(dead_code)]
    fn touch_instance(&mut self, r: CapRef) -> Result<()> {
        use nub_host_common::cache::INSTANCE_MASK;
        let va = self
            .typed_cache
            .entry_va(CapHashOrRef::Ref(r))
            .ok_or_else(|| new_error!("cache: instance {r} missing"))?;
        let dir_ptr = self.directory_ptr().as_ptr();
        let slot_idx = ((r - 1) & INSTANCE_MASK) as usize;
        let slot = unsafe { CacheDirectory::instance_slot_ptr(dir_ptr, slot_idx) };
        let existing = unsafe { (*slot).ref_id };
        if existing == r {
            // Idempotent update: same ref, refresh entry_va.
            unsafe { (*slot).entry_va = va };
            return Ok(());
        }
        if existing != 0 {
            return Err(CacheError::InstanceDirectoryFull(
                nub_host_common::cache::MAX_INSTANCE_SLOTS,
            )
            .into());
        }
        unsafe {
            (*slot).ref_id = r;
            (*slot).entry_va = va;
        }
        unsafe { (*dir_ptr).instance_count_incr() };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let (idx, slot_ptr) = unsafe { CacheDirectory::find_blob(dir_ptr, &h) }.expect("found");
        assert_eq!(idx, 0);
        unsafe {
            assert_eq!((*slot_ptr).hash, h);
            // entry_va points inside the cache region.
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
}
