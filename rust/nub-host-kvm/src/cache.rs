/*
Copyright 2025  The Nub Authors.
Licensed under the Apache License, Version 2.0.
*/

//! Host-side state cache.
//!
//! Owns a 1 GiB shared-memory region mapped at the fixed
//! [`STATE_CACHE_VA`] on both host and guest. A `TalcLock` at offset 0
//! manages allocations. At offset [`CACHE_DIRECTORY_OFFSET`] (= 0x1000)
//! sits the guest-readable [`CacheDirectory`] mapping `CapHash` /
//! `CapRef` to entry VAs. The talc heap fills the rest.
//!
//! All cap content (Vec<u8, TalcAlloc>, Box<_, TalcAlloc>, …) lives in
//! the talc-managed region. Because host and guest map the region at
//! the same VA (via `MAP_FIXED_NOREPLACE`), pointers inside that
//! content are interchangeable: the guest can walk caps purely by
//! pointer dereference.
//!
//! Per-process singleton: only one cache region can be mapped per
//! process (`MAP_FIXED_NOREPLACE`). Each [`Cache`] holds an exclusive
//! lease ([`REGION_LEASE`]) over the region for its lifetime; parallel
//! tests serialise on it.

use std::ptr::NonNull;
use std::sync::{Mutex, MutexGuard, OnceLock};

use javm_cap::slot::SlotIdx;
use javm_cap::{Cache as TypedCache, CapHashOrRef, CapRef, ImageCap as TImageCap, image_cap_in};
use nub_arch_x86_abi::CapHash;
use nub_host_common::cache::{
    BlobSlot, CACHE_DIRECTORY_OFFSET, CacheDirectory, CacheTalcLock, InstanceSlot,
    STATE_CACHE_SIZE, STATE_CACHE_VA, TALC_HEAP_OFFSET, TALC_HEAP_SIZE, TalcAlloc,
};
use talc::source::Manual;

use crate::{HyperlightError, Result, new_error};

// --- Process-singleton mmap'd cache region ---

static REGION_BASE: OnceLock<usize> = OnceLock::new();
static REGION_LEASE: Mutex<()> = Mutex::new(());

/// Lazily map the cache region at [`STATE_CACHE_VA`]. Calls into the
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
/// 2. `pinned`/`talc`/`directory` are plain handles into `region`.
/// 3. `region` drops last (releases the lease; mmap stays mapped for
///    the process lifetime).
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
    /// Pointer to the TalcLock living at offset 0 of `region`. Held
    /// for talc-pointer construction via `TalcAlloc::from_raw`.
    #[allow(dead_code)]
    talc: NonNull<CacheTalcLock>,
    /// Pointer to the `CacheDirectory` at `region.base + CACHE_DIRECTORY_OFFSET`.
    directory: NonNull<CacheDirectory>,
    /// Allocator handle used internally for typed publishes that need
    /// allocator-aware container construction (e.g. `image_cap_in`).
    alloc: TalcAlloc,
    /// The mmap'd region. Drops LAST.
    region: CacheRegion,
}

// SAFETY: all inner pointers live inside `region` (Send); host side is
// single-threaded in V0 anyway.
unsafe impl Send for Cache {}

impl Cache {
    /// Allocate the cache region, initialise the TalcLock at offset 0
    /// and the CacheDirectory at [`CACHE_DIRECTORY_OFFSET`]. The talc
    /// heap covers everything from [`TALC_HEAP_OFFSET`] to the end of
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
        let directory = unsafe { NonNull::new_unchecked(dir_ptr) };

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
            talc,
            directory,
            alloc,
            region,
        })
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
    /// `*_from_cap` publish.
    pub fn alloc(&self) -> TalcAlloc {
        self.alloc
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
        unsafe { self.directory.as_ref() }
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

    // --- Typed publish methods ---

    /// Publish an inline DataCap and record it in the directory.
    pub fn publish_data_inline(&mut self, bytes: &[u8]) -> Result<CapHash> {
        let h = self
            .typed_cache
            .publish_data_inline(bytes)
            .map_err(CacheError::from)?;
        self.touch_blob(h)?;
        Ok(h)
    }

    /// Publish an inline DataCap with explicit logical size.
    pub fn publish_data_inline_with_size(&mut self, bytes: &[u8], size: u64) -> Result<CapHash> {
        let h = self
            .typed_cache
            .publish_data_inline_with_size(bytes, size)
            .map_err(CacheError::from)?;
        self.touch_blob(h)?;
        Ok(h)
    }

    /// Publish an Image (SCALE-encoded shape) end-to-end: walks
    /// pinned/initial slots, publishes each Data, then publishes the
    /// `ImageCap`. Records the resulting Image blob in the directory.
    pub fn publish_image(&mut self, image: &javm_cap::image::Image) -> Result<CapHash> {
        let h = self
            .typed_cache
            .publish_image(image)
            .map_err(CacheError::from)?;
        self.touch_blob(h)?;
        Ok(h)
    }

    /// Publish a pre-built `ImageCap<TalcAlloc>`. Lower-level; the
    /// caller is responsible for constructing the cap in this cache's
    /// allocator (see [`Self::alloc`]).
    pub fn publish_image_from_cap(&mut self, image: TImageCap<TalcAlloc>) -> Result<CapHash> {
        let h = self
            .typed_cache
            .publish_image_from_cap(image)
            .map_err(CacheError::from)?;
        self.touch_blob(h)?;
        Ok(h)
    }

    /// Convert a borrowed SCALE [`javm_cap::image::Image`] into a
    /// talc-resident [`TImageCap<TalcAlloc>`] using this cache's
    /// allocator, given resolved hashes for the image's pinned and
    /// initial slots.
    pub fn image_cap_in(
        &self,
        image: &javm_cap::image::Image,
        pinned_hashes: &[(SlotIdx, CapHash)],
        initial_hashes: &[(SlotIdx, CapHash)],
    ) -> Result<TImageCap<TalcAlloc>> {
        image_cap_in(image, pinned_hashes, initial_hashes, self.alloc)
            .map_err(|e| new_error!("cache: image_cap_in: {e}"))
    }

    /// Publish a CNode and record it.
    pub fn publish_cnode(
        &mut self,
        size_log: u8,
        entries: &[(SlotIdx, CapHashOrRef)],
    ) -> Result<CapHash> {
        let h = self
            .typed_cache
            .publish_cnode(size_log, entries)
            .map_err(CacheError::from)?;
        self.touch_blob(h)?;
        Ok(h)
    }

    /// Publish an InstanceCap blob and record it.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_instance_blob(
        &mut self,
        image_hash_chain: CapHash,
        image_hash: CapHash,
        root_cnode: CapHash,
        rw_overlays: &[(u32, &[u8])],
        mem_size: u32,
        regs: [u64; javm_cap::NUM_REGS],
        pc: u64,
        gas_remaining: u64,
    ) -> Result<CapHash> {
        let h = self
            .typed_cache
            .publish_instance_blob(
                image_hash_chain,
                image_hash,
                root_cnode,
                rw_overlays,
                mem_size,
                regs,
                pc,
                gas_remaining,
            )
            .map_err(CacheError::from)?;
        self.touch_blob(h)?;
        Ok(h)
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
        let dir_ptr = self.directory.as_ptr();
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

    /// Record an instance ref in the directory. Used after a `get_mut`
    /// promotes a blob to an instance entry, or after a fresh instance
    /// publish (not currently used in V1 — Instances live as blobs).
    #[allow(dead_code)]
    fn touch_instance(&mut self, r: CapRef) -> Result<()> {
        let va = self
            .typed_cache
            .entry_va(CapHashOrRef::Ref(r))
            .ok_or_else(|| new_error!("cache: instance {r} missing"))?;
        let dir_ptr = self.directory.as_ptr();
        if let Some((_, slot_ptr)) = unsafe { CacheDirectory::find_instance(dir_ptr, r) } {
            unsafe {
                (*(slot_ptr as *mut InstanceSlot)).entry_va = va;
            }
            return Ok(());
        }
        let idx = unsafe { CacheDirectory::first_empty_instance(dir_ptr) }.ok_or(
            CacheError::InstanceDirectoryFull(nub_host_common::cache::MAX_INSTANCE_SLOTS),
        )?;
        let slot = unsafe { CacheDirectory::instance_slot_ptr(dir_ptr, idx) };
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
            .publish_data_inline(&[0xAA, 0xBB, 0xCC])
            .expect("publish");
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
        let h1 = cache.publish_data_inline(&[1, 2, 3]).expect("publish 1");
        let h2 = cache.publish_data_inline(&[1, 2, 3]).expect("publish 2");
        assert_eq!(h1, h2);
        let dir = cache.directory();
        // Only one directory slot consumed (touch_blob updates an
        // existing slot rather than allocating a new one).
        assert_eq!(dir.blob_count.load(std::sync::atomic::Ordering::Acquire), 1);
    }

    #[test]
    fn publish_chain_data_cnode_image_instance() {
        use javm_cap::CapHashOrRef;

        let mut cache = Cache::new().expect("alloc");
        // Data
        let data_h = cache.publish_data_inline(&[0x42; 8]).expect("data");
        // CNode referencing it
        let cnode_h = cache
            .publish_cnode(4, &[(SlotIdx(0), CapHashOrRef::Hash(data_h))])
            .expect("cnode");
        // Build an image cap with a pinned reference to data, publish it
        let img = cache
            .image_cap_in(
                &javm_cap::image::Image::empty(),
                &[(SlotIdx(7), data_h)],
                &[],
            )
            .expect("image_cap_in");
        let image_h = cache.publish_image_from_cap(img).expect("image");
        // Instance
        let inst_h = cache
            .publish_instance_blob(
                [0; 32],
                image_h,
                cnode_h,
                &[],
                4096,
                [0u64; javm_cap::NUM_REGS],
                0x1000,
                1_000_000,
            )
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
        let h = cache.publish_data_inline(&[0; 4]).expect("publish");
        cache.pin(h).expect("pin");
        assert_eq!(cache.pinned.len(), 1);
        cache.unpin(h);
        assert!(cache.pinned.is_empty());
    }
}
