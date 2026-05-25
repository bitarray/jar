//! State-cache layout + unified [`Cache`] handle.
//!
//! The state cache is a shared memory region (1 GiB) mapped at the
//! same fixed VA ([`STATE_CACHE_VA`]) on both host and guest.
//!
//! ## Layout
//!
//! ```text
//! offset 0                       CacheHeader (talc + locked directory),
//!                                page-aligned (`repr(align(4096))`)
//! offset CacheHeader::SIZE       talc-managed heap (rest of region)
//! ```
//!
//! `CacheHeader` carries:
//! - the talc allocator + its internal spinlock (allocation primitive
//!   used by both host and guest);
//! - the cap directory: `CacheDirectory<FixedState, TalcAlloc>` under
//!   a `Mutex<RawSpinlock, _>` so mutations on either side serialise
//!   correctly. In V0 the lock never contends (Hyperlight ensures
//!   host and guest are never running simultaneously).

extern crate alloc;

use alloc::vec::Vec;
use core::ptr::NonNull;

use allocate::talc::{MutexGuard, RawSpinlock, TalcAlloc};
use javm_cap::cap::Cap;
use javm_cap::{CacheError, CapHash, CapHashOrRef, CapRef};

pub mod header;

#[cfg(feature = "std")]
pub mod host;

#[cfg(target_os = "none")]
pub mod guest;

pub use header::{CacheHeader, LockedDirectory, SharedCacheDirectory};

#[cfg(feature = "std")]
pub use host::{HostCacheError, HostRegion};

/// Fixed guest virtual address the cache region is mapped at. The
/// guest's per-invocation page-table builder maps this VA to
/// [`STATE_CACHE_GPA`] with user RW permission. The host accesses
/// cache memory via its own (kernel-chosen) host VA returned by
/// `mmap`; index offsets translate between the two.
pub const STATE_CACHE_VA: u64 = 0x4000_0000_0000;

/// Fixed guest physical address the cache region is mapped at. Sits
/// at 8 GiB, well clear of the snapshot region (low GPAs) and the
/// scratch region (top of [`crate::layout::MAX_GPA`]).
pub const STATE_CACHE_GPA: u64 = 0x2_0000_0000;

/// Total size of the cache region. 1 GiB.
pub const STATE_CACHE_SIZE: usize = 1 << 30;

// --- Unified `Cache` type ---

/// Unified host/guest cache handle. Holds a pointer to the region
/// base (so the `CacheHeader` at offset 0 is `&self.header()`-able);
/// host instances additionally own the mmap lease and a pin-set,
/// guest instances additionally own the per-RPC scratch tracker.
///
/// Construction is platform-specific:
/// - host: [`Cache::new`] (this module, gated `feature = "std"`)
/// - guest: [`Cache::from_mapped_region`] (this module, gated
///   `target_os = "none"`), typically wrapped by `nub-arch-x86`'s
///   `state_cache::init_guest_cache` after the kernel page-table
///   mapping is installed.
pub struct Cache {
    base: NonNull<u8>,

    /// Host-only: RAII lease over the singleton mmap region. Dropped
    /// last so cap content (which lives in the mmap'd talc heap) is
    /// only torn down after every Cap-holding field is gone.
    #[cfg(feature = "std")]
    _region: host::HostRegion,

    /// Host-only: hashes currently pinned (active call frames).
    /// Eviction (future stage) skips these.
    #[cfg(feature = "std")]
    pub(crate) pinned: smallvec::SmallVec<[CapHash; 8]>,

    /// Guest-only: per-RPC tracker of entries the guest published in
    /// this invocation, swept by `clear_scratch` (called by Drop).
    #[cfg(target_os = "none")]
    scratch: guest::ScratchTracker,
}

// SAFETY: all data lives in the shared mmap region; concurrent access
// is excluded by the directory's spinlock and (in V0) by Hyperlight's
// host/guest serialisation.
unsafe impl Send for Cache {}

impl Cache {
    /// Read-only access to the embedded [`CacheHeader`].
    #[inline]
    pub fn header(&self) -> &CacheHeader {
        // SAFETY: by construction (host: `Cache::new`; guest:
        // `Cache::from_mapped_region`) the region starts with a
        // CacheHeader at offset 0, page-aligned and initialised.
        unsafe { &*self.base.cast::<CacheHeader>().as_ptr() }
    }

    /// Host VA of the cache region's base. Equal to [`STATE_CACHE_VA`]
    /// post-`MAP_FIXED_NOREPLACE`.
    pub fn base_va(&self) -> u64 {
        self.base.as_ptr() as u64
    }

    /// Total cache size in bytes.
    pub fn size(&self) -> usize {
        STATE_CACHE_SIZE
    }

    /// Crate-private allocator handle. Public callers go through the
    /// typed `publish_*` API so that every talc allocation is reachable
    /// from the directory or scratch tracker.
    ///
    /// The `'static` lifetime is the standard pinned-mapping fiction:
    /// the talc lives at the `CacheHeader`'s field address, which is
    /// pinned for the cache region's process lifetime. See
    /// `allocate::talc::TalcAlloc` for the contract.
    #[allow(dead_code)] // shared cache deletion comes in commit 5
    pub(crate) fn alloc(&self) -> TalcAlloc {
        // SAFETY: the talc lock is initialised by `CacheHeader::init_at`
        // before the `Cache` exists, and the region is pinned for the
        // process lifetime.
        unsafe { &*core::ptr::addr_of!(self.header().talc) }
    }

    /// Locked access to the underlying [`SharedCacheDirectory`]. The
    /// returned guard scopes the spinlock; drop it as soon as the
    /// operation finishes. In V0 the lock never contends (Hyperlight
    /// serialises host↔guest), but holding it is still cheap (one CAS).
    pub fn directory(&self) -> MutexGuard<'_, RawSpinlock, SharedCacheDirectory> {
        self.header().directory.lock()
    }
}

// --- Shared API: published verbs available on both host and guest. ---

impl Cache {
    /// Whether a content-addressed blob is present.
    pub fn contains(&self, hash: &CapHash) -> bool {
        self.directory().contains_blob(hash)
    }

    /// Publish a `Cap` into the blobs tier under the given hash.
    ///
    /// Guest-side: the published hash is tracked in the per-RPC
    /// scratch tracker and decref'd by `clear_scratch` on Drop.
    pub fn publish_blob(&mut self, hash: CapHash, cap: Cap) -> Result<(), CacheError> {
        {
            let mut dir = self.directory();
            dir.put_blob(hash, cap)?;
        }
        #[cfg(target_os = "none")]
        self.track_scratch_blob(hash);
        Ok(())
    }

    /// Publish a `Cap` as a fresh mutable instance. Returns
    /// the allocated [`CapRef`].
    ///
    /// Guest-side: the returned ref is tracked in the per-RPC scratch
    /// tracker and decref'd by `clear_scratch` on Drop.
    pub fn publish_instance(&mut self, cap: Cap) -> Result<CapRef, CacheError> {
        let r = {
            let mut dir = self.directory();
            dir.put_instance(cap)?
        };
        #[cfg(target_os = "none")]
        self.track_scratch_instance(r);
        Ok(r)
    }

    /// Build a fresh `Cap::Instance` in the cache's talc heap and
    /// publish it. Inherits the parent's chain via `image_hash_chain`;
    /// `regs`, `pc`, `gas_remaining`, `rw_overlays` start empty. This
    /// is the typed alternative to the old
    /// `cache.allocator() + Cap::Instance(...) + publish_instance(cap)`
    /// pattern.
    pub fn publish_transient_instance(
        &mut self,
        image_hash: CapHash,
        image_hash_chain: CapHash,
    ) -> Result<CapRef, CacheError> {
        let cap = Cap::Instance(javm_cap::instance::InstanceCap {
            image_hash_chain,
            image_hash,
            root_cnode: CapHashOrRef::Hash([0u8; 32]),
            rw_overlays: Vec::new(),
            mem_size: 0,
            regs: [0u64; javm_cap::NUM_REGS],
            pc: 0,
            gas_remaining: 0,
        });
        self.publish_instance(cap)
    }

    /// Increment refcount on a key.
    pub fn incref(&self, key: CapHashOrRef) -> Result<(), CacheError> {
        self.directory().incref(key)
    }

    /// Decrement refcount on a key. If it drops to zero the entry is
    /// removed (talc-allocated Box dropped). Returns the new refcount.
    pub fn decref(&mut self, key: CapHashOrRef) -> Result<u32, CacheError> {
        self.directory().decref(key)
    }
}
