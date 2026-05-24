//! State-cache layout + unified [`Cache`] handle.
//!
//! The state cache is a shared memory region (1 GiB) mapped at the
//! same fixed VA ([`STATE_CACHE_VA`]) on both host and guest.
//!
//! ## Layout (post-refactor)
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
//!
//! ## Legacy: POD `CacheDirectory`
//!
//! The raw POD [`directory::CacheDirectory`] is the old layout (open-
//! addressed Vec table). It's preserved here for Commit 2's
//! intermediate state and gets deleted in Commit 3 once every caller
//! has migrated to the unified [`Cache`].

extern crate alloc;

use core::ptr::NonNull;

#[cfg(feature = "std")]
use javm_cap::CapHash;

pub mod directory;
pub mod header;

#[cfg(feature = "std")]
pub mod host;

#[cfg(target_os = "none")]
pub mod guest;

#[cfg(test)]
mod directory_tests;

pub use directory::{
    BlobSlot, CacheDirectory, INSTANCE_MASK, InstanceSlot, MAX_BLOB_SLOTS, MAX_INSTANCE_SLOTS,
};
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

// --- Legacy layout constants (consumed by the soon-to-be-deleted POD
// `CacheDirectory` machinery in `nub-host-kvm::cache::HostCache` and
// `nub-arch-x86::state_cache::GuestCache`). Kept here through Commit 2
// so the workspace still compiles; gone in Commit 3.

/// Legacy: offset where the POD `CacheDirectory` starts.
pub const CACHE_DIRECTORY_OFFSET: usize = 0x1000;
/// Legacy: offset where the talc heap starts (post POD directory).
pub const TALC_HEAP_OFFSET: usize = CACHE_DIRECTORY_OFFSET + CacheDirectory::SIZE;
/// Legacy: bytes available to the talc heap under the old layout.
pub const TALC_HEAP_SIZE: usize = STATE_CACHE_SIZE - TALC_HEAP_OFFSET;

// --- Unified `Cache` type ---

/// Unified host/guest cache handle. Holds a pointer to the region
/// base (so the `CacheHeader` at offset 0 is `&self.header()`-able);
/// host instances additionally own the mmap lease and a pin-set,
/// guest instances additionally own the per-RPC scratch tracker.
///
/// Construction is platform-specific:
/// - host: [`Cache::new`] (this module, gated `not(target_os = "none")`)
/// - guest: [`Cache::from_mapped_region`] (this module, gated
///   `target_os = "none"`), called by `nub-arch-x86`'s
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
    // Read by `pin`/`unpin` once wired in Commit 3.
    #[cfg(feature = "std")]
    #[allow(dead_code)]
    pinned: smallvec::SmallVec<[CapHash; 8]>,

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
    /// typed `publish_*` API (added in Commit 3) so that every talc
    /// allocation is reachable from the directory or scratch tracker.
    ///
    /// The `'static` lifetime is the standard pinned-mapping fiction:
    /// the talc lives at the `CacheHeader`'s field address, which is
    /// pinned for the cache region's process lifetime. See
    /// `allocate::talc::TalcAlloc` for the contract.
    #[allow(dead_code)]
    pub(crate) fn alloc(&self) -> allocate::talc::TalcAlloc {
        // SAFETY: the talc lock is initialised by `CacheHeader::init_at`
        // before the `Cache` exists, and the region is pinned for the
        // process lifetime.
        unsafe { &*core::ptr::addr_of!(self.header().talc) }
    }
}
