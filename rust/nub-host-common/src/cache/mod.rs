//! State-cache support types.
//!
//! The state cache is a shared memory region (1 GiB) mapped at the
//! same fixed VA ([`STATE_CACHE_VA`]) on both host and guest. A single
//! `TalcLock` instance at offset 0 manages allocations from the
//! region; both parties call `.allocate()` / `.deallocate()` on it
//! under the same spinlock. Phase-based mutual exclusion (guest is
//! never running while host is mutating) means the spinlock never
//! contends in V0.
//!
//! ## Layout
//!
//! ```text
//! offset 0           TalcLock<RawSpinlock, Manual> (padded to 4 KiB)
//! offset 0x1000      CacheDirectory (BlobSlot[256] + InstanceSlot[256])
//! offset 0x6000-ish  talc-managed heap (rest of the 1 GiB region)
//! ```
//!
//! ## What lives here
//!
//! - [`TalcBox<T>`] / [`TalcSlice`] — hand-rolled smart pointers that
//!   manage a value/slab inside talc memory. Drop = `talc.lock().free(...)`.
//! - [`CacheDirectory`] — the guest-readable directory at
//!   [`CACHE_DIRECTORY_OFFSET`]. Host populates entries when it
//!   publishes a Cap; guest scans linearly when resolving
//!   `CapHash` / `CapRef` into entry VAs.
//! - Layout constants ([`STATE_CACHE_VA`], [`STATE_CACHE_SIZE`],
//!   [`CACHE_DIRECTORY_OFFSET`], [`TALC_HEAP_OFFSET`]).

pub mod directory;
pub mod talc_alloc;
pub mod talc_arc;
pub mod talc_box;

pub use directory::{
    BlobSlot, CacheDirectory, INSTANCE_MASK, InstanceSlot, MAX_BLOB_SLOTS, MAX_INSTANCE_SLOTS,
};
pub use talc_alloc::TalcAlloc;
pub use talc_arc::{Aarc, AarcRefCounted, TalcArc, TalcRefCounted};
pub use talc_box::{CacheTalcLock, TalcBox, TalcSlice};

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

/// Offset within the cache region where [`CacheDirectory`] starts.
/// Sits at 4 KiB so the talc lock has a full page to itself; the
/// directory itself is page-aligned for cheap atomic writes.
pub const CACHE_DIRECTORY_OFFSET: usize = 0x1000;

/// Offset within the cache region where the talc-managed heap
/// begins (after [`CacheDirectory`]). Page-aligned by construction
/// because [`CacheDirectory::SIZE`] is a multiple of the slot
/// stride; the trailing pad rounds to the next page boundary
/// implicitly via the talc claim.
pub const TALC_HEAP_OFFSET: usize = CACHE_DIRECTORY_OFFSET + CacheDirectory::SIZE;

/// Number of bytes available to the talc-managed heap.
pub const TALC_HEAP_SIZE: usize = STATE_CACHE_SIZE - TALC_HEAP_OFFSET;
