//! State-cache support types.
//!
//! The state cache is a shared memory region (1 GiB) mapped at the
//! same fixed VA on both host and guest. A single `TalcLock` instance
//! at offset 0 manages allocations from the region; both parties call
//! `.allocate()` / `.deallocate()` on it under the same spinlock.
//! Phase-based mutual exclusion (guest is never running while host is
//! mutating) means the spinlock never contends in V0.
//!
//! ## Layout
//!
//! ```text
//! offset 0           TalcLock<RawSpinlock, Manual> (padded to 4 KiB)
//! offset 0x1000      InstanceIndex (fixed slot table, ~4.5 KiB)
//! offset ~0x2200     talc-managed heap (rest of the 1 GiB region)
//! ```
//!
//! ## What lives here
//!
//! - [`TalcBox<T>`] / [`TalcSlice`] — hand-rolled smart pointers that
//!   manage a value/slab inside talc memory. Drop = `talc.lock().free(...)`.
//!   Used on the host side to own per-instance code/ro/rw slabs.
//! - [`InstanceIndex`] / [`IndexSlot`] — the guest-readable directory.
//!   Host populates entries when it publishes a Cap into the cache;
//!   guest scans linearly when resolving `(instance_hash, endpoint_idx)`
//!   into VAs for the JIT path.
//! - Layout constants ([`STATE_CACHE_VA`], [`STATE_CACHE_SIZE`],
//!   [`INSTANCE_INDEX_OFFSET`], [`TALC_HEAP_OFFSET`]).

pub mod index;
pub mod talc_box;

pub use index::{INSTANCE_INDEX_OFFSET, IndexSlot, InstanceIndex, MAX_ENDPOINTS, MAX_INDEX_SLOTS};
pub use talc_box::{CacheTalcLock, TalcBox, TalcSlice};

/// Fixed virtual address the cache region is mapped at, on both
/// host and guest. 64 TiB into user-half canonical space; well clear
/// of the JIT (low 4 GiB) and the kernel half (0xFFFF_FFFF_8000_0000).
pub const STATE_CACHE_VA: u64 = 0x4000_0000_0000;

/// Total size of the cache region. 1 GiB.
pub const STATE_CACHE_SIZE: usize = 1 << 30;

/// Offset within the cache region where the talc-managed heap
/// begins (after [`InstanceIndex`]).
pub const TALC_HEAP_OFFSET: usize = INSTANCE_INDEX_OFFSET + InstanceIndex::SIZE;

/// Number of bytes available to the talc-managed heap.
pub const TALC_HEAP_SIZE: usize = STATE_CACHE_SIZE - TALC_HEAP_OFFSET;
