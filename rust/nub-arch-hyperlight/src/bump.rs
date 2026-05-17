//! Bump-pointer arena for per-invocation kernel allocations.
//!
//! Backing is a single fixed-size buffer allocated once at
//! `hyperlight_main` time from the buddy heap. Every per-invocation
//! object (page tables, JIT code buffer, JitContext, trap table)
//! lives in this arena. Between invocations the kernel calls
//! [`BumpArena::reset`] to rewind the high-water mark; objects are
//! POD and have no Drop semantics.
//!
//! The arena's backing buffer is page-aligned so allocations that
//! request `PAGE_SIZE` alignment can be satisfied without a separate
//! page allocator.
//!
//! # Concurrency
//!
//! Single-threaded by construction — the guest runs cooperatively;
//! there's exactly one active invocation at a time. `BumpArena` is
//! `!Sync`; storing it in a `static mut` requires the caller to
//! enforce non-reentrancy (per the Hyperlight ABI, host calls into
//! the guest are serialised by the sandbox).

#![cfg(target_os = "none")]

use core::cell::Cell;
use core::ptr::NonNull;

/// 4 KiB page size — the unit of alignment for page-aligned
/// allocations (page tables, JIT exec pages, etc.).
pub const PAGE_SIZE: usize = 4096;

/// Maximum live arena size. Sized to comfortably accommodate the
/// per-invocation working set: page tables (~64 KiB), JIT code
/// buffer (~1 MiB), JitContext + trap table (~few hundred KiB),
/// plus headroom.
pub const ARENA_CAPACITY: usize = 16 * 1024 * 1024;

/// Bump arena holding a contiguous, page-aligned buffer.
pub struct BumpArena {
    /// Base of the backing buffer.
    base: NonNull<u8>,
    /// Length of the backing buffer.
    capacity: usize,
    /// Current high-water mark (next-alloc offset from `base`).
    cursor: Cell<usize>,
}

impl BumpArena {
    /// Construct a `BumpArena` with `ARENA_CAPACITY` bytes allocated
    /// from the global allocator. Returns `None` if the allocator
    /// fails or the returned buffer isn't `PAGE_SIZE`-aligned.
    ///
    /// The caller is expected to leak the backing buffer for the
    /// lifetime of the guest (a `static mut BumpArena` set up at
    /// `hyperlight_main` time, never freed).
    pub fn new() -> Option<Self> {
        // Allocate via the buddy heap. `Vec::with_capacity` doesn't
        // give us page alignment, so use the raw allocator API.
        let layout = core::alloc::Layout::from_size_align(ARENA_CAPACITY, PAGE_SIZE).ok()?;
        // SAFETY: layout is valid (positive size, power-of-two
        // alignment). The pointer's lifetime is the entire guest.
        let raw = unsafe { alloc::alloc::alloc(layout) };
        let base = NonNull::new(raw)?;
        Some(Self {
            base,
            capacity: ARENA_CAPACITY,
            cursor: Cell::new(0),
        })
    }

    /// Bump-allocate `size` bytes with `align` alignment. Returns
    /// `None` if the request would overflow the arena.
    pub fn alloc(&self, size: usize, align: usize) -> Option<NonNull<u8>> {
        debug_assert!(align.is_power_of_two());
        let cursor = self.cursor.get();
        let aligned = (cursor + align - 1) & !(align - 1);
        let next = aligned.checked_add(size)?;
        if next > self.capacity {
            return None;
        }
        self.cursor.set(next);
        // SAFETY: `aligned` is in `[0, capacity)` by the bound above.
        let ptr = unsafe { self.base.as_ptr().add(aligned) };
        NonNull::new(ptr)
    }

    /// Allocate `count` page-aligned, page-sized blocks. Returns a
    /// pointer to the first byte. The returned region is contiguous.
    #[allow(dead_code)] // consumed by Stage A3 (page tables)
    pub fn alloc_pages(&self, count: usize) -> Option<NonNull<u8>> {
        let size = count.checked_mul(PAGE_SIZE)?;
        self.alloc(size, PAGE_SIZE)
    }

    /// Reset the high-water mark. All prior allocations become
    /// invalid; the caller must ensure no live references survive.
    pub fn reset(&self) {
        self.cursor.set(0);
    }

    /// Current high-water mark (bytes used).
    #[allow(dead_code)] // diagnostic only
    pub fn used(&self) -> usize {
        self.cursor.get()
    }

    /// Total capacity.
    #[allow(dead_code)] // diagnostic only
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}
