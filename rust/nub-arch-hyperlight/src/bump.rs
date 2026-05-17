//! Bump-pointer arena for per-invocation kernel allocations.
//!
//! Backing is a contiguous run of physical pages obtained from
//! [`hyperlight_guest::prim_alloc::alloc_phys_pages`], rather than the
//! buddy heap. The reason: anything that ends up in a page-table PTE
//! (page tables themselves, JIT exec pages, JitContext) needs its
//! physical address to be exactly recoverable from its virtual
//! address, and the buddy heap lives at a VA whose PA we'd have to
//! page-walk to recover. `prim_alloc` returns a GPA in Hyperlight's
//! scratch region, whose VA is `scratch_base_gva + (gpa -
//! scratch_base_gpa)` — a constant offset (see [`crate::paging`]).
//!
//! Between invocations the kernel calls [`BumpArena::reset`] to
//! rewind the high-water mark; objects are POD with no Drop semantics.
//!
//! The backing is page-aligned (each call to `alloc_phys_pages`
//! returns a page-aligned region), so allocations requesting
//! `PAGE_SIZE` alignment are satisfied without a separate page
//! allocator.
//!
//! # Concurrency
//!
//! Single-threaded by construction — the guest runs cooperatively;
//! there's exactly one active invocation at a time. `BumpArena` is
//! `!Sync`; storing it in a `static mut` requires the caller to
//! enforce non-reentrancy (per the Hyperlight ABI, host calls into
//! the guest are serialised by the sandbox).
//!
//! Physical pages obtained from `alloc_phys_pages` cannot be released
//! back to Hyperlight; the arena leaks them at drop. Production use
//! is one global arena per guest, reset between invocations.

#![cfg(target_os = "none")]

use core::cell::Cell;
use core::ptr::NonNull;

use crate::paging;

/// 4 KiB page size — the unit of alignment for page-aligned
/// allocations (page tables, JIT exec pages, etc.).
pub const PAGE_SIZE: usize = 4096;

/// Default arena size for smoke tests. Just enough for a 4-level
/// page-table set (PML4 + PDPT + PD + PT) per smoke invocation.
/// Production per-invocation arenas (Stage C+) will use a larger
/// capacity sized to fit page tables + JIT code + JitContext +
/// trap table.
pub const SMOKE_CAPACITY: usize = 4 * PAGE_SIZE;

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
    /// Construct a `BumpArena` whose backing is `capacity / PAGE_SIZE`
    /// physical pages obtained from `prim_alloc::alloc_phys_pages`.
    /// `capacity` must be a multiple of [`PAGE_SIZE`].
    ///
    /// Pages cannot be returned to Hyperlight, so smoke tests that
    /// drop the arena leak the backing. In production, a single
    /// global arena is created at `hyperlight_main` time and
    /// reset between invocations.
    pub fn new(capacity: usize) -> Option<Self> {
        assert!(capacity.is_multiple_of(PAGE_SIZE));
        let pages = (capacity / PAGE_SIZE) as u64;
        // SAFETY: prim_alloc::alloc_phys_pages is safe to call from
        // ring-0 guest code; it returns a GPA backing `pages` 4 KiB pages.
        let base_pa = unsafe { hyperlight_guest::prim_alloc::alloc_phys_pages(pages) };
        let base_va = paging::pa_to_va(base_pa)?;
        let base = NonNull::new(base_va as *mut u8)?;
        Some(Self {
            base,
            capacity,
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
