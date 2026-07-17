//! Page-aligned allocations from talc.
//!
//! Used by both [`jit_cache`](crate::jit_cache) (per-Image arenas
//! holding the DISPATCH/JIT/TRAMP regions) and
//! [`jit_run`](crate::jit_run) (per-call CTX, MEM, STACK pages).
//!
//! All allocations come from the global heap (talc); the page-aligned
//! [`Layout`] guarantees physical pages we can plug into a ring-3
//! page table directly.

extern crate alloc;

use alloc::alloc::{alloc_zeroed, dealloc};
use core::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::paging::PAGE_SIZE;

/// Page-aligned heap allocation. Frees on drop. Used for buffers that
/// need a stable physical address mappable into a ring-3 page table.
pub struct PageBuf {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl PageBuf {
    /// Allocate `size` bytes (rounded up to a page boundary), zeroed,
    /// aligned to a page.
    pub fn new(size: usize) -> Option<Self> {
        let size = size.next_multiple_of(PAGE_SIZE).max(PAGE_SIZE);
        let layout = Layout::from_size_align(size, PAGE_SIZE).ok()?;
        // SAFETY: layout is non-zero and well-formed.
        let raw = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(raw)?;
        Some(Self { ptr, layout })
    }

    /// Kernel VA of the buffer.
    pub fn kva(&self) -> u64 {
        self.ptr.as_ptr() as u64
    }

    /// Physical address. Talc heap lives at high kernel VA (Stage F);
    /// `va_to_pa` walks back through the kernel-half offset.
    pub fn pa(&self) -> u64 {
        crate::paging::va_to_pa(self.kva()).expect("talc kva must lie in kernel half")
    }

    /// Total size in bytes (multiple of `PAGE_SIZE`).
    pub fn size(&self) -> u64 {
        self.layout.size() as u64
    }

    /// Borrow the buffer as a mutable byte slice. Useful for filling
    /// the arena layout from compile output.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: ptr is valid for `layout.size()` bytes; we hold
        // unique access through `&mut self`.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.layout.size()) }
    }
}

impl Drop for PageBuf {
    fn drop(&mut self) {
        // SAFETY: layout matches the one we passed to `alloc_zeroed`.
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

/// A process-global, leak-once page-aligned 4 KiB page. Allocated from talc on
/// first access and **never freed** (lives for the kernel's lifetime).
///
/// Used for ring-3 scratch that is per-*execution*, not per-*frame*, and so is
/// safe to share across every frame: the shared read-only zero page (a pure
/// CoW/page-in source) and — once the ctx/stack are shared — the ring-3 CTX and
/// STACK pages. Only ever one frame runs in ring 3 at a time (cooperative
/// nesting; each `host_call` fully exits to ring 0), so a single physical page
/// backs them all without any per-frame state leaking between frames.
///
/// Lazy init uses a compare-exchange so future multi-vCPU workers can race on
/// first touch safely; the winning page is leaked, and any losing allocation is
/// dropped immediately.
pub struct GlobalPage {
    /// Kernel VA of the leaked page, or 0 before first init.
    kva: AtomicU64,
}

impl Default for GlobalPage {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalPage {
    pub const fn new() -> Self {
        Self {
            kva: AtomicU64::new(0),
        }
    }

    /// Kernel VA of the page, allocating + leaking it on first call.
    #[inline]
    pub fn kva(&self) -> u64 {
        let cur = self.kva.load(Ordering::Acquire);
        if cur != 0 {
            return cur;
        }
        // First touch: allocate a zeroed page and try to publish it. If another
        // lane wins the race, this `PageBuf` drops normally at the end of the
        // function and frees the unused page.
        let buf = PageBuf::new(PAGE_SIZE).expect("global page alloc");
        let kva = buf.kva();
        match self
            .kva
            .compare_exchange(0, kva, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {
                core::mem::forget(buf);
                kva
            }
            Err(existing) => existing,
        }
    }

    /// Physical address of the page (allocating it on first call).
    #[inline]
    pub fn pa(&self) -> u64 {
        crate::paging::va_to_pa(self.kva()).expect("global page kva must lie in kernel half")
    }
}
