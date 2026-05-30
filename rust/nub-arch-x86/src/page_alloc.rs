//! Page-aligned allocations from talc.
//!
//! Used by both [`jit_cache`](crate::jit_cache) (per-Image arenas
//! holding the DISPATCH/JIT/TRAMP regions) and
//! [`jit_run`](crate::jit_run) (per-call CTX, MEM, STACK pages).
//!
//! All allocations come from the global heap (talc); the page-aligned
//! [`Layout`] guarantees physical pages we can plug into a ring-3
//! page table directly.

#![cfg(target_os = "none")]

extern crate alloc;

use alloc::alloc::{alloc_zeroed, dealloc};
use core::alloc::Layout;
use core::ptr::NonNull;

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
