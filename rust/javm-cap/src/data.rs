//! `DataCap<A>` — talc-friendly Data cap.
//!
//! Two storage forms:
//! - `Inline` — bytes in one `Vec<u8, A>`. Used for "small" Data
//!   (typically a single page).
//! - `Paged` — page-merkleized; each page is owned by the DataCap
//!   via a reference-counted [`PageRef`](crate::page::PageRef) so
//!   multiple DataCap clones can share page bytes between CoW
//!   operations.
//!
//! ## Page-aligned invariant
//!
//! `DataCap` content storage is always a multiple of [`PAGE_SIZE`]
//! bytes. There is no separate logical-size field — `content.len()`
//! is the size, always 4 KiB-multiple. This lets the kernel map the
//! cap's pages directly into a ring-3 page table without an
//! intermediate per-call copy (see the v3 spec, §2 "Memory model").
//!
//! Callers that want to pass shorter payloads (variable-length args)
//! pad up to the next page boundary at mint time; the meaningful
//! bytes are interpreted by the receiver (length-prefix encoding or
//! zero-terminator scanning).

use core::alloc::Layout;

use allocate::vec::Vec;
use allocate::{Allocator, Global};

use super::page::PageSlot;

/// Cap-level page size. Mirrors the architecture's 4 KiB page (must
/// match `nub_arch_x86::paging::PAGE_SIZE` for direct PT mapping to
/// work).
pub const PAGE_SIZE: usize = 4096;

#[derive(Clone, Debug, ssz_derive::HashTreeRoot)]
pub struct DataCap<A: Allocator + Clone = Global> {
    pub content: DataContent<A>,
}

#[derive(Clone, Debug, ssz_derive::HashTreeRoot)]
pub enum DataContent<A: Allocator + Clone = Global> {
    /// Bytes in a single slab. `bytes.len()` must be a multiple of
    /// [`PAGE_SIZE`] (zero-padded by the constructor).
    #[ssz(selector = 0)]
    Inline(Vec<u8, A>),
    /// Page-merkleized form. Each page is owned (via refcounted
    /// PageRef) so DataCap clones can share unmodified pages.
    #[ssz(selector = 1)]
    Paged {
        /// Logical page size (typically 4 KiB). Every page slab
        /// has exactly this many bytes.
        page_size: u32,
        /// Dense slot table indexed by page index.
        pages: Vec<PageSlot<A>, A>,
    },
}

impl<A: Allocator + Clone> DataCap<A> {
    /// Total content size in bytes. Always a multiple of
    /// [`PAGE_SIZE`].
    pub fn content_len(&self) -> u64 {
        match &self.content {
            DataContent::Inline(bytes) => bytes.len() as u64,
            DataContent::Paged { page_size, pages } => {
                (*page_size as u64).saturating_mul(pages.len() as u64)
            }
        }
    }
}

/// Allocate a zero-filled `Vec<u8, A>` of `len` bytes (rounded up to
/// the next page boundary) with `PAGE_SIZE`-aligned backing storage.
///
/// The resulting `Vec` has `len == capacity == padded_len`; all bytes
/// are zero. Page alignment of the underlying allocation is what lets
/// the kernel later map the buffer directly into a ring-3 PT.
///
/// Panics if the allocator returns null (out-of-memory) or if
/// constructing the `Layout` overflows.
pub fn alloc_page_aligned_zeroed<A: Allocator + Clone>(len: usize, alloc: A) -> Vec<u8, A> {
    let padded = len.next_multiple_of(PAGE_SIZE).max(PAGE_SIZE);
    let layout =
        Layout::from_size_align(padded, PAGE_SIZE).expect("DataCap page-aligned layout overflow");
    let nn = alloc
        .allocate_zeroed(layout)
        .expect("DataCap page-aligned allocation failed");
    // SAFETY: `allocate_zeroed` returned a non-null pointer to
    // `padded` zeroed bytes aligned to PAGE_SIZE. The capacity we
    // pass to `from_raw_parts_in` matches the allocation; the length
    // (== capacity) reflects that all bytes are initialised (to zero).
    unsafe { Vec::from_raw_parts_in(nn.as_ptr() as *mut u8, padded, padded, alloc) }
}
