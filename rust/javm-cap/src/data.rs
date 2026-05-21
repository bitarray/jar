//! `DataCap<A>` — talc-friendly Data cap.
//!
//! Two storage forms:
//! - `Inline` — bytes in one `Vec<u8, A>`. Used for "small" Data
//!   (typically ≤ 1 page; the exact threshold is a callers' choice).
//! - `Paged` — page-merkleized; each page is owned by the DataCap
//!   via a reference-counted [`PageRef`](crate::page::PageRef) so
//!   multiple DataCap clones can share page bytes between CoW
//!   operations.

use allocator_api2::alloc::{Allocator, Global};
use allocator_api2::vec::Vec;

use super::page::PageSlot;

#[derive(Clone, Debug, ssz_derive::HashTreeRoot)]
pub struct DataCap<A: Allocator + Clone = Global> {
    pub size: u64,
    pub content: DataContent<A>,
}

#[derive(Clone, Debug, ssz_derive::HashTreeRoot)]
pub enum DataContent<A: Allocator + Clone = Global> {
    /// Bytes in a single slab.
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
