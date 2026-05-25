//! `PageSlot` and `PageRef` — DataCap page storage.
//!
//! Each page is owned by the DataCap that holds it. Sharing across
//! DataCap CoW clones is done via [`PageRef`], a refcounted handle
//! over [`PageBytes`] backed by the global allocator. The cache
//! subsystem doesn't index pages by hash — pages aren't first-class
//! caps. They're internal to the DataCap layer.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::CapHash;

/// Sparse representation of a paged DataCap's pages. `Empty` is the
/// canonical zero page; `Loaded` holds a refcounted byte slab;
/// `Missing` records the page's content hash so a host callback can
/// later resolve it (V1: never observed — we always pre-publish).
#[derive(Clone, Debug)]
pub enum PageSlot {
    Empty,
    Loaded(PageRef),
    Missing(CapHash),
}

/// Refcounted handle to a [`PageBytes`] allocated by the global
/// allocator. Plain `std::sync::Arc` alias for cap-layer readability.
pub type PageRef = Arc<PageBytes>;

/// One page's bytes plus its precomputed content hash.
///
/// Sharing across DataCap CoW clones is via [`PageRef`] (= `Arc`),
/// which carries its own refcount — `PageBytes` itself is not
/// refcounted.
#[derive(Debug)]
pub struct PageBytes {
    pub hash: CapHash,
    pub bytes: Vec<u8>,
}

// --------------------------------------------------------------------------
// Hand-written SSZ impls for `PageSlot` and `PageBytes`.
//
// `HashTreeRoot` is deliberately not derived: the pass-through semantics
// are load-bearing for the substitution invariant. A `Loaded(page)` slot
// must hash identically to a `Missing(h)` slot when `h == page.hash`, and
// a `Loaded(page)` slot's root must equal `page.hash` (the precomputed
// page digest). A `derive(HashTreeRoot)` would mix in a selector byte and
// break that equality.
//
// --------------------------------------------------------------------------

impl ssz::HashTreeRoot for PageSlot {
    fn hash_tree_root<D: ::ssz::digest::Digest<OutputSize = ::ssz::digest::typenum::U32>>(
        &self,
    ) -> [u8; 32] {
        match self {
            // Canonical zero-page sentinel. Under SSZ, an empty page's
            // root is the empty 32-byte chunk.
            PageSlot::Empty => [0u8; 32],
            PageSlot::Loaded(pr) => (**pr).hash_tree_root::<D>(),
            PageSlot::Missing(h) => *h,
        }
    }
}

impl ssz::HashTreeRoot for PageBytes {
    fn hash_tree_root<D: ::ssz::digest::Digest<OutputSize = ::ssz::digest::typenum::U32>>(
        &self,
    ) -> [u8; 32] {
        // `self.hash` is the precomputed page-content identity (kept
        // consistent with `bytes` by `cache.rs`). Returning it directly
        // preserves substitution: a `Loaded(page)` slot is
        // indistinguishable from `Missing(page.hash)` at the SSZ
        // merkleization level.
        self.hash
    }
}

impl ssz::Encode for PageSlot {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        ssz::BYTES_PER_LENGTH_OFFSET
    }
    fn ssz_bytes_len(&self) -> usize {
        match self {
            PageSlot::Empty => 1,
            PageSlot::Loaded(pr) => 1 + (**pr).ssz_bytes_len(),
            PageSlot::Missing(_) => 1 + 32,
        }
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match self {
            PageSlot::Empty => buf.push(0),
            PageSlot::Loaded(pr) => {
                buf.push(1);
                (**pr).ssz_append(buf);
            }
            PageSlot::Missing(h) => {
                buf.push(2);
                buf.extend_from_slice(h);
            }
        }
    }
}

impl ssz::Encode for PageBytes {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        ssz::BYTES_PER_LENGTH_OFFSET
    }
    fn ssz_bytes_len(&self) -> usize {
        // SSZ container with one fixed (hash) and one variable (bytes):
        // fixed-region = 32 (hash) + 4 (offset slot) = 36; variable
        // payload = bytes.len().
        32 + 4 + self.bytes.len()
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // Field 0: hash (fixed, 32 bytes).
        // Field 1: bytes (variable, offset slot + payload).
        let fixed_region = 32 + 4;
        buf.extend_from_slice(&self.hash);
        // Offset to the variable payload = fixed_region size.
        buf.extend_from_slice(&(fixed_region as u32).to_le_bytes());
        buf.extend_from_slice(self.bytes.as_slice());
    }
}
