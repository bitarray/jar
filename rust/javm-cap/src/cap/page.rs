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
#[derive(Clone, Debug, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
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
///
/// `Clone` and rkyv `Deserialize` are **hand-written** to preserve the
/// `PAGE_SIZE`-alignment invariant of `bytes`: the recompiler resolves a
/// page's physical address from its slab pointer and direct-maps it into a
/// ring-3 page table (`pt_map_leaf` requires a page-aligned PA). The derived
/// `Clone` / `Deserialize` would `Vec`-allocate `bytes` at alignment 1, so a
/// cloned or wire-decoded page would land mid-page and the recompiler would map
/// the wrong physical frame. Both re-allocate through
/// [`super::data::alloc_page_aligned_zeroed`]. (Mirrors the page-alignment
/// discipline the legacy `DataContent::Inline` kept in its manual `Clone`.)
#[derive(Debug, rkyv::Archive, rkyv::Serialize)]
pub struct PageBytes {
    pub hash: CapHash,
    pub bytes: Vec<u8>,
}

impl Clone for PageBytes {
    fn clone(&self) -> Self {
        Self::realigned(self.hash, &self.bytes)
    }
}

impl PageBytes {
    /// Build a `PageBytes` with `bytes` re-allocated into a `PAGE_SIZE`-aligned
    /// slab (zero-padded tail). Used by the page-aligning `Clone` / rkyv
    /// `Deserialize`.
    fn realigned(hash: CapHash, src: &[u8]) -> Self {
        use super::data::{PAGE_SIZE, alloc_page_aligned_zeroed};
        let mut bytes = alloc_page_aligned_zeroed(src.len().max(PAGE_SIZE));
        bytes[..src.len()].copy_from_slice(src);
        Self { hash, bytes }
    }
}

impl<D: rkyv::rancor::Fallible + ?Sized> rkyv::Deserialize<PageBytes, D> for ArchivedPageBytes {
    fn deserialize(&self, _deserializer: &mut D) -> Result<PageBytes, D::Error> {
        // Re-align into a `PAGE_SIZE` slab (load-bearing for the recompiler
        // direct-map — see the `PageBytes` docs).
        Ok(PageBytes::realigned(self.hash, self.bytes.as_slice()))
    }
}

impl PageBytes {
    /// Build a `PageBytes` from up to `PAGE_SIZE` content bytes: a
    /// `PAGE_SIZE`-aligned slab (zero-padded tail) plus the precomputed
    /// content hash ([`super::data::page_content_hash`]). The slab alignment is
    /// load-bearing — the recompiler maps the page's slab directly into a
    /// ring-3 page table.
    pub fn from_content(content: &[u8]) -> Self {
        use super::data::{PAGE_SIZE, alloc_page_aligned_zeroed, page_content_hash};
        let hash = page_content_hash(content);
        let mut bytes = alloc_page_aligned_zeroed(PAGE_SIZE);
        let n = content.len().min(PAGE_SIZE);
        bytes[..n].copy_from_slice(&content[..n]);
        Self { hash, bytes }
    }
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
