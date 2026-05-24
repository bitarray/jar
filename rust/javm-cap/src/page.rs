//! `PageSlot<A>` and `PageRef<A>` — DataCap page storage.
//!
//! Each page is owned by the DataCap that holds it. Sharing across
//! DataCap CoW clones is done via [`PageRef`], a refcounted handle
//! over [`PageBytes`] backed by the caller-supplied allocator. The
//! cache subsystem doesn't index pages by hash — pages aren't
//! first-class caps. They're internal to the DataCap layer.

use allocator_api2::alloc::{Allocator, Global};
use allocator_api2::vec::Vec;
use core::sync::atomic::AtomicU32;

use nub_talc_util::{Aarc, AarcRefCounted};

use super::cap::CapHash;

/// Sparse representation of a paged DataCap's pages. `Empty` is the
/// canonical zero page; `Loaded` holds a refcounted byte slab;
/// `Missing` records the page's content hash so a host callback can
/// later resolve it (V1: never observed — we always pre-publish).
#[derive(Clone, Debug)]
pub enum PageSlot<A: Allocator + Clone = Global> {
    Empty,
    Loaded(PageRef<A>),
    Missing(CapHash),
}

/// Hand-rolled `Arc<PageBytes>` backed by an arbitrary allocator.
/// Aliases the generic `Aarc` from `nub-host-common` for cap-layer
/// readability.
pub type PageRef<A> = Aarc<PageBytes<A>, A>;

/// One page's bytes plus metadata. The `refcount` is what the
/// `Aarc` machinery uses to manage sharing.
#[derive(Debug)]
pub struct PageBytes<A: Allocator + Clone = Global> {
    pub refcount: AtomicU32,
    pub hash: CapHash,
    pub bytes: Vec<u8, A>,
}

impl<A: Allocator + Clone> AarcRefCounted for PageBytes<A> {
    fn refcount(&self) -> &AtomicU32 {
        &self.refcount
    }
}

// --------------------------------------------------------------------------
// Hand-written SSZ impls for `PageSlot<A>` and `PageBytes<A>`.
//
// `HashTreeRoot` is deliberately not derived: the pass-through semantics
// are load-bearing for the substitution invariant. A `Loaded(page)` slot
// must hash identically to a `Missing(h)` slot when `h == page.hash`, and
// a `Loaded(page)` slot's root must equal `page.hash` (the precomputed
// page digest). A `derive(HashTreeRoot)` would mix in a selector byte and
// break that equality.
//
// `Encode` is hand-written too — needed because `Vec<PageSlot<A>, A>:
// HashTreeRoot` requires `PageSlot<A>: Encode` (the Vec impl uses
// `is_ssz_fixed_len` / `is_basic_type` to pick its merkleization path).
// The encoded form mirrors the standard SSZ Union: a selector byte plus
// the variant payload. PageBytes encodes its `(hash, bytes)` pair; the
// `refcount` is `Aarc` machinery and stays out of the wire form. We don't
// implement `Decode`: pages aren't wire-transmitted, and decoding a
// `Loaded` variant would require allocator threading that isn't worth
// the complexity for a never-exercised path.
// --------------------------------------------------------------------------

impl<A: Allocator + Clone> ssz::HashTreeRoot for PageSlot<A> {
    fn hash_tree_root<D: ::ssz::digest::Digest<OutputSize = ::ssz::digest::typenum::U32>>(
        &self,
    ) -> [u8; 32] {
        match self {
            // Canonical zero-page sentinel. Under SSZ, an empty page's
            // root is the empty 32-byte chunk.
            PageSlot::Empty => [0u8; 32],
            PageSlot::Loaded(pr) => pr.get().hash_tree_root::<D>(),
            PageSlot::Missing(h) => *h,
        }
    }
}

impl<A: Allocator + Clone> ssz::HashTreeRoot for PageBytes<A> {
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

impl<A: Allocator + Clone> ssz::Encode for PageSlot<A> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        ssz::BYTES_PER_LENGTH_OFFSET
    }
    fn ssz_bytes_len(&self) -> usize {
        match self {
            PageSlot::Empty => 1,
            PageSlot::Loaded(pr) => 1 + pr.get().ssz_bytes_len(),
            PageSlot::Missing(_) => 1 + 32,
        }
    }
    fn ssz_append<Al: Allocator + Clone>(&self, buf: &mut Vec<u8, Al>) {
        match self {
            PageSlot::Empty => buf.push(0),
            PageSlot::Loaded(pr) => {
                buf.push(1);
                pr.get().ssz_append(buf);
            }
            PageSlot::Missing(h) => {
                buf.push(2);
                buf.extend_from_slice(h);
            }
        }
    }
}

impl<A: Allocator + Clone> ssz::Encode for PageBytes<A> {
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
    fn ssz_append<Al: Allocator + Clone>(&self, buf: &mut Vec<u8, Al>) {
        // Field 0: hash (fixed, 32 bytes).
        // Field 1: bytes (variable, offset slot + payload).
        let fixed_region = 32 + 4;
        buf.extend_from_slice(&self.hash);
        // Offset to the variable payload = fixed_region size.
        buf.extend_from_slice(&(fixed_region as u32).to_le_bytes());
        buf.extend_from_slice(self.bytes.as_slice());
    }
}
