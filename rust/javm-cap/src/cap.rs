//! `Cap` — cap enum + shared constants.
//!
//! Cap types and their inner storage use the default `Global` allocator
//! (= std heap on host, talc on guest via `#[global_allocator]`).
//!
//! `Cap::CNode` slots and `Cap::Instance.root_cnode` hold
//! [`CapHashOrRef::Ref`] (a `super::cache::CapRef`) directly, so cloning
//! a Cap deep-bumps every nested handle and dropping a Cap deep-releases
//! them. Recursive cleanup is automatic via Rust's Drop semantics; cycles
//! are structurally impossible (data-flow principle: no shared mutable
//! state across Instance boundaries). See [`super::cache::CapRef`] for
//! the handle's full lifecycle.

use alloc::vec::Vec;

use super::cache::CapHashOrRef;
use super::cnode::CNodeCap;
use super::data::DataCap;
use super::image_cap::ImageCap;
use super::instance::InstanceCap;

/// 32-byte digest used for all v3 cap identity / content hashes.
pub type CapHash = [u8; 32];

/// Number of PVM general-purpose registers (φ\[0\]..φ\[12\]).
pub const NUM_REGS: usize = 13;

/// Maximum depth of a `MemoryMapping.source_path`. v3 cap graphs
/// stay shallow; eight is plenty.
pub const MAX_SOURCE_DEPTH: usize = 8;

/// Maximum number of endpoints per Image.
pub const MAX_ENDPOINTS: usize = 64;

/// One of the five v3 cap kinds.
///
/// **SSZ note**: the `HashTreeRoot` derive treats `Cap` as an SSZ
/// Union over the five variants. Each variant's selector provides the
/// domain separation that the legacy byte-protocol kind tags
/// (`0x10..0x50`) provided; the per-variant root is computed by that
/// variant's own `HashTreeRoot` impl. We do not derive `Encode +
/// Decode` on `Cap` itself; caps move through the cache by direct
/// allocation and aren't wire-transmitted at this layer.
///
/// **Clone**: the derived `Clone` recursively clones field-by-field.
/// `Cap::Instance` and `Cap::CNode` carry `CapHashOrRef` values; the
/// `Ref(CapRef)` arm `Arc::clone`s the handle, so cloning a Cap
/// deep-bumps every nested instance reference. Drop is symmetric.
#[derive(Clone, Debug, ssz_derive::HashTreeRoot)]
pub enum Cap {
    #[ssz(selector = 0)]
    Instance(InstanceCap),
    #[ssz(selector = 1)]
    Image(ImageCap),
    #[ssz(selector = 2)]
    Data(DataCap),
    #[ssz(selector = 3)]
    CNode(CNodeCap),
    #[ssz(selector = 4)]
    Type(TypeCap),
}

/// `Cap::Type` payload. Pure identifier; no owned content, so no
/// allocator parameter needed.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    ssz_derive::Encode,
    ssz_derive::Decode,
    ssz_derive::HashTreeRoot,
)]
pub struct TypeCap {
    pub image_hash_chain: CapHash,
}

/// Discriminant for `Cap`. Useful for matching, error messages, and
/// places where the payload is irrelevant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CapKind {
    Instance,
    Image,
    Data,
    CNode,
    Type,
}

impl Cap {
    pub fn kind(&self) -> CapKind {
        match self {
            Cap::Instance(_) => CapKind::Instance,
            Cap::Image(_) => CapKind::Image,
            Cap::Data(_) => CapKind::Data,
            Cap::CNode(_) => CapKind::CNode,
            Cap::Type(_) => CapKind::Type,
        }
    }

    /// 32-byte content hash. Walks the cap tree via SSZ `HashTreeRoot`
    /// with SHA-256 as the digest; the five variants get their domain
    /// separation from the SSZ Union selector.
    ///
    /// **Substitution invariants** preserved by hand-written
    /// `HashTreeRoot` impls on [`super::page::PageSlot`],
    /// [`super::page::PageBytes`], and [`CapHashOrRef`]:
    /// - `PageSlot::Loaded(p)` hashes identically to
    ///   `PageSlot::Missing(p.hash)` — a freshly-loaded page
    ///   substitutes for a missing page without changing the
    ///   enclosing cap's hash.
    /// - `CapHashOrRef::Hash(h)` hashes to `h` exactly — a freshly-
    ///   published cap blob substitutes for a `CapRef` reference
    ///   without changing the enclosing cap's hash.
    ///
    /// **Unresolved refs panic**: hashing a cap whose graph still
    /// contains `CapHashOrRef::Ref(_)` targets will panic. Callers
    /// must `settle` the cap graph first.
    ///
    /// **Image hash distinction**: `Cap::Image(_).cap_hash()` and
    /// `crate::image::image_content_hash` hash different types — the
    /// cap-resident `ImageCap` has a flatter layout than the SCALE
    /// `Image`. The cache publishes by `cap_hash`; the image-hash
    /// chain protocol uses `image_content_hash`.
    pub fn cap_hash(&self) -> CapHash {
        ssz::hash_tree_root(self)
    }

    /// Build a heap `Cap::Data` whose content is `bytes` padded up to
    /// the next [`PAGE_SIZE`](super::data::PAGE_SIZE) boundary with
    /// zeros. The backing allocation is page-aligned so the kernel
    /// can later map the cap's pages directly into a ring-3 PT.
    ///
    /// `DataCap.content_len()` returns the padded length (always a
    /// 4 KiB-multiple). There is no separate logical-size field;
    /// callers needing a shorter logical payload (e.g. variable-length
    /// args) interpret the meaningful prefix themselves.
    pub fn data_inline(bytes: &[u8]) -> Self {
        let mut buf = super::data::alloc_page_aligned_zeroed(bytes.len());
        buf[..bytes.len()].copy_from_slice(bytes);
        Cap::Data(DataCap {
            content: super::data::DataContent::Inline(buf),
        })
    }

    /// Build a heap `Cap::Data` whose backing buffer is at least
    /// `target_size` bytes (rounded up to the next page boundary).
    /// `bytes` is copied to the start of the buffer; the remainder is
    /// zero-padded. Used by callers that need a cap matching a specific
    /// `MemoryMapping.size` from an image manifest (e.g. genesis +
    /// transpiler-emitted initial data).
    ///
    /// If `target_size < bytes.len()`, the buffer is sized to fit
    /// `bytes` (still page-multiple) — i.e. `target_size` is a floor,
    /// not a ceiling.
    pub fn data_inline_with_size(bytes: &[u8], target_size: u64) -> Self {
        let target = (target_size as usize).max(bytes.len());
        let mut buf = super::data::alloc_page_aligned_zeroed(target);
        buf[..bytes.len()].copy_from_slice(bytes);
        Cap::Data(DataCap {
            content: super::data::DataContent::Inline(buf),
        })
    }

    /// Build a heap `Cap::Image` from a SCALE `Image` value. Pinned
    /// and initial slot references are left empty; callers that need
    /// them should drive [`super::image_cap::image_cap`] directly
    /// with the already-resolved `(slot, CapHash)` pairs.
    pub fn image_from(
        image: &crate::image::Image,
    ) -> Result<Self, super::image_cap::ImageConvertError> {
        Ok(Cap::Image(super::image_cap::image_cap(image, &[], &[])?))
    }

    /// Build an empty heap `Cap::CNode` of `2^size_log` slots. Rejects
    /// `size_log > 16`.
    pub fn empty_cnode(size_log: u8) -> Result<Self, crate::error::CapError> {
        Ok(Cap::CNode(CNodeCap::new(size_log)?))
    }

    /// Build a heap `Cap::Image` from a SCALE `Image` plus the caller-resolved
    /// pinned/initial slot `CapHash` pairs.
    ///
    /// Wraps [`super::image_cap::image_cap`] with the `Cap::Image`
    /// constructor. Use this when the caller has already
    /// published (or knows the hashes of) the pinned/initial data blobs that
    /// the image references.
    pub fn image_with_slots(
        image: &crate::image::Image,
        pinned_hashes: &[(crate::slot::SlotIdx, CapHash)],
        initial_hashes: &[(crate::slot::SlotIdx, CapHash)],
    ) -> Result<Self, super::image_cap::ImageConvertError> {
        Ok(Cap::Image(super::image_cap::image_cap(
            image,
            pinned_hashes,
            initial_hashes,
        )?))
    }

    /// Build a heap `Cap::Instance` directly from field values. Mirrors the
    /// shape the old `CacheDirectory::publish_instance_blob` reconstructed
    /// field-by-field but produces a `Cap::Instance(InstanceCap)`
    /// the caller owns.
    ///
    /// `rw_overlays` is the list of `(start_va, bytes)` overlays the
    /// Instance carries — each becomes one `RwOverlay` entry.
    #[allow(clippy::too_many_arguments)]
    pub fn instance_with_overlays(
        image_hash_chain: CapHash,
        image_hash: CapHash,
        root_cnode: CapHash,
        rw_overlays: &[(u32, &[u8])],
        mem_size: u32,
        regs: [u64; NUM_REGS],
        pc: u64,
        gas_remaining: u64,
    ) -> Self {
        let mut overlays: Vec<super::instance::RwOverlay> = Vec::new();
        for (start, bytes) in rw_overlays {
            let mut buf = Vec::with_capacity(bytes.len());
            buf.extend_from_slice(bytes);
            overlays.push(super::instance::RwOverlay {
                start: *start,
                bytes: buf,
            });
        }
        Cap::Instance(super::instance::InstanceCap {
            image_hash_chain,
            image_hash,
            root_cnode: CapHashOrRef::Hash(root_cnode),
            rw_overlays: overlays,
            mem_size,
            regs,
            pc,
            gas_remaining,
        })
    }
}
