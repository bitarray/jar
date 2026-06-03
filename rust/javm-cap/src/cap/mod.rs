//! `Cap` — cap enum + shared constants.
//!
//! The five Cap variants live one-per-submodule under this directory:
//! [`cnode`], [`data`], [`image`], [`instance`], [`page`] (a `data`
//! detail). The root [`Cap`] enum dispatches to those structs.
//!
//! Cap types and their inner storage use the default `Global` allocator
//! (= std heap on host, talc on guest via `#[global_allocator]`).
//!
//! ## Wire form
//!
//! `Cap` itself is the wire form. It derives
//! `rkyv::Archive`/`Serialize`/`Deserialize` so callers write
//! `rkyv::to_bytes(&cap)?` directly. The slot-target
//! [`super::cache::CapHashOrRef`] has a hand-rolled rkyv impl whose
//! `Serialize` returns an error ([`super::cache::CapHasRefError`]) if
//! the cap graph still contains a `Ref`. The
//! archived form for both `Hash` and `Ref` arms is `[u8; 32]` (= the
//! `CapHash` archived form), so settled cap graphs serialise to the
//! same bytes regardless of provenance, and `Ref`-bearing graphs
//! surface as a typed `Result::Err` at encode time (no panic).
//!
//! See [`super::cache::CapRef`] for the cache-handle lifecycle and
//! `Cap`-cloning semantics.

pub mod cnode;
pub mod data;
pub mod image;
pub mod instance;
pub mod page;
pub mod view;

use cnode::CNodeCap;
use data::DataCap;
use image::ImageCap;
use instance::InstanceCap;
use view::DataViewCap;

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
/// allocation and aren't wire-transmitted at this SSZ-encoded layer.
///
/// **rkyv note**: the `Archive`/`Serialize`/`Deserialize` derives
/// provide the I/O-boundary wire form. Serialization errors out (no
/// panic) if any slot target is a `CapHashOrRef::Ref` — see the
/// module docs.
///
/// **Clone**: the derived `Clone` recursively clones field-by-field.
/// `Ref(CapRef)` arms `Arc::clone` the handle, deep-bumping every
/// nested instance reference. Drop is symmetric.
#[derive(
    Clone, Debug, ssz_derive::HashTreeRoot, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
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
    #[ssz(selector = 5)]
    DataView(DataViewCap),
}

/// `Cap::Type` payload. Pure identifier; no slot references.
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
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct TypeCap {
    pub image_hash_chain: CapHash,
}

impl Cap {
    /// 32-byte content hash. Walks the cap tree via SSZ `HashTreeRoot`
    /// with SHA-256 as the digest; the five variants get their domain
    /// separation from the SSZ Union selector.
    ///
    /// **Substitution invariants** preserved by hand-written
    /// `HashTreeRoot` impls on [`page::PageSlot`], [`page::PageBytes`],
    /// and [`super::cache::CapHashOrRef`]:
    /// - `PageSlot::Loaded(p)` hashes identically to
    ///   `PageSlot::Missing(p.hash)` — a freshly-loaded page
    ///   substitutes for a missing page without changing the
    ///   enclosing cap's hash.
    /// - `CapHashOrRef::Hash(h)` hashes to `h` exactly — a freshly-
    ///   published cap blob substitutes for a `CapRef` reference
    ///   without changing the enclosing cap's hash.
    ///
    /// **Unresolved refs panic**: hashing a `Cap` whose graph still
    /// contains `CapHashOrRef::Ref(_)` targets will panic in the SSZ
    /// path. Callers must `settle` the cap graph first. (The rkyv
    /// serialise path is fallible for the same case — see the module
    /// docs.)
    ///
    /// **Image hash distinction**: `Cap::Image(_).cap_hash()` and
    /// `crate::image::image_content_hash` hash different types — the
    /// cap-resident `ImageCap` has a flatter layout than the SSZ
    /// `Image`. The cache publishes by `cap_hash`; the image-hash
    /// chain protocol uses `image_content_hash`.
    pub fn cap_hash(&self) -> CapHash {
        ssz::hash_tree_root(self)
    }

    /// Build a heap `Cap::Data` whose content is `bytes` padded up to
    /// the next [`PAGE_SIZE`](data::PAGE_SIZE) boundary with
    /// zeros. The backing allocation is page-aligned so the kernel
    /// can later map the cap's pages directly into a ring-3 PT.
    ///
    /// `DataCap.content_len()` returns the padded length (always a
    /// 4 KiB-multiple). There is no separate logical-size field;
    /// callers needing a shorter logical payload (e.g. variable-length
    /// args) interpret the meaningful prefix themselves.
    pub fn data_inline(bytes: &[u8]) -> Self {
        Cap::Data(DataCap::from_bytes(bytes))
    }

    /// Build a heap `Cap::Data` whose logical size is at least `target_size`
    /// bytes (rounded up to the next page boundary). `bytes` fills the low
    /// bytes; the remainder is zero (sparse).
    pub fn data_inline_with_size(bytes: &[u8], target_size: u64) -> Self {
        Cap::Data(DataCap::from_bytes_sized(bytes, target_size))
    }

    /// Build an empty heap `Cap::CNode`. A CNode is an unbounded
    /// hash-keyed map (bounded by storage quota), so there is no
    /// `size_log` to declare.
    pub fn empty_cnode() -> Self {
        Cap::CNode(CNodeCap::new())
    }

    /// Build a heap `Cap::Image` from an SSZ `Image` plus the
    /// caller-resolved pinned/initial slot `CapHash` pairs.
    pub fn image_with_slots(
        image: &crate::image::Image,
        pinned_hashes: &[(crate::slot::Key, CapHash)],
        initial_hashes: &[(crate::slot::Key, CapHash)],
    ) -> Result<Self, image::ImageConvertError> {
        Ok(Cap::Image(image::image_cap(
            image,
            pinned_hashes,
            initial_hashes,
        )?))
    }

    /// Build a heap `Cap::Instance` directly from field values.
    ///
    /// `mem` is the Instance's read-write memory image (a dense [`DataCap`]
    /// covering the data extent; pinned read-only mappings are not part of it —
    /// see [`instance::InstanceCap::mem`]).
    #[allow(clippy::too_many_arguments)]
    pub fn instance_with_mem(
        image_hash_chain: CapHash,
        image_hash: CapHash,
        root_cnode: CapHash,
        mem: DataCap,
        regs: [u64; NUM_REGS],
        pc: u64,
        gas_remaining: u64,
    ) -> Self {
        Cap::Instance(instance::InstanceCap {
            image_hash_chain,
            image_hash,
            root_cnode: crate::cache::CapHashOrRef::Hash(root_cnode),
            mem,
            regs,
            pc,
            gas_remaining,
        })
    }
}
