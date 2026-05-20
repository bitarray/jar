//! `Cap<A>` — allocator-parameterised cap enum + shared constants.

use allocator_api2::alloc::{Allocator, Global};

use super::cnode::CNodeCap;
use super::data::DataCap;
use super::image_cap::ImageCap;
use super::instance::InstanceCap;

/// 32-byte digest used for all v3 cap identity / content hashes.
pub type CapHash = [u8; 32];

/// Monotonic, cache-local handle for a mutable working entry in
/// `cache.instances`. Two separate `Cache` instances produce
/// independent `CapRef` namespaces; refs must not be serialised
/// across caches.
pub type CapRef = u64;

/// Slot/field reference: either a content-addressed blob in
/// `cache.blobs` or a mutable working entry in `cache.instances`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CapHashOrRef {
    Hash(CapHash),
    Ref(CapRef),
}

/// Number of PVM general-purpose registers (φ[0]..φ[12]).
pub const NUM_REGS: usize = 13;

/// Maximum depth of a `MemoryMapping.source_path`. v3 cap graphs
/// stay shallow; eight is plenty.
pub const MAX_SOURCE_DEPTH: usize = 8;

/// Maximum number of endpoints per Image stored in the cache.
/// Matches `nub_host_common::cache::MAX_ENDPOINTS`.
pub const MAX_ENDPOINTS: usize = 64;

/// One of the five v3 cap kinds.
///
/// The default allocator is `Global` (heap) so existing callers that
/// just say `Cap` continue to work. The cache layer instantiates
/// `Cap<TalcAlloc>` so the content lives in shared talc memory.
#[derive(Clone, Debug)]
pub enum Cap<A: Allocator + Clone = Global> {
    Instance(InstanceCap<A>),
    Image(ImageCap<A>),
    Data(DataCap<A>),
    CNode(CNodeCap<A>),
    Type(TypeCap),
}

/// `Cap::Type` payload. Pure identifier; no owned content, so no
/// allocator parameter needed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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

impl<A: Allocator + Clone> Cap<A> {
    pub fn kind(&self) -> CapKind {
        match self {
            Cap::Instance(_) => CapKind::Instance,
            Cap::Image(_) => CapKind::Image,
            Cap::Data(_) => CapKind::Data,
            Cap::CNode(_) => CapKind::CNode,
            Cap::Type(_) => CapKind::Type,
        }
    }
}

// Heap-only convenience constructors. These produce `Cap<Global>`
// values without going through a `Cache`, suitable for callers (jar-
// kernel, javm) that build caps locally before publishing.
impl Cap<Global> {
    /// Build a heap `Cap::Data` whose content is `bytes` inline.
    /// `DataCap.size` is set to `bytes.len()`. Use a direct
    /// `DataCap { size, content: DataContent::Inline(...) }` build
    /// if the logical size differs from the inline byte count
    /// (e.g. zero-padded paged data).
    pub fn data_inline(bytes: &[u8]) -> Self {
        let mut buf = allocator_api2::vec::Vec::with_capacity_in(bytes.len(), Global);
        buf.extend_from_slice(bytes);
        Cap::Data(DataCap {
            size: bytes.len() as u64,
            content: super::data::DataContent::Inline(buf),
        })
    }

    /// Build a heap `Cap::Image` from a SCALE `Image` value. Pinned
    /// and initial slot references are left empty; callers that need
    /// them should drive [`super::image_cap::image_cap_in`] directly
    /// with the already-resolved `(slot, CapHash)` pairs.
    pub fn image_from(
        image: &crate::image::Image,
    ) -> Result<Self, super::image_cap::ImageConvertError> {
        Ok(Cap::Image(super::image_cap::image_cap_in(
            image,
            &[],
            &[],
            Global,
        )?))
    }

    /// Build an empty heap `Cap::CNode` of `2^size_log` slots. Rejects
    /// `size_log > 16`.
    pub fn empty_cnode(size_log: u8) -> Result<Self, crate::error::CapError> {
        Ok(Cap::CNode(CNodeCap::new(size_log)?))
    }
}
