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
///
/// **SSZ note**: `CapHashOrRef`'s `HashTreeRoot` impl is hand-rolled
/// (see below), not derived. The pass-through semantics — `Hash(h)`
/// hashes to `h` — let a freshly-published cap substitute for a
/// `Ref` reference without changing the hash of any cap that holds
/// it. The `Ref` arm panics: callers must `settle` a cap graph before
/// hashing it. We deliberately do not derive `Encode + Decode` either,
/// because `CapHashOrRef` never appears on the wire (it lives only
/// in the cache).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CapHashOrRef {
    Hash(CapHash),
    Ref(CapRef),
}

impl ssz::HashTreeRoot for CapHashOrRef {
    fn hash_tree_root<D: ::ssz::digest::Digest<OutputSize = ::ssz::digest::typenum::U32>>(
        &self,
    ) -> [u8; 32] {
        match self {
            CapHashOrRef::Hash(h) => *h,
            CapHashOrRef::Ref(_) => {
                panic!("cap_hash: unresolved CapRef in cap graph; settle first")
            }
        }
    }
}

// `Encode`/`Decode` on `CapHashOrRef` is a standard SSZ Union: selector
// 0 + 32 bytes for `Hash`, selector 1 + 8 bytes for `Ref`. These exist so
// derives on outer types (`CNodeSlotEntry`, `InstanceCap`) can compose
// the SSZ wire form; in practice these wire encodings aren't transmitted
// (caps are in-process state), but providing them keeps the derive set
// consistent.
impl ssz::Encode for CapHashOrRef {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        ssz::BYTES_PER_LENGTH_OFFSET
    }
    fn ssz_bytes_len(&self) -> usize {
        match self {
            CapHashOrRef::Hash(_) => 1 + 32,
            CapHashOrRef::Ref(_) => 1 + 8,
        }
    }
    fn ssz_append<A: allocator_api2::alloc::Allocator + Clone>(
        &self,
        buf: &mut allocator_api2::vec::Vec<u8, A>,
    ) {
        match self {
            CapHashOrRef::Hash(h) => {
                buf.push(0);
                buf.extend_from_slice(h);
            }
            CapHashOrRef::Ref(r) => {
                buf.push(1);
                buf.extend_from_slice(&r.to_le_bytes());
            }
        }
    }
}

impl ssz::Decode for CapHashOrRef {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        ssz::BYTES_PER_LENGTH_OFFSET
    }
    fn from_ssz_bytes_in<A: allocator_api2::alloc::Allocator + Clone>(
        bytes: &[u8],
        _alloc: A,
    ) -> Result<Self, ssz::DecodeError> {
        if bytes.is_empty() {
            return Err(ssz::DecodeError::UnexpectedEof {
                expected: 1,
                actual: 0,
            });
        }
        match bytes[0] {
            0 => {
                if bytes.len() != 1 + 32 {
                    return Err(ssz::DecodeError::UnexpectedEof {
                        expected: 1 + 32,
                        actual: bytes.len(),
                    });
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&bytes[1..1 + 32]);
                Ok(CapHashOrRef::Hash(h))
            }
            1 => {
                if bytes.len() != 1 + 8 {
                    return Err(ssz::DecodeError::UnexpectedEof {
                        expected: 1 + 8,
                        actual: bytes.len(),
                    });
                }
                let arr: [u8; 8] = bytes[1..1 + 8].try_into().expect("len checked");
                Ok(CapHashOrRef::Ref(u64::from_le_bytes(arr)))
            }
            v => Err(ssz::DecodeError::InvalidSelector(v)),
        }
    }
}

/// Number of PVM general-purpose registers (φ\[0\]..φ\[12\]).
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
///
/// **SSZ note**: the `HashTreeRoot` derive treats `Cap<A>` as an SSZ
/// Union over the five variants. Each variant's selector provides the
/// domain separation that the legacy byte-protocol kind tags
/// (`0x10..0x50`) provided; the per-variant root is computed by that
/// variant's own `HashTreeRoot` impl. We do not derive `Encode +
/// Decode` on `Cap<A>` itself; caps move through the cache by direct
/// allocation and aren't wire-transmitted at this layer.
#[derive(Clone, Debug, ssz_derive::HashTreeRoot)]
pub enum Cap<A: Allocator + Clone = Global> {
    #[ssz(selector = 0)]
    Instance(InstanceCap<A>),
    #[ssz(selector = 1)]
    Image(ImageCap<A>),
    #[ssz(selector = 2)]
    Data(DataCap<A>),
    #[ssz(selector = 3)]
    CNode(CNodeCap<A>),
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
        Self::data_inline_with_size(bytes, bytes.len() as u64)
    }

    /// Build a heap `Cap::Data` with an explicit logical `size` that
    /// may exceed `bytes.len()` (e.g. zero-padded paged data, or a
    /// pinned `.bss`-style region with non-empty initial content but a
    /// larger declared size).
    pub fn data_inline_with_size(bytes: &[u8], size: u64) -> Self {
        let mut buf = allocator_api2::vec::Vec::with_capacity_in(bytes.len(), Global);
        buf.extend_from_slice(bytes);
        Cap::Data(DataCap {
            size,
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

    /// Build a heap `Cap::Image` from a SCALE `Image` plus the caller-resolved
    /// pinned/initial slot `CapHash` pairs.
    ///
    /// Wraps [`super::image_cap::image_cap_in`] with `A = Global` and the
    /// `Cap::Image` constructor. Use this when the caller has already
    /// published (or knows the hashes of) the pinned/initial data blobs that
    /// the image references.
    pub fn image_with_slots(
        image: &crate::image::Image,
        pinned_hashes: &[(crate::slot::SlotIdx, CapHash)],
        initial_hashes: &[(crate::slot::SlotIdx, CapHash)],
    ) -> Result<Self, super::image_cap::ImageConvertError> {
        Ok(Cap::Image(super::image_cap::image_cap_in(
            image,
            pinned_hashes,
            initial_hashes,
            Global,
        )?))
    }

    /// Build a heap `Cap::Instance` directly from field values. Mirrors the
    /// shape the old `Cache::publish_instance_blob` reconstructed
    /// field-by-field but produces a `Cap::Instance(InstanceCap<Global>)`
    /// the caller owns.
    ///
    /// `rw_overlays` is the list of `(start_va, bytes)` overlays the
    /// Instance carries — each becomes one `RwOverlay<Global>` entry.
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
        let mut overlays: allocator_api2::vec::Vec<super::instance::RwOverlay<Global>, Global> =
            allocator_api2::vec::Vec::new_in(Global);
        for (start, bytes) in rw_overlays {
            let mut buf = allocator_api2::vec::Vec::with_capacity_in(bytes.len(), Global);
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
