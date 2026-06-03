//! Image: the smallest unit of program specification.
//!
//! An `Image` is content-addressed (its `image_id` is the hash of
//! its serialized content). An Instance's `image_hash` is the
//! cumulative chain hash tracking the lineage of `set_image` /
//! `host_derive_spawn` extensions from genesis.
//!
//! ```text
//! genesis (host_derive_spawn from no source):
//!     image_hash = hash(image)
//!
//! after set_image(new):
//!     image_hash = hash(prev_chain || hash(new))
//!
//! after host_derive_spawn(new, cnode) by a spawner:
//!     spawned.image_hash = hash(spawner.image_hash || hash(new))
//!
//! after MGMT_COPY of a Cap::Instance:
//!     copy.image_hash = source.image_hash   (preserved)
//! ```
//!
//! This module provides the pure data structures + the chain-hash
//! computations. Image *content hashing* is done by serializing the
//! Image canonically and feeding the bytes to `H::hash`; we provide
//! a simple deterministic encoder here so the v3 implementation
//! has one canonical form.

use crate::hash::Hash;
use crate::slot::Key;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use ssz_derive::{Decode, Encode};

/// Image: the program spec (code, endpoints, memory layout, slot
/// declarations, pinned ro caps).
///
/// `pinned_slots` and `yield_marker_slot` reference cnode slots; the
/// kernel installs declared pinned content into the Instance's cnode
/// at `set_image` / `host_derive_spawn` time and treats them as
/// read-only thereafter.
///
/// **Validation model.** This is the untrusted SSZ wire form; converting
/// it to a [`crate::cap::image::ImageCap`] via
/// [`crate::cap::image::image_cap`] is the "deblob" that validates the
/// Image's *structure* eagerly (sizes, bounds, slot indices, path depth).
/// The `code` *bytes* are never screened — instruction *semantics* are
/// validated lazily, at execution. See [`crate::cap::image::ImageCap`] for
/// the full structure-eager / semantics-lazy rationale.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, ssz_derive::HashTreeRoot)]
pub struct Image {
    /// The (single) code region: raw RV+C+custom-0 bytes. Mapped RO at
    /// the fixed protocol constant [`crate::layout::CODE_BASE`] (PC =
    /// `CODE_BASE + byte_offset`) — the load address is *not* chosen by
    /// the Image, so an untrusted Image cannot place code arbitrarily.
    /// Code is mapped RO into the guest address space so the guest can
    /// read its own bytes (AUIPC+load PIC); the JIT executes the native
    /// translation. Empty for codeless images (kernel placeholders).
    pub code: Vec<u8>,
    /// Endpoints addressable by `endpoint_idx` (u8). Sparse — only
    /// declared endpoints are present.
    pub endpoints: BTreeMap<u8, EndpointDef>,
    /// Memory layout. Each entry maps a `Cap::Data` (resolved through
    /// the `source` slot path) into the address space at `[start, start
    /// + size)`. RO vs RW is derived from whether the target slot
    /// appears in `pinned_slots`. Code is mapped separately at
    /// [`crate::layout::CODE_BASE`] and is not described here.
    pub memory_mappings: Vec<MemoryMapping>,
    /// Pinned read-only caps (Cap::Data or Cap::Image) baked into
    /// the spec. The kernel rejects mutations to these slots.
    pub pinned_slots: BTreeMap<Key, PinnedCap>,
    /// Initial cnode state for non-pinned mutable slots. Only
    /// honored at standalone (root) Instance bootstrap — a
    /// parented Instance receives its cnode from the spawner.
    pub initial_slots: BTreeMap<Key, InitialDataCap>,
    /// Slot holding `Cap::Instance[YieldCatcher]`, if this Instance
    /// catches yields. None = no catcher.
    pub yield_marker_slot: Option<Key>,
}

/// Endpoint definition: entry PC + register conventions.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, ssz_derive::HashTreeRoot)]
pub struct EndpointDef {
    /// Bytecode address to jump to.
    pub entry_pc: u64,
    /// Number of register args supplied by the caller (0..=4
    /// per spec convention; we store as u8 for flexibility).
    pub arg_registers: u8,
    /// Size of the arg cnode the caller may attach.
    pub arg_cnode_size: u8,
    /// PVM registers to seed before entering the endpoint. Keyed
    /// by register index (0..=12). Common usage: φ\[1\] (RISC-V SP)
    /// ← `stack_top`. The kernel applies these on top of the
    /// calling-convention defaults (φ\[11\] = endpoint_idx).
    pub initial_regs: BTreeMap<u8, u64>,
}

/// One mapped region. The kernel resolves `source` (a cnode slot path
/// to a `Cap::Data`) at instance start and lays the bytes at `[start,
/// start + size)` in the address space. RO vs RW is derived from
/// whether the target slot is in `Image.pinned_slots`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, ssz_derive::HashTreeRoot)]
pub struct MemoryMapping {
    pub start: u64,
    pub size: u64,
    /// Cnode path resolving to the `Cap::Data` whose bytes back this
    /// region.
    pub source: crate::slot::SlotPath,
}

/// Pinned slot content. Only content-addressed cap kinds can be
/// pinned (Data or Image). `Cap::Data` bytes are inlined in the
/// Image; a future optimisation can add a hash-only variant for
/// content that lives in σ.data_payloads.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, ssz_derive::HashTreeRoot)]
pub enum PinnedCap {
    #[ssz(selector = 0)]
    /// Pinned `Cap::Data` with bytes baked into the Image. `size`
    /// may be larger than `content.len()`; trailing bytes are
    /// zero-filled per the DataCap canonical form.
    Data { content: Vec<u8>, size: u64 },
    #[ssz(selector = 1)]
    /// Pinned `Cap::Image` by content hash. Cap::Image is itself
    /// content-addressed; inlining a whole sub-Image makes less
    /// sense than for Data.
    Image { content_hash: [u8; 32] },
}

/// Initial `Cap::Data` content for a non-pinned mutable slot. Used
/// at standalone (root) Instance bootstrap to seed the cnode. A
/// parented Instance receives its slots from the spawner and
/// ignores this field.
#[derive(Debug, Clone, Default, PartialEq, Eq, Encode, Decode, ssz_derive::HashTreeRoot)]
pub struct InitialDataCap {
    /// Initial bytes. May be empty for zero-filled regions like
    /// stack and heap.
    pub content: Vec<u8>,
    /// Logical size of the cap. `size` may be larger than
    /// `content.len()`; trailing bytes are zero-filled when the
    /// cap is mapped.
    pub size: u64,
}

impl Image {
    /// Empty Image: no code, no endpoints, no mappings, no slots.
    /// Useful for tests and as a starting point.
    pub fn empty() -> Self {
        Self {
            code: Vec::new(),
            endpoints: BTreeMap::new(),
            memory_mappings: Vec::new(),
            pinned_slots: BTreeMap::new(),
            initial_slots: BTreeMap::new(),
            yield_marker_slot: None,
        }
    }

    /// The Instance data extent in bytes: `mem_top − DATA_BASE`, page-rounded
    /// (the size of the RW memory `DataCap`). Code is RO direct-mapped at
    /// `CODE_BASE`, so it contributes nothing here.
    pub fn mem_extent(&self) -> u64 {
        let mut mem_top: u32 = 0;
        for mapping in &self.memory_mappings {
            let end = (mapping.start + mapping.size) as u32;
            if end > mem_top {
                mem_top = end;
            }
        }
        (mem_top as u64)
            .saturating_sub(crate::layout::DATA_BASE as u64)
            .next_multiple_of(crate::cap::data::PAGE_SIZE as u64)
    }

    /// Build the Instance's memory backing [`crate::DataCap`]: every mapping's source
    /// content (pinned **and** initial) folded at the mapping's offset above
    /// `DATA_BASE`. This is the same byte layout the legacy `data_overlays`
    /// produced, collapsed into one dense `DataCap`.
    ///
    /// Pinned content is included here (not kept separate) so the cache-free
    /// `nub-arch-local` engine can seed memory without resolving caps; both
    /// engines still mark the pinned VAs read-only at seed time, and the
    /// recompiler maps them as `PinnedCapRo` directly from these slabs, so the
    /// pinned-RO gas tier is preserved.
    ///
    /// Single source of truth for Instance memory layout: both engines seed
    /// from this backing, so they materialize byte-identical memory.
    pub fn instance_mem_backing(&self) -> crate::cap::data::DataCap {
        use crate::cap::data::{DataCap, PAGE_SIZE};
        let size = self.mem_extent().max(PAGE_SIZE as u64);
        let mut backing = DataCap::from_bytes_sized(&[], size);
        let data_base = crate::layout::DATA_BASE as u64;
        for mapping in &self.memory_mappings {
            let Some(target) = mapping.source.target() else {
                continue;
            };
            let content: &[u8] =
                if let Some(PinnedCap::Data { content, .. }) = self.pinned_slots.get(target) {
                    content
                } else if let Some(init) = self.initial_slots.get(target) {
                    &init.content
                } else {
                    continue;
                };
            if content.is_empty() {
                continue;
            }
            let base_off = mapping.start.saturating_sub(data_base);
            for (i, chunk) in content.chunks(PAGE_SIZE).enumerate() {
                backing.put_page(base_off + (i * PAGE_SIZE) as u64, chunk);
            }
        }
        backing
    }
}

/// Content hash of an Image: SSZ `hash_tree_root` (SHA-256 merkleization
/// of the derived SSZ container). The canonical encoding/merkleization is
/// defined by `Image`'s `ssz-derive` impl.
pub fn image_content_hash(image: &Image) -> [u8; 32] {
    ssz::hash_tree_root(image)
}

/// Genesis image-hash chain: a freshly-derived Instance (with no
/// prior chain) has `image_hash = image_content_hash`.
///
/// This is the case for the very first Instance the chain spec
/// produces. Subsequent Instances always derive from some spawner
/// via `chain_extend`.
pub fn chain_genesis<H: Hash>(image: &Image) -> H::Out
where
    H::Out: From<[u8; 32]>,
{
    image_content_hash(image).into()
}

/// Extend an image-hash chain with a new image:
/// `result = H(prev_chain || image_content_hash(new_image))`.
///
/// Used for both `set_image(new)` on an existing Instance and
/// `host_derive_spawn(new, cnode)` from a spawner.
pub fn chain_extend<H: Hash>(prev_chain: &H::Out, new_image: &Image) -> H::Out
where
    H::Out: AsRef<[u8]>,
{
    let new_image_hash = image_content_hash(new_image);
    H::hash_pair(prev_chain.as_ref(), &new_image_hash)
}
