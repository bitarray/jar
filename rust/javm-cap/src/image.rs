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
use crate::slot::SlotIdx;
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
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, ssz_derive::HashTreeRoot)]
pub struct Image {
    /// Bytecode bytes (validated at construction; see `host_make_image`).
    pub code: Vec<u8>,
    /// Packed bitmask, one bit per `code` byte, LSB-first.
    /// `packed_bitmask.len() == code.len().div_ceil(8)`. A `1` bit
    /// marks the start of an instruction; a `0` bit marks a
    /// continuation byte. Use `javm_exec::unpack_bitmask` to
    /// recover the unpacked form at decode time.
    pub packed_bitmask: Vec<u8>,
    /// Jump-table entries (PVM PCs into `code`). Indexed by
    /// `djump` immediates.
    pub jump_table: Vec<u32>,
    /// Endpoints addressable by `endpoint_idx` (u8). Sparse — only
    /// declared endpoints are present.
    pub endpoints: BTreeMap<u8, EndpointDef>,
    /// Memory layout. Each entry maps a `Cap::Data` (resolved
    /// through `source`) into the address space at `[start, start
    /// + size)`. Permissions are derived from whether the target
    /// slot appears in `pinned_slots` (RO) or not (RW).
    pub memory_mappings: Vec<MemoryMapping>,
    /// Cnode slots holding `Cap::Instance[Gas{meter_id}]`. Active
    /// gas debit comes from the first slot's meter; the rest are
    /// fallback reserves (chain-spec policy).
    pub gas_slots: Vec<SlotIdx>,
    /// Cnode slots holding `Cap::Instance[Quota{quota_id}]`.
    /// Symmetric with `gas_slots`.
    pub quota_slots: Vec<SlotIdx>,
    /// Pinned read-only caps (Cap::Data or Cap::Image) baked into
    /// the spec. The kernel rejects mutations to these slots.
    pub pinned_slots: BTreeMap<SlotIdx, PinnedCap>,
    /// Initial cnode state for non-pinned mutable slots. Only
    /// honored at standalone (root) Instance bootstrap — a
    /// parented Instance receives its cnode from the spawner.
    pub initial_slots: BTreeMap<SlotIdx, InitialDataCap>,
    /// Slot holding `Cap::Instance[YieldCatcher]`, if this Instance
    /// catches yields. None = no catcher.
    pub yield_marker_slot: Option<SlotIdx>,
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

/// One mapped region. The kernel resolves `source` at instance
/// start, reads the bytes from the resulting `Cap::Data`, and lays
/// them at `[start, start + size)` in the address space. Whether
/// the region is RO or RW is derived from whether `source.target()`
/// is in `Image.pinned_slots`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, ssz_derive::HashTreeRoot)]
pub struct MemoryMapping {
    pub start: u64,
    pub size: u64,
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
            packed_bitmask: Vec::new(),
            jump_table: Vec::new(),
            endpoints: BTreeMap::new(),
            memory_mappings: Vec::new(),
            gas_slots: Vec::new(),
            quota_slots: Vec::new(),
            pinned_slots: BTreeMap::new(),
            initial_slots: BTreeMap::new(),
            yield_marker_slot: None,
        }
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
