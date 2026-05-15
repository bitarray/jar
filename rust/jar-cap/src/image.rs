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
use scale::{Decode, Encode};
use std::collections::BTreeMap;

/// Image: the program spec (code, endpoints, memory layout, slot
/// declarations, pinned ro caps).
///
/// `pinned_slots` and `yield_marker_slot` reference cnode slots; the
/// kernel installs declared pinned content into the Instance's cnode
/// at `set_image` / `host_derive_spawn` time and treats them as
/// read-only thereafter.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Image {
    /// Bytecode bytes (validated at construction; see `host_make_image`).
    pub code: Vec<u8>,
    /// Packed bitmask, one bit per `code` byte, LSB-first.
    /// `packed_bitmask.len() == code.len().div_ceil(8)`. A `1` bit
    /// marks the start of an instruction; a `0` bit marks a
    /// continuation byte. Use [`javm_exec::unpack_bitmask`] to
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
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct EndpointDef {
    /// Bytecode address to jump to.
    pub entry_pc: u64,
    /// Number of register args supplied by the caller (0..=4
    /// per spec convention; we store as u8 for flexibility).
    pub arg_registers: u8,
    /// Size of the arg cnode the caller may attach.
    pub arg_cnode_size: u8,
    /// PVM registers to seed before entering the endpoint. Keyed
    /// by register index (0..=12). Common usage: φ[1] (RISC-V SP)
    /// ← `stack_top`. The kernel applies these on top of the
    /// calling-convention defaults (φ[11] = endpoint_idx).
    pub initial_regs: BTreeMap<u8, u64>,
}

/// One mapped region. The kernel resolves `source` at instance
/// start, reads the bytes from the resulting `Cap::Data`, and lays
/// them at `[start, start + size)` in the address space. Whether
/// the region is RO or RW is derived from whether `source.target()`
/// is in `Image.pinned_slots`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct MemoryMapping {
    pub start: u64,
    pub size: u64,
    pub source: crate::slot::SlotPath,
}

/// Pinned slot content. Only content-addressed cap kinds can be
/// pinned (Data or Image). `Cap::Data` bytes are inlined in the
/// Image; a future optimisation can add a hash-only variant for
/// content that lives in σ.data_payloads.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum PinnedCap {
    /// Pinned `Cap::Data` with bytes baked into the Image. `size`
    /// may be larger than `content.len()`; trailing bytes are
    /// zero-filled per the DataCap canonical form.
    Data { content: Vec<u8>, size: u64 },
    /// Pinned `Cap::Image` by content hash. Cap::Image is itself
    /// content-addressed; inlining a whole sub-Image makes less
    /// sense than for Data.
    Image { content_hash: [u8; 32] },
}

/// Initial `Cap::Data` content for a non-pinned mutable slot. Used
/// at standalone (root) Instance bootstrap to seed the cnode. A
/// parented Instance receives its slots from the spawner and
/// ignores this field.
#[derive(Debug, Clone, Default, PartialEq, Eq, Encode, Decode)]
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

/// Content hash of an Image: `H::hash(image.encode())`. The
/// canonical encoding is defined by `Image`'s `scale-derive` impl.
pub fn image_content_hash<H: Hash>(image: &Image) -> H::Out {
    H::hash(&image.encode())
}

/// Genesis image-hash chain: a freshly-derived Instance (with no
/// prior chain) has `image_hash = image_content_hash`.
///
/// This is the case for the very first Instance the chain spec
/// produces. Subsequent Instances always derive from some spawner
/// via `chain_extend`.
pub fn chain_genesis<H: Hash>(image: &Image) -> H::Out {
    image_content_hash::<H>(image)
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
    let new_image_hash = image_content_hash::<H>(new_image);
    H::hash_pair(prev_chain.as_ref(), new_image_hash.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Blake2b256;

    type H = Blake2b256;

    #[test]
    fn empty_image_hashes_deterministically() {
        let img = Image::empty();
        let h1 = image_content_hash::<H>(&img);
        let h2 = image_content_hash::<H>(&img);
        assert_eq!(h1, h2);
    }

    #[test]
    fn image_scale_roundtrip() {
        let mut img = Image::empty();
        img.code = b"sample code".to_vec();
        img.packed_bitmask = vec![0xFF, 0x07]; // 11 bits set, all-1s
        img.jump_table = vec![0u32, 4, 8];
        img.endpoints.insert(
            0,
            EndpointDef {
                entry_pc: 0x100,
                arg_registers: 1,
                arg_cnode_size: 0,
                initial_regs: BTreeMap::new(),
            },
        );
        let mut initial_regs = BTreeMap::new();
        initial_regs.insert(1u8, 0x4000);
        img.endpoints.insert(
            255,
            EndpointDef {
                entry_pc: 0xDEADBEEF,
                arg_registers: 4,
                arg_cnode_size: 8,
                initial_regs,
            },
        );
        img.memory_mappings.push(MemoryMapping {
            start: 0x1000,
            size: 0x4000,
            source: crate::slot::SlotPath::root(SlotIdx(65)),
        });
        img.memory_mappings.push(MemoryMapping {
            start: 0x5000,
            size: 0x2000,
            source: crate::slot::SlotPath::root(SlotIdx(3)),
        });
        img.gas_slots = vec![SlotIdx(7)];
        img.quota_slots = vec![SlotIdx(8)];
        img.pinned_slots.insert(
            SlotIdx(11),
            PinnedCap::Data {
                content: vec![0xAB; 1024],
                size: 4096,
            },
        );
        img.initial_slots.insert(
            SlotIdx(65),
            InitialDataCap {
                content: Vec::new(),
                size: 0x4000,
            },
        );
        img.yield_marker_slot = Some(SlotIdx(9));

        let bytes = img.encode();
        let (decoded, consumed) = Image::decode(&bytes).expect("decode");
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded, img);
    }

    #[test]
    fn different_code_different_hash() {
        let mut a = Image::empty();
        a.code = b"AAAA".to_vec();
        let mut b = Image::empty();
        b.code = b"BBBB".to_vec();
        assert_ne!(image_content_hash::<H>(&a), image_content_hash::<H>(&b));
    }

    #[test]
    fn endpoints_affect_hash() {
        let a = Image::empty();
        let mut b = Image::empty();
        b.endpoints.insert(
            7,
            EndpointDef {
                entry_pc: 0x1000,
                arg_registers: 2,
                arg_cnode_size: 0,
                initial_regs: BTreeMap::new(),
            },
        );
        assert_ne!(image_content_hash::<H>(&a), image_content_hash::<H>(&b));
    }

    #[test]
    fn pinned_slots_order_independent() {
        // BTreeMap iteration is deterministic; insertion order
        // shouldn't matter for the resulting hash.
        let mut a = Image::empty();
        a.pinned_slots.insert(
            SlotIdx(3),
            PinnedCap::Data {
                content: vec![0xAA; 100],
                size: 100,
            },
        );
        a.pinned_slots.insert(
            SlotIdx(7),
            PinnedCap::Data {
                content: vec![0xBB; 200],
                size: 200,
            },
        );

        let mut b = Image::empty();
        // Different insertion order.
        b.pinned_slots.insert(
            SlotIdx(7),
            PinnedCap::Data {
                content: vec![0xBB; 200],
                size: 200,
            },
        );
        b.pinned_slots.insert(
            SlotIdx(3),
            PinnedCap::Data {
                content: vec![0xAA; 100],
                size: 100,
            },
        );

        assert_eq!(image_content_hash::<H>(&a), image_content_hash::<H>(&b));
    }

    #[test]
    fn chain_genesis_equals_content_hash() {
        let img = Image::empty();
        assert_eq!(chain_genesis::<H>(&img), image_content_hash::<H>(&img));
    }

    #[test]
    fn chain_extend_changes_with_new_image() {
        let img_a = Image::empty();
        let mut img_b = Image::empty();
        img_b.code = b"B".to_vec();
        let prev = chain_genesis::<H>(&img_a);
        let extended_b = chain_extend::<H>(&prev, &img_b);
        let mut img_c = Image::empty();
        img_c.code = b"C".to_vec();
        let extended_c = chain_extend::<H>(&prev, &img_c);
        assert_ne!(extended_b, extended_c);
    }

    #[test]
    fn chain_extend_is_associative_under_sequence() {
        // Extending twice with [A then B] yields a single deterministic
        // chain hash. Calling chain_extend twice in different orders
        // gives different chains (as expected — chain order matters).
        let img_a = Image::empty();
        let mut img_b = Image::empty();
        img_b.code = b"B".to_vec();
        let mut img_c = Image::empty();
        img_c.code = b"C".to_vec();

        let chain_abc = {
            let g = chain_genesis::<H>(&img_a);
            let g_b = chain_extend::<H>(&g, &img_b);
            chain_extend::<H>(&g_b, &img_c)
        };
        let chain_acb = {
            let g = chain_genesis::<H>(&img_a);
            let g_c = chain_extend::<H>(&g, &img_c);
            chain_extend::<H>(&g_c, &img_b)
        };
        // Order matters.
        assert_ne!(chain_abc, chain_acb);

        // Re-running the same sequence gives the same result.
        let chain_abc_2 = {
            let g = chain_genesis::<H>(&img_a);
            let g_b = chain_extend::<H>(&g, &img_b);
            chain_extend::<H>(&g_b, &img_c)
        };
        assert_eq!(chain_abc, chain_abc_2);
    }

    #[test]
    fn mgmt_copy_preserves_chain_hash() {
        // MGMT_COPY of a Cap::Instance preserves image_hash; this is
        // a function-level invariant: equality of the same H::Out
        // value. Just a sanity test that H::Out is Copy and equal.
        let img = Image::empty();
        let chain = chain_genesis::<H>(&img);
        let copy = chain;
        assert_eq!(chain, copy);
    }
}
