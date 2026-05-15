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
use std::collections::BTreeMap;

/// Image: the program spec (code, endpoints, memory layout, slot
/// declarations, pinned ro caps).
///
/// `pinned_slots` and `yield_marker_slot` reference cnode slots; the
/// kernel installs declared pinned content into the Instance's cnode
/// at `set_image` / `host_derive_spawn` time and treats them as
/// read-only thereafter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    /// Bytecode (validated at construction; see `host_make_image`).
    pub code: Vec<u8>,
    /// Endpoints indexed by `endpoint_idx` (0..256). `None` means
    /// "no endpoint at this index."
    pub endpoints: [Option<EndpointDef>; 256],
    /// Memory layout (declared mappings between cnode slots and
    /// the address space).
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
    /// Slot holding `Cap::Instance[YieldCatcher]`, if this Instance
    /// catches yields. None = no catcher.
    pub yield_marker_slot: Option<SlotIdx>,
}

/// Endpoint definition: entry PC + register conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointDef {
    /// Bytecode address to jump to.
    pub entry_pc: u64,
    /// Number of register args supplied by the caller (0..=4
    /// per spec convention; we store as u8 for flexibility).
    pub arg_registers: u8,
    /// Size of the arg cnode the caller may attach.
    pub arg_cnode_size: u8,
}

/// Memory mapping: a region of the address space backed by a cnode
/// slot (Persistent) or kernel-allocated for the apply (Ephemeral).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryMapping {
    pub start: u64,
    pub size: u64,
    pub source: MappingSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingSource {
    /// Backed by the DataCap at the named slot path.
    Persistent(crate::slot::SlotPath),
    /// Kernel-allocated per-apply; not in cnode.
    Ephemeral,
}

/// Pinned slot content. Only content-addressed cap kinds can be
/// pinned (Data or Image references).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinnedCap {
    /// Pinned `Cap::Data` content hash (32 bytes for Blake2b256).
    Data { content_hash: [u8; 32], size: u64 },
    /// Pinned `Cap::Image` content hash.
    Image { content_hash: [u8; 32] },
}

impl Image {
    /// Empty Image: no code, no endpoints, no mappings, no slots.
    /// Useful for tests and as a starting point.
    pub fn empty() -> Self {
        Self {
            code: Vec::new(),
            endpoints: std::array::from_fn(|_| None),
            memory_mappings: Vec::new(),
            gas_slots: Vec::new(),
            quota_slots: Vec::new(),
            pinned_slots: BTreeMap::new(),
            yield_marker_slot: None,
        }
    }
}

/// Canonical byte encoding of an Image, used as input to
/// `image_content_hash`.
///
/// Format (v3 canonical, version-agnostic — bump if the layout
/// changes):
///
/// ```text
///   varlen<u32>(code) ++ code
///   for i in 0..256:
///     if endpoints[i] is Some(e): tag(0x01) ++ encode(e)
///     else:                       tag(0x00)
///   varlen<u32>(memory_mappings.len()) ++ each encoded
///   varlen<u32>(gas_slots.len()) ++ each SlotIdx (u32-le)
///   varlen<u32>(quota_slots.len()) ++ each SlotIdx (u32-le)
///   varlen<u32>(pinned_slots.len()) ++ each (SlotIdx-le, PinnedCap)
///   tag<u8>(yield_marker_slot) ++ optional SlotIdx-le
/// ```
///
/// All multi-byte integers little-endian. Pinned slots iterated in
/// `BTreeMap` order (ascending by SlotIdx) for determinism.
pub fn image_canonical_encoding(image: &Image) -> Vec<u8> {
    let mut buf = Vec::with_capacity(image.code.len() + 256);

    fn push_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    fn push_u64(buf: &mut Vec<u8>, v: u64) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    // code
    push_u32(&mut buf, image.code.len() as u32);
    buf.extend_from_slice(&image.code);

    // endpoints (fixed 256 entries)
    for ep in image.endpoints.iter() {
        match ep {
            None => buf.push(0x00),
            Some(e) => {
                buf.push(0x01);
                push_u64(&mut buf, e.entry_pc);
                buf.push(e.arg_registers);
                buf.push(e.arg_cnode_size);
            }
        }
    }

    // memory_mappings
    push_u32(&mut buf, image.memory_mappings.len() as u32);
    for m in &image.memory_mappings {
        push_u64(&mut buf, m.start);
        push_u64(&mut buf, m.size);
        match &m.source {
            MappingSource::Ephemeral => buf.push(0x00),
            MappingSource::Persistent(path) => {
                buf.push(0x01);
                push_u32(&mut buf, path.steps.len() as u32);
                for s in &path.steps {
                    push_u32(&mut buf, s.get());
                }
            }
        }
    }

    // gas_slots / quota_slots
    push_u32(&mut buf, image.gas_slots.len() as u32);
    for s in &image.gas_slots {
        push_u32(&mut buf, s.get());
    }
    push_u32(&mut buf, image.quota_slots.len() as u32);
    for s in &image.quota_slots {
        push_u32(&mut buf, s.get());
    }

    // pinned_slots (BTreeMap order = ascending by SlotIdx; deterministic)
    push_u32(&mut buf, image.pinned_slots.len() as u32);
    for (idx, cap) in &image.pinned_slots {
        push_u32(&mut buf, idx.get());
        match cap {
            PinnedCap::Data { content_hash, size } => {
                buf.push(0x00);
                buf.extend_from_slice(content_hash);
                push_u64(&mut buf, *size);
            }
            PinnedCap::Image { content_hash } => {
                buf.push(0x01);
                buf.extend_from_slice(content_hash);
            }
        }
    }

    // yield_marker_slot
    match image.yield_marker_slot {
        None => buf.push(0x00),
        Some(idx) => {
            buf.push(0x01);
            push_u32(&mut buf, idx.get());
        }
    }

    buf
}

/// Content hash of an Image: `H::hash(canonical_encoding(image))`.
pub fn image_content_hash<H: Hash>(image: &Image) -> H::Out {
    H::hash(&image_canonical_encoding(image))
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
        b.endpoints[7] = Some(EndpointDef {
            entry_pc: 0x1000,
            arg_registers: 2,
            arg_cnode_size: 0,
        });
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
                content_hash: [0xAA; 32],
                size: 100,
            },
        );
        a.pinned_slots.insert(
            SlotIdx(7),
            PinnedCap::Data {
                content_hash: [0xBB; 32],
                size: 200,
            },
        );

        let mut b = Image::empty();
        // Different insertion order.
        b.pinned_slots.insert(
            SlotIdx(7),
            PinnedCap::Data {
                content_hash: [0xBB; 32],
                size: 200,
            },
        );
        b.pinned_slots.insert(
            SlotIdx(3),
            PinnedCap::Data {
                content_hash: [0xAA; 32],
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
