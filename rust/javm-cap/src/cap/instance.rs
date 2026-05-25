//! `InstanceCap` — Instance cap with mutable working state.
//!
//! Holds the mutable working state of a running Cap::Instance:
//! image reference (by hash, since Images are immutable), root
//! cnode reference (by hash when clean / by ref while mutating),
//! per-mapping rw overlays, register file, PC, gas counter.
//!
//! ## Generic parameter `R`
//!
//! The `root_cnode` field's type is `R`. `R = CapHashOrRef` (default)
//! lets the running Instance CoW-mutate via a directory-backed handle;
//! `R = CapHash` is the wire form where the root cnode is always
//! content-addressed.

use alloc::vec::Vec;

use crate::cache::CapHashOrRef;

use super::cnode::SlotTarget;
use super::{CapHash, NUM_REGS};

#[derive(Clone, Debug, ssz_derive::HashTreeRoot)]
pub struct InstanceCap<R: SlotTarget = CapHashOrRef> {
    /// Cumulative chain hash identifying the Instance's type.
    pub image_hash_chain: CapHash,
    /// Hash of the Image cap currently bound. Always content-
    /// addressed (Images are immutable).
    pub image_hash: CapHash,
    /// Reference to the root cnode. For `R = CapHashOrRef`: `Hash`
    /// when clean / not yet promoted for mutation; `Ref` while the
    /// running Instance is mutating it via CoW. For `R = CapHash`:
    /// always content-addressed (wire form).
    pub root_cnode: R,
    /// Mutable byte overlays per memory mapping. Each entry's
    /// `start` matches one of the Image's `MemoryMapping.start`
    /// values; `bytes` is the per-instance content (initial state
    /// at boot, then evolves under JIT writes).
    pub rw_overlays: Vec<RwOverlay>,
    /// Total addressable memory size for the Instance.
    pub mem_size: u32,
    /// PVM register file (`φ[0]..φ[12]`).
    pub regs: [u64; NUM_REGS],
    /// Current PC. Zero between calls; updated to entry_pc at
    /// invoke start and to the post-execution PC on HALT.
    pub pc: u64,
    /// Gas left after the last call, for callers that want to
    /// observe residual gas. Set to 0 between calls in V1.
    pub gas_remaining: u64,
}

/// One byte overlay backing a memory mapping. `bytes.len()` ≤
/// the mapping's `size`; trailing untouched bytes default to zero.
#[derive(
    Clone,
    Debug,
    ssz_derive::Encode,
    ssz_derive::HashTreeRoot,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct RwOverlay {
    pub start: u32,
    pub bytes: Vec<u8>,
}
