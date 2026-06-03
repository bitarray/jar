//! `InstanceCap` — Instance cap with mutable working state.
//!
//! Holds the mutable working state of a running Cap::Instance:
//! image reference (by hash, since Images are immutable), root
//! cnode reference (by hash when clean / by ref while mutating),
//! the read-write memory image, register file, PC, gas counter.

use crate::cache::CapHashOrRef;

use super::CapHash;
use super::NUM_REGS;
use super::data::{DataCap, PAGE_SIZE};

#[derive(
    Clone, Debug, ssz_derive::HashTreeRoot, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct InstanceCap {
    /// Cumulative chain hash identifying the Instance's type.
    pub image_hash_chain: CapHash,
    /// Hash of the Image cap currently bound. Always content-
    /// addressed (Images are immutable).
    pub image_hash: CapHash,
    /// Reference to the root cnode. `Hash` when clean / not yet
    /// promoted for mutation; `Ref` while the running Instance is
    /// mutating it via CoW.
    pub root_cnode: CapHashOrRef,
    /// The Instance's read-write memory image: a dense `DataCap` covering the
    /// data extent `[DATA_BASE, DATA_BASE + mem.size)`. Holds the initial
    /// content at boot and the settled (folded) content after each HALT — the
    /// **immutable backing** half of the Backing+View mutability model. A
    /// running engine wraps this in a transient CoW `DataViewCap`; at settle the
    /// View folds back into a fresh `DataCap` that replaces this field. Pinned
    /// (read-only) mappings are **not** stored here — they stay in their own
    /// `Cap::Data` and are mapped RO separately, so the pinned-RO gas tier is
    /// preserved.
    pub mem: DataCap,
    /// PVM register file (`φ[0]..φ[12]`).
    pub regs: [u64; NUM_REGS],
    /// Current PC. Zero between calls; updated to entry_pc at
    /// invoke start and to the post-execution PC on HALT.
    pub pc: u64,
    /// Gas left after the last call, for callers that want to
    /// observe residual gas. Set to 0 between calls in V1.
    pub gas_remaining: u64,
}

impl InstanceCap {
    /// Absolute exclusive top of the data region (`DATA_BASE + mem.size`). The
    /// data extent `[DATA_BASE, mem_size)` is what the engines map; this matches
    /// the legacy `mem_size` field's semantics for call sites.
    pub fn mem_size(&self) -> u32 {
        (crate::layout::DATA_BASE as u64 + self.mem.content_len()) as u32
    }

    /// The data extent (RW memory size above `DATA_BASE`) in bytes — always a
    /// [`PAGE_SIZE`] multiple.
    pub fn mem_extent(&self) -> u64 {
        self.mem.content_len()
    }

    /// The data extent as a count of [`PAGE_SIZE`] pages.
    pub fn mem_pages(&self) -> usize {
        (self.mem.content_len() / PAGE_SIZE as u64) as usize
    }
}
