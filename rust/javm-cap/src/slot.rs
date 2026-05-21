//! Slot addressing for cnodes.
//!
//! A `SlotIdx` names one slot in a single cnode (root or nested).
//! A `SlotPath` walks from the root cnode through nested
//! `Cap::CNode` slots down to a target slot.
//!
//! The root cnode is fixed-size 256 slots per v3 spec; nested
//! `Cap::CNode` values have variable size `2^k`. `SlotIdx` is a u32
//! to accommodate the largest cnode reachable in practice.

use crate::error::CapError;
use alloc::vec::Vec;
use ssz_derive::{Decode, Encode};

/// Index into a single cnode (root or nested).
///
/// For the root cnode (256 slots) only `0..256` is valid; for a
/// nested `Cap::CNode` of `size_log = k`, `0..2^k` is valid.
/// `CNodeCap` rejects out-of-range indices.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    ssz_derive::HashTreeRoot,
)]
pub struct SlotIdx(#[ssz(transparent)] pub u32);

impl SlotIdx {
    pub const fn new(idx: u32) -> Self {
        Self(idx)
    }

    pub const fn get(self) -> u32 {
        self.0
    }

    /// True iff this index fits in a cnode of `2^size_log` slots.
    pub fn fits(self, size_log: u8) -> bool {
        if size_log >= 32 {
            // 2^32 indices addressable
            true
        } else {
            self.0 < (1u32 << size_log)
        }
    }

    /// Convert to a `usize` for indexing into an in-memory slot vector.
    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl From<u8> for SlotIdx {
    fn from(v: u8) -> Self {
        Self(v as u32)
    }
}

impl From<u16> for SlotIdx {
    fn from(v: u16) -> Self {
        Self(v as u32)
    }
}

/// Path from the root cnode through nested cnodes to a slot.
///
/// `steps` is the sequence of slot indices walked through nested
/// `Cap::CNode` slots; the final step's slot is the target. An
/// empty `steps` is invalid (must address some slot).
///
/// Example: `SlotPath { steps: vec![SlotIdx(7)] }` addresses
/// slot 7 of the root cnode. `SlotPath { steps: vec![SlotIdx(7),
/// SlotIdx(3)] }` addresses slot 3 of the Cap::CNode held in
/// root slot 7.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Encode, Decode, ssz_derive::HashTreeRoot)]
pub struct SlotPath {
    pub steps: Vec<SlotIdx>,
}

impl SlotPath {
    /// Construct from a single root-cnode slot index.
    pub fn root(idx: SlotIdx) -> Self {
        Self { steps: vec![idx] }
    }

    /// Construct from a list of steps. Returns `Err` if empty.
    pub fn new(steps: Vec<SlotIdx>) -> Result<Self, CapError> {
        if steps.is_empty() {
            // We need a "Path::Empty" error; use SlotOutOfRange as a
            // placeholder for now. A dedicated variant could be added
            // if this surfaces.
            Err(CapError::SlotOutOfRange(0, 0))
        } else {
            Ok(Self { steps })
        }
    }

    /// True iff this path has exactly one step (i.e., addresses a
    /// slot in the root cnode, not nested).
    pub fn is_root_slot(&self) -> bool {
        self.steps.len() == 1
    }

    /// The final step (the slot index in the deepest cnode this
    /// path addresses).
    pub fn target(&self) -> SlotIdx {
        // Invariant from `new` / `root`: steps is non-empty.
        *self.steps.last().unwrap()
    }

    /// All steps before the target — the chain of nested-cnode
    /// indices that must be walked to reach the target's cnode.
    pub fn prefix(&self) -> &[SlotIdx] {
        let len = self.steps.len();
        &self.steps[..len - 1]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_idx_fits_within_size_log() {
        assert!(SlotIdx(0).fits(0)); // 2^0 = 1 slot; idx 0 fits
        assert!(!SlotIdx(1).fits(0)); // doesn't fit
        assert!(SlotIdx(255).fits(8)); // 2^8 = 256
        assert!(!SlotIdx(256).fits(8));
        assert!(SlotIdx(255).fits(16));
        assert!(SlotIdx(u32::MAX).fits(32));
    }

    #[test]
    fn slot_idx_conversions() {
        assert_eq!(SlotIdx::from(7u8).get(), 7);
        assert_eq!(SlotIdx::from(1000u16).get(), 1000);
        assert_eq!(SlotIdx(42).as_usize(), 42);
    }

    #[test]
    fn slot_path_root_single_step() {
        let p = SlotPath::root(SlotIdx(7));
        assert!(p.is_root_slot());
        assert_eq!(p.target(), SlotIdx(7));
        assert_eq!(p.prefix(), &[]);
    }

    #[test]
    fn slot_path_nested() {
        let p = SlotPath::new(vec![SlotIdx(7), SlotIdx(3), SlotIdx(12)]).unwrap();
        assert!(!p.is_root_slot());
        assert_eq!(p.target(), SlotIdx(12));
        assert_eq!(p.prefix(), &[SlotIdx(7), SlotIdx(3)]);
    }

    #[test]
    fn slot_path_empty_rejected() {
        assert!(SlotPath::new(vec![]).is_err());
    }

    #[test]
    fn slot_path_equality_by_value() {
        let a = SlotPath::root(SlotIdx(5));
        let b = SlotPath::new(vec![SlotIdx(5)]).unwrap();
        assert_eq!(a, b);
    }
}
