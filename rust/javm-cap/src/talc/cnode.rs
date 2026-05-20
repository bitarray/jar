//! `CNodeCap<A>` — talc-friendly CNode cap.
//!
//! V1 representation: a flat sparse array of populated slots, sorted
//! by slot index for `O(log N)` binary-search lookup. Empty slots are
//! represented by absence. Adequate for cnodes up through
//! `size_log ≈ 14` (16K slots). Larger sparse cnodes get a merkle
//! trie representation in V2 — see plan
//! `distributed-puzzling-tower.md`.

use allocator_api2::alloc::{Allocator, Global};
use allocator_api2::vec::Vec;

use crate::slot::SlotIdx;

use super::cap::CapHashOrRef;

pub struct CNodeCap<A: Allocator + Clone = Global> {
    pub size_log: u8,
    /// Populated slots, sorted by slot index for binary search.
    pub slots: Vec<CNodeSlotEntry, A>,
}

impl<A: Allocator + Clone> CNodeCap<A> {
    /// Construct an empty cnode of `2^size_log` slots in the given
    /// allocator. Empty cnodes carry no allocation past the
    /// allocator-handle bytes inside the Vec.
    pub fn new_in(size_log: u8, alloc: A) -> Self {
        Self {
            size_log,
            slots: Vec::new_in(alloc),
        }
    }

    /// Number of slots in the cnode (`2^size_log`).
    pub fn capacity(&self) -> u64 {
        1u64 << self.size_log
    }

    /// Look up a slot by index. Returns `None` for empty slots (the
    /// common case in sparse cnodes).
    pub fn get(&self, slot: SlotIdx) -> Option<CapHashOrRef> {
        let idx = self
            .slots
            .binary_search_by_key(&slot, |entry| entry.slot)
            .ok()?;
        Some(self.slots[idx].target)
    }
}

/// One populated slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CNodeSlotEntry {
    pub slot: SlotIdx,
    pub target: CapHashOrRef,
}
