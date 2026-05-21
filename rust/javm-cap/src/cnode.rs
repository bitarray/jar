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

use crate::error::CapError;
use crate::slot::SlotIdx;

use super::cap::CapHashOrRef;

#[derive(Clone, Debug, ssz_derive::HashTreeRoot)]
pub struct CNodeCap<A: Allocator + Clone = Global> {
    pub size_log: u8,
    /// Populated slots, sorted by slot index for binary search.
    pub slots: Vec<CNodeSlotEntry, A>,
}

impl<A: Allocator + Clone> CNodeCap<A> {
    /// Construct an empty cnode of `2^size_log` slots in the given
    /// allocator. Empty cnodes carry no allocation past the
    /// allocator-handle bytes inside the Vec. Rejects
    /// `size_log > 16` (the spec's hard ceiling).
    pub fn new_in(size_log: u8, alloc: A) -> Result<Self, CapError> {
        if size_log > 16 {
            return Err(CapError::InvalidCNodeSize(size_log));
        }
        Ok(Self {
            size_log,
            slots: Vec::new_in(alloc),
        })
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

    /// Bind `slot` to `target`, or remove the binding if `target` is
    /// `None`. Rejects slot indices outside the cnode's
    /// `2^size_log` range. Returns the prior target at `slot`, if any.
    pub fn set(
        &mut self,
        slot: SlotIdx,
        target: Option<CapHashOrRef>,
    ) -> Result<Option<CapHashOrRef>, CapError> {
        if !slot.fits(self.size_log) {
            return Err(CapError::SlotOutOfRange(slot.get(), self.size_log));
        }
        match self.slots.binary_search_by_key(&slot, |e| e.slot) {
            Ok(idx) => match target {
                Some(t) => {
                    let prior = self.slots[idx].target;
                    self.slots[idx].target = t;
                    Ok(Some(prior))
                }
                None => Ok(Some(self.slots.remove(idx).target)),
            },
            Err(idx) => {
                if let Some(t) = target {
                    self.slots.insert(idx, CNodeSlotEntry { slot, target: t });
                }
                Ok(None)
            }
        }
    }

    /// Take the binding at `slot`, leaving the slot empty. Returns the
    /// prior target (or `None` if the slot was already empty).
    pub fn take(&mut self, slot: SlotIdx) -> Result<Option<CapHashOrRef>, CapError> {
        self.set(slot, None)
    }

    /// Alias of `set(slot, None)`.
    pub fn remove(&mut self, slot: SlotIdx) -> Result<Option<CapHashOrRef>, CapError> {
        self.set(slot, None)
    }
}

impl CNodeCap<Global> {
    /// Construct an empty heap-resident cnode. Equivalent to
    /// `CNodeCap::new_in(size_log, Global)`.
    pub fn new(size_log: u8) -> Result<Self, CapError> {
        Self::new_in(size_log, Global)
    }
}

/// One populated slot.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    ssz_derive::Encode,
    ssz_derive::Decode,
    ssz_derive::HashTreeRoot,
)]
pub struct CNodeSlotEntry {
    pub slot: SlotIdx,
    pub target: CapHashOrRef,
}
