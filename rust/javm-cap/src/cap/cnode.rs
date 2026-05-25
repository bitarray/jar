//! `CNodeCap` — CNode cap.
//!
//! Slot table is a [`SparseList`] of [`MissingOr`] entries: a sparse
//! materialized-on-demand map from `SlotIdx` to a slot target `R`. The
//! merkle tree shape is fixed at depth 16 (= ceil_log2(MAX_CNODE_SLOTS))
//! regardless of `size_log`; `size_log` is runtime metadata used for
//! bounds-checking slot indices.
//!
//! Empty slots contribute `zero_hash` at the depth-16 leaf level; a
//! `Missing(h)` placeholder substitutes losslessly for the materialized
//! contents whose `hash_tree_root` equals `h`. This is the load-bearing
//! property for sparse cnode loading from cold storage.
//!
//! `size_log` is permitted in `0..=16` (the spec's hard ceiling).
//!
//! ## Generic parameter `R`
//!
//! The slot target type `R` is `CapHashOrRef` for the in-memory working
//! form (default) and `CapHash` for the wire form. The wire form
//! structurally excludes `CapHashOrRef::Ref(_)` handles.

use alloc::vec::Vec;
use core::fmt::Debug;

use ssz::{Encode, HashTreeRoot, MissingOr, SparseList};

use crate::cache::CapHashOrRef;
use crate::error::CapError;
use crate::slot::SlotIdx;

/// Maximum cnode capacity (`2^16` slots). The SSZ merkle tree depth is
/// fixed at 16 regardless of an individual cnode's declared `size_log`.
pub const MAX_CNODE_SLOTS: u64 = 1u64 << 16;

/// Trait bound bundle for the slot-target type. Matches what
/// `SparseList<R, N>`'s derived `HashTreeRoot` requires.
pub trait SlotTarget: Clone + Debug + HashTreeRoot + Encode {}
impl<T: Clone + Debug + HashTreeRoot + Encode> SlotTarget for T {}

#[derive(Clone, Debug, ssz_derive::HashTreeRoot)]
pub struct CNodeCap<R: SlotTarget = CapHashOrRef> {
    pub size_log: u8,
    /// Sparse slot table keyed by slot index. Missing keys are absent
    /// slots (contribute `zero_hash` to the merkle root). The merkle
    /// tree is always size `MAX_CNODE_SLOTS = 2^16`; `size_log` bounds
    /// the addressable range.
    pub slots: SparseList<R, MAX_CNODE_SLOTS>,
}

impl<R: SlotTarget> CNodeCap<R> {
    /// Construct an empty cnode of `2^size_log` slots.
    /// Rejects `size_log > 16`.
    pub fn new(size_log: u8) -> Result<Self, CapError> {
        if size_log > 16 {
            return Err(CapError::InvalidCNodeSize(size_log));
        }
        Ok(Self {
            size_log,
            slots: SparseList::new(),
        })
    }

    /// Number of slots in the cnode (`2^size_log`).
    pub fn capacity(&self) -> u64 {
        1u64 << self.size_log
    }

    /// Look up a slot by index. Returns `None` for empty (unmaterialized)
    /// slots; returns the materialized target otherwise.
    ///
    /// For a `MissingOr::Missing(_)` placeholder slot (used when a
    /// subtree was loaded by hash without contents), this returns
    /// `None` — callers needing to distinguish "absent" from "missing
    /// placeholder" should inspect `self.slots.get(...)` directly.
    pub fn get(&self, slot: SlotIdx) -> Option<R> {
        match self.slots.get(slot.get() as u64)? {
            MissingOr::Materialized(t) => Some(t.clone()),
            MissingOr::Missing(_) => None,
        }
    }

    /// Bind `slot` to `target`, or clear the binding if `target` is
    /// `None`. Rejects slot indices outside the cnode's `2^size_log`
    /// range. Returns the prior materialized target at `slot`, if any.
    pub fn set(&mut self, slot: SlotIdx, target: Option<R>) -> Result<Option<R>, CapError> {
        if !slot.fits(self.size_log) {
            return Err(CapError::SlotOutOfRange(slot.get(), self.size_log));
        }
        let key = slot.get() as u64;
        let prior = match self.slots.get(key) {
            Some(MissingOr::Materialized(t)) => Some(t.clone()),
            Some(MissingOr::Missing(_)) | None => None,
        };
        match target {
            Some(t) => {
                // `MAX_CNODE_SLOTS = 2^16` and `slot.fits(size_log)` with
                // `size_log <= 16` guarantee `key < MAX_CNODE_SLOTS`, so
                // the bound check inside `SparseList::insert` cannot fail.
                self.slots
                    .insert(key, MissingOr::Materialized(t))
                    .expect("slot index fits cnode capacity (checked above)");
            }
            None => {
                self.slots.remove(key);
            }
        }
        Ok(prior)
    }

    /// Take the binding at `slot`, leaving the slot empty. Returns the
    /// prior target (or `None` if the slot was already empty).
    pub fn take(&mut self, slot: SlotIdx) -> Result<Option<R>, CapError> {
        self.set(slot, None)
    }

    /// Alias of `set(slot, None)`.
    pub fn remove(&mut self, slot: SlotIdx) -> Result<Option<R>, CapError> {
        self.set(slot, None)
    }

    /// Iterator over materialized `(slot, &target)` pairs in slot order.
    /// `Missing(_)` placeholders are skipped.
    pub fn iter_materialized(&self) -> impl Iterator<Item = (u32, &R)> + '_ {
        self.slots.iter().filter_map(|(idx, entry)| match entry {
            MissingOr::Materialized(t) => Some((idx as u32, t)),
            MissingOr::Missing(_) => None,
        })
    }

    /// Collect the materialized entries into a `Vec<(u32, R)>`. Used by
    /// the wire encoder.
    pub fn materialized_entries(&self) -> Vec<(u32, R)>
    where
        R: Clone,
    {
        self.iter_materialized()
            .map(|(idx, t)| (idx, t.clone()))
            .collect()
    }
}

/// One populated slot — retained as a serialisation helper for callers
/// that need a flat `(slot, target)` pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CNodeSlotEntry {
    pub slot: SlotIdx,
    pub target: CapHashOrRef,
}
