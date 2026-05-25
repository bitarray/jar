//! `CNodeCap` — CNode cap.
//!
//! Slot table is a [`SparseList`] of [`MissingOr`] entries: a sparse
//! materialized-on-demand map from `SlotIdx` to [`CapHashOrRef`]. The
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

use ssz::{MissingOr, SparseList};

use crate::error::CapError;
use crate::slot::SlotIdx;

use super::cap::CapHashOrRef;

/// Maximum cnode capacity (`2^16` slots). The SSZ merkle tree depth is
/// fixed at 16 regardless of an individual cnode's declared `size_log`.
pub const MAX_CNODE_SLOTS: u64 = 1u64 << 16;

#[derive(Clone, Debug, ssz_derive::HashTreeRoot)]
pub struct CNodeCap {
    pub size_log: u8,
    /// Sparse slot table keyed by slot index. Missing keys are absent
    /// slots (contribute `zero_hash` to the merkle root). The merkle
    /// tree is always size `MAX_CNODE_SLOTS = 2^16`; `size_log` bounds
    /// the addressable range.
    pub slots: SparseList<CapHashOrRef, MAX_CNODE_SLOTS>,
}

impl CNodeCap {
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
    /// slots; returns the materialized `CapHashOrRef` otherwise.
    ///
    /// For a `MissingOr::Missing(_)` placeholder slot (used when a
    /// subtree was loaded by hash without contents), this returns
    /// `None` — callers needing to distinguish "absent" from "missing
    /// placeholder" should inspect `self.slots.get(...)` directly.
    pub fn get(&self, slot: SlotIdx) -> Option<CapHashOrRef> {
        match self.slots.get(slot.get() as u64)? {
            MissingOr::Materialized(t) => Some(t.clone()),
            MissingOr::Missing(_) => None,
        }
    }

    /// Bind `slot` to `target`, or clear the binding if `target` is
    /// `None`. Rejects slot indices outside the cnode's `2^size_log`
    /// range. Returns the prior materialized target at `slot`, if any.
    pub fn set(
        &mut self,
        slot: SlotIdx,
        target: Option<CapHashOrRef>,
    ) -> Result<Option<CapHashOrRef>, CapError> {
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
    pub fn take(&mut self, slot: SlotIdx) -> Result<Option<CapHashOrRef>, CapError> {
        self.set(slot, None)
    }

    /// Alias of `set(slot, None)`.
    pub fn remove(&mut self, slot: SlotIdx) -> Result<Option<CapHashOrRef>, CapError> {
        self.set(slot, None)
    }
}

/// One populated slot — retained as a serialisation helper for callers
/// that need a flat `(slot, target)` pair (e.g., `CacheDirectory::publish_cnode`).
///
/// The on-the-wire/hash representation of `CNodeCap` no longer uses this
/// type; the cnode is encoded directly as a `SparseList<CapHashOrRef, ...>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CNodeSlotEntry {
    pub slot: SlotIdx,
    pub target: CapHashOrRef,
}
