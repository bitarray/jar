//! `MainFrame` and `BareFrame` views over the active Instance's
//! cnode.
//!
//! Per v3 spec §3 and §22:
//!
//! - **MainFrame**: the active Instance's root cnode (256 slots).
//!   Holds all caps accessible to apply — both user-mutable slots
//!   and Image-declared pinned slots.
//!
//! - **BareFrame**: the read-only subset of the MainFrame consisting
//!   of the Image's declared pinned slots. These are kernel-issued
//!   caps (SetGasMeter, OOGMarker, ...) at chain init, or
//!   Image-baked Data/Image references injected at set_image. The
//!   kernel rejects mutations to these slots.
//!
//! Both are lightweight borrow views; the data lives on
//! `InstanceEntry::{root_cnode, pinned_slots}` plus the `CacheDirectory` that
//! resolves nested-cnode walks. The MGMT dispatcher (Stage 3.6) uses
//! these views to:
//! 1. Resolve a `SlotPath` to a cap target (CapHashOrRef).
//! 2. Enforce pinned-slot read-only semantics on writes.
//! 3. Expose pinned-cap content to host calls that need it (e.g.,
//!    `host_yield` reads the Cap::Instance\[YieldCatcher\] from the
//!    Image-declared `yield_marker_slot`).

use javm_cap::{CNodeCap, CacheDirectory, Cap, CapHashOrRef, SlotIdx, SlotPath};

use crate::error::VmError;

/// Read-only view of an active Instance's MainFrame cnode.
pub struct MainFrame<'a> {
    cnode: &'a CNodeCap,
    pinned: &'a [SlotIdx],
    cache: &'a CacheDirectory,
}

impl<'a> MainFrame<'a> {
    pub fn new(cnode: &'a CNodeCap, pinned: &'a [SlotIdx], cache: &'a CacheDirectory) -> Self {
        Self {
            cnode,
            pinned,
            cache,
        }
    }

    /// Cnode size as `log2(slots)`.
    pub fn size_log(&self) -> u8 {
        self.cnode.size_log
    }

    /// True if `idx` is declared pinned by the Image.
    pub fn is_pinned(&self, idx: SlotIdx) -> bool {
        self.pinned.binary_search(&idx).is_ok()
    }

    /// Read a single root-cnode slot target.
    pub fn get(&self, idx: SlotIdx) -> Option<CapHashOrRef> {
        self.cnode.get(idx)
    }

    /// Resolve a `SlotPath` against this MainFrame. Walks nested
    /// `Cap::CNode` slots via the cache; returns the cap target at
    /// the path's terminal slot (or `None` if the slot is empty).
    ///
    /// Error: if any intermediate step fails to land on a
    /// `Cap::CNode` or hits an empty slot, returns
    /// `VmError::{SlotKindMismatch, SlotEmpty}`.
    pub fn resolve(&self, path: &SlotPath) -> Result<Option<CapHashOrRef>, VmError> {
        let prefix = path.prefix();
        if prefix.is_empty() {
            return Ok(self.cnode.get(path.target()));
        }
        // Walk intermediate cnodes by cloning. `cache.get` returns an
        // owned `Arc<Cap>` rather than the old `&Cap`, so we can no
        // longer chain borrows; cloning the CNodeCap (cheap for
        // sparsely-populated tables) sidesteps the lifetime issue.
        // SlotPath depth is bounded to MAX_SOURCE_DEPTH = 8.
        let mut current = self.cnode.clone();
        for step in prefix {
            let target = current.get(*step).ok_or(VmError::SlotEmpty(step.get()))?;
            let cap = self
                .cache
                .get(target)
                .ok_or(VmError::SlotKindMismatch(step.get()))?;
            match &*cap {
                Cap::CNode(inner) => {
                    current = inner.clone();
                }
                _ => return Err(VmError::SlotKindMismatch(step.get())),
            }
        }
        Ok(current.get(path.target()))
    }
}

/// Read-only view of just the pinned slots of an Instance's MainFrame.
/// This is the "BareFrame" surface in §22: kernel-issued caps live
/// here, addressed by `SlotIdx` matching the Image's pinning
/// declarations.
pub struct BareFrame<'a> {
    main: MainFrame<'a>,
}

impl<'a> BareFrame<'a> {
    pub fn new(cnode: &'a CNodeCap, pinned: &'a [SlotIdx], cache: &'a CacheDirectory) -> Self {
        Self {
            main: MainFrame::new(cnode, pinned, cache),
        }
    }

    /// Read the cap target at a pinned slot. Returns `None` if the
    /// slot is either not pinned by this Image's declarations or
    /// empty.
    pub fn get(&self, idx: SlotIdx) -> Option<CapHashOrRef> {
        if self.main.is_pinned(idx) {
            self.main.get(idx)
        } else {
            None
        }
    }

    /// Image-declared pinned-slot iterator.
    pub fn pinned_slots(&self) -> impl Iterator<Item = &SlotIdx> {
        self.main.pinned.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use javm_cap::CacheDirectory;

    fn empty_cache() -> CacheDirectory {
        CacheDirectory::new()
    }

    #[test]
    fn mainframe_get_root_slot() {
        let mut cn = CNodeCap::new(8).unwrap();
        cn.set(SlotIdx(5), Some(CapHashOrRef::Hash([1u8; 32])))
            .unwrap();
        let cache = empty_cache();
        let m = MainFrame::new(&cn, &[], &cache);
        assert!(m.get(SlotIdx(5)).is_some());
        assert!(m.get(SlotIdx(6)).is_none());
    }

    #[test]
    fn mainframe_is_pinned_reads_pinned_list() {
        let cn = CNodeCap::new(8).unwrap();
        let cache = empty_cache();
        let pinned = vec![SlotIdx(2), SlotIdx(5)];
        let m = MainFrame::new(&cn, &pinned, &cache);
        assert!(m.is_pinned(SlotIdx(2)));
        assert!(!m.is_pinned(SlotIdx(3)));
        assert!(m.is_pinned(SlotIdx(5)));
    }

    #[test]
    fn mainframe_resolve_root_path() {
        let mut cn = CNodeCap::new(8).unwrap();
        cn.set(SlotIdx(9), Some(CapHashOrRef::Hash([7u8; 32])))
            .unwrap();
        let cache = empty_cache();
        let m = MainFrame::new(&cn, &[], &cache);
        let p = SlotPath::root(SlotIdx(9));
        let got = m.resolve(&p).unwrap();
        assert_eq!(got, Some(CapHashOrRef::Hash([7u8; 32])));
    }

    #[test]
    fn mainframe_resolve_empty_intermediate_errors() {
        let cn = CNodeCap::new(8).unwrap();
        let cache = empty_cache();
        let m = MainFrame::new(&cn, &[], &cache);
        let p = SlotPath::new(vec![SlotIdx(7), SlotIdx(0)]).unwrap();
        let res = m.resolve(&p);
        assert!(matches!(res, Err(VmError::SlotEmpty(7))));
    }

    #[test]
    fn bareframe_only_reads_pinned() {
        let mut cn = CNodeCap::new(8).unwrap();
        cn.set(SlotIdx(2), Some(CapHashOrRef::Hash([3u8; 32])))
            .unwrap();
        cn.set(SlotIdx(3), Some(CapHashOrRef::Hash([4u8; 32])))
            .unwrap();
        let cache = empty_cache();
        let pinned = vec![SlotIdx(2)];
        let b = BareFrame::new(&cn, &pinned, &cache);
        // Slot 2 is pinned and present → readable.
        assert!(b.get(SlotIdx(2)).is_some());
        // Slot 3 is present but NOT pinned → hidden.
        assert!(b.get(SlotIdx(3)).is_none());
    }
}
