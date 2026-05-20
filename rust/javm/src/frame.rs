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
//! `InstanceEntry::{cnode, image}`. The MGMT dispatcher (Stage 3.6)
//! uses these views to:
//! 1. Resolve a `SlotPath` to a cap.
//! 2. Enforce pinned-slot read-only semantics on writes.
//! 3. Expose pinned-cap content to host calls that need it (e.g.,
//!    `host_yield` reads the Cap::Instance\[YieldCatcher\] from the
//!    Image-declared `yield_marker_slot`).
//!
//! Multi-step `SlotPath` traversal (walking through nested
//! `Cap::CNode` slots) is provided here too: the MGMT dispatcher
//! takes a `SlotPath` operand, this module walks it.

use javm_cap::image::{Image, PinnedCap};
use javm_cap::legacy::{CNodeBackend, Cap};
use javm_cap::{CapError, SlotIdx, SlotPath};

use crate::error::VmError;

/// Read-only view of an active Instance's MainFrame cnode.
pub struct MainFrame<'a> {
    cnode: &'a (dyn CNodeBackend<Cap> + Send + Sync),
    image: &'a Image,
}

impl<'a> MainFrame<'a> {
    pub fn new(cnode: &'a (dyn CNodeBackend<Cap> + Send + Sync), image: &'a Image) -> Self {
        Self { cnode, image }
    }

    /// Cnode size as `log2(slots)`.
    pub fn size_log(&self) -> u8 {
        self.cnode.size_log()
    }

    /// True if `idx` is declared pinned by the Image.
    pub fn is_pinned(&self, idx: SlotIdx) -> bool {
        self.image.pinned_slots.contains_key(&idx)
    }

    /// Read a single root-cnode slot.
    pub fn get(&self, idx: SlotIdx) -> Result<Option<&Cap>, CapError> {
        self.cnode.get(idx)
    }

    /// Resolve a `SlotPath` against this MainFrame. Walks nested
    /// `Cap::CNode` slots; returns the cap at the target slot (or
    /// `None` if the slot is empty).
    ///
    /// Error: if any intermediate step fails to land on a
    /// `Cap::CNode` or hits an empty slot, returns
    /// `VmError::{SlotKindMismatch, SlotEmpty}`.
    pub fn resolve<'b>(&'b self, path: &SlotPath) -> Result<Option<&'b Cap>, VmError>
    where
        'a: 'b,
    {
        let mut cur: &dyn CNodeBackend<Cap> = self.cnode;
        for step in path.prefix() {
            let entry = cur.get(*step)?;
            match entry {
                Some(Cap::CNode(c)) => {
                    cur = c.backend.as_ref();
                }
                Some(_) => return Err(VmError::SlotKindMismatch(step.get())),
                None => return Err(VmError::SlotEmpty(step.get())),
            }
        }
        Ok(cur.get(path.target())?)
    }

    /// Image-declared pinned slots iterator.
    pub fn pinned_slots(&self) -> impl Iterator<Item = (&SlotIdx, &PinnedCap)> {
        self.image.pinned_slots.iter()
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
    pub fn new(cnode: &'a (dyn CNodeBackend<Cap> + Send + Sync), image: &'a Image) -> Self {
        Self {
            main: MainFrame::new(cnode, image),
        }
    }

    /// Read the cap at a pinned slot. Returns `None` if the slot is
    /// either not pinned by this Image's declarations or empty.
    pub fn get(&self, idx: SlotIdx) -> Result<Option<&Cap>, CapError> {
        if self.main.is_pinned(idx) {
            self.main.get(idx)
        } else {
            Ok(None)
        }
    }

    /// Image-declared pinned-slot iterator.
    pub fn pinned_slots(&self) -> impl Iterator<Item = (&SlotIdx, &PinnedCap)> {
        self.main.pinned_slots()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use javm_cap::legacy::{CNodeCap, InMemoryCNode};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn empty_image() -> Image {
        Image {
            code: vec![0u8],
            packed_bitmask: vec![0x01],
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

    fn cnode_with(slots: &[(SlotIdx, Cap)]) -> InMemoryCNode<Cap> {
        let mut c = InMemoryCNode::<Cap>::new(8).unwrap();
        for (i, cap) in slots {
            c.set(*i, Some(cap.clone())).unwrap();
        }
        c
    }

    #[test]
    fn mainframe_get_root_slot() {
        let cap = Cap::Image(javm_cap::legacy::ImageCap {
            content_hash: [1; 32],
        });
        let cn = cnode_with(&[(SlotIdx(5), cap.clone())]);
        let img = empty_image();
        let m = MainFrame::new(&cn, &img);
        assert!(m.get(SlotIdx(5)).unwrap().is_some());
        assert!(m.get(SlotIdx(6)).unwrap().is_none());
    }

    #[test]
    fn mainframe_is_pinned_reads_image_decl() {
        let cn = InMemoryCNode::<Cap>::new(8).unwrap();
        let mut img = empty_image();
        img.pinned_slots.insert(
            SlotIdx(2),
            PinnedCap::Data {
                content: Vec::new(),
                size: 0,
            },
        );
        let m = MainFrame::new(&cn, &img);
        assert!(m.is_pinned(SlotIdx(2)));
        assert!(!m.is_pinned(SlotIdx(3)));
    }

    #[test]
    fn mainframe_resolve_root_path() {
        let cap = Cap::Image(javm_cap::legacy::ImageCap {
            content_hash: [7; 32],
        });
        let cn = cnode_with(&[(SlotIdx(9), cap)]);
        let img = empty_image();
        let m = MainFrame::new(&cn, &img);
        let p = SlotPath::root(SlotIdx(9));
        let got = m.resolve(&p).unwrap();
        assert!(matches!(got, Some(Cap::Image(_))));
    }

    #[test]
    fn mainframe_resolve_nested_path() {
        // Inner cnode at slot 3 of root; inner slot 1 holds a Cap::Type.
        let inner = cnode_with(&[(
            SlotIdx(1),
            Cap::Type(javm_cap::legacy::TypeCap {
                image_hash_chain: [42; 32],
            }),
        )]);
        let inner_cap = Cap::CNode(CNodeCap::new(Arc::new(inner)));
        let root = cnode_with(&[(SlotIdx(3), inner_cap)]);
        let img = empty_image();
        let m = MainFrame::new(&root, &img);
        let p = SlotPath::new(vec![SlotIdx(3), SlotIdx(1)]).unwrap();
        let got = m.resolve(&p).unwrap();
        assert!(matches!(got, Some(Cap::Type(_))));
    }

    #[test]
    fn mainframe_resolve_non_cnode_intermediate_errors() {
        // Root slot 4 holds a Cap::Image (not a Cap::CNode); walking
        // through it should fail.
        let img_cap = Cap::Image(javm_cap::legacy::ImageCap {
            content_hash: [9; 32],
        });
        let root = cnode_with(&[(SlotIdx(4), img_cap)]);
        let img = empty_image();
        let m = MainFrame::new(&root, &img);
        let p = SlotPath::new(vec![SlotIdx(4), SlotIdx(0)]).unwrap();
        let res = m.resolve(&p);
        assert!(matches!(res, Err(VmError::SlotKindMismatch(4))));
    }

    #[test]
    fn mainframe_resolve_empty_intermediate_errors() {
        let root = InMemoryCNode::<Cap>::new(8).unwrap();
        let img = empty_image();
        let m = MainFrame::new(&root, &img);
        let p = SlotPath::new(vec![SlotIdx(7), SlotIdx(0)]).unwrap();
        let res = m.resolve(&p);
        assert!(matches!(res, Err(VmError::SlotEmpty(7))));
    }

    #[test]
    fn bareframe_only_reads_pinned() {
        let cap = Cap::Image(javm_cap::legacy::ImageCap {
            content_hash: [3; 32],
        });
        let cn = cnode_with(&[
            (SlotIdx(2), cap),
            (
                SlotIdx(3),
                Cap::Type(javm_cap::legacy::TypeCap {
                    image_hash_chain: [0; 32],
                }),
            ),
        ]);
        let mut img = empty_image();
        img.pinned_slots.insert(
            SlotIdx(2),
            PinnedCap::Image {
                content_hash: [3; 32],
            },
        );
        let b = BareFrame::new(&cn, &img);
        // Slot 2 is pinned and present → readable.
        assert!(b.get(SlotIdx(2)).unwrap().is_some());
        // Slot 3 is present but NOT pinned → hidden.
        assert!(b.get(SlotIdx(3)).unwrap().is_none());
    }
}
