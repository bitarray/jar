//! Internal rkyv-archive representation backing `Cap<CapHash>`.
//!
//! `Cap<CapHash>` (the wire form of [`Cap`]) holds shapes that don't
//! derive rkyv directly — [`SparseList`](ssz::SparseList) inside
//! [`CNodeCap`], `Arc<PageBytes>` inside `PageSlot::Loaded`. This
//! module defines a parallel `*Repr` type tree whose shape mirrors
//! `Cap<CapHash>` but flattens those fields into plain `Vec<…>`
//! shapes that derive `rkyv::{Archive, Serialize, Deserialize}`
//! cleanly. The hand-rolled `rkyv` impls on `Cap<CapHash>` in
//! [`crate::cap`] delegate to these `*Repr` types — callers write
//! `rkyv::to_bytes::<_, _>(&cap)` directly.
//!
//! The conversion is infallible in both directions because
//! `Cap<CapHash>` is structurally Ref-free (no `CapHashOrRef::Ref`
//! variant exists when `R = CapHash`).
//!
//! ## Wire shape vs in-memory shape
//!
//! - `CNodeCap<CapHash>`'s `SparseList` flattens to `Vec<CNodeSlotRepr>`
//!   carrying both materialized `Hash` entries and `Missing(hash)`
//!   placeholders. The wire preserves sparsity — only populated slots
//!   travel, not the full `2^size_log` table.
//! - `DataCap`'s `Paged` arm flattens to `Vec<PageSlotRepr>` with one
//!   entry per non-empty page. `PageSlot::Loaded(Arc<PageBytes>)`
//!   inlines the byte slab into the repr; receiver wraps in a fresh
//!   `Arc`. `PageSlot::Empty` pages omit their entry entirely
//!   (sparse).
//! - Every other field is a direct mirror.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::cap::cnode::CNodeCap;
use crate::cap::data::{DataCap, DataContent, alloc_page_aligned_zeroed};
use crate::cap::image::{EndpointDef, ImageCap, ImageSlotEntry, MemoryMapping};
use crate::cap::instance::{InstanceCap, RwOverlay};
use crate::cap::page::{PageBytes, PageSlot};
use crate::cap::{Cap, CapHash, NUM_REGS, TypeCap};
use crate::slot::SlotIdx;

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum CapRepr {
    Instance(InstanceCapRepr),
    Image(ImageCapRepr),
    Data(DataCapRepr),
    CNode(CNodeCapRepr),
    Type(TypeCapRepr),
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct InstanceCapRepr {
    pub image_hash_chain: CapHash,
    pub image_hash: CapHash,
    pub root_cnode_hash: CapHash,
    pub rw_overlays: Vec<RwOverlayRepr>,
    pub mem_size: u32,
    pub regs: [u64; NUM_REGS],
    pub pc: u64,
    pub gas_remaining: u64,
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct RwOverlayRepr {
    pub start: u32,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ImageCapRepr {
    pub code: Vec<u8>,
    pub bitmask: Vec<u8>,
    pub jump_table: Vec<u32>,
    pub endpoints: Vec<EndpointDefRepr>,
    pub mappings: Vec<MemoryMappingRepr>,
    pub pinned: Vec<ImageSlotEntryRepr>,
    pub initial: Vec<ImageSlotEntryRepr>,
    pub yield_marker_slot: Option<u32>,
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct EndpointDefRepr {
    pub entry_pc: u64,
    pub stack_top: u64,
    pub arg_cnode_slot: u32,
    pub arg_cnode_size: u8,
    pub initial_regs: [u64; NUM_REGS],
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct MemoryMappingRepr {
    pub start: u64,
    pub size: u64,
    pub source_path: Vec<u32>,
    pub source_path_len: u8,
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct ImageSlotEntryRepr {
    pub slot: u32,
    pub cap_hash: CapHash,
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum DataCapRepr {
    Inline(Vec<u8>),
    Paged {
        page_size: u32,
        total_pages: u32,
        /// Sparse: only non-`Empty` pages travel. Receiver fills the
        /// gaps with `PageSlot::Empty` up to `total_pages`.
        pages: Vec<PageSlotRepr>,
    },
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct PageSlotRepr {
    pub index: u32,
    pub data: PageDataRepr,
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum PageDataRepr {
    /// Page bytes inlined; receiver wraps in a fresh `Arc`.
    Loaded { hash: CapHash, bytes: Vec<u8> },
    /// Subtree-hash placeholder.
    Missing(CapHash),
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct CNodeCapRepr {
    pub size_log: u8,
    /// Sparse: only populated slots travel. Receiver reconstructs a
    /// fresh `SparseList` of the same logical capacity.
    pub slots: Vec<CNodeSlotRepr>,
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct CNodeSlotRepr {
    pub slot: u32,
    pub entry: CNodeEntryRepr,
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum CNodeEntryRepr {
    Materialized(CapHash),
    Missing(CapHash),
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct TypeCapRepr {
    pub image_hash_chain: CapHash,
}

// --- Conversions ---

impl CapRepr {
    pub fn from_cap(cap: &Cap<CapHash>) -> Self {
        match cap {
            Cap::Instance(i) => CapRepr::Instance(InstanceCapRepr::from_instance(i)),
            Cap::Image(i) => CapRepr::Image(ImageCapRepr::from_image(i)),
            Cap::Data(d) => CapRepr::Data(DataCapRepr::from_data(d)),
            Cap::CNode(c) => CapRepr::CNode(CNodeCapRepr::from_cnode(c)),
            Cap::Type(t) => CapRepr::Type(TypeCapRepr {
                image_hash_chain: t.image_hash_chain,
            }),
        }
    }

    pub fn into_cap(self) -> Cap<CapHash> {
        match self {
            CapRepr::Instance(i) => Cap::Instance(i.into_instance()),
            CapRepr::Image(i) => Cap::Image(i.into_image()),
            CapRepr::Data(d) => Cap::Data(d.into_data()),
            CapRepr::CNode(c) => Cap::CNode(c.into_cnode()),
            CapRepr::Type(t) => Cap::Type(TypeCap {
                image_hash_chain: t.image_hash_chain,
            }),
        }
    }
}

impl InstanceCapRepr {
    fn from_instance(inst: &InstanceCap<CapHash>) -> Self {
        let rw_overlays = inst
            .rw_overlays
            .iter()
            .map(|ov| RwOverlayRepr {
                start: ov.start,
                bytes: ov.bytes.clone(),
            })
            .collect();
        Self {
            image_hash_chain: inst.image_hash_chain,
            image_hash: inst.image_hash,
            root_cnode_hash: inst.root_cnode,
            rw_overlays,
            mem_size: inst.mem_size,
            regs: inst.regs,
            pc: inst.pc,
            gas_remaining: inst.gas_remaining,
        }
    }

    fn into_instance(self) -> InstanceCap<CapHash> {
        let rw_overlays = self
            .rw_overlays
            .into_iter()
            .map(|w| RwOverlay {
                start: w.start,
                bytes: w.bytes,
            })
            .collect();
        InstanceCap {
            image_hash_chain: self.image_hash_chain,
            image_hash: self.image_hash,
            root_cnode: self.root_cnode_hash,
            rw_overlays,
            mem_size: self.mem_size,
            regs: self.regs,
            pc: self.pc,
            gas_remaining: self.gas_remaining,
        }
    }
}

impl ImageCapRepr {
    fn from_image(img: &ImageCap) -> Self {
        let endpoints = img
            .endpoints
            .iter()
            .map(|e| EndpointDefRepr {
                entry_pc: e.entry_pc,
                stack_top: e.stack_top,
                arg_cnode_slot: e.arg_cnode_slot.get(),
                arg_cnode_size: e.arg_cnode_size,
                initial_regs: e.initial_regs,
            })
            .collect();
        let mappings = img
            .mappings
            .iter()
            .map(|m| MemoryMappingRepr {
                start: m.start,
                size: m.size,
                source_path: m.source_path.iter().map(|s| s.get()).collect(),
                source_path_len: m.source_path_len,
            })
            .collect();
        let pinned = img
            .pinned
            .iter()
            .map(|e| ImageSlotEntryRepr {
                slot: e.slot.get(),
                cap_hash: e.cap_hash,
            })
            .collect();
        let initial = img
            .initial
            .iter()
            .map(|e| ImageSlotEntryRepr {
                slot: e.slot.get(),
                cap_hash: e.cap_hash,
            })
            .collect();
        Self {
            code: img.code.clone(),
            bitmask: img.bitmask.clone(),
            jump_table: img.jump_table.clone(),
            endpoints,
            mappings,
            pinned,
            initial,
            yield_marker_slot: img.yield_marker_slot.map(|s| s.get()),
        }
    }

    fn into_image(self) -> ImageCap {
        let endpoints = self
            .endpoints
            .into_iter()
            .map(|w| EndpointDef {
                entry_pc: w.entry_pc,
                stack_top: w.stack_top,
                arg_cnode_slot: SlotIdx(w.arg_cnode_slot),
                arg_cnode_size: w.arg_cnode_size,
                initial_regs: w.initial_regs,
            })
            .collect();
        let mappings = self
            .mappings
            .into_iter()
            .map(|w| {
                let mut source_path = [SlotIdx(0); crate::cap::MAX_SOURCE_DEPTH];
                for (i, v) in w.source_path.iter().enumerate() {
                    if i >= crate::cap::MAX_SOURCE_DEPTH {
                        break;
                    }
                    source_path[i] = SlotIdx(*v);
                }
                MemoryMapping {
                    start: w.start,
                    size: w.size,
                    source_path,
                    source_path_len: w.source_path_len,
                }
            })
            .collect();
        let pinned = self
            .pinned
            .into_iter()
            .map(|w| ImageSlotEntry {
                slot: SlotIdx(w.slot),
                cap_hash: w.cap_hash,
            })
            .collect();
        let initial = self
            .initial
            .into_iter()
            .map(|w| ImageSlotEntry {
                slot: SlotIdx(w.slot),
                cap_hash: w.cap_hash,
            })
            .collect();
        ImageCap {
            code: self.code,
            bitmask: self.bitmask,
            jump_table: self.jump_table,
            endpoints,
            mappings,
            pinned,
            initial,
            yield_marker_slot: self.yield_marker_slot.map(SlotIdx),
        }
    }
}

impl DataCapRepr {
    fn from_data(d: &DataCap) -> Self {
        match &d.content {
            DataContent::Inline(bytes) => DataCapRepr::Inline(bytes.clone()),
            DataContent::Paged { page_size, pages } => {
                let mut sparse: Vec<PageSlotRepr> = Vec::new();
                for (i, slot) in pages.iter().enumerate() {
                    match slot {
                        PageSlot::Empty => {}
                        PageSlot::Loaded(arc) => sparse.push(PageSlotRepr {
                            index: i as u32,
                            data: PageDataRepr::Loaded {
                                hash: arc.hash,
                                bytes: arc.bytes.clone(),
                            },
                        }),
                        PageSlot::Missing(h) => sparse.push(PageSlotRepr {
                            index: i as u32,
                            data: PageDataRepr::Missing(*h),
                        }),
                    }
                }
                DataCapRepr::Paged {
                    page_size: *page_size,
                    total_pages: pages.len() as u32,
                    pages: sparse,
                }
            }
        }
    }

    fn into_data(self) -> DataCap {
        match self {
            DataCapRepr::Inline(bytes) => {
                // Preserve page-alignment invariant on the receive
                // side: the kernel direct-maps inline content.
                let mut buf = alloc_page_aligned_zeroed(bytes.len());
                let copy_len = bytes.len().min(buf.len());
                buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
                DataCap {
                    content: DataContent::Inline(buf),
                }
            }
            DataCapRepr::Paged {
                page_size,
                total_pages,
                pages: sparse,
            } => {
                let mut pages: Vec<PageSlot> = (0..total_pages).map(|_| PageSlot::Empty).collect();
                for entry in sparse {
                    let idx = entry.index as usize;
                    if idx >= pages.len() {
                        // Out-of-range entries are silently dropped;
                        // `total_pages` is the authoritative bound.
                        continue;
                    }
                    pages[idx] = match entry.data {
                        PageDataRepr::Loaded { hash, bytes } => {
                            PageSlot::Loaded(Arc::new(PageBytes { hash, bytes }))
                        }
                        PageDataRepr::Missing(h) => PageSlot::Missing(h),
                    };
                }
                DataCap {
                    content: DataContent::Paged { page_size, pages },
                }
            }
        }
    }
}

impl CNodeCapRepr {
    fn from_cnode(cn: &CNodeCap<CapHash>) -> Self {
        let mut slots = Vec::new();
        for (idx, entry) in cn.slots.iter() {
            let repr_entry = match entry {
                ssz::MissingOr::Materialized(h) => CNodeEntryRepr::Materialized(*h),
                ssz::MissingOr::Missing(h) => CNodeEntryRepr::Missing(*h),
            };
            slots.push(CNodeSlotRepr {
                slot: idx as u32,
                entry: repr_entry,
            });
        }
        Self {
            size_log: cn.size_log,
            slots,
        }
    }

    fn into_cnode(self) -> CNodeCap<CapHash> {
        // Construct via the public API so the size_log bound is
        // re-checked on the receive side. The constructor only fails
        // on `size_log > 16`; a malformed wire payload at this point
        // is a programmer bug, so panic.
        let mut cn = CNodeCap::<CapHash>::new(self.size_log)
            .expect("CNodeCapRepr::into_cnode: size_log > 16 from wire");
        for entry in self.slots {
            let key = entry.slot as u64;
            let value = match entry.entry {
                CNodeEntryRepr::Materialized(h) => ssz::MissingOr::Materialized(h),
                CNodeEntryRepr::Missing(h) => ssz::MissingOr::Missing(h),
            };
            // SparseList::insert can fail only on out-of-range index;
            // again, panic on malformed wire input.
            cn.slots
                .insert(key, value)
                .expect("CNodeCapRepr::into_cnode: slot index >= MAX_CNODE_SLOTS from wire");
        }
        cn
    }
}
