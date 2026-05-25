//! Wire-form caps for the host ↔ guest `put_cap` RPC.
//!
//! [`Cap`] and its inner types use the SSZ derive macro for content
//! hashing and carry rkyv-incompatible fields (`SparseList` in
//! [`CNodeCap`], `Arc<PageBytes>` in `PageSlot::Loaded`). Adding
//! rkyv derives there would either require hand-written `Archive` /
//! `Serialize` / `Deserialize` impls for those types or a
//! transformation wrapper. We pick a third option: a sibling enum
//! whose shape mirrors `Cap` but flattens or omits the unsupported
//! fields, with explicit `From<&Cap>` / `TryInto<Cap>` conversions
//! at the wire boundary.
//!
//! ## V0 limitations
//!
//! - **`WireCap::CNode` only carries materialized `Hash` slot
//!   entries.** `SparseList` cached-subtree-roots and
//!   `MissingOr::Missing(_)` placeholders are dropped on the wire;
//!   the receiver reconstructs a fresh [`CNodeCap`] without them.
//!   `Ref(_)` slot targets are rejected (`WireConvertError::CapHasRef`)
//!   because the receiver has no way to resolve them in its own
//!   `CapRef` namespace.
//! - **`WireCap::Data` only supports `DataContent::Inline`.** The
//!   `Paged` variant errors out (`WireConvertError::PagedData`) —
//!   `PageRef = Arc<PageBytes>` doesn't archive cleanly and the V0
//!   bench guests don't need it.
//! - **`WireCap::Instance` only carries `Hash` `root_cnode`** (no
//!   live `Ref` targets, same reasoning as CNode).
//!
//! These limits cover the smoke-test path (Image + empty CNode +
//! Instance with no rw_overlays containing Refs) and are tightened
//! at the type level: the wire types simply don't have fields for
//! the unsupported shapes.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::cache::CapHashOrRef;
use crate::cap::{Cap, NUM_REGS, TypeCap};
use crate::cnode::CNodeCap;
use crate::data::{DataCap, DataContent};
use crate::image_cap::{EndpointDef, ImageCap, ImageSlotEntry, MemoryMapping};
use crate::instance::{InstanceCap, RwOverlay};
use crate::slot::SlotIdx;

/// Failures the wire-form conversion can produce. All non-fatal:
/// they indicate the cap shape isn't supported on the V0 RPC path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireConvertError {
    /// A `Cap` field held a `CapHashOrRef::Ref(_)` target. The
    /// receiver has no way to resolve refs in its own `CapRef`
    /// namespace, so refs are rejected.
    CapHasRef,
    /// A `Cap::Data` carried a `DataContent::Paged` body. V0 doesn't
    /// serialise paged data.
    PagedData,
    /// A `Cap::CNode` carried a `MissingOr::Missing(_)` placeholder.
    /// The wire form only carries materialized slot entries.
    CNodeMissingSlot,
}

/// Wire-shaped cap. Derives `rkyv::{Archive, Serialize, Deserialize}`
/// using only `alloc::Vec`/`Box` and plain `repr(C)` fields. The
/// shape mirrors [`Cap`] but with the constraints called out in the
/// module docs.
#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum WireCap {
    Instance(WireInstanceCap),
    Image(WireImageCap),
    Data(WireDataCap),
    CNode(WireCNodeCap),
    Type(WireTypeCap),
}

/// Wire form of [`InstanceCap`]. `root_cnode` collapses
/// [`CapHashOrRef`] down to a plain hash (V0: refs unsupported).
#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct WireInstanceCap {
    pub image_hash_chain: [u8; 32],
    pub image_hash: [u8; 32],
    pub root_cnode_hash: [u8; 32],
    pub rw_overlays: Vec<WireRwOverlay>,
    pub mem_size: u32,
    pub regs: [u64; NUM_REGS],
    pub pc: u64,
    pub gas_remaining: u64,
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct WireRwOverlay {
    pub start: u32,
    pub bytes: Vec<u8>,
}

/// Wire form of [`ImageCap`]. Direct field-for-field mirror — all
/// inner types are derive-compatible already.
#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct WireImageCap {
    pub code: Vec<u8>,
    pub bitmask: Vec<u8>,
    pub jump_table: Vec<u32>,
    pub endpoints: Vec<WireEndpointDef>,
    pub mappings: Vec<WireMemoryMapping>,
    pub pinned: Vec<WireImageSlotEntry>,
    pub initial: Vec<WireImageSlotEntry>,
    pub yield_marker_slot: Option<u32>,
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct WireEndpointDef {
    pub entry_pc: u64,
    pub stack_top: u64,
    pub arg_cnode_slot: u32,
    pub arg_cnode_size: u8,
    pub initial_regs: [u64; NUM_REGS],
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct WireMemoryMapping {
    pub start: u64,
    pub size: u64,
    pub source_path: Vec<u32>,
    pub source_path_len: u8,
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct WireImageSlotEntry {
    pub slot: u32,
    pub cap_hash: [u8; 32],
}

/// Wire form of [`DataCap`]. V0: inline-only.
#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct WireDataCap {
    pub bytes: Vec<u8>,
}

/// Wire form of [`CNodeCap`]. Flat list of `(slot, hash)` pairs;
/// only materialized `Hash` slot entries are carried.
#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct WireCNodeCap {
    pub size_log: u8,
    pub slots: Vec<WireCNodeSlot>,
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct WireCNodeSlot {
    pub slot: u32,
    pub cap_hash: [u8; 32],
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct WireTypeCap {
    pub image_hash_chain: [u8; 32],
}

// --- Conversions ---

impl WireCap {
    /// Build a wire form from a borrowed [`Cap`]. The cap is read but
    /// not mutated; the wire form owns its own allocations.
    pub fn from_cap(cap: &Cap) -> Result<Self, WireConvertError> {
        Ok(match cap {
            Cap::Instance(i) => WireCap::Instance(WireInstanceCap::from_instance(i)?),
            Cap::Image(i) => WireCap::Image(WireImageCap::from_image(i)),
            Cap::Data(d) => WireCap::Data(WireDataCap::from_data(d)?),
            Cap::CNode(c) => WireCap::CNode(WireCNodeCap::from_cnode(c)?),
            Cap::Type(t) => WireCap::Type(WireTypeCap {
                image_hash_chain: t.image_hash_chain,
            }),
        })
    }

    /// Recover an owned [`Cap`] from this wire form. Allocates fresh
    /// storage in the caller's allocator.
    pub fn into_cap(self) -> Result<Cap, WireConvertError> {
        Ok(match self {
            WireCap::Instance(i) => Cap::Instance(i.into_instance()),
            WireCap::Image(i) => Cap::Image(i.into_image()),
            WireCap::Data(d) => Cap::Data(d.into_data()),
            WireCap::CNode(c) => Cap::CNode(c.into_cnode()?),
            WireCap::Type(t) => Cap::Type(TypeCap {
                image_hash_chain: t.image_hash_chain,
            }),
        })
    }
}

impl WireInstanceCap {
    fn from_instance(inst: &InstanceCap) -> Result<Self, WireConvertError> {
        let root_cnode_hash = match inst.root_cnode {
            CapHashOrRef::Hash(h) => h,
            CapHashOrRef::Ref(_) => return Err(WireConvertError::CapHasRef),
        };
        let rw_overlays = inst
            .rw_overlays
            .iter()
            .map(|ov| WireRwOverlay {
                start: ov.start,
                bytes: ov.bytes.clone(),
            })
            .collect();
        Ok(Self {
            image_hash_chain: inst.image_hash_chain,
            image_hash: inst.image_hash,
            root_cnode_hash,
            rw_overlays,
            mem_size: inst.mem_size,
            regs: inst.regs,
            pc: inst.pc,
            gas_remaining: inst.gas_remaining,
        })
    }

    fn into_instance(self) -> InstanceCap {
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
            root_cnode: CapHashOrRef::Hash(self.root_cnode_hash),
            rw_overlays,
            mem_size: self.mem_size,
            regs: self.regs,
            pc: self.pc,
            gas_remaining: self.gas_remaining,
        }
    }
}

impl WireImageCap {
    fn from_image(img: &ImageCap) -> Self {
        let endpoints = img
            .endpoints
            .iter()
            .map(|e| WireEndpointDef {
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
            .map(|m| WireMemoryMapping {
                start: m.start,
                size: m.size,
                source_path: m.source_path.iter().map(|s| s.get()).collect(),
                source_path_len: m.source_path_len,
            })
            .collect();
        let pinned = img
            .pinned
            .iter()
            .map(|e| WireImageSlotEntry {
                slot: e.slot.get(),
                cap_hash: e.cap_hash,
            })
            .collect();
        let initial = img
            .initial
            .iter()
            .map(|e| WireImageSlotEntry {
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

impl WireDataCap {
    fn from_data(d: &DataCap) -> Result<Self, WireConvertError> {
        match &d.content {
            DataContent::Inline(bytes) => Ok(Self {
                bytes: bytes.clone(),
            }),
            DataContent::Paged { .. } => Err(WireConvertError::PagedData),
        }
    }

    fn into_data(self) -> DataCap {
        // Build a page-aligned, zero-padded buffer so the receiver's
        // `DataCap` retains the page-alignment invariant the kernel
        // expects when direct-mapping data caps into ring 3.
        let bytes = self.bytes;
        let mut buf = crate::data::alloc_page_aligned_zeroed(bytes.len());
        let copy_len = bytes.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
        DataCap {
            content: DataContent::Inline(buf),
        }
    }
}

impl WireCNodeCap {
    fn from_cnode(cn: &CNodeCap) -> Result<Self, WireConvertError> {
        let mut slots = Vec::new();
        for (idx, entry) in cn.slots.iter() {
            match entry {
                ssz::MissingOr::Materialized(CapHashOrRef::Hash(h)) => {
                    slots.push(WireCNodeSlot {
                        slot: idx as u32,
                        cap_hash: *h,
                    });
                }
                ssz::MissingOr::Materialized(CapHashOrRef::Ref(_)) => {
                    return Err(WireConvertError::CapHasRef);
                }
                ssz::MissingOr::Missing(_) => {
                    return Err(WireConvertError::CNodeMissingSlot);
                }
            }
        }
        Ok(Self {
            size_log: cn.size_log,
            slots,
        })
    }

    fn into_cnode(self) -> Result<CNodeCap, WireConvertError> {
        // Reconstruct via the public CNodeCap API so invariants
        // (size_log bound + slot-fits check) are upheld.
        let mut cn =
            CNodeCap::new(self.size_log).map_err(|_| WireConvertError::CNodeMissingSlot)?;
        for entry in self.slots {
            cn.set(
                SlotIdx(entry.slot),
                Some(CapHashOrRef::Hash(entry.cap_hash)),
            )
            .map_err(|_| WireConvertError::CNodeMissingSlot)?;
        }
        Ok(cn)
    }
}

// --- Helpers used by the host driver ---

/// Box-ed convenience: produce a `Box<Cap>` from an archived
/// `WireCap`. Used by the guest's `put_cap` RPC handler to deposit
/// the decoded cap into its directory.
pub fn box_from_wire(wire: WireCap) -> Result<Box<Cap>, WireConvertError> {
    wire.into_cap().map(Box::new)
}

/// Convenience: pretty-print a `WireConvertError` without depending
/// on `thiserror` (so this module stays usable in `no_std` contexts
/// that don't pull in the error infra).
impl core::fmt::Display for WireConvertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WireConvertError::CapHasRef => {
                f.write_str("cap holds a CapHashOrRef::Ref target; refs are unsupported on the wire")
            }
            WireConvertError::PagedData => {
                f.write_str("DataContent::Paged is not supported on the wire (V0 inline-only)")
            }
            WireConvertError::CNodeMissingSlot => {
                f.write_str("CNodeCap slot is unrepresentable on the wire (missing placeholder or oversized cnode)")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WireConvertError {}
