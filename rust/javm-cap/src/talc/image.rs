//! `ImageCap<A>` — talc-friendly Image cap.
//!
//! Stores code, bitmask, jump_table, endpoints, mappings, and slot
//! references as separate `Vec<T, A>` allocations. Allocation count
//! per ImageCap is bounded (seven Vecs, regardless of content size);
//! we accept that in exchange for direct field accessors.

use allocator_api2::alloc::{Allocator, Global};
use allocator_api2::vec::Vec;

use crate::slot::SlotIdx;

use super::cap::{CapHash, MAX_ENDPOINTS, MAX_SOURCE_DEPTH, NUM_REGS};

pub struct ImageCap<A: Allocator + Clone = Global> {
    /// Bytecode bytes.
    pub code: Vec<u8, A>,
    /// Packed bit-per-byte instruction-start bitmask. Same layout
    /// as `crate::image::Image::packed_bitmask`.
    pub bitmask: Vec<u8, A>,
    /// Jump-table entries (PVM PCs).
    pub jump_table: Vec<u32, A>,
    /// Endpoint definitions. Stored as a dense array keyed by
    /// endpoint index — `endpoints[i].entry_pc == 0` means the
    /// endpoint at index `i` is not defined.
    pub endpoints: Vec<EndpointDef, A>,
    /// Memory mappings.
    pub mappings: Vec<MemoryMapping, A>,
    /// Pinned read-only slots (Cap::Data / Cap::Image). Images only
    /// ever reference content-addressed caps, so the target is a
    /// plain `CapHash`.
    pub pinned: Vec<ImageSlotEntry, A>,
    /// Initial mutable slot state for non-pinned slots.
    pub initial: Vec<ImageSlotEntry, A>,
    /// Slot holding `Cap::Instance[YieldCatcher]`, if any.
    pub yield_marker_slot: Option<SlotIdx>,
}

/// Endpoint definition. Dense `initial_regs` array; index `i`
/// corresponds to PVM register `φ[i]`. `0` is "use default" (same
/// semantics as the spec's old `BTreeMap<u8, u64>` when the key is
/// absent).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointDef {
    pub entry_pc: u64,
    pub stack_top: u64,
    pub arg_cnode_slot: SlotIdx,
    pub arg_cnode_size: u8,
    pub initial_regs: [u64; NUM_REGS],
}

impl EndpointDef {
    /// Empty endpoint — `entry_pc == 0` is the canonical sentinel
    /// for "not defined" (since a real entry PC is never zero — PC 0
    /// is reserved as the fallback PC in our convention).
    pub const fn empty() -> Self {
        Self {
            entry_pc: 0,
            stack_top: 0,
            arg_cnode_slot: SlotIdx(0),
            arg_cnode_size: 0,
            initial_regs: [0; NUM_REGS],
        }
    }
}

/// One mapped region. The kernel resolves `source_path` at instance
/// start, reads the bytes from the resulting `Cap::Data`, and lays
/// them at `[start, start + size)`. `source_path` is a fixed-cap
/// array; `source_path_len` is the actual depth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryMapping {
    pub start: u64,
    pub size: u64,
    pub source_path: [SlotIdx; MAX_SOURCE_DEPTH],
    pub source_path_len: u8,
}

impl MemoryMapping {
    /// Live slot indices (length = `source_path_len`).
    pub fn path(&self) -> &[SlotIdx] {
        &self.source_path[..self.source_path_len as usize]
    }
}

/// `(slot_idx, cap_hash)` pair used by Image's `pinned` and
/// `initial` arrays. References content-addressed caps only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageSlotEntry {
    pub slot: SlotIdx,
    pub cap_hash: CapHash,
}

/// Failure modes when converting a SCALE-encoded [`crate::image::Image`]
/// into an [`ImageCap`]. The conversion is lossy in fields the v3 cap
/// shape no longer carries (`gas_slots`, `quota_slots`, per-endpoint
/// `arg_registers`) and constrained in others — these errors flag the
/// constraint violations.
#[derive(Debug, thiserror::Error)]
pub enum ImageConvertError {
    #[error("memory mapping source path empty")]
    SourcePathEmpty,
    #[error("memory mapping source path too deep (steps={0} > MAX_SOURCE_DEPTH)")]
    SourcePathTooDeep(usize),
    #[error("endpoint index {0} >= MAX_ENDPOINTS")]
    EndpointIndexOutOfRange(u8),
    #[error("register index {0} >= NUM_REGS")]
    RegisterIndexOutOfRange(u8),
}

/// Build an [`ImageCap<A>`] from the SCALE-encoded [`crate::image::Image`]
/// shape. The Data content referenced by pinned and initial slots must
/// already be published — pass the resolved `(SlotIdx, CapHash)` pairs
/// in `pinned_hashes` and `initial_hashes`. The builder sorts both lists
/// by slot index.
///
/// **Lossy fields (intentionally dropped):**
/// - `gas_slots` / `quota_slots`: gas is now tracked on
///   [`super::instance::InstanceCap::gas_remaining`]; the v3 cap shape
///   no longer pins gas/quota slots in the Image.
/// - per-endpoint `arg_registers`: the calling convention is implicit
///   in the new shape.
///
/// **Field mappings:**
/// - Endpoints are stored in a dense `MAX_ENDPOINTS`-sized array,
///   indexed by endpoint id. Empty slots use [`EndpointDef::empty`].
///   `stack_top` is extracted from the old `initial_regs[1]` (RISC-V
///   SP convention); `arg_cnode_slot` defaults to `SlotIdx(0)`.
/// - `MemoryMapping.source: SlotPath` becomes `source_path: [SlotIdx;
///   MAX_SOURCE_DEPTH] + source_path_len`; paths deeper than 8 error.
pub fn image_cap_in<A: Allocator + Clone>(
    image: &crate::image::Image,
    pinned_hashes: &[(SlotIdx, CapHash)],
    initial_hashes: &[(SlotIdx, CapHash)],
    alloc: A,
) -> Result<ImageCap<A>, ImageConvertError> {
    let mut code = Vec::with_capacity_in(image.code.len(), alloc.clone());
    code.extend_from_slice(&image.code);

    let mut bitmask = Vec::with_capacity_in(image.packed_bitmask.len(), alloc.clone());
    bitmask.extend_from_slice(&image.packed_bitmask);

    let mut jump_table = Vec::with_capacity_in(image.jump_table.len(), alloc.clone());
    for &j in &image.jump_table {
        jump_table.push(j);
    }

    // Endpoints: dense `MAX_ENDPOINTS`-sized array; empty entries have
    // `entry_pc == 0`.
    let mut endpoints = Vec::with_capacity_in(MAX_ENDPOINTS, alloc.clone());
    for _ in 0..MAX_ENDPOINTS {
        endpoints.push(EndpointDef::empty());
    }
    for (&idx, ep) in &image.endpoints {
        if (idx as usize) >= MAX_ENDPOINTS {
            return Err(ImageConvertError::EndpointIndexOutOfRange(idx));
        }
        let mut initial_regs = [0u64; NUM_REGS];
        for (&reg_idx, &val) in &ep.initial_regs {
            if (reg_idx as usize) >= NUM_REGS {
                return Err(ImageConvertError::RegisterIndexOutOfRange(reg_idx));
            }
            initial_regs[reg_idx as usize] = val;
        }
        // RISC-V SP convention: φ[1] = stack pointer.
        let stack_top = ep.initial_regs.get(&1).copied().unwrap_or(0);
        endpoints[idx as usize] = EndpointDef {
            entry_pc: ep.entry_pc,
            stack_top,
            arg_cnode_slot: SlotIdx(0),
            arg_cnode_size: ep.arg_cnode_size,
            initial_regs,
        };
    }

    let mut mappings = Vec::with_capacity_in(image.memory_mappings.len(), alloc.clone());
    for m in &image.memory_mappings {
        let steps = &m.source.steps;
        if steps.is_empty() {
            return Err(ImageConvertError::SourcePathEmpty);
        }
        if steps.len() > MAX_SOURCE_DEPTH {
            return Err(ImageConvertError::SourcePathTooDeep(steps.len()));
        }
        let mut source_path = [SlotIdx(0); MAX_SOURCE_DEPTH];
        for (i, s) in steps.iter().enumerate() {
            source_path[i] = *s;
        }
        mappings.push(MemoryMapping {
            start: m.start,
            size: m.size,
            source_path,
            source_path_len: steps.len() as u8,
        });
    }

    let pinned = build_image_slot_vec(pinned_hashes, alloc.clone());
    let initial = build_image_slot_vec(initial_hashes, alloc.clone());

    Ok(ImageCap {
        code,
        bitmask,
        jump_table,
        endpoints,
        mappings,
        pinned,
        initial,
        yield_marker_slot: image.yield_marker_slot,
    })
}

fn build_image_slot_vec<A: Allocator + Clone>(
    pairs: &[(SlotIdx, CapHash)],
    alloc: A,
) -> Vec<ImageSlotEntry, A> {
    let mut sorted: alloc::vec::Vec<(SlotIdx, CapHash)> = pairs.to_vec();
    sorted.sort_by_key(|(s, _)| *s);
    let mut out = Vec::with_capacity_in(sorted.len(), alloc);
    for (slot, cap_hash) in &sorted {
        out.push(ImageSlotEntry {
            slot: *slot,
            cap_hash: *cap_hash,
        });
    }
    out
}
