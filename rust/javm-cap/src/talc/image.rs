//! `ImageCap<A>` — talc-friendly Image cap.
//!
//! Stores code, bitmask, jump_table, endpoints, mappings, and slot
//! references as separate `Vec<T, A>` allocations. Allocation count
//! per ImageCap is bounded (seven Vecs, regardless of content size);
//! we accept that in exchange for direct field accessors.

use allocator_api2::alloc::{Allocator, Global};
use allocator_api2::vec::Vec;

use crate::slot::SlotIdx;

use super::cap::{CapHash, MAX_SOURCE_DEPTH, NUM_REGS};

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
