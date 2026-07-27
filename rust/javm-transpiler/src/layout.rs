//! Cap-index convention for transpiler-emitted Images.
//!
//! The *geometry* of a linked program — which data regions exist, how
//! many pages each occupies, and where they land in the guest address
//! space — belongs to [`nub_program::Regions`] and is decided by the
//! linker. What lives here is the one thing that is genuinely a JAVM
//! choice: which cnode slot each region's `Cap::Data` is filed under.
//!
//! Slots 65..68 are arbitrary but fixed. They sit above the low slots a
//! guest's own cnode uses, and the runtime resolves each Image
//! `MemoryMapping`'s `source` path through them.

use nub_program::RegionKind;

/// Cap index of the stack DATA cap.
pub const STACK_CAP_INDEX: u8 = 65;
/// Cap index of the read-only DATA cap (`.rodata`).
pub const RO_CAP_INDEX: u8 = 66;
/// Cap index of the read-write DATA cap (`.data` + `.bss`).
pub const RW_CAP_INDEX: u8 = 67;
/// Cap index of the heap DATA cap.
pub const HEAP_CAP_INDEX: u8 = 68;

/// Re-exported PVM2 ABI layout constants (see [`nub_program::abi`]).
pub use javm_cap::layout::{CODE_BASE, DATA_BASE, MAX_CODE_SIZE};
/// PVM page size in bytes.
pub use nub_program::abi::PAGE_SIZE as PVM_PAGE_SIZE;

/// The cnode slot a region's `Cap::Data` is filed under.
pub const fn cap_index(kind: RegionKind) -> u8 {
    match kind {
        RegionKind::Stack => STACK_CAP_INDEX,
        RegionKind::Ro => RO_CAP_INDEX,
        RegionKind::Rw => RW_CAP_INDEX,
        RegionKind::Heap => HEAP_CAP_INDEX,
    }
}
