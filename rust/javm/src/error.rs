//! Errors surfaced by the v3 Vm.

use javm_cap::{CacheError, CapError, OpError};

/// Errors from the Vm driver. Distinct from per-instruction
/// `ExitReason` values (those come from `javm_exec`).
#[derive(Debug, thiserror::Error)]
pub enum VmError {
    #[error("call stack full (max depth reached)")]
    CallStackFull,
    #[error("call stack empty")]
    CallStackEmpty,
    #[error("invariant violated: {0}")]
    Invariant(&'static str),
    #[error("reference entry targets out-of-range position {0}")]
    ReferenceOutOfRange(usize),
    #[error("reference entry targets a non-instance entry at position {0}")]
    ReferenceNonInstance(usize),
    #[error("instance lookup failed (no live state for the named instance hash)")]
    InstanceNotFound,
    #[error("image lookup failed for content hash")]
    ImageNotFound,
    #[error("cap-table operation failed: {0}")]
    CapTable(#[from] CapError),
    #[error("MGMT op failed: {0}")]
    Op(#[from] OpError),
    #[error("cache operation failed: {0}")]
    CacheDirectory(#[from] CacheError),
    #[error("yield marker did not match any handler on the call stack")]
    UnhandledMarker,
    #[error("image bytecode failed to parse: {0}")]
    InvalidBytecode(String),
    #[error("slot path step {0} expected a Cap::CNode but found a different kind")]
    SlotKindMismatch(u32),
    #[error("slot path step {0} traversed an empty slot")]
    SlotEmpty(u32),
    #[error("memory mapping setup failed: {0:?}")]
    MapRegion(javm_exec::MapError),
}
