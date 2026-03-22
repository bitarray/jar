//! Join-Accumulate VM (JAVM) — PVM implementation for JAM (Appendix A).
//!
//! The PVM is a register-based virtual machine with:
//! - 13 general-purpose 64-bit registers (φ₀..φ₁₂)
//! - 32-bit pageable memory address space
//! - Gas metering for bounded execution
//! - Host-call interface for system interactions

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod args;
pub mod gas_cost;
pub mod gas_sim;
pub mod instruction;
pub mod program;
#[cfg(feature = "std")]
pub mod recompiler;
pub mod vm;

pub use vm::{ExitReason, Pvm};
#[cfg(feature = "std")]
pub use recompiler::RecompiledPvm;

// --- PVM constants (Gray Paper Appendix A / I.4.4) ---

/// Gas type: NG = N_{2^64} (eq 4.23).
pub type Gas = u64;

/// ZP = 2^12 = 4096: PVM memory page size.
pub const PVM_PAGE_SIZE: u32 = 1 << 12;

/// ZI = 2^24: Standard PVM program initialization input data size.
pub const PVM_INIT_INPUT_SIZE: u32 = 1 << 24;

/// ZZ = 2^16 = 65536: Standard PVM program initialization zone size.
pub const PVM_ZONE_SIZE: u32 = 1 << 16;

/// Number of registers in the PVM.
pub const PVM_REGISTER_COUNT: usize = 13;
