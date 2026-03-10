//! Polkadot Virtual Machine (PVM) implementation for JAM (Appendix A).
//!
//! The PVM is a register-based virtual machine with:
//! - 13 general-purpose 64-bit registers (φ₀..φ₁₂)
//! - 32-bit pageable memory address space
//! - Gas metering for bounded execution
//! - Host-call interface for system interactions

pub mod args;
pub mod instruction;
pub mod memory;
pub mod program;
pub mod recompiler;
pub mod vm;

pub use memory::Memory;
pub use vm::{ExitReason, Pvm};
pub use recompiler::RecompiledPvm;
