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
pub mod backend;
#[cfg(feature = "std")]
pub mod backing;
pub mod cap;
pub mod gas_cost;
pub mod gas_sim;
pub mod instruction;
pub mod interpreter;
#[cfg(feature = "std")]
pub mod kernel;
pub mod program;
pub mod vm_pool;
// Real JIT recompiler on Linux x86-64.
#[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
pub mod recompiler;
// On non-Linux/x86-64 only predecode is needed (used by gas_cost).
// All JIT-specific types are behind cfg guards in backend.rs and kernel.rs.
#[cfg(all(feature = "std", not(all(target_os = "linux", target_arch = "x86_64"))))]
pub mod recompiler {
    pub mod predecode;
}

pub use backend::PvmBackend;
pub use interpreter::Interpreter;
#[cfg(feature = "std")]
pub use kernel::CodeCache;

// --- PVM types ---

/// Exit reason for PVM execution (ε values, eq A.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitReason {
    /// ∎: Normal halt.
    Halt,
    /// Deliberate trap (opcode 0). Program-initiated termination.
    Trap,
    /// ☇: Panic / runtime error (bad djump, invalid opcode).
    Panic,
    /// ∞: Out of gas.
    OutOfGas,
    /// ×: Page fault at the given page address.
    PageFault(u32),
    /// h̵: Host-call with the given identifier (ecalli).
    HostCall(u32),
    /// Management op or dynamic CALL (ecall). φ\[11\]=op, φ\[12\]=subject|object.
    Ecall,
}

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

/// Gas cost per page for initial memory allocation and retype.
pub const GAS_PER_PAGE: u64 = 1500;

/// Compute memory tier load/store cycles based on total accessible pages.
pub fn compute_mem_cycles(total_pages: u32) -> u8 {
    match total_pages {
        0..=2048 => 25,     // ≤ 8MB: L2 baseline
        2049..=8192 => 50,  // ≤ 32MB: L3
        8193..=65536 => 75, // ≤ 256MB: DRAM
        _ => 100,           // > 256MB: DRAM saturated
    }
}
