#![no_std]

//! PVM recompiler — compiles PVM bytecode to native x86-64 machine code.
//!
//! This crate is the no_std bytes-producer: it emits x86-64 machine
//! code into a `Vec<u8>`. The runtime substrate that loads + executes
//! the emitted code lives in `nub-arch-x86`, which compiles this
//! crate with `default-features = false` and supplies its own
//! per-invocation page table.
//!
//! Public surface:
//! - [`JitContext`] — `#[repr(C)]` execution context, written by the
//!   driver before entry and read after exit. Layout is mirrored by
//!   the codegen-side `CTX_*` offset constants in
//!   `nub-recompiler-x86::codegen`.
//! - [`asm`], [`codegen`] — codegen pipeline.

extern crate alloc;

pub mod asm;
pub mod codegen;

/// JIT execution context passed to compiled code via R15.
/// Must be `#[repr(C)]` with exact field ordering matching the
/// `CTX_*` offset constants in [`codegen`].
#[repr(C)]
pub struct JitContext {
    /// PVM2 registers (offset 0, 15 × 8 = 120 bytes). Slots 0..12 are the
    /// host-mapped GPRs (flushed to/from x86 registers at the prologue /
    /// epilogue); slots 13/14 are the spilled `x3`/`x4`, which live here in
    /// memory for the whole block and are materialised per access.
    pub regs: [u64; 15],
    /// Gas counter. Signed to detect underflow.
    pub gas: i64,
    /// Exit reason code.
    pub exit_reason: u32,
    /// Exit argument — host call ID, page fault addr, etc.
    pub exit_arg: u32,
    /// Heap base address.
    pub heap_base: u32,
    /// Current heap top.
    pub heap_top: u32,
    /// Entry PC for re-entry after host calls.
    pub entry_pc: u32,
    /// Current PC when execution stopped (offset 164).
    pub pc: u32,
    /// Dispatch table: PVM PC → native code offset (offset 168).
    pub dispatch_table: *const i32,
    /// Base address of native code (offset 176).
    pub code_base: u64,
    /// Flat guest memory buffer base pointer (offset 184).
    pub flat_buf: *mut u8,
    /// Fast re-entry flag.
    pub fast_reentry: u32,
    pub _pad2: u32,
    /// Maximum heap pages — grow_heap refuses beyond this.
    pub max_heap_pages: u32,
    pub _pad3: u32,
    /// RSP saved at JIT entry (after the prologue's callee-saved pushes
    /// but before any guest code runs). The exit_label restores RSP
    /// from this slot before popping the callee-saved registers, so an
    /// OOG / page-fault redirect taken mid-sequence leaves the exit
    /// path with a clean stack.
    pub host_rsp_base: u64,
}
