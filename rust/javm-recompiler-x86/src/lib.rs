#![no_std]

//! PVM recompiler — compiles PVM bytecode to native x86-64 machine code.
//!
//! This crate is the no_std bytes-producer: it emits x86-64 machine
//! code into a `Vec<u8>` (or directly into an mmap region when run
//! under the std-gated paths in `asm.rs` / `codegen.rs` that are
//! currently dormant). The runtime substrate that loads + executes
//! the emitted code lives in `nub-arch-x86`, which compiles this
//! crate with `default-features = false` and supplies its own
//! per-invocation page table.
//!
//! Public surface:
//! - [`JitContext`] — `#[repr(C)]` execution context, written by the
//!   driver before entry and read after exit. Layout is mirrored by
//!   the codegen-side `CTX_*` offset constants in
//!   `javm-recompiler-x86::codegen`.
//! - [`asm`], [`codegen`], [`predecode`] — codegen pipeline.

extern crate alloc;

pub mod asm;
pub mod codegen;
pub mod predecode;

/// JIT execution context passed to compiled code via R15.
/// Must be `#[repr(C)]` with exact field ordering matching the
/// `CTX_*` offset constants in [`codegen`].
#[repr(C)]
pub struct JitContext {
    /// PVM registers (offset 0, 13 × 8 = 104 bytes).
    pub regs: [u64; 13],
    /// Gas counter (offset 104). Signed to detect underflow.
    pub gas: i64,
    /// Exit reason code (offset 112).
    pub exit_reason: u32,
    /// Exit argument (offset 116) — host call ID, page fault addr, etc.
    pub exit_arg: u32,
    /// Heap base address (offset 120).
    pub heap_base: u32,
    /// Current heap top (offset 124).
    pub heap_top: u32,
    /// Jump table pointer (offset 128).
    pub jt_ptr: *const u32,
    /// Jump table length (offset 136).
    pub jt_len: u32,
    pub _pad0: u32,
    /// Basic block starts pointer (offset 144).
    pub bb_starts: *const u8,
    /// Basic block starts length (offset 152).
    pub bb_len: u32,
    pub _pad1: u32,
    /// Entry PC for re-entry after host calls (offset 160).
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
}
