//! x86-64 JIT recompiler for byte-PVM.
//!
//! Cherry-picked from v2 `javm/src/recompiler/`. Gated to Linux/x86-64
//! at the call site (only platforms where the SIGSEGV-based page-fault
//! interception works). The interpreter remains the fallback on every
//! other platform.
//!
//! Sub-modules (in dependency order):
//! - [`asm`] — x86-64 assembler primitives (no external deps).
//!
//! Stage B is being landed piece-by-piece; this module will grow to
//! include `predecode`, `codegen`, `signal`, and the `CompiledCode`
//! driver as those land.

pub mod asm;
