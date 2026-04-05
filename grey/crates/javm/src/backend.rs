//! PVM backend selection — interpreter or recompiler.
//!
//! The kernel creates CODE caps that wrap compiled code in one of two backends.
//! `PvmBackend` controls the selection; `CompiledProgram` holds the result.

use alloc::vec::Vec;

/// Backend selection for PVM execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PvmBackend {
    /// Use recompiler if available (x86-64 Linux), else interpreter.
    /// Reads `GREY_PVM` env var: "interpreter" forces interpreter,
    /// "recompiler" forces recompiler.
    Default,
    /// Always use the software interpreter.
    ForceInterpreter,
    /// Always use the JIT recompiler (panics if unavailable).
    ForceRecompiler,
}

/// Pre-decoded interpreter program state.
///
/// Contains the instruction stream pre-decoded for the fast interpreter path.
/// Created by `Interpreter::predecode()` and stored in a `CodeCap`.
pub struct InterpreterProgram {
    /// Pre-decoded instruction stream.
    pub decoded_insts: Vec<crate::interpreter::DecodedInst>,
    /// PC byte offset → instruction index mapping.
    pub pc_to_idx: Vec<u32>,
    /// Valid branch/jump landing targets.
    pub basic_block_starts: Vec<bool>,
    /// Per-gas-block costs (indexed by block start PC).
    pub block_gas_costs: Vec<u64>,
    /// Instruction bytecode (kept for step/trace fallback).
    pub code: Vec<u8>,
    /// Opcode bitmask.
    pub bitmask: Vec<u8>,
    /// Dynamic jump table.
    pub jump_table: Vec<u32>,
    /// Memory tier cycles.
    pub mem_cycles: u8,
}

/// Compiled PVM program — either interpreter or recompiler backend.
pub enum CompiledProgram {
    /// Software interpreter with pre-decoded instructions.
    Interpreter(InterpreterProgram),
    /// JIT-compiled native x86-64 code.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    Recompiler(crate::recompiler::CompiledCode),
}

impl core::fmt::Debug for CompiledProgram {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Interpreter(p) => f
                .debug_struct("Interpreter")
                .field("insts", &p.decoded_insts.len())
                .finish(),
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            Self::Recompiler(c) => f
                .debug_struct("Recompiler")
                .field("native_len", &c.native_code.len)
                .finish(),
        }
    }
}

/// Resolve the backend to use based on `PvmBackend` selection and platform.
fn resolve_backend(backend: PvmBackend) -> ResolvedBackend {
    match backend {
        PvmBackend::ForceInterpreter => ResolvedBackend::Interpreter,
        PvmBackend::ForceRecompiler => {
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            return ResolvedBackend::Recompiler;
            #[cfg(not(all(feature = "std", target_os = "linux", target_arch = "x86_64")))]
            panic!("ForceRecompiler requested but JIT recompiler not available on this platform");
        }
        PvmBackend::Default => {
            // Check GREY_PVM env var
            #[cfg(feature = "std")]
            {
                if let Ok(val) = std::env::var("GREY_PVM") {
                    match val.as_str() {
                        "interpreter" => return ResolvedBackend::Interpreter,
                        "recompiler" => {
                            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                            return ResolvedBackend::Recompiler;
                            #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
                            panic!("GREY_PVM=recompiler but JIT not available on this platform");
                        }
                        _ => {} // fall through to platform default
                    }
                }
            }
            // Platform default: recompiler if available
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            return ResolvedBackend::Recompiler;
            #[cfg(not(all(feature = "std", target_os = "linux", target_arch = "x86_64")))]
            return ResolvedBackend::Interpreter;
        }
    }
}

enum ResolvedBackend {
    Interpreter,
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    Recompiler,
}

/// Compile PVM code into a `CompiledProgram` using the selected backend.
pub fn compile(
    code: &[u8],
    bitmask: &[u8],
    jump_table: &[u32],
    mem_cycles: u8,
    backend: PvmBackend,
) -> Result<CompiledProgram, alloc::string::String> {
    match resolve_backend(backend) {
        ResolvedBackend::Interpreter => {
            let prog =
                crate::interpreter::Interpreter::predecode(code, bitmask, jump_table, mem_cycles);
            Ok(CompiledProgram::Interpreter(prog))
        }
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        ResolvedBackend::Recompiler => {
            let compiled = crate::recompiler::compile_code(code, bitmask, jump_table, mem_cycles)?;
            Ok(CompiledProgram::Recompiler(compiled))
        }
    }
}
