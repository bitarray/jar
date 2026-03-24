//! RISC-V ELF to JAM PVM transpiler.
//!
//! Converts RISC-V rv64em ELF binaries into PVM program blobs
//! suitable for execution by the Grey PVM (Appendix A).
//!
//! Also provides utilities to hand-assemble PVM programs directly.

pub mod riscv;
pub mod emitter;
pub mod assembler;
pub mod linker;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TranspileError {
    #[error("ELF parse error: {0}")]
    ElfParse(String),
    #[error("unsupported RISC-V instruction at offset {offset:#x}: {detail}")]
    UnsupportedInstruction { offset: usize, detail: String },
    #[error("unsupported relocation: {0}")]
    UnsupportedRelocation(String),
    #[error("register mapping error: RISC-V register {0} has no PVM equivalent")]
    RegisterMapping(u8),
    #[error("code too large: {0} bytes")]
    CodeTooLarge(usize),
    #[error("invalid section: {0}")]
    InvalidSection(String),
}

/// Link a RISC-V rv64em ELF binary into a PVM standard program blob.
pub fn link_elf(elf_data: &[u8]) -> Result<Vec<u8>, TranspileError> {
    linker::link_elf(elf_data)
}

/// Link a RISC-V rv64em ELF binary into a JAM service PVM blob.
pub fn link_elf_service(elf_data: &[u8]) -> Result<Vec<u8>, TranspileError> {
    linker::link_elf_service(elf_data)
}
