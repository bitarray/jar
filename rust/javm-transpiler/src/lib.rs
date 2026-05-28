//! RISC-V ELF to PVM2 transpiler.
//!
//! Converts RISC-V rv64em+C+Zbb+Zba+Zbs+Zicond+custom-0 ELF binaries
//! into PVM2 program blobs suitable for execution by the JAR PVM2
//! engine (interpreter / x86 recompiler).

pub mod elf;
pub mod layout;
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
