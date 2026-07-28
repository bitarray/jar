//! RISC-V ELF → PVM2 linker.
//!
//! Converts a linked RV64EMC (+Zbb/Zba/Zbs/Zicond/Zicclsm/custom-0) ELF
//! — as produced by the `riscv64emc-pvm2` target — into a
//! [`nub_program::ProgramBlob`] the interpreter and recompiler can run
//! directly.
//!
//! This is ISA work, not policy work: section concatenation, AUIPC-pair
//! resolution, ecall-marker rewriting, fallthrough injection and PVM2
//! validation. Nothing here knows about capabilities, cnodes or content
//! hashing. A personality that wants those wraps the emitted blob —
//! `javm-transpiler` does exactly that to produce a cap `Image`.
//!
//! ```no_run
//! let elf = std::fs::read("guest.elf").unwrap();
//! let blob = nub_linker::link_elf(&elf).unwrap();
//! std::fs::write("guest.nubp", blob.to_bytes()).unwrap();
//! ```

pub mod elf;
mod link;

pub use link::link_elf;

use thiserror::Error;

/// Why an ELF could not be linked into a [`nub_program::ProgramBlob`].
#[derive(Error, Debug)]
pub enum LinkError {
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
    /// The linked result violates a [`nub_program::ProgramBlob`]
    /// invariant — code overlapping `DATA_BASE`, data past the 4 GiB
    /// guest range, or a program with no endpoints.
    #[error("invalid program: {0}")]
    InvalidProgram(#[from] nub_program::InvalidProgram),
}
