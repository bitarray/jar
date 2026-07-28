//! RISC-V ELF to JAVM `Image`.
//!
//! A thin adapter over [`nub_linker`]: that crate turns an RV64EMC ELF
//! into a personality-free [`nub_program::ProgramBlob`], and this one
//! wraps the blob in the JAVM capability shape — one `Cap::Data` per
//! data region at its conventional cnode slot, declarative
//! `MemoryMapping`s, SSZ encoding and content hashing.
//!
//! The split is deliberate: everything above is PVM2 ISA work that nub
//! must be able to do without knowing JAVM exists.

pub mod layout;
pub mod linker;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TranspileError {
    #[error("link error: {0}")]
    Link(#[from] nub_linker::LinkError),
}
