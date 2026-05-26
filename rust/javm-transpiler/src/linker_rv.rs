//! ELF → PVM2 (raw RV+C+custom-0 bytes) linker.
//!
//! Parallel to [`super::linker::link_elf`] but emits raw RV bytes
//! instead of PVM-translated bytes. Reuses the ELF parsing + reloc
//! collection done by [`super::linker::parse_linked_elf`].
//!
//! The pipeline:
//! 1. **Parse ELF + relocs** (shared with the PVM path).
//! 2. **Concatenate code sections** into one byte buffer; each
//!    instruction keeps its original RV encoding.
//! 3. **Rewrite AUIPC pairs** (`R_RISCV_PCREL_HI20` /
//!    `R_RISCV_PCREL_LO12_*` / `R_RISCV_CALL_PLT`) to absolute
//!    `LUI`-based sequences. PVM2's 32-bit memory cap guarantees the
//!    upper bits are zero, so each `auipc + X` collapses to `lui + X`
//!    with the absolute target.
//! 4. **Replace standard `ECALL` markers** (`CSR 0x800` / `CSR 0x801`)
//!    with custom-0 `ecall.jar` / `ecalli` encodings.
//! 5. **Validate**: no AUIPC remaining, no x3/x4 use, no other
//!    forbidden encodings (see `~/docs/pvm-isa/05-pvm2-rv-diff.md`).
//! 6. **Emit Image** with `code = raw RV bytes`, empty `packed_bitmask`,
//!    empty `jump_table`. The recompiler-side `compile_rv` consumes
//!    these directly.
//!
//! This module is **NOT WIRED INTO link_elf yet**. It lives alongside
//! the PVM path until Phase 2 flips the switch.

use crate::TranspileError;
use crate::linker::{LinkedElf, parse_linked_elf};
use javm_cap::image::Image;

/// Link an RV ELF into a PVM2 [`Image`] whose `code` field is raw
/// RV+C+custom-0 bytes.
///
/// **Stub**: full implementation is the remaining bulk of Phase 2
/// (AUIPC desugar, ecall replace, validate, endpoint resolution by
/// RV PC). The module structure is in place to host that code; the
/// callable signature is locked in so callers can be wired up
/// independently.
#[allow(dead_code)]
pub fn link_elf_rv(elf_data: &[u8]) -> Result<Image, TranspileError> {
    let _elf: LinkedElf = parse_linked_elf(elf_data)?;
    Err(TranspileError::UnsupportedInstruction {
        offset: 0,
        detail: "link_elf_rv: not yet implemented (Phase 2 in progress)".into(),
    })
}
