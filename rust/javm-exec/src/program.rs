//! PVM program input: raw bytecode + bitmask + jump table.
//!
//! javm-exec consumes pre-decoded program fields. The JAR blob
//! container (cap manifest + data section + code sub-blob) lives
//! upstream — at the cap layer or integration crate. By the time
//! the program reaches the execution engine, the caller has already
//! extracted the executable parts.
//!
//! This module is a thin container plus a few helpers. The
//! interpreter and recompiler both consume `&PvmProgram`.

use crate::error::ProgramError;
use alloc::vec::Vec;

/// PVM program for execution.
///
/// - `code` is the raw byte-encoded PVM bytecode (JAM Gray Paper
///   Appendix A.5).
/// - `bitmask` is the **unpacked** form (one byte per code position);
///   `bitmask[i] == 1` iff a PVM instruction starts at `code[i]`.
///   Packed bitmasks (1 bit per byte) live only in the serialized
///   blob format upstream; by the time the program reaches this
///   layer the upstream parser has unpacked them.
/// - `jump_table[i]` is the target byte offset within `code` for a
///   branch / jump whose immediate decodes to `i`.
/// - `mem_cycles` is the L/S latency tier (see `compute_mem_cycles`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PvmProgram {
    pub code: Vec<u8>,
    pub bitmask: Vec<u8>,
    pub jump_table: Vec<u32>,
    pub mem_cycles: u8,
}

impl PvmProgram {
    /// Construct with validation: `bitmask.len()` must equal
    /// `code.len()`.
    pub fn new(
        code: Vec<u8>,
        bitmask: Vec<u8>,
        jump_table: Vec<u32>,
        mem_cycles: u8,
    ) -> Result<Self, ProgramError> {
        if bitmask.len() != code.len() {
            return Err(ProgramError::BitmaskLenMismatch {
                code_len: code.len(),
                bitmask_len: bitmask.len(),
            });
        }
        Ok(Self {
            code,
            bitmask,
            jump_table,
            mem_cycles,
        })
    }

    /// `true` iff a PVM instruction starts at byte offset `pc` in
    /// `code`. False if `pc` is out of range.
    pub fn is_insn_start(&self, pc: u32) -> bool {
        self.bitmask
            .get(pc as usize)
            .map(|&b| b != 0)
            .unwrap_or(false)
    }

    /// Number of bytecode bytes.
    pub fn code_len(&self) -> usize {
        self.code.len()
    }
}

/// L/S memory cycle latency tier as a function of accessible page
/// count (cherry-picked from v2 `javm/src/lib.rs::compute_mem_cycles`):
///
/// - ≤ 8 MiB (2048 pages):  25 cycles (L2)
/// - ≤ 32 MiB (8192 pages): 50 cycles (L3)
/// - ≤ 256 MiB:             75 cycles (DRAM)
/// - > 256 MiB:             100 cycles (DRAM saturated)
pub fn compute_mem_cycles(total_pages: u32) -> u8 {
    match total_pages {
        0..=2048 => 25,
        2049..=8192 => 50,
        8193..=65536 => 75,
        _ => 100,
    }
}

/// Unpack a packed bitmask (1 bit per byte) into the unpacked form
/// (one byte per code position; 0 or 1). The packed form is the
/// serialized representation; the unpacked form is what
/// `PvmProgram::bitmask` carries.
pub fn unpack_bitmask(packed: &[u8], code_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; code_len];
    for i in 0..code_len {
        out[i] = (packed[i / 8] >> (i % 8)) & 1;
    }
    out
}
