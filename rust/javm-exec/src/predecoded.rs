//! Pre-decoded PVM instruction representation, shared between the
//! pure execution-engine gas accounting (here in `javm-exec`) and
//! the recompiler crate that populates the slice via its
//! `predecode` pass.
//!
//! The struct is a plain data tuple of opcode + decoded args + PC
//! metadata. It carries no recompiler-internal state, so it lives
//! here so that `gas_cost.rs` can reference it without javm-exec
//! depending on the recompiler crate.

use crate::args::Args;
use crate::instruction::Opcode;

/// Pre-decoded PVM instruction. Stores everything the codegen and
/// the gas simulator need per instruction.
#[derive(Clone, Copy, Debug)]
pub struct PreDecodedInst {
    /// PVM opcode (for compile_instruction match dispatch).
    pub opcode: Opcode,
    /// Decoded arguments (registers, immediates, offsets).
    pub args: Args,
    /// PVM byte offset of this instruction.
    pub pc: u32,
    /// PVM byte offset of the next instruction.
    pub next_pc: u32,
    /// Gas cost if this is a gas block start (>0), 0 otherwise.
    /// Set by the recompiler's single-pass codegen via placeholder + patch.
    pub gas_cost: u32,
    /// Whether this instruction starts a gas metering block.
    pub is_gas_block_start: bool,
    /// Flat register fields for fast gas cost lookup (avoids Args enum match).
    pub ra: u8,
    pub rb: u8,
    pub rd: u8,
}
