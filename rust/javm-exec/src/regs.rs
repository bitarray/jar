//! Register state: 13 general-purpose 64-bit registers + PC.
//!
//! Per JAM Gray Paper Appendix A / PVM spec: the PVM has 13 GPRs
//! (φ₀..φ₁₂) plus an instruction pointer. PVM2 replaces the legacy PVM
//! ISA with RISC-V (RV64EMC + Zbb/Zba/Zbs/Zicond/Zicclsm) but keeps the
//! same 13-GPR + PC register file.

/// Number of general-purpose registers.
pub const REG_COUNT: usize = 13;

/// Full register state: 13 GPRs + PC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Regs {
    /// General-purpose registers φ₀..φ₁₂.
    pub gpr: [u64; REG_COUNT],
    /// Program counter — a code byte-offset, not a memory address.
    /// (Register-held code addresses, e.g. a saved return address or an
    /// `auipc` result, are guest VAs `code_base + offset`.)
    pub pc: u64,
}

impl Regs {
    /// All zeros, PC = 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read register `i`. Returns 0 if `i >= REG_COUNT` (defensive;
    /// callers should validate the opcode first).
    pub fn read(&self, i: usize) -> u64 {
        self.gpr.get(i).copied().unwrap_or(0)
    }

    /// Write register `i`. No-op if `i >= REG_COUNT`.
    pub fn write(&mut self, i: usize, v: u64) {
        if let Some(slot) = self.gpr.get_mut(i) {
            *slot = v;
        }
    }
}

impl Default for Regs {
    fn default() -> Self {
        Self {
            gpr: [0u64; REG_COUNT],
            pc: 0,
        }
    }
}
