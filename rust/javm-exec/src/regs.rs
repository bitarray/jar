//! Register state: 13 general-purpose 64-bit registers + PC.
//!
//! Per JAM Gray Paper Appendix A / PVM spec: the PVM has 13 GPRs
//! (φ₀..φ₁₂) plus an instruction pointer. v3 keeps the same layout
//! since v3 doesn't change the PVM instruction set.

/// Number of general-purpose registers.
pub const REG_COUNT: usize = 13;

/// Full register state: 13 GPRs + PC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Regs {
    /// General-purpose registers φ₀..φ₁₂.
    pub gpr: [u64; REG_COUNT],
    /// Program counter (bytecode offset, not memory address).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_zero() {
        let r = Regs::new();
        assert_eq!(r.pc, 0);
        for i in 0..REG_COUNT {
            assert_eq!(r.read(i), 0);
        }
    }

    #[test]
    fn read_write_round_trip() {
        let mut r = Regs::new();
        r.write(7, 0xDEAD_BEEF);
        assert_eq!(r.read(7), 0xDEAD_BEEF);
    }

    #[test]
    fn out_of_range_read_returns_zero() {
        let r = Regs::new();
        assert_eq!(r.read(99), 0);
    }

    #[test]
    fn out_of_range_write_is_noop() {
        let mut r = Regs::new();
        r.write(99, 1);
        // No panic; no state change.
        for i in 0..REG_COUNT {
            assert_eq!(r.read(i), 0);
        }
    }
}
