//! Register state: 13 general-purpose 64-bit registers + PC.
//!
//! Per JAM Gray Paper Appendix A / PVM spec: the PVM has 13 GPRs
//! (φ₀..φ₁₂) plus an instruction pointer. PVM2 replaces the legacy PVM
//! ISA with RISC-V (RV64EMC + Zbb/Zba/Zbs/Zicond/Zicclsm) but keeps the
//! same 13-GPR + PC register file.

/// Number of general-purpose registers.
pub const REG_COUNT: usize = 13;

/// Classification of a 5-bit RV register index in PVM2.
///
/// PVM2 is an RV64E base — a 16-register file (`x0`–`x15`) — that
/// additionally reserves `x3`/`x4`. This is the **single source of truth**
/// for every place that needs register classification: the gas-simulator
/// slot map, the recompiler's codegen slot map, the interpreter's register
/// file access, and the reserved-register check both engines use. They all
/// derive from [`reg_class`] rather than re-encoding the valid/reserved
/// sets (which is how `rv_is_reserved` once drifted to miss `x16..x31`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegClass {
    /// `x0` — hardwired zero. Valid, but has no GPR slot.
    Zero,
    /// `x1`, `x2`, `x5`–`x15` — general-purpose; the payload is the slot
    /// `0..=12` into [`Regs::gpr`].
    Gpr(u8),
    /// `x3`, `x4` (PVM2-reserved) or `x16`–`x31` (don't exist in RV64E, so
    /// naming one is an illegal encoding). Such an instruction is a
    /// reserved encoding and panics if executed.
    Reserved,
}

/// Classify a 5-bit RV register index (low 5 bits of `x`). See [`RegClass`].
#[inline]
pub const fn reg_class(x: u8) -> RegClass {
    match x & 31 {
        0 => RegClass::Zero,
        1 => RegClass::Gpr(0),
        2 => RegClass::Gpr(1),
        n @ 5..=15 => RegClass::Gpr(n - 3),
        _ => RegClass::Reserved, // x3, x4, x16..x31
    }
}

/// PVM2 GPR slot (`0..=12`) for `x`, or `0xFF` if `x` has no slot — `x0`
/// (hardwired zero) *or* a reserved register. The gas simulator reads
/// `0xFF` as "no dependency / no write"; both engines' gas paths use this
/// (the recompiler via the const-folded [`REG_SLOT_LUT`]) so gas agrees
/// bit-for-bit. Note `0xFF` conflates `x0` with reserved — use
/// [`reg_is_reserved`] when that distinction matters.
#[inline]
pub const fn reg_slot_or_ff(x: u8) -> u8 {
    match reg_class(x) {
        RegClass::Gpr(s) => s,
        _ => 0xFF,
    }
}

/// True iff `x` is a *reserved* register (`x3`/`x4`/`x16..x31`) — as
/// opposed to `x0`, which also lacks a slot but is valid. Drives the
/// reserved-encoding check in both engines.
#[inline]
pub const fn reg_is_reserved(x: u8) -> bool {
    matches!(reg_class(x), RegClass::Reserved)
}

/// 32-entry const-folded copy of [`reg_slot_or_ff`] for the recompiler's
/// codegen/gas hot path — a single load beats the range-match (the
/// profiler showed the match at ~8.8% of compile). Generated from
/// [`reg_class`], so it cannot drift from the canonical classification.
pub const REG_SLOT_LUT: [u8; 32] = {
    let mut t = [0u8; 32];
    let mut x = 0u8;
    while x < 32 {
        t[x as usize] = reg_slot_or_ff(x);
        x += 1;
    }
    t
};

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
