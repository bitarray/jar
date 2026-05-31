//! Register state: 15 general-purpose 64-bit registers + PC.
//!
//! PVM2 is RV64E — a 16-register integer base (`x0`–`x15`) — so it has the
//! full **15** GPRs (`x1`, `x2`, `x5`–`x15`, plus `x3`, `x4`) with `x0`
//! hardwired to zero, plus an instruction pointer. `x3`/`x4` map to the two
//! *high* slots (13, 14) so the 13 commonly-used registers keep slots
//! `0..=12`; the recompiler holds those 13 in host registers and **spills**
//! `x3`/`x4` to memory (see [`reg_is_spilled`]). Only `x16`–`x31` (which do
//! not exist in the E base) remain reserved.

/// Number of general-purpose registers.
pub const REG_COUNT: usize = 15;

/// Classification of a 5-bit RV register index in PVM2.
///
/// PVM2 is an RV64E base — a 16-register file (`x0`–`x15`). This is the
/// **single source of truth** for every place that needs register
/// classification: the gas-simulator slot map, the recompiler's codegen
/// slot map, the interpreter's register file access, the spilled-register
/// routing, and the reserved-register check both engines use. They all
/// derive from [`reg_class`] rather than re-encoding the valid/reserved
/// sets (which is how `rv_is_reserved` once drifted to miss `x16..x31`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegClass {
    /// `x0` — hardwired zero. Valid, but has no GPR slot.
    Zero,
    /// `x1`, `x2`, `x5`–`x15`, `x3`, `x4` — general-purpose; the payload is
    /// the slot `0..=14` into [`Regs::gpr`]. Slots `0..=12` are the 13
    /// commonly-used registers (`x1`, `x2`, `x5`–`x15`); slots `13`/`14` are
    /// `x3`/`x4`, which the recompiler spills to memory ([`reg_is_spilled`]).
    Gpr(u8),
    /// `x16`–`x31` — do not exist in RV64E (a 16-register base), so naming
    /// one is an illegal encoding. Such an instruction is a reserved
    /// encoding and panics if executed.
    Reserved,
}

/// Classify a 5-bit RV register index (low 5 bits of `x`). See [`RegClass`].
#[inline]
pub const fn reg_class(x: u8) -> RegClass {
    match x & 31 {
        0 => RegClass::Zero,
        1 => RegClass::Gpr(0),
        2 => RegClass::Gpr(1),
        3 => RegClass::Gpr(13), // x3 → high spill slot
        4 => RegClass::Gpr(14), // x4 → high spill slot
        n @ 5..=15 => RegClass::Gpr(n - 3),
        _ => RegClass::Reserved, // x16..x31 only
    }
}

/// PVM2 GPR slot (`0..=14`) for `x`, or `0xFF` if `x` has no slot — `x0`
/// (hardwired zero) *or* a reserved register (`x16..x31`). The gas
/// simulator reads `0xFF` as "no dependency / no write"; both engines' gas
/// paths use this (the recompiler via the const-folded [`REG_SLOT_LUT`]) so
/// gas agrees bit-for-bit. Note `0xFF` conflates `x0` with reserved — use
/// [`reg_is_reserved`] when that distinction matters.
#[inline]
pub const fn reg_slot_or_ff(x: u8) -> u8 {
    match reg_class(x) {
        RegClass::Gpr(s) => s,
        _ => 0xFF,
    }
}

/// True iff `x` is a *reserved* register (`x16..x31` — they do not exist in
/// the RV64E base) — as opposed to `x0`, which also lacks a slot but is
/// valid. Drives the reserved-encoding (illegal) check in both engines.
#[inline]
pub const fn reg_is_reserved(x: u8) -> bool {
    matches!(reg_class(x), RegClass::Reserved)
}

/// True iff `x` is a *spilled* register — `x3` or `x4`, the two GPRs that
/// map to the high slots (13, 14). They are real, fully-valid registers
/// (the interpreter executes them as ordinary GPRs), but the x86-64
/// recompiler's host register file is exhausted by the other 13 slots, so
/// it holds `x3`/`x4` in memory and materialises them per access. The
/// recompiler uses this to route an `x3`/`x4` instruction to its cold spill
/// path; the gas model uses it to charge the memory-spill cost.
#[inline]
pub const fn reg_is_spilled(x: u8) -> bool {
    matches!(reg_class(x), RegClass::Gpr(13) | RegClass::Gpr(14))
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
