//! RV64E-subset program generator.
//!
//! Two modes, sharing one boundary-biased operand pool:
//! - [`enumerate_boundary`] — deterministic, near-exhaustive over each op ×
//!   boundary-operand combination. This is what *guarantees* the high-value
//!   corners appear (e.g. `div x?, INT_MIN, -1`).
//! - [`Gen::random_program`] — random instruction sequences for cross-op /
//!   cross-state breadth, seeded for reproducibility.
//!
//! Every generated program is **total** by construction: register-only,
//! straight-line, x0–x15 minus the spilled (x3/x4) and fold-scratch (x6/x7)
//! registers, ending in [`encode::fold_epilogue`]. So it always halts cleanly
//! on a conformant engine — and on the oracle — with a defined `x10`. (The div
//! corners are *included*: RISC-V defines INT_MIN/-1 as a value, so the oracle
//! and interpreter produce one; only a buggy recompiler diverges.)
//!
//! v1 emits register-only ops (no loads/stores/branches — those want a memory
//! window / control flow and come later); this already covers the
//! value-domain edge cases that matter most (div overflow, shift masking, W-op
//! sign-extension, `mulhsu`, Zbb corners).

use crate::Program;
use crate::encode::{self, Fmt, OpSpec};
use javm_exec::regs::reg_slot_or_ff;
use std::collections::BTreeMap;

/// Boundary-biased operand pool — the values bugs hide at.
pub const OPERANDS: &[u64] = &[
    0x0000_0000_0000_0000, // 0
    0x0000_0000_0000_0001, // 1
    0x0000_0000_0000_0002, // 2
    0xFFFF_FFFF_FFFF_FFFF, // -1
    0x8000_0000_0000_0000, // i64::MIN
    0x7FFF_FFFF_FFFF_FFFF, // i64::MAX
    0x0000_0000_7FFF_FFFF, // i32::MAX
    0x0000_0000_8000_0000, // i32::MIN, zero-extended
    0xFFFF_FFFF_8000_0000, // i32::MIN, sign-extended
    0x0000_0000_FFFF_FFFF, // u32::MAX
    0x0000_0000_0000_0010, // 16
    0x0000_0000_0000_0040, // 64
    0xDEAD_BEEF_CAFE_BABE, // arbitrary
];

/// Boundary 12-bit-signed immediates (for I-type ALU).
pub const IMMS: &[i32] = &[0, 1, -1, 2, -2, 2047, -2048, 0x555, -0x555];

/// Boundary shift amounts — includes the out-of-range 64/65 that exercise the
/// `& 63` / `& 31` masking both engines (must) perform.
pub const SHAMTS: &[i32] = &[0, 1, 7, 8, 31, 32, 63, 64, 65];

/// Boundary 20-bit upper immediates (for `lui`/`auipc`).
pub const IMM20S: &[i32] = &[0, 1, 0xF_FFFF, 0x8_0000, 0x7_FFFF, 0xA_5A5A];

/// Writable / foldable registers — x1, x2, x5, x8–x15. Excludes x0 (zero),
/// x3/x4 (spilled, never named), x6/x7 (fold scratch), x16–31 (reserved).
const DEST: &[u8] = &[1, 2, 5, 8, 9, 10, 11, 12, 13, 14, 15];
/// Source registers — `DEST` plus x0.
const SRC: &[u8] = &[0, 1, 2, 5, 8, 9, 10, 11, 12, 13, 14, 15];

/// Seed register `xreg` to `val` in a slot-keyed init map (no-op for x0 /
/// reserved, which have no slot).
fn seed(init: &mut BTreeMap<u8, u64>, xreg: u8, val: u64) {
    let slot = reg_slot_or_ff(xreg);
    if slot != 0xFF {
        init.insert(slot, val);
    }
}

/// Wrap a body in the (no-memory) fold epilogue → a complete program.
fn finish(body: Vec<u32>, init_regs: BTreeMap<u8, u64>) -> Program {
    let mut code = body;
    code.extend(encode::fold_epilogue(None));
    Program {
        code,
        init_regs,
        init_mem: None,
    }
}

/// Register-only ops (skip loads/stores/branches).
fn reg_only_ops() -> impl Iterator<Item = &'static OpSpec> {
    encode::OPS
        .iter()
        .filter(|s| !s.touches_memory_or_control())
}

/// Deterministic boundary enumeration. For each register-only op, emit one
/// program per relevant boundary-operand combination, seeding source registers
/// x8/x9 and writing the result to x10. Guarantees the corner cases appear.
pub fn enumerate_boundary() -> Vec<Program> {
    const RA: u8 = 8;
    const RB: u8 = 9;
    const RD: u8 = 10;
    let mut progs = Vec::new();
    for spec in reg_only_ops() {
        match spec.fmt {
            // Two source operands: full a × b boundary cross-product.
            Fmt::R => {
                for &a in OPERANDS {
                    for &b in OPERANDS {
                        let mut init = BTreeMap::new();
                        seed(&mut init, RA, a);
                        seed(&mut init, RB, b);
                        let body = vec![encode::encode_op(spec, RD, RA, RB, 0)];
                        progs.push(finish(body, init));
                    }
                }
            }
            // One source operand + a boundary immediate.
            Fmt::I => {
                for &a in OPERANDS {
                    for &imm in IMMS {
                        let mut init = BTreeMap::new();
                        seed(&mut init, RA, a);
                        let body = vec![encode::encode_op(spec, RD, RA, 0, imm)];
                        progs.push(finish(body, init));
                    }
                }
            }
            // One source operand + a boundary shift amount.
            Fmt::IShift | Fmt::IShift32 => {
                for &a in OPERANDS {
                    for &sh in SHAMTS {
                        let mut init = BTreeMap::new();
                        seed(&mut init, RA, a);
                        let body = vec![encode::encode_op(spec, RD, RA, 0, sh)];
                        progs.push(finish(body, init));
                    }
                }
            }
            // One source operand, no immediate.
            Fmt::Unary => {
                for &a in OPERANDS {
                    let mut init = BTreeMap::new();
                    seed(&mut init, RA, a);
                    let body = vec![encode::encode_op(spec, RD, RA, 0, 0)];
                    progs.push(finish(body, init));
                }
            }
            // Upper immediate (no source register).
            Fmt::U => {
                for &imm in IMM20S {
                    let body = vec![encode::encode_op(spec, RD, 0, 0, imm)];
                    progs.push(finish(body, BTreeMap::new()));
                }
            }
            Fmt::Store | Fmt::Branch => {} // skipped (filtered out above)
        }
    }
    progs
}

/// Small, fast, deterministic PRNG (xorshift64* — state never zero).
pub struct XorShift64(u64);

impl XorShift64 {
    pub fn new(seed: u64) -> Self {
        XorShift64(seed ^ 0x9E37_79B9_7F4A_7C15 | 1)
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[(self.next_u64() % xs.len() as u64) as usize]
    }
}

/// Random program generator.
pub struct Gen {
    rng: XorShift64,
}

impl Gen {
    pub fn new(seed: u64) -> Self {
        Gen {
            rng: XorShift64::new(seed),
        }
    }

    /// A random straight-line register-only program of `body_len` instructions,
    /// with `DEST` registers pre-seeded to random boundary operands.
    pub fn random_program(&mut self, body_len: usize) -> Program {
        let mut init = BTreeMap::new();
        for &xr in DEST {
            // Seed most destinations with a boundary value (some left at 0).
            if self.rng.next_u64() & 3 != 0 {
                seed(&mut init, xr, self.rng.pick(OPERANDS));
            }
        }
        let ops: Vec<&OpSpec> = reg_only_ops().collect();
        let mut body = Vec::with_capacity(body_len);
        for _ in 0..body_len {
            let spec = self.rng.pick(&ops);
            let rd = self.rng.pick(DEST);
            let rs1 = self.rng.pick(SRC);
            let rs2 = self.rng.pick(SRC);
            let imm = match spec.fmt {
                Fmt::IShift | Fmt::IShift32 => self.rng.pick(SHAMTS),
                Fmt::U => self.rng.pick(IMM20S),
                _ => self.rng.pick(IMMS),
            };
            body.push(encode::encode_op(spec, rd, rs1, rs2, imm));
        }
        finish(body, init)
    }

    /// `count` random programs, each `body_len` instructions.
    pub fn random_batch(&mut self, count: usize, body_len: usize) -> Vec<Program> {
        (0..count).map(|_| self.random_program(body_len)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use javm_exec::instruction::{Inst, decode};

    /// Every generated instruction must decode to a non-`Reserved`,
    /// non-terminator instruction (terminators come only from the appended
    /// HALT, which these programs don't include) — i.e. the generator never
    /// emits x3/x4, x16–31, or a bad encoding.
    fn assert_all_valid(prog: &Program) {
        let bytes = prog.code_bytes();
        let mut off = 0;
        while off < bytes.len() {
            let (inst, len) = decode(&bytes[off..]).expect("decodes");
            let w =
                u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
            assert!(
                !matches!(inst, Inst::Reserved { .. }),
                "generator emitted a reserved encoding {w:#010x} at byte {off}",
            );
            off += len as usize;
        }
    }

    #[test]
    fn boundary_enumeration_is_all_valid_and_hits_div() {
        let progs = enumerate_boundary();
        assert!(progs.len() > 100, "expected a broad enumeration");
        for p in &progs {
            assert_all_valid(p);
        }
    }

    #[test]
    fn random_programs_are_valid_and_deterministic() {
        let a = Gen::new(42).random_batch(50, 8);
        let b = Gen::new(42).random_batch(50, 8);
        assert_eq!(a, b, "same seed must reproduce the same programs");
        for p in &a {
            assert_all_valid(p);
        }
    }
}
