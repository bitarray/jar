//! Instruction argument decoding (Appendix A.5 of the Gray Paper v0.7.2).
//!
//! Handles register extraction, immediate decoding, and sign extension.

/// Sign-extend a value from `n` bytes to 64 bits (eq A.16: Xₙ).
///
/// X_n(x) = x + floor(x / 2^(8n-1)) * (2^64 - 2^(8n))
#[inline(always)]
pub fn sign_extend(value: u64, n: usize) -> u64 {
    match n {
        0 => 0,
        1 => value as u8 as i8 as i64 as u64,
        2 => value as u16 as i16 as i64 as u64,
        3 => {
            let v = value & 0xFF_FFFF;
            if v & 0x80_0000 != 0 {
                v | 0xFFFF_FFFF_FF00_0000
            } else {
                v
            }
        }
        4 => value as u32 as i32 as i64 as u64,
        _ => value, // 8 bytes: no extension needed
    }
}

/// Signed interpretation of a 64-bit register value (eq A.10: Z₈).
pub fn to_signed(value: u64) -> i64 {
    value as i64
}

/// Unsigned interpretation of a signed value (eq A.11: Z₈⁻¹).
pub fn to_unsigned(value: i64) -> u64 {
    value as u64
}

/// Sign-extend from 32 bits to 64 bits (X₄).
pub fn sign_extend_32(value: u64) -> u64 {
    (value as u32) as i32 as i64 as u64
}

/// Decode a little-endian unsigned integer from a byte slice (E_l⁻¹).
pub fn decode_le(bytes: &[u8]) -> u64 {
    let mut value: u64 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        value |= (b as u64) << (i * 8);
    }
    value
}

/// Decoded instruction arguments.
#[derive(Clone, Copy, Debug)]
pub enum Args {
    /// No arguments (trap, fallthrough).
    None,
    /// One immediate value (ecalli).
    Imm { imm: u64 },
    /// One register + extended width immediate (load_imm_64).
    RegExtImm { ra: usize, imm: u64 },
    /// Two immediates (store_imm_*).
    TwoImm { imm_x: u64, imm_y: u64 },
    /// One offset (jump).
    Offset { offset: u64 },
    /// One register + one immediate.
    RegImm { ra: usize, imm: u64 },
    /// One register + two immediates.
    RegTwoImm { ra: usize, imm_x: u64, imm_y: u64 },
    /// One register + one immediate + one offset.
    RegImmOffset { ra: usize, imm: u64, offset: u64 },
    /// Two registers.
    TwoReg { rd: usize, ra: usize },
    /// Two registers + one immediate.
    TwoRegImm { ra: usize, rb: usize, imm: u64 },
    /// Two registers + one offset.
    TwoRegOffset { ra: usize, rb: usize, offset: u64 },
    /// Two registers + two immediates.
    TwoRegTwoImm {
        ra: usize,
        rb: usize,
        imm_x: u64,
        imm_y: u64,
    },
    /// Three registers.
    ThreeReg { ra: usize, rb: usize, rd: usize },
}

/// Read from the zero-extended code blob (ζ, eq A.4).
#[inline(always)]
fn zeta(code: &[u8], i: usize) -> u8 {
    if i < code.len() { code[i] } else { 0 }
}

/// Read `n` bytes from code at offset as little-endian u64 (no allocation).
#[inline(always)]
fn read_le_at(code: &[u8], offset: usize, n: usize) -> u64 {
    // Fast path: all bytes in bounds — read directly without per-byte checks
    if offset + n <= code.len() {
        let s = &code[offset..offset + n];
        match n {
            0 => 0,
            1 => s[0] as u64,
            2 => u16::from_le_bytes([s[0], s[1]]) as u64,
            3 => s[0] as u64 | (s[1] as u64) << 8 | (s[2] as u64) << 16,
            4 => u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as u64,
            _ => {
                let mut buf = [0u8; 8];
                buf[..n].copy_from_slice(s);
                u64::from_le_bytes(buf)
            }
        }
    } else {
        // Slow path: near end of code, use zero-extending reads
        let mut val = 0u64;
        for i in 0..n {
            val |= (zeta(code, offset + i) as u64) << (i * 8);
        }
        val
    }
}

/// Read `n` bytes from code at offset, sign-extend, and return as u64.
/// Public for use by the recompiler's inline decode path.
#[inline(always)]
pub fn read_signed_imm(code: &[u8], offset: usize, n: usize) -> u64 {
    read_signed_at(code, offset, n)
}

/// Read `n` bytes from code at offset as little-endian u64 (no sign extension).
/// Public for use by the recompiler's inline decode path (e.g., OneRegExtImm).
#[inline(always)]
pub fn read_le_imm(code: &[u8], offset: usize, n: usize) -> u64 {
    read_le_at(code, offset, n)
}

/// Read `n` bytes and sign-extend (no allocation).
#[inline(always)]
fn read_signed_at(code: &[u8], offset: usize, n: usize) -> u64 {
    sign_extend(read_le_at(code, offset, n), n)
}

/// Decode arguments based on instruction category.
///
/// `pc` is the instruction counter (ı), `skip` is the skip length (ℓ),
/// `code` is the instruction data with implicit zero extension.
pub fn decode_args(
    code: &[u8],
    pc: usize,
    skip: usize,
    category: crate::instruction::InstructionCategory,
) -> Args {
    use crate::instruction::InstructionCategory::*;
    let l = skip; // ℓ = skip(ı)

    match category {
        NoArgs => Args::None,

        // A.5.2: lX = min(4, ℓ), νX = X_lX(E_lX⁻¹(ζ[ı+1..+lX]))
        OneImm => {
            let lx = l.min(4);
            let imm = read_signed_at(code, pc + 1, lx);
            Args::Imm { imm }
        }

        // A.5.3: rA = min(12, ζ[ı+1] mod 16), νX = E₈⁻¹(ζ[ı+2..+8])
        OneRegExtImm => {
            let ra = (zeta(code, pc + 1) % 16).min(12) as usize;
            let imm = read_le_at(code, pc + 2, 8);
            Args::RegExtImm { ra, imm }
        }

        // A.5.4: lX = min(4, ζ[ı+1] mod 8)
        TwoImm => {
            let lx = (zeta(code, pc + 1) as usize % 8).min(4);
            let ly = if l > lx + 1 { (l - lx - 1).min(4) } else { 0 };
            let imm_x = read_signed_at(code, pc + 2, lx);
            let imm_y = read_signed_at(code, pc + 2 + lx, ly);
            Args::TwoImm { imm_x, imm_y }
        }

        // A.5.5: lX = min(4, ℓ), νX = ı + Z_lX(...)
        OneOffset => {
            let lx = l.min(4);
            let signed_offset = read_signed_at(code, pc + 1, lx) as i64;
            let offset = (pc as i64).wrapping_add(signed_offset) as u64;
            Args::Offset { offset }
        }

        // A.5.6: rA = min(12, ζ[ı+1] mod 16), lX = min(4, max(0, ℓ-1))
        OneRegOneImm => {
            let ra = (zeta(code, pc + 1) % 16).min(12) as usize;
            let lx = if l > 1 { (l - 1).min(4) } else { 0 };
            let imm = read_signed_at(code, pc + 2, lx);
            Args::RegImm { ra, imm }
        }

        // A.5.7: rA = min(12, ζ[ı+1] mod 16), lX = min(4, floor(ζ[ı+1]/16) mod 8)
        OneRegTwoImm => {
            let reg_byte = zeta(code, pc + 1);
            let ra = (reg_byte % 16).min(12) as usize;
            let lx = ((reg_byte as usize / 16) % 8).min(4);
            let ly = if l > lx + 1 { (l - lx - 1).min(4) } else { 0 };
            let imm_x = read_signed_at(code, pc + 2, lx);
            let imm_y = read_signed_at(code, pc + 2 + lx, ly);
            Args::RegTwoImm { ra, imm_x, imm_y }
        }

        // A.5.8: Same register/immediate encoding as OneRegTwoImm, but second is offset
        OneRegImmOffset => {
            let reg_byte = zeta(code, pc + 1);
            let ra = (reg_byte % 16).min(12) as usize;
            let lx = ((reg_byte as usize / 16) % 8).min(4);
            let ly = if l > lx + 1 { (l - lx - 1).min(4) } else { 0 };
            let imm = read_signed_at(code, pc + 2, lx);
            let signed_offset = read_signed_at(code, pc + 2 + lx, ly) as i64;
            let offset = (pc as i64).wrapping_add(signed_offset) as u64;
            Args::RegImmOffset { ra, imm, offset }
        }

        // A.5.9: rD = min(12, ζ[ı+1] mod 16), rA = min(12, floor(ζ[ı+1]/16))
        TwoReg => {
            let reg_byte = zeta(code, pc + 1);
            let rd = (reg_byte % 16).min(12) as usize;
            let ra = (reg_byte / 16).min(12) as usize;
            Args::TwoReg { rd, ra }
        }

        // A.5.10: rA = min(12, ζ[ı+1] mod 16), rB = min(12, floor(ζ[ı+1]/16))
        TwoRegOneImm => {
            let reg_byte = zeta(code, pc + 1);
            let ra = (reg_byte % 16).min(12) as usize;
            let rb = (reg_byte / 16).min(12) as usize;
            let lx = if l > 1 { (l - 1).min(4) } else { 0 };
            let imm = read_signed_at(code, pc + 2, lx);
            Args::TwoRegImm { ra, rb, imm }
        }

        // A.5.11: Same as TwoRegOneImm but immediate is an offset
        TwoRegOneOffset => {
            let reg_byte = zeta(code, pc + 1);
            let ra = (reg_byte % 16).min(12) as usize;
            let rb = (reg_byte / 16).min(12) as usize;
            let lx = if l > 1 { (l - 1).min(4) } else { 0 };
            let signed_offset = read_signed_at(code, pc + 2, lx) as i64;
            let offset = (pc as i64).wrapping_add(signed_offset) as u64;
            Args::TwoRegOffset { ra, rb, offset }
        }

        // A.5.12: rA, rB from reg_byte, lX from ζ[ı+2]
        TwoRegTwoImm => {
            let reg_byte = zeta(code, pc + 1);
            let ra = (reg_byte % 16).min(12) as usize;
            let rb = (reg_byte / 16).min(12) as usize;
            let lx = (zeta(code, pc + 2) as usize % 8).min(4);
            let ly = if l > lx + 2 { (l - lx - 2).min(4) } else { 0 };
            let imm_x = read_signed_at(code, pc + 3, lx);
            let imm_y = read_signed_at(code, pc + 3 + lx, ly);
            Args::TwoRegTwoImm {
                ra,
                rb,
                imm_x,
                imm_y,
            }
        }

        // A.5.13: rA, rB from first reg_byte, rD from second byte
        ThreeReg => {
            let reg_byte = zeta(code, pc + 1);
            let ra = (reg_byte % 16).min(12) as usize;
            let rb = (reg_byte / 16).min(12) as usize;
            let rd = zeta(code, pc + 2).min(12) as usize;
            Args::ThreeReg { ra, rb, rd }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_extend_positive() {
        assert_eq!(sign_extend(0x7F, 1), 0x7F);
        assert_eq!(sign_extend(0x7FFF, 2), 0x7FFF);
        assert_eq!(sign_extend(0x7FFF_FFFF, 4), 0x7FFF_FFFF);
    }

    #[test]
    fn test_sign_extend_negative() {
        assert_eq!(sign_extend(0x80, 1), 0xFFFF_FFFF_FFFF_FF80);
        assert_eq!(sign_extend(0x8000, 2), 0xFFFF_FFFF_FFFF_8000);
        assert_eq!(sign_extend(0x8000_0000, 4), 0xFFFF_FFFF_8000_0000);
    }

    #[test]
    fn test_sign_extend_3byte() {
        assert_eq!(sign_extend(0x7F_FFFF, 3), 0x7F_FFFF);
        assert_eq!(sign_extend(0x80_0000, 3), 0xFFFF_FFFF_FF80_0000);
    }

    #[test]
    fn test_decode_le() {
        assert_eq!(decode_le(&[0x01, 0x02, 0x03, 0x04]), 0x04030201);
        assert_eq!(decode_le(&[0xFF]), 0xFF);
        assert_eq!(decode_le(&[]), 0);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// sign_extend is idempotent: extending twice gives the same result.
        #[test]
        fn sign_extend_idempotent(value in any::<u64>(), n in 0usize..=4) {
            let once = sign_extend(value, n);
            let twice = sign_extend(once, n);
            prop_assert_eq!(once, twice);
        }

        /// to_signed and to_unsigned are inverses.
        #[test]
        fn signed_unsigned_roundtrip(value in any::<u64>()) {
            prop_assert_eq!(to_unsigned(to_signed(value)), value);
        }

        /// decode_le of a single byte equals that byte.
        #[test]
        fn decode_le_single_byte(b in any::<u8>()) {
            prop_assert_eq!(decode_le(&[b]), b as u64);
        }

        /// decode_le is deterministic.
        #[test]
        fn decode_le_deterministic(
            bytes in proptest::collection::vec(any::<u8>(), 0..8),
        ) {
            prop_assert_eq!(decode_le(&bytes), decode_le(&bytes));
        }

        /// sign_extend with n=0 always returns 0.
        #[test]
        fn sign_extend_zero_width_is_zero(value in any::<u64>()) {
            prop_assert_eq!(sign_extend(value, 0), 0);
        }

        /// sign_extend_32 matches sign_extend with n=4.
        #[test]
        fn sign_extend_32_matches_generic(value in any::<u64>()) {
            prop_assert_eq!(sign_extend_32(value), sign_extend(value, 4));
        }

        /// decode_args register indices are always <= 12 for all categories.
        #[test]
        fn decode_args_registers_bounded(
            code in proptest::collection::vec(any::<u8>(), 3..16),
            skip in 0usize..8,
            category_idx in 0u8..13,
        ) {
            use crate::instruction::InstructionCategory::*;
            let category = match category_idx {
                0 => NoArgs,
                1 => OneImm,
                2 => OneRegExtImm,
                3 => TwoImm,
                4 => OneOffset,
                5 => OneRegOneImm,
                6 => OneRegTwoImm,
                7 => OneRegImmOffset,
                8 => TwoReg,
                9 => TwoRegOneImm,
                10 => TwoRegOneOffset,
                11 => TwoRegTwoImm,
                12 => ThreeReg,
                _ => unreachable!(),
            };
            let args = decode_args(&code, 0, skip, category);
            match args {
                Args::None | Args::Imm { .. } | Args::TwoImm { .. } | Args::Offset { .. } => {}
                Args::RegExtImm { ra, .. }
                | Args::RegImm { ra, .. }
                | Args::RegTwoImm { ra, .. }
                | Args::RegImmOffset { ra, .. } => {
                    prop_assert!(ra <= 12);
                }
                Args::TwoReg { rd, ra } => {
                    prop_assert!(rd <= 12);
                    prop_assert!(ra <= 12);
                }
                Args::TwoRegImm { ra, rb, .. }
                | Args::TwoRegOffset { ra, rb, .. }
                | Args::TwoRegTwoImm { ra, rb, .. } => {
                    prop_assert!(ra <= 12);
                    prop_assert!(rb <= 12);
                }
                Args::ThreeReg { ra, rb, rd } => {
                    prop_assert!(ra <= 12);
                    prop_assert!(rb <= 12);
                    prop_assert!(rd <= 12);
                }
            }
        }

        /// decode_args is deterministic: same inputs produce the same variant.
        #[test]
        fn decode_args_deterministic(
            code in proptest::collection::vec(any::<u8>(), 3..16),
            skip in 0usize..8,
        ) {
            use crate::instruction::InstructionCategory::*;
            let args1 = decode_args(&code, 0, skip, TwoRegOneImm);
            let args2 = decode_args(&code, 0, skip, TwoRegOneImm);
            // Check same variant and same register values
            match (args1, args2) {
                (Args::TwoRegImm { ra: a1, rb: b1, imm: i1 },
                 Args::TwoRegImm { ra: a2, rb: b2, imm: i2 }) => {
                    prop_assert_eq!(a1, a2);
                    prop_assert_eq!(b1, b2);
                    prop_assert_eq!(i1, i2);
                }
                _ => prop_assert!(false),
            }
        }
    }
}
