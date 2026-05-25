use javm_exec::InstructionCategory;
use javm_exec::args::{
    Args, decode_args, decode_le, sign_extend, sign_extend_32, to_signed, to_unsigned,
};
use proptest::prelude::*;

#[test]
fn sign_extend_positive() {
    assert_eq!(sign_extend(0x7F, 1), 0x7F);
    assert_eq!(sign_extend(0x7FFF, 2), 0x7FFF);
    assert_eq!(sign_extend(0x7FFF_FFFF, 4), 0x7FFF_FFFF);
}

#[test]
fn sign_extend_negative() {
    assert_eq!(sign_extend(0x80, 1), 0xFFFF_FFFF_FFFF_FF80);
    assert_eq!(sign_extend(0x8000, 2), 0xFFFF_FFFF_FFFF_8000);
    assert_eq!(sign_extend(0x8000_0000, 4), 0xFFFF_FFFF_8000_0000);
}

#[test]
fn sign_extend_3byte() {
    assert_eq!(sign_extend(0x7F_FFFF, 3), 0x7F_FFFF);
    assert_eq!(sign_extend(0x80_0000, 3), 0xFFFF_FFFF_FF80_0000);
}

#[test]
fn decode_le_smoke() {
    assert_eq!(decode_le(&[0x01, 0x02, 0x03, 0x04]), 0x04030201);
    assert_eq!(decode_le(&[0xFF]), 0xFF);
    assert_eq!(decode_le(&[]), 0);
}

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
        use InstructionCategory::*;
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
        use InstructionCategory::*;
        let args1 = decode_args(&code, 0, skip, TwoRegOneImm);
        let args2 = decode_args(&code, 0, skip, TwoRegOneImm);
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
