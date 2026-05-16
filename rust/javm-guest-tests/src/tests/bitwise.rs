//! Bitwise and shift test vectors.
//!
//! Shift/rotate input: u64 value (8 bytes) + u32 shift amount (4 bytes).
//! Binary ops input: two u64 values (16 bytes).
//! Unary ops input: one u64 value (8 bytes).
//! Output: one u64 result (8 bytes).
//!
//! Each operation comes with a baked-corpus `_suite() -> u64` that
//! XOR-folds the per-case u64 results into a single fingerprint —
//! consumed by the three-way conformance harness.

use crate::tests::arithmetic::{run_binary_u64, BINARY_U64_CASES};
use crate::{read_u32, read_u64, write_u64};

/// `(value, shift_amount)` pairs covering low, mid, boundary, and
/// >=64 (wrapping_shl/shr is defined for these on RISC-V via mask).
const SHIFT_CASES: &[(u64, u32)] = &[
    (0, 0),
    (1, 1),
    (0xFFFF_FFFF_FFFF_FFFF, 0),
    (0xFFFF_FFFF_FFFF_FFFF, 63),
    (0xDEAD_BEEF_DEAD_BEEF, 7),
    (0x8000_0000_0000_0000, 1),
    (0x1, 63),
];

const UNARY_U64_CASES: &[u64] = &[
    0,
    1,
    0xFFFF_FFFF_FFFF_FFFF,
    0x8000_0000_0000_0000,
    0x0000_0000_0000_0001,
    0xDEAD_BEEF_DEAD_BEEF,
];

fn run_shift(op: fn(&[u8], &mut [u8]) -> usize) -> u64 {
    let mut acc = 0u64;
    let mut input = [0u8; 12];
    let mut output = [0u8; 8];
    for (val, amt) in SHIFT_CASES {
        input[0..8].copy_from_slice(&val.to_le_bytes());
        input[8..12].copy_from_slice(&amt.to_le_bytes());
        let len = op(&input, &mut output);
        debug_assert!(len == 8);
        acc ^= u64::from_le_bytes(output);
    }
    acc
}

fn run_unary(op: fn(&[u8], &mut [u8]) -> usize) -> u64 {
    let mut acc = 0u64;
    let mut input = [0u8; 8];
    let mut output = [0u8; 8];
    for val in UNARY_U64_CASES {
        input.copy_from_slice(&val.to_le_bytes());
        let len = op(&input, &mut output);
        debug_assert!(len == 8);
        acc ^= u64::from_le_bytes(output);
    }
    acc
}

// -- Byte-level helpers --------------------------------------------------------

pub fn shift_left(input: &[u8], output: &mut [u8]) -> usize {
    let (mut off, mut out) = (0, 0);
    let val = read_u64(input, &mut off);
    let amt = read_u32(input, &mut off);
    write_u64(output, &mut out, val.wrapping_shl(amt));
    out
}

pub fn shift_right_logical(input: &[u8], output: &mut [u8]) -> usize {
    let (mut off, mut out) = (0, 0);
    let val = read_u64(input, &mut off);
    let amt = read_u32(input, &mut off);
    write_u64(output, &mut out, val.wrapping_shr(amt));
    out
}

pub fn shift_right_arithmetic(input: &[u8], output: &mut [u8]) -> usize {
    let (mut off, mut out) = (0, 0);
    let val = read_u64(input, &mut off) as i64;
    let amt = read_u32(input, &mut off);
    write_u64(output, &mut out, val.wrapping_shr(amt) as u64);
    out
}

pub fn rotate_right(input: &[u8], output: &mut [u8]) -> usize {
    let (mut off, mut out) = (0, 0);
    let val = read_u64(input, &mut off);
    let amt = read_u32(input, &mut off);
    write_u64(output, &mut out, val.rotate_right(amt));
    out
}

pub fn and(input: &[u8], output: &mut [u8]) -> usize {
    let (mut off, mut out) = (0, 0);
    let a = read_u64(input, &mut off);
    let b = read_u64(input, &mut off);
    write_u64(output, &mut out, a & b);
    out
}

pub fn or(input: &[u8], output: &mut [u8]) -> usize {
    let (mut off, mut out) = (0, 0);
    let a = read_u64(input, &mut off);
    let b = read_u64(input, &mut off);
    write_u64(output, &mut out, a | b);
    out
}

pub fn xor(input: &[u8], output: &mut [u8]) -> usize {
    let (mut off, mut out) = (0, 0);
    let a = read_u64(input, &mut off);
    let b = read_u64(input, &mut off);
    write_u64(output, &mut out, a ^ b);
    out
}

pub fn clz(input: &[u8], output: &mut [u8]) -> usize {
    let (mut off, mut out) = (0, 0);
    let val = read_u64(input, &mut off);
    write_u64(output, &mut out, val.leading_zeros() as u64);
    out
}

pub fn ctz(input: &[u8], output: &mut [u8]) -> usize {
    let (mut off, mut out) = (0, 0);
    let val = read_u64(input, &mut off);
    write_u64(output, &mut out, val.trailing_zeros() as u64);
    out
}

pub fn set_lt_u(input: &[u8], output: &mut [u8]) -> usize {
    let (mut off, mut out) = (0, 0);
    let a = read_u64(input, &mut off);
    let b = read_u64(input, &mut off);
    write_u64(output, &mut out, if a < b { 1 } else { 0 });
    out
}

pub fn set_lt_s(input: &[u8], output: &mut [u8]) -> usize {
    let (mut off, mut out) = (0, 0);
    let a = read_u64(input, &mut off) as i64;
    let b = read_u64(input, &mut off) as i64;
    write_u64(output, &mut out, if a < b { 1 } else { 0 });
    out
}

// -- Suites --------------------------------------------------------------------

pub fn shift_left_suite() -> u64 {
    run_shift(shift_left)
}
pub fn shift_right_logical_suite() -> u64 {
    run_shift(shift_right_logical)
}
pub fn shift_right_arithmetic_suite() -> u64 {
    run_shift(shift_right_arithmetic)
}
pub fn rotate_right_suite() -> u64 {
    run_shift(rotate_right)
}
pub fn and_suite() -> u64 {
    run_binary_u64(BINARY_U64_CASES, and)
}
pub fn or_suite() -> u64 {
    run_binary_u64(BINARY_U64_CASES, or)
}
pub fn xor_suite() -> u64 {
    run_binary_u64(BINARY_U64_CASES, xor)
}
pub fn clz_suite() -> u64 {
    run_unary(clz)
}
pub fn ctz_suite() -> u64 {
    run_unary(ctz)
}
pub fn set_lt_u_suite() -> u64 {
    run_binary_u64(BINARY_U64_CASES, set_lt_u)
}
pub fn set_lt_s_suite() -> u64 {
    run_binary_u64(BINARY_U64_CASES, set_lt_s)
}
