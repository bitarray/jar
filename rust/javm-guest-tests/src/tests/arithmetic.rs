//! Arithmetic test vectors: add, sub, mul, div, rem, wide multiply.
//!
//! Each operation has two faces:
//!   - `<name>(input: &[u8], output: &mut [u8]) -> usize`: a byte-level
//!     helper, the legacy unit-test entry point.
//!   - `<name>_suite() -> u64`: runs the helper over a baked corpus
//!     of `(a, b)` pairs and XOR-folds the u64 results into a single
//!     fingerprint. Used by the three-way conformance harness.

use crate::{read_u64, write_u64};

/// Inputs reused by every binary u64 op (add, sub, mul, mul_upper_*,
/// AND, OR, XOR). Mix of identity, overflow boundaries, and arbitrary
/// patterns.
pub(crate) const BINARY_U64_CASES: &[(u64, u64)] = &[
    (0, 0),
    (1, 2),
    (1, 1),
    (u64::MAX, 1),
    (u64::MAX, u64::MAX),
    (0xDEAD_BEEF_DEAD_BEEF, 0x0123_4567_89AB_CDEF),
    (0x8000_0000_0000_0000, 0x8000_0000_0000_0000),
];

/// Inputs for the division/remainder ops (signed and unsigned).
/// Includes the `÷0` and `i64::MIN ÷ -1` edge cases.
pub(crate) const DIV_U64_CASES: &[(u64, u64)] = &[
    (10, 3),
    (u64::MAX, 1),
    (u64::MAX, 2),
    (100, 0),
    (0, 7),
    (i64::MIN as u64, (-1i64) as u64),
];

/// Run a binary u64-in / u64-out op over a corpus, XOR-fold results.
pub(crate) fn run_binary_u64(cases: &[(u64, u64)], op: fn(&[u8], &mut [u8]) -> usize) -> u64 {
    let mut acc = 0u64;
    let mut input = [0u8; 16];
    let mut output = [0u8; 8];
    for (a, b) in cases {
        input[0..8].copy_from_slice(&a.to_le_bytes());
        input[8..16].copy_from_slice(&b.to_le_bytes());
        let len = op(&input, &mut output);
        debug_assert!(len == 8);
        acc ^= u64::from_le_bytes(output);
    }
    acc
}

// -- Byte-level helpers --------------------------------------------------------

pub fn add_u64(input: &[u8], output: &mut [u8]) -> usize {
    let (mut off, mut out) = (0, 0);
    let a = read_u64(input, &mut off);
    let b = read_u64(input, &mut off);
    write_u64(output, &mut out, a.wrapping_add(b));
    out
}

pub fn sub_u64(input: &[u8], output: &mut [u8]) -> usize {
    let (mut off, mut out) = (0, 0);
    let a = read_u64(input, &mut off);
    let b = read_u64(input, &mut off);
    write_u64(output, &mut out, a.wrapping_sub(b));
    out
}

pub fn mul_u64(input: &[u8], output: &mut [u8]) -> usize {
    let (mut off, mut out) = (0, 0);
    let a = read_u64(input, &mut off);
    let b = read_u64(input, &mut off);
    write_u64(output, &mut out, a.wrapping_mul(b));
    out
}

pub fn mul_upper_uu(input: &[u8], output: &mut [u8]) -> usize {
    let (mut off, mut out) = (0, 0);
    let a = read_u64(input, &mut off);
    let b = read_u64(input, &mut off);
    let hi = ((a as u128).wrapping_mul(b as u128) >> 64) as u64;
    write_u64(output, &mut out, hi);
    out
}

pub fn mul_upper_ss(input: &[u8], output: &mut [u8]) -> usize {
    let (mut off, mut out) = (0, 0);
    let a = read_u64(input, &mut off) as i64;
    let b = read_u64(input, &mut off) as i64;
    let hi = ((a as i128).wrapping_mul(b as i128) >> 64) as u64;
    write_u64(output, &mut out, hi);
    out
}

pub fn div_u64(input: &[u8], output: &mut [u8]) -> usize {
    let (mut off, mut out) = (0, 0);
    let a = read_u64(input, &mut off);
    let b = read_u64(input, &mut off);
    let result = a.checked_div(b).unwrap_or(u64::MAX);
    write_u64(output, &mut out, result);
    out
}

pub fn rem_u64(input: &[u8], output: &mut [u8]) -> usize {
    let (mut off, mut out) = (0, 0);
    let a = read_u64(input, &mut off);
    let b = read_u64(input, &mut off);
    let result = if b == 0 { a } else { a % b };
    write_u64(output, &mut out, result);
    out
}

pub fn div_s64(input: &[u8], output: &mut [u8]) -> usize {
    let (mut off, mut out) = (0, 0);
    let a = read_u64(input, &mut off) as i64;
    let b = read_u64(input, &mut off) as i64;
    let result = if b == 0 {
        -1i64 as u64
    } else if a == i64::MIN && b == -1 {
        a as u64 // overflow: return a unchanged
    } else {
        (a / b) as u64
    };
    write_u64(output, &mut out, result);
    out
}

pub fn rem_s64(input: &[u8], output: &mut [u8]) -> usize {
    let (mut off, mut out) = (0, 0);
    let a = read_u64(input, &mut off) as i64;
    let b = read_u64(input, &mut off) as i64;
    let result = if b == 0 {
        a as u64
    } else if a == i64::MIN && b == -1 {
        0u64
    } else {
        (a % b) as u64
    };
    write_u64(output, &mut out, result);
    out
}

// -- Suites --------------------------------------------------------------------

pub fn add_u64_suite() -> u64 {
    run_binary_u64(BINARY_U64_CASES, add_u64)
}
pub fn sub_u64_suite() -> u64 {
    run_binary_u64(BINARY_U64_CASES, sub_u64)
}
pub fn mul_u64_suite() -> u64 {
    run_binary_u64(BINARY_U64_CASES, mul_u64)
}
pub fn mul_upper_uu_suite() -> u64 {
    run_binary_u64(BINARY_U64_CASES, mul_upper_uu)
}
pub fn mul_upper_ss_suite() -> u64 {
    run_binary_u64(BINARY_U64_CASES, mul_upper_ss)
}
pub fn div_u64_suite() -> u64 {
    run_binary_u64(DIV_U64_CASES, div_u64)
}
pub fn rem_u64_suite() -> u64 {
    run_binary_u64(DIV_U64_CASES, rem_u64)
}
pub fn div_s64_suite() -> u64 {
    run_binary_u64(DIV_U64_CASES, div_s64)
}
pub fn rem_s64_suite() -> u64 {
    run_binary_u64(DIV_U64_CASES, rem_s64)
}
