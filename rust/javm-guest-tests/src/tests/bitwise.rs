//! Bitwise and shift test vectors.
//!
//! Shift/rotate input: u64 value (8 bytes) + u32 shift amount (4 bytes) = 12 bytes.
//! Binary ops input: two u64 values (16 bytes).
//! Unary ops input: one u64 value (8 bytes).
//! Output: one u64 result (8 bytes).

use crate::{read_u32, read_u64, write_u64};

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
