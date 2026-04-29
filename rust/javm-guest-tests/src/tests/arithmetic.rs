//! Arithmetic test vectors: add, sub, mul, div, rem, wide multiply.
//!
//! Input: two u64 values as 16 bytes LE.
//! Output: one u64 result as 8 bytes LE.

use crate::{read_u64, write_u64};

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
