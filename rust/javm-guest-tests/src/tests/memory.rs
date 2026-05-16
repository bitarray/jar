//! Memory and control-flow test vectors.
//!
//! `memcpy_test` and `sort_u32` produce variable-length byte output;
//! `fib` returns a single u64. The `_suite()` fns XOR-fold each
//! op's output bytes (interpreted as u64 stride where appropriate)
//! into a single fingerprint.

use crate::{fold_bytes_to_u64, read_u32, write_u64};

const MEMCPY_INPUTS: &[&[u8]] = &[
    &[],
    &[0xAA],
    &[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04],
    b"abcdefghijklmnopqrstuvwxyz",
];

const SORT_INPUTS: &[&[u32]] = &[
    &[],
    &[42],
    &[3, 1, 2],
    &[u32::MAX, 0, 100_000, 7, 7, 0],
    &[5, 4, 3, 2, 1, 0, u32::MAX / 2, u32::MAX],
];

const FIB_INDICES: &[u32] = &[0, 1, 2, 3, 10, 20, 50, 90];

// -- Byte-level helpers --------------------------------------------------------

/// Copy input bytes to output (exercises load/store patterns).
pub fn memcpy_test(input: &[u8], output: &mut [u8]) -> usize {
    let len = input.len();
    let mut i = 0;
    while i < len {
        output[i] = input[i];
        i += 1;
    }
    len
}

/// Sort an array of u32 LE values via insertion sort.
pub fn sort_u32(input: &[u8], output: &mut [u8]) -> usize {
    let n = input.len() / 4;
    output[..input.len()].copy_from_slice(input);

    let mut i = 1;
    while i < n {
        let key = u32::from_le_bytes(output[i * 4..(i + 1) * 4].try_into().unwrap());
        let mut j = i;
        while j > 0 {
            let prev = u32::from_le_bytes(output[(j - 1) * 4..j * 4].try_into().unwrap());
            if prev <= key {
                break;
            }
            output[j * 4..(j + 1) * 4].copy_from_slice(&prev.to_le_bytes());
            j -= 1;
        }
        output[j * 4..(j + 1) * 4].copy_from_slice(&key.to_le_bytes());
        i += 1;
    }
    n * 4
}

/// Iterative Fibonacci. Input: n as u32 LE; output: fib(n) as u64 LE.
pub fn fib(input: &[u8], output: &mut [u8]) -> usize {
    let mut off = 0;
    let n = read_u32(input, &mut off);

    let result = if n == 0 {
        0u64
    } else {
        let mut a: u64 = 0;
        let mut b: u64 = 1;
        let mut i = 1u32;
        while i < n {
            let next = a.wrapping_add(b);
            a = b;
            b = next;
            i += 1;
        }
        b
    };
    let mut out = 0;
    write_u64(output, &mut out, result);
    out
}

// -- Suites --------------------------------------------------------------------

pub fn memcpy_test_suite() -> u64 {
    let mut acc = 0u64;
    let mut buf = [0u8; 64];
    for input in MEMCPY_INPUTS {
        let len = memcpy_test(input, &mut buf);
        acc ^= fold_bytes_to_u64(&buf[..len]);
        acc = acc.wrapping_add(len as u64); // cardinality fold
    }
    acc
}

pub fn sort_u32_suite() -> u64 {
    let mut acc = 0u64;
    let mut input_bytes = [0u8; 64];
    let mut output_bytes = [0u8; 64];
    for vals in SORT_INPUTS {
        let in_len = vals.len() * 4;
        for (i, v) in vals.iter().enumerate() {
            input_bytes[i * 4..(i + 1) * 4].copy_from_slice(&v.to_le_bytes());
        }
        let out_len = sort_u32(&input_bytes[..in_len], &mut output_bytes);
        debug_assert_eq!(out_len, in_len);
        acc ^= fold_bytes_to_u64(&output_bytes[..out_len]);
        acc = acc.wrapping_add(out_len as u64);
    }
    acc
}

pub fn fib_suite() -> u64 {
    let mut acc = 0u64;
    let mut input = [0u8; 4];
    let mut output = [0u8; 8];
    for n in FIB_INDICES {
        input.copy_from_slice(&n.to_le_bytes());
        let len = fib(&input, &mut output);
        debug_assert!(len == 8);
        acc ^= u64::from_le_bytes(output);
    }
    acc
}
