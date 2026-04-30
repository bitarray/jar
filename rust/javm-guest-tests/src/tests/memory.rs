//! Memory and control flow test vectors.

use crate::{read_u32, write_u64};

/// Copy input bytes to output (exercises load/store patterns).
/// Input: raw bytes. Output: same bytes.
pub fn memcpy_test(input: &[u8], output: &mut [u8]) -> usize {
    let len = input.len();
    let mut i = 0;
    while i < len {
        output[i] = input[i];
        i += 1;
    }
    len
}

/// Sort an array of u32 values (insertion sort).
/// Input: array of u32 LE values. Output: sorted array of u32 LE values.
pub fn sort_u32(input: &[u8], output: &mut [u8]) -> usize {
    let n = input.len() / 4;
    // Copy input to output first
    output[..input.len()].copy_from_slice(input);

    // Insertion sort on the output buffer (in-place on u32 LE values)
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

/// Iterative Fibonacci.
/// Input: n as u32 LE. Output: fib(n) as u64 LE.
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
