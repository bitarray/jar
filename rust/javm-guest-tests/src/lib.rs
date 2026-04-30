//! JAVM guest test vectors.
//!
//! A library of pure test functions that compile to both host (native Rust)
//! and JAVM (PVM bytecode). Each test takes input bytes and writes output
//! bytes to a static buffer, enabling three-way comparison:
//! host vs interpreter vs recompiler.
//!
//! ## I/O Protocol
//!
//! Input: `[test_id: u32 LE] [test_args: ...]`
//! Output: written to `OUTPUT` buffer; `dispatch()` returns bytes written.
//! After PVM halt: `φ[7]` = output_ptr, `φ[8]` = output_len.

#![cfg_attr(target_os = "none", no_std)]

use javm_builtins as _;

mod tests;

/// Output buffer — guest writes results here.
static mut OUTPUT: [u8; 4096] = [0; 4096];

/// Dispatch to a test by ID. Returns number of bytes written to `OUTPUT`.
///
/// # Panics
/// Panics if `input` is too short or `test_id` is unknown.
pub fn dispatch(input: &[u8]) -> usize {
    let test_id = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    let args = &input[4..];
    #[allow(static_mut_refs)]
    let output = unsafe { &mut OUTPUT };
    tests::dispatch_by_id(test_id, args, output)
}

/// Get a pointer to the output buffer (for PVM-side reading).
pub fn output_buffer() -> *const u8 {
    (&raw const OUTPUT).cast()
}

/// Run a test and return the output as a Vec (thread-safe for host tests).
/// On host, uses a local buffer to avoid data races on the global OUTPUT.
#[cfg(not(target_os = "none"))]
pub fn dispatch_to_vec(input: &[u8]) -> Vec<u8> {
    let test_id = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    let args = &input[4..];
    let mut output = vec![0u8; 4096];
    let len = tests::dispatch_by_id(test_id, args, &mut output);
    output.truncate(len);
    output
}

// -- Helpers for test functions -----------------------------------------------

/// Read a u64 from LE bytes at offset, advancing the offset.
fn read_u64(input: &[u8], off: &mut usize) -> u64 {
    let v = u64::from_le_bytes(input[*off..*off + 8].try_into().unwrap());
    *off += 8;
    v
}

/// Read a u32 from LE bytes at offset, advancing the offset.
fn read_u32(input: &[u8], off: &mut usize) -> u32 {
    let v = u32::from_le_bytes(input[*off..*off + 4].try_into().unwrap());
    *off += 4;
    v
}

/// Write a u64 as LE bytes to output at offset, advancing the offset.
fn write_u64(output: &mut [u8], off: &mut usize, v: u64) {
    output[*off..*off + 8].copy_from_slice(&v.to_le_bytes());
    *off += 8;
}
