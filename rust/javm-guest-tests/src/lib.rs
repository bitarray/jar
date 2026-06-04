//! JAVM guest test vectors — three-way conformance corpus.
//!
//! A library of pure, deterministic, `no_std`-friendly test
//! functions that compile to both host (native Rust) and JAVM (PVM
//! bytecode). Each operation has a `<name>_suite() -> u64`
//! companion that runs the underlying byte-level helper over a
//! baked corpus of inputs and XOR-folds the results into a single
//! u64 fingerprint.
//!
//! The conformance harness (`tests/conformance.rs`) calls every
//! suite three ways — host native, the PVM2 interpreter (via
//! `nub::Nub` local `nub-arch-local`), and the JIT recompiler (via
//! `nub::Nub` Hyperlight, x86 codegen in `javm-recompiler-x86`) —
//! and asserts the fingerprints agree, plus that the two PVM backends
//! consume identical gas.
//!
//! Baking the corpus into the guest sidesteps the args-delivery
//! problem: the kernel can pass `event.payload` into the
//! interpreter, but the standalone recompiler has no equivalent.
//! Returning one u64 also avoids reading guest memory post-halt.

#![cfg_attr(target_os = "none", no_std)]

use subsoil as _;

pub mod tests;

/// One row of [`SUITE_TABLE`]: (endpoint index, suite name, host fn).
#[cfg(not(target_os = "none"))]
pub type SuiteEntry = (u8, &'static str, fn() -> u64);

/// Endpoint index → suite directory.
///
/// The host-side mirror of `src/main.rs`'s `#[subsoil::endpoint(N)]`
/// table. Both lists must stay in sync; the conformance harness
/// iterates this one to drive every endpoint without duplicating
/// the indices in the test code.
///
/// The `#[subsoil::endpoint(N)]` annotations live in `main.rs`
/// (the binary crate) because `#[used] static` in an rlib doesn't
/// propagate into a bin's final ELF if nothing in the bin
/// references it — the linker drops the whole rlib object file.
#[cfg(not(target_os = "none"))]
pub const SUITE_TABLE: &[SuiteEntry] = &[
    (0, "add_u64_suite", tests::arithmetic::add_u64_suite),
    (1, "sub_u64_suite", tests::arithmetic::sub_u64_suite),
    (2, "mul_u64_suite", tests::arithmetic::mul_u64_suite),
    (
        3,
        "mul_upper_uu_suite",
        tests::arithmetic::mul_upper_uu_suite,
    ),
    (
        4,
        "mul_upper_ss_suite",
        tests::arithmetic::mul_upper_ss_suite,
    ),
    (5, "div_u64_suite", tests::arithmetic::div_u64_suite),
    (6, "rem_u64_suite", tests::arithmetic::rem_u64_suite),
    (7, "div_s64_suite", tests::arithmetic::div_s64_suite),
    (8, "rem_s64_suite", tests::arithmetic::rem_s64_suite),
    (10, "shift_left_suite", tests::bitwise::shift_left_suite),
    (
        11,
        "shift_right_logical_suite",
        tests::bitwise::shift_right_logical_suite,
    ),
    (
        12,
        "shift_right_arithmetic_suite",
        tests::bitwise::shift_right_arithmetic_suite,
    ),
    (13, "rotate_right_suite", tests::bitwise::rotate_right_suite),
    (14, "and_suite", tests::bitwise::and_suite),
    (15, "or_suite", tests::bitwise::or_suite),
    (16, "xor_suite", tests::bitwise::xor_suite),
    (17, "clz_suite", tests::bitwise::clz_suite),
    (18, "ctz_suite", tests::bitwise::ctz_suite),
    (19, "set_lt_u_suite", tests::bitwise::set_lt_u_suite),
    (20, "set_lt_s_suite", tests::bitwise::set_lt_s_suite),
    (30, "memcpy_test_suite", tests::memory::memcpy_test_suite),
    (31, "sort_u32_suite", tests::memory::sort_u32_suite),
    (32, "fib_suite", tests::memory::fib_suite),
    (40, "blake2b_256_suite", tests::crypto::blake2b_256_suite),
    (41, "keccak_256_suite", tests::crypto::keccak_256_suite),
];

// -- Helpers for test functions -----------------------------------------------

/// Read a u64 from LE bytes at offset, advancing the offset.
pub(crate) fn read_u64(input: &[u8], off: &mut usize) -> u64 {
    let v = u64::from_le_bytes(input[*off..*off + 8].try_into().unwrap());
    *off += 8;
    v
}

/// Read a u32 from LE bytes at offset, advancing the offset.
pub(crate) fn read_u32(input: &[u8], off: &mut usize) -> u32 {
    let v = u32::from_le_bytes(input[*off..*off + 4].try_into().unwrap());
    *off += 4;
    v
}

/// Write a u64 as LE bytes to output at offset, advancing the offset.
pub(crate) fn write_u64(output: &mut [u8], off: &mut usize, v: u64) {
    output[*off..*off + 8].copy_from_slice(&v.to_le_bytes());
    *off += 8;
}

/// Fold an arbitrary byte slice into a single u64 fingerprint.
///
/// Processes bytes in 8-byte LE chunks, XORing each into the
/// accumulator. The byte length is mixed in to distinguish e.g.
/// `[]` from `[0]`.
pub(crate) fn fold_bytes_to_u64(bytes: &[u8]) -> u64 {
    let mut acc = bytes.len() as u64;
    let mut chunk = [0u8; 8];
    let mut i = 0;
    while i < bytes.len() {
        let take = core::cmp::min(8, bytes.len() - i);
        chunk.fill(0);
        chunk[..take].copy_from_slice(&bytes[i..i + take]);
        acc ^= u64::from_le_bytes(chunk);
        i += 8;
    }
    acc
}
