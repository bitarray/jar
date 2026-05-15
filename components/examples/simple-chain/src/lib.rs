//! Example JAR chain.
//!
//! The chain's endpoint receives an `args_len` (currently ignored)
//! and returns a u64 — the sum of a fixed array. Exercises the
//! transpiled-Image runtime end-to-end: stack frame, array on
//! the stack, iterative sum, function return through
//! `subsoil::entry!`'s halt wrapper.

#![cfg_attr(target_os = "none", no_std)]

/// Compute and return the sum of `[1, 2, 3, 4, 5]`.
///
/// Lives in the lib so the bench/test infrastructure can call it
/// natively on the host as well.
pub fn simple_chain_sum() -> u64 {
    let xs = [1u64, 2, 3, 4, 5];
    let mut acc = 0u64;
    let mut i = 0;
    while i < xs.len() {
        acc = acc.wrapping_add(xs[i]);
        i += 1;
    }
    acc
}
