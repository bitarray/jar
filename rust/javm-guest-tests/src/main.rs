//! Guest entry binary for `javm-guest-tests`.
//!
//! Defines one `#[nub_rt::endpoint(N)]` per legacy test_id. Each
//! endpoint calls into its corresponding library suite, which bakes
//! its own input corpus and returns a u64 fingerprint of the
//! results.
//!
//! The trampoline definitions live here (the binary) rather than in
//! `lib.rs` because rustc/ld drop rlib object files whose only
//! contribution is `#[used]` statics — putting them directly in the
//! bin's compilation unit ensures the `.nub_rt.endpoints`
//! descriptors propagate into the final ELF.
//!
//! The `SUITE_TABLE` in [`lib.rs`] mirrors this assignment for the
//! host-side harness. Both lists must stay in sync.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

use javm_guest_tests as _;
use nub_rt as _;

macro_rules! suite_endpoints {
    ($($idx:literal => $family:ident :: $suite:ident,)*) => {
        $(
            #[cfg(target_os = "none")]
            #[nub_rt::endpoint($idx)]
            fn $suite(_: u64) -> u64 {
                ::javm_guest_tests::tests::$family::$suite()
            }
        )*
    };
}

suite_endpoints! {
    0  => arithmetic::add_u64_suite,
    1  => arithmetic::sub_u64_suite,
    2  => arithmetic::mul_u64_suite,
    3  => arithmetic::mul_upper_uu_suite,
    4  => arithmetic::mul_upper_ss_suite,
    5  => arithmetic::div_u64_suite,
    6  => arithmetic::rem_u64_suite,
    7  => arithmetic::div_s64_suite,
    8  => arithmetic::rem_s64_suite,
    10 => bitwise::shift_left_suite,
    11 => bitwise::shift_right_logical_suite,
    12 => bitwise::shift_right_arithmetic_suite,
    13 => bitwise::rotate_right_suite,
    14 => bitwise::and_suite,
    15 => bitwise::or_suite,
    16 => bitwise::xor_suite,
    17 => bitwise::clz_suite,
    18 => bitwise::ctz_suite,
    19 => bitwise::set_lt_u_suite,
    20 => bitwise::set_lt_s_suite,
    30 => memory::memcpy_test_suite,
    31 => memory::sort_u32_suite,
    32 => memory::fib_suite,
    40 => crypto::blake2b_256_suite,
    41 => crypto::keccak_256_suite,
}

#[cfg(not(target_os = "none"))]
fn main() {}
