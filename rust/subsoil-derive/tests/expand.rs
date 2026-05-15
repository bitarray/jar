//! Compile-only smoke test for `#[subsoil::endpoint(N)]`. The
//! descriptor static is gated behind `cfg(all(target_env = "javm",
//! target_os = "none"))`, so on host this test just checks that
//! the macro accepts a valid signature and leaves the function body
//! intact.

use subsoil::endpoint;

#[endpoint(0)]
fn handler_zero(args_len: u64) -> u64 {
    args_len.wrapping_add(1)
}

#[endpoint(255)]
fn handler_max(args_len: u64) -> u64 {
    args_len
}

#[test]
fn endpoint_attribute_preserves_function_bodies() {
    assert_eq!(handler_zero(41), 42);
    assert_eq!(handler_max(7), 7);
}
