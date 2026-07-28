//! Production guest binary for the flat personality.
//!
//! A shell: all logic lives in the `nub_flat_guest_x86` library, and
//! `extern crate` forces the linker to include its `#[guest_function]`
//! linkme contributions in this ELF.
//!
//! On host targets this compiles to an empty `main`, so
//! `cargo build --workspace` succeeds without dragging the guest deps
//! onto host platforms. Only
//! `cargo build --target=x86_64-unknown-none --bin nub-flat-guest-x86`
//! produces a real guest ELF.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
extern crate alloc;
#[cfg(target_os = "none")]
extern crate hyperlight_guest_bin;

#[cfg(target_os = "none")]
extern crate nub_flat_guest_x86;

#[cfg(not(target_os = "none"))]
fn main() {}
