//! Production guest binary for `nub-arch-x86`.
//!
//! Thin shell: all logic lives in the `nub_arch_x86` library;
//! `extern crate nub_arch_x86` forces the linker to include the
//! lib's `#[guest_function]` linkme contributions in this ELF.
//! See [`nub_arch_x86`] for the kernel modules and production
//! guest function table.
//!
//! On host targets (target_os != "none") this compiles to a
//! trivial empty `main` so `cargo build --workspace` succeeds
//! without dragging Hyperlight-guest deps onto host platforms.
//! Only `cargo build --target=x86_64-unknown-none --bin nub-arch-x86`
//! produces a real guest ELF.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
extern crate alloc;
#[cfg(target_os = "none")]
extern crate hyperlight_guest_bin;

#[cfg(target_os = "none")]
extern crate nub_arch_x86;

#[cfg(not(target_os = "none"))]
fn main() {}
