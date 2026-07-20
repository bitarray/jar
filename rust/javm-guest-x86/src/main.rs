//! Production guest binary for `javm-guest-x86`.
//!
//! Thin shell: all logic lives in the `javm_guest_x86` library (whose
//! `guest_prod` stamps the production table via the generic
//! `nub_arch_x86` kernel lib); `extern crate javm_guest_x86` forces
//! the linker to include the lib's `#[guest_function]` linkme
//! contributions in this ELF.
//!
//! On host targets (target_os != "none") this compiles to a
//! trivial empty `main` so `cargo build --workspace` succeeds
//! without dragging Hyperlight-guest deps onto host platforms.
//! Only `cargo build --target=x86_64-unknown-none --bin javm-guest-x86`
//! produces a real guest ELF.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
extern crate alloc;
#[cfg(target_os = "none")]
extern crate hyperlight_guest_bin;

#[cfg(target_os = "none")]
extern crate javm_guest_x86;

#[cfg(not(target_os = "none"))]
fn main() {}
