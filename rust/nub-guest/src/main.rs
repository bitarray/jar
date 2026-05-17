//! Bare-metal Hyperlight guest for the `nub` ring-0 spike.
//!
//! Built with `build-nub` → `cargo build --target=x86_64-unknown-none`.
//! Links against `hyperlight-guest-bin` with `default-features = false`
//! (no picolibc, no C). Entry point is `entrypoint` (provided by
//! `hyperlight-guest-bin`), which initialises the heap + GDT + IDT
//! then calls `hyperlight_main`. We don't define `hyperlight_main`
//! ourselves; the weak default in `hyperlight-guest-bin` is fine.
//!
//! Guest functions are registered via `#[guest_function]`, which
//! uses `linkme` to slot them into a static `GuestFunctionRegister`
//! at compile time. The host invokes them by name via Hyperlight's
//! `OUT`-port + shared-memory function-call ABI.
//!
//! On host targets (target_os != "none") this crate compiles to a
//! trivial empty `main` so `cargo build --workspace` succeeds
//! without dragging hyperlight-guest deps onto host platforms.
//! Only `cargo build --target=x86_64-unknown-none` produces a real
//! Hyperlight guest binary.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
extern crate alloc;
#[cfg(target_os = "none")]
extern crate hyperlight_guest_bin;

#[cfg(target_os = "none")]
use hyperlight_guest_bin::guest_function;

/// A1: trivial round-trip. Host calls; guest returns 42.
/// Validates that build-nub + hyperlight-guest-bin link cleanly
/// and Hyperlight's host-callable ABI works end-to-end.
#[cfg(target_os = "none")]
#[guest_function("smoke")]
fn smoke() -> u64 {
    42
}

/// `hyperlight_guest_bin::generic_init` unconditionally calls
/// `srand` to seed picolibc's PRNG. With `default-features = false`
/// (no `libc` feature) there is no picolibc to provide that
/// symbol. We don't use libc rand-functions, so a no-op stub is
/// sufficient to satisfy the linker.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub extern "C" fn srand(_seed: u32) {}

#[cfg(not(target_os = "none"))]
fn main() {}
