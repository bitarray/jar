//! JAVM guest personality — the javm-cap state/cap system plugged into the
//! generic nub guest kernel (`nub_arch_x86`). Three binary targets link
//! against this lib: `javm-guest-x86` (production), `javm-guest-x86-tests`,
//! `javm-guest-x86-benches`. The production guest-function table is stamped
//! in `guest_prod` via `nub_arch_x86::register_guest_kernel!`.

#![cfg_attr(target_os = "none", no_std)]

#[cfg(target_os = "none")]
extern crate alloc; // register_guest_kernel! requirement
#[cfg(target_os = "none")]
extern crate hyperlight_guest_bin; // panic handler + allocator + macro paths

#[cfg(target_os = "none")]
pub mod cached_cap;
#[cfg(target_os = "none")]
pub mod call_loop;
#[cfg(target_os = "none")]
pub mod state_cache;

/// Production guest-function table (linkme contributions).
#[cfg(target_os = "none")]
pub mod guest_prod;
