//! Nub Arch implementation for Hyperlight — library form.
//!
//! Houses the kernel modules (page tables, JIT runtime, page
//! allocator, state cache, call loop) and the production guest-
//! function table. Three binary targets link against this lib:
//!
//! - `nub-arch-x86` (`src/main.rs`) — production. Empty shell;
//!   `extern crate nub_arch_x86` pulls in the lib's
//!   `#[guest_function]` linkme contributions.
//! - `nub-arch-x86-tests` (`src/bin/tests.rs`) — production fns +
//!   test-only RPCs (e.g. `nub_smoke`).
//! - `nub-arch-x86-benches` (`src/bin/benches.rs`) — production
//!   fns + bench probes (e.g. `bench_arc_page_alloc`).
//!
//! Production deps + the kernel modules are gated on
//! `cfg(target_os = "none")` so the lib also compiles on host
//! targets — host code (`nub` crate) imports the [`test_abi`]
//! module for FN_ID constants without dragging in any bare-metal
//! deps.

#![cfg_attr(target_os = "none", no_std)]

#[cfg(target_os = "none")]
extern crate alloc;
#[cfg(target_os = "none")]
extern crate hyperlight_guest_bin;

// Kernel modules — guest-only.
#[cfg(target_os = "none")]
pub mod cached_cap;
#[cfg(target_os = "none")]
pub mod call_loop;
#[cfg(target_os = "none")]
pub mod execution_lane;
#[cfg(target_os = "none")]
pub mod jit_cache;
#[cfg(target_os = "none")]
pub mod jit_run;
#[cfg(target_os = "none")]
pub mod page_alloc;
#[cfg(target_os = "none")]
pub mod paging;
#[cfg(target_os = "none")]
pub mod personality;
#[cfg(target_os = "none")]
pub mod ring3;
#[cfg(target_os = "none")]
pub mod segments;
#[cfg(target_os = "none")]
pub mod state_cache;
#[cfg(target_os = "none")]
pub mod task;

/// Production guest function table — `#[guest_function]` linkme
/// contributions. Any bin that `extern crate`s `nub_arch_x86` pulls
/// these into its dispatch table.
#[cfg(target_os = "none")]
pub mod guest_prod;

/// FN_ID constants shared between the test/bench guest binaries and
/// host-side test/bench drivers. Always compiled — host-visible.
pub mod test_abi;
