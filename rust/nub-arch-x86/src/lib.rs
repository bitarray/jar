//! Generic nub guest-kernel library for Hyperlight.
//!
//! Houses the personality seam (`personality`), the CALL/HALT task
//! loop (`task`), the generic RPC bodies + [`register_guest_kernel!`]
//! (`guest_fns`), and the bare-metal substrate modules (page tables,
//! JIT runtime, page allocator, ring-3 entry, segments). This crate
//! produces **no** binaries: a personality crate (e.g.
//! `rust/javm-guest-x86`, the Javm personality) plugs its state/cap
//! system into the seam and owns the `[[bin]]` targets.
//!
//! Downstream personality-crate requirements:
//!
//! - a **direct, unrenamed** `hyperlight-guest-bin` dependency
//!   (`register_guest_kernel!` expands `#[guest_function]` attrs whose
//!   proc-macro resolves the crate by package name at the invoking
//!   crate) plus `extern crate alloc;` and
//!   `extern crate hyperlight_guest_bin;` at its lib root;
//! - its own `link.x` next to its manifest — `nub_build::build`
//!   resolves the linker script as `manifest_dir.join("link.x")`;
//!   copy `rust/javm-guest-x86/link.x` (canonical script until
//!   nub-build grows an explicit link-script parameter);
//! - a `heap-diag = ["nub-arch-x86/heap-diag"]` feature — the
//!   macro-stamped `nub_heap_stats` wrapper's `#[cfg(feature =
//!   "heap-diag")]` resolves against the invoking crate.
//!
//! Guest modules are gated on `cfg(target_os = "none")` so the lib
//! also compiles on host targets — host code imports the [`test_abi`]
//! module for FN_ID constants without dragging in any bare-metal
//! deps.

#![cfg_attr(target_os = "none", no_std)]

#[cfg(target_os = "none")]
extern crate alloc;
#[cfg(target_os = "none")]
extern crate hyperlight_guest_bin;

// Kernel modules — guest-only.
#[cfg(target_os = "none")]
pub mod execution_lane;
#[cfg(target_os = "none")]
pub mod guest_fns;
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
pub mod task;

/// FN_ID constants shared between the test/bench guest binaries and
/// host-side test/bench drivers. Always compiled — host-visible.
pub mod test_abi;
