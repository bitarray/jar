//! Sub-VM recursion test guest that **re-reads its memory after the
//! `host_call` returns** — the case the bench guests (`sub-vm-recurse`,
//! `sub-vm-data-recurse`) deliberately omit (they return a register value and
//! touch no memory on the way up).
//!
//! Each level reads its 64 KiB pinned RO mapping (page-in on the way down) and
//! CoW-writes its 4 KiB initial-slot RW page, then `derive_spawn`s + `host_call`s
//! a child. After the child HALTs and the level **resumes**, it re-reads both
//! the RO and the RW data and folds them into its return value.
//!
//! The post-resume re-read makes each level exercise the full category-#3 path
//! (RO-unit page-in + CoW) on both the way down and the way up.
//! `tests/sub_vm_gas_parity.rs` drives this guest and asserts the recursion's
//! gas is affine in depth (identical per-level charge — a multi-frame
//! determinism guard). It was originally the regression test for the runtime
//! eviction-recharge fork: a frame whose page table was evicted while paused and
//! rebuilt on resume must not re-charge category-#3 for pages it already paid
//! for. Eviction has since been removed (the call stack is bounded
//! structurally), so the gas state lives on the `KernelFrame` purely to survive
//! any future runtime reclamation (host-backed swap).

#![cfg_attr(target_os = "none", no_std)]

use nub_rt as _;
