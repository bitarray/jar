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
//! That post-resume re-read is the whole point: a deep frame whose
//! `FrameRuntime` was evicted while it was paused rebuilds a fresh, empty page
//! table on resume. The category-#3 charge for those already-materialized pages
//! must NOT be paid again — eviction is a memory-management optimization and is
//! gas-transparent. `tests/sub_vm_gas_parity.rs` drives this guest across the
//! eviction boundary and asserts the recursion's gas stays affine in depth.

#![cfg_attr(target_os = "none", no_std)]

use subsoil as _;
