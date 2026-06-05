//! Page-table-cache bench guest (one image, two endpoints).
//!
//! - **Endpoint 0 (caller `A`):** reads a count `n` from `φ[7]`,
//!   `derive_spawn`s a child Instance once (from its own image — the
//!   kernel's `derive_spawn` falls back to the running frame's image
//!   when the image slot is empty), then `host_call`s that resident
//!   child's **echo** endpoint `n` times, summing the echoes. Because
//!   the child is an `Owned` sub-VM that HALT folds back into the same
//!   cnode slot, every iteration re-CALLs the *same* resident `B`.
//! - **Endpoint 1 (echo `B`):** returns its argument (`φ[7]`)
//!   unchanged. No data-region access ⇒ no CoW, no per-instance
//!   page-table delta.
//!
//! Goal: a steady-state CALL into the resident `B` allocates nothing
//! beyond a small `KernelFrame` — no per-CALL page-table rebuild. The
//! companion `tests/pt_cache_heap.rs` measures that directly.

#![cfg_attr(target_os = "none", no_std)]

use subsoil as _;
