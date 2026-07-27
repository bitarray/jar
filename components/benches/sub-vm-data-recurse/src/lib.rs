//! Sub-VM recursive-spawn bench guest with a 64 KiB pinned RO data
//! mapping. Every recursion level reads (sums) the mapped bytes —
//! exercising the direct-mapping path landed by Issue #855 part A
//! (Commit 2). The RO blob lives in `.rodata` so nub_rt auto-
//! generates a pinned-slot `MemoryMapping` for it.
//!
//! When this bench is built into the JIT/javm target it ships a
//! self-recursive image: each level `derive_spawn`s a fresh sub-VM,
//! sums the RO data, and CALLs into the child with `depth - 1`. The
//! parent's RO mapping is shared across every child by content
//! address — `Cap::Data` pages get refcount-pinned at frame build,
//! mapped read-only into each frame's PT, and the cache is hit
//! exactly once per Image type.

#![cfg_attr(target_os = "none", no_std)]

use nub_rt as _;
