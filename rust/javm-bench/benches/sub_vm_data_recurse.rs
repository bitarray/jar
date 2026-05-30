//! Sub-VM recursive-spawn-with-data bench for the in-kernel JIT path.
//!
//! Same recursion shape as
//! [`sub_vm_recurse`](../sub_vm_recurse/index.html), but the bench guest
//! ships a 64 KiB pinned `Cap::Data` mapped read-only into every sub-VM
//! frame. Every level sums the mapped bytes, so the bench exercises the
//! direct-mapping path landed by Issue #855 part A (Commit 2). Before
//! that change the harness memcpy'd the entire 64 KiB into each level's
//! per-frame mem_buf; after it the bytes are projected straight from the
//! cache.
//!
//! ## What this measures
//!
//! Per recursion level the kernel pays roughly:
//!
//! 1. ~3 µs `derive_spawn`.
//! 2. ~10–15 µs PT setup + ring-3 entry + JIT entry.
//! 3. ~10–15 µs HALT exit + PT teardown + parent restore.
//! 4. ~RO_DATA_LEN / 4 KiB × ~50 ns for PT-level overwrite of the
//!    direct-mapped pages on the per-frame PT (Commit 2 path).
//!
//! Pre-Commit 2 the per-level cost included a full 64 KiB memcpy
//! (~3 µs depending on cache state); the direct-mapping path
//! should eliminate that.
//!
//! The build/invoke/criterion driver is shared with `sub_vm_recurse`
//! via [`javm_bench::run_recurse_bench`].

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use criterion::{Criterion, criterion_group, criterion_main};

const BLOB: &[u8] = include_bytes!(env!("SUB_VM_DATA_RECURSE_BLOB"));

fn sub_vm_data_recurse(c: &mut Criterion) {
    javm_bench::run_recurse_bench(c, BLOB, "sub_vm_data_recurse");
}

criterion_group!(benches, sub_vm_data_recurse);
criterion_main!(benches);
