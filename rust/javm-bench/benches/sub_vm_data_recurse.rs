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
    // Correctness gate (before the throughput loop): every recursion level
    // reads its pinned 64 KiB RO pattern — `RO_DATA[i] = i & 0xFF`, summed
    // every 64th byte = 256 cycles × (0+64+128+192) = 98304 — and writes+reads
    // its 4 KiB initial-slot RW byte (`+= depth & 0xFF`). The guest returns its
    // own level's sum. Before the child-mem fix a derived child ran against an
    // empty extent and faulted on its RW write; now each child shares its
    // Image's pages, so depth ≥ 1 (sub-VMs) completes with the right value.
    // depth 300 keeps 301 frames (each with its page table) resident — a
    // value-checked pass confirms deep recursion holds the right per-frame
    // `mem`/regs.
    {
        let mut nub = javm_bench::nub_hyperlight_lock();
        let top = javm_bench::build_sub_vm_top(&mut nub, BLOB);
        const RO_SUM: u64 = 98_304;
        for depth in [0u64, 1, 2, 5, 300] {
            javm_bench::invoke_sub_vm_expect(&nub, &top, depth, RO_SUM + (depth & 0xFF));
        }
    }

    javm_bench::run_recurse_bench(c, BLOB, "sub_vm_data_recurse");
}

criterion_group!(benches, sub_vm_data_recurse);
criterion_main!(benches);
