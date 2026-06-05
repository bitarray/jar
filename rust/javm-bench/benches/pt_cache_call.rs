//! Page-table-cache bench for the in-kernel JIT path.
//!
//! Measures the steady-state cost of a CALL into an already-resident
//! `Cap::Instance`. The caller `A`
//! ([`components/benches/pt-cache-call`]) reads a count `n` from φ[7]
//! and `host_call`s the echo callee `B`
//! ([`components/benches/pt-cache-echo`]) `n` times; `B` returns its
//! argument unchanged (no data-region writes, no sub-calls). `B` is
//! published once as an Instance and lives in a fixed cnode slot, so
//! every iteration re-CALLs the same `B`.
//!
//! ## What this measures
//!
//! Per CALL the kernel pays a frame round-trip into `B`: build the
//! child `KernelFrame`, set up its ring-3 page table, enter/exit
//! ring 3, fold state back. The page-table-cache work caches the
//! per-instance page table across CALLs so the steady-state CALL
//! allocates nothing beyond a small `KernelFrame` — this bench (with
//! `Throughput::Elements(n)`, reporting per-CALL) tracks that win.
//! The companion `tests/pt_cache_heap.rs` asserts the per-CALL
//! allocation churn directly.
//!
//! The build/invoke/criterion driver is shared via
//! [`javm_bench::run_pt_cache_bench`].

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use criterion::{Criterion, criterion_group, criterion_main};

const BLOB: &[u8] = include_bytes!(env!("PT_CACHE_BLOB"));

fn pt_cache_call(c: &mut Criterion) {
    javm_bench::run_pt_cache_bench(c, BLOB, "pt_cache_call");
}

criterion_group!(benches, pt_cache_call);
criterion_main!(benches);
