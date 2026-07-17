//! Bench: cost of allocating N × `Arc<[u8; 4096]>` (page-aligned)
//! in the ring-0 guest.
//!
//! Drives the `bench_arc_page_alloc` guest function in the
//! `javm-guest-x86-benches` binary. Each iteration:
//!
//! 1. RPC into the guest with `N` as a u32 LE payload.
//! 2. Guest allocates `N × Arc<Page>` where `Page` is a 4 KiB
//!    page-aligned block, bracketed by RDTSC.
//! 3. Guest returns elapsed cycles; host decodes and reports.
//!
//! Reported number is end-to-end (RPC roundtrip + guest allocation).
//! The criterion output's per-iter cycle count is what to compare
//! to the ~500 ns / Arc estimate from the DataCap design discussion.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use nub::Nub;
use nub_arch_x86::test_abi::FN_ID_BENCH_ARC_PAGE_ALLOC;

fn bench(c: &mut Criterion) {
    // Warm up: instantiate the Nub so the first sample doesn't pay
    // sandbox-boot cost.
    drop(Nub::hyperlight_benches().expect("bench guest binary"));

    let mut group = c.benchmark_group("arc_page_alloc");
    for &n in &[16u32, 256, 1024, 4096] {
        group.throughput(Throughput::Elements(u64::from(n)));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let nub = Nub::hyperlight_benches().expect("bench guest binary");
                let payload = n.to_le_bytes();
                let bytes = nub
                    .call_raw(FN_ID_BENCH_ARC_PAGE_ALLOC, &payload)
                    .expect("bench rpc");
                let cycles = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
                criterion::black_box(cycles)
            })
        });
    }
    group.finish();
}

criterion_group!(arc_page_alloc, bench);
criterion_main!(arc_page_alloc);
