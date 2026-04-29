//! Sub-VM benchmark: recursive fibonacci via CALL(CODE) + CALL(HANDLE).
//!
//! Exercises the kernel's multi-VM capabilities:
//!   - CALL(CODE) → CREATE child VM
//!   - CALL(HANDLE) → cross-VM invocation
//!   - REPLY → return to caller
//!
//! javm-only — polkavm has no multi-VM kernel model.

use criterion::{Criterion, criterion_group, criterion_main};
use javm_bench::*;

fn bench_fib_recur(c: &mut Criterion) {
    let blob = javm_fib_recur_blob();
    let n = FIB_RECUR_N;
    let gas = 10_000_000_000u64;

    // Validate correctness before benchmarking
    let (result, gas_used, vm_count) =
        run_fib_recur_with_backend(&blob, n, gas, javm::PvmBackend::Default);
    assert_eq!(result, 6765, "fib(20) should be 6765");
    eprintln!("fib_recur({n}): result={result} gas_used={gas_used} vms={vm_count}");

    let mut group = c.benchmark_group("fib_recur");
    group.sample_size(10);

    group.bench_function("javm-interpreter", |b| {
        b.iter(|| run_fib_recur_with_backend(&blob, n, gas, javm::PvmBackend::ForceInterpreter))
    });

    group.bench_function("javm-recompiler", |b| {
        b.iter(|| run_fib_recur_with_backend(&blob, n, gas, javm::PvmBackend::ForceRecompiler))
    });

    group.finish();
}

criterion_group!(benches, bench_fib_recur);
criterion_main!(benches);
