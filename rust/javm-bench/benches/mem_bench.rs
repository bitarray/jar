//! Memory cache pressure benchmark.
//!
//! Measures how PVM load instruction throughput degrades as the working set
//! grows beyond L1 → L2 → L3 → DRAM. Two access patterns:
//!   - `mem_seq`: sequential sweep (prefetch-friendly, best case)
//!   - `mem_rand`: pseudo-random stride (cache-hostile, worst case)
//!
//! Run: `cargo bench -p javm-bench --bench mem_bench`

use criterion::{Criterion, criterion_group, criterion_main};
use javm_bench::mem::*;

/// Compute gas limit proportional to working set size.
///
/// Each loop iteration has multiple instructions (load/store + add + add +
/// branch), and there is both an init loop (n_elems stores) and sweep loops
/// (n_elems * SWEEPS loads). Budget generously to avoid OutOfGas on large
/// working sets.
fn gas_for_size(size_bytes: u64) -> u64 {
    let n_elems = size_bytes / 4;
    let sweeps = 15u64;
    // ~4 instructions per iteration, ~100 gas each, plus 2x headroom
    let init_cost = n_elems * 800;
    let sweep_cost = n_elems * sweeps * 800;
    init_cost + sweep_cost + 10_000_000
}

const SIZES: &[(&str, u64)] = &[
    ("4K", 4 * 1024),
    ("32K", 32 * 1024),
    ("256K", 256 * 1024),
    ("1M", 1024 * 1024),
    ("8M", 8 * 1024 * 1024),
    ("32M", 32 * 1024 * 1024),
    ("128M", 128 * 1024 * 1024),
    ("256M", 256 * 1024 * 1024),
    ("1G", 1024 * 1024 * 1024),
    ("2G", 2 * 1024 * 1024 * 1024),
    ("3G", 3 * 1024 * 1024 * 1024),
];

/// Initialize a kernel for the given blob.
fn init_kernel(blob: &[u8], gas: u64) -> javm::kernel::InvocationKernel {
    javm::kernel::InvocationKernel::new_with_backend(
        blob,
        &[],
        gas,
        javm::PvmBackend::ForceRecompiler,
    )
    .unwrap()
}

fn bench_mem_seq(c: &mut Criterion) {
    for &(label, size) in SIZES {
        let blob = javm_mem_seq_blob(size);
        let gas = gas_for_size(size);

        let mut group = c.benchmark_group(format!("mem_seq/{label}"));
        if size >= 8 * 1024 * 1024 {
            group.sample_size(10);
        }
        group.bench_function("javm-recompiler-exec", |b| {
            b.iter_batched(
                || init_kernel(&blob, gas),
                |mut kernel| {
                    loop {
                        match kernel.run() {
                            javm::kernel::KernelResult::Halt(v) => break v,
                            javm::kernel::KernelResult::ProtocolCall { .. } => continue,
                            other => panic!("unexpected: {:?}", other),
                        }
                    }
                },
                criterion::BatchSize::LargeInput,
            );
        });
        group.finish();
    }
}

fn bench_mem_rand(c: &mut Criterion) {
    for &(label, size) in SIZES {
        let blob = javm_mem_rand_blob(size);
        let gas = gas_for_size(size);

        let mut group = c.benchmark_group(format!("mem_rand/{label}"));
        if size >= 8 * 1024 * 1024 {
            group.sample_size(10);
        }
        group.bench_function("javm-recompiler-exec", |b| {
            b.iter_batched(
                || init_kernel(&blob, gas),
                |mut kernel| {
                    loop {
                        match kernel.run() {
                            javm::kernel::KernelResult::Halt(v) => break v,
                            javm::kernel::KernelResult::ProtocolCall { .. } => continue,
                            other => panic!("unexpected: {:?}", other),
                        }
                    }
                },
                criterion::BatchSize::LargeInput,
            );
        });
        group.finish();
    }
}

criterion_group!(mem_benches, bench_mem_seq, bench_mem_rand);
criterion_main!(mem_benches);
