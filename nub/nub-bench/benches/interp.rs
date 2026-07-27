//! Interpreter throughput, one criterion group per program.
//!
//! Measures `run_blob` end to end: build the address space, predecode,
//! interpret to a clean halt. That is nub's real single-shot
//! invocation model, so nothing here is hoisted out of the timed
//! region — a program that spends its time in predecode should show it.

use criterion::{Criterion, criterion_group, criterion_main};
use nub_bench::PROGRAMS;

fn bench_interpreter(c: &mut Criterion) {
    for p in PROGRAMS {
        let blob = p.decode();

        // Correctness gate before timing: a benchmark that measures a
        // trapping program is worse than no benchmark.
        let (value, gas) = nub_bench::run_interpreter(p.name, &blob);
        assert_eq!(value, p.expected_value, "[{}] return value", p.name);
        assert_eq!(gas, p.expected_gas, "[{}] gas", p.name);

        let mut group = c.benchmark_group(p.name);
        group.bench_function("nub_interp", |b| {
            b.iter(|| {
                let r = nub_arch_local::run_blob(
                    std::hint::black_box(&blob),
                    0,
                    [0; 4],
                    nub_bench::BENCH_GAS,
                )
                .expect("prepare");
                std::hint::black_box(r.return_value)
            })
        });
        group.finish();
    }
}

criterion_group!(benches, bench_interpreter);
criterion_main!(benches);
