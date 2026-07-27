//! Interpreter throughput, one criterion group per program.
//!
//! Two rows, because they answer different questions:
//!
//! - `cold` — `run_blob` end to end: build the address space, predecode,
//!   interpret to a clean halt, on endpoint 0. This is nub's real
//!   single-shot invocation model, and it includes the one-time
//!   first-touch page materialization that gas charges for.
//! - `warm` — endpoint 2 re-invoked on one instance. Steady-state
//!   execution with setup amortized away, which is what to look at when
//!   judging the interpreter's inner loop rather than its startup.

use criterion::{Criterion, criterion_group, criterion_main};
use nub_arch_local::{PreparedProgram, ProgramInstance};
use nub_bench::PROGRAMS;

/// Endpoint 2 resets the guest heap on entry, so it is safe to invoke
/// repeatedly on one instance. Endpoint 0 is not.
const EP_RUN: u8 = 2;

fn bench_interpreter(c: &mut Criterion) {
    for p in PROGRAMS {
        let blob = p.decode();

        // Correctness gate before timing: a benchmark that measures a
        // trapping program is worse than no benchmark.
        let (value, gas) = nub_bench::run_interpreter(p.name, &blob);
        assert_eq!(value, p.expected_value, "[{}] return value", p.name);
        assert_eq!(gas, p.expected_gas, "[{}] gas", p.name);

        let mut group = c.benchmark_group(p.name);

        group.bench_function("nub_interp_cold", |b| {
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

        let prepared = PreparedProgram::new(&blob, EP_RUN, [0; 4]).expect("prepare endpoint 2");
        let mut instance = ProgramInstance::new(&prepared.spec());
        // Burn the cold invocation outside the measurement, so the first
        // timed sample is not the one paying for page materialization.
        let mut handler = nub_arch_local::ExitingEcallHandler;
        instance.invoke(&mut handler, nub_bench::BENCH_GAS);

        group.bench_function("nub_interp_warm", |b| {
            b.iter(|| {
                let mut handler = nub_arch_local::ExitingEcallHandler;
                let r = instance.invoke(&mut handler, nub_bench::BENCH_GAS);
                std::hint::black_box(r.return_value)
            })
        });

        group.finish();
    }
}

criterion_group!(benches, bench_interpreter);
criterion_main!(benches);
