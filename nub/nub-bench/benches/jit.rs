//! x86-64 JIT execution, through the KVM sandbox and the flat
//! personality. Two rows per program.
//!
//! This is the counterpart to `interp.rs`: same programs, same endpoint,
//! same pinned `(value, gas)` gate, but running recompiled native code
//! instead of interpreting. It needs the ring-0 substrate in
//! `nub-arch-x86`, which needs a `GuestPersonality` — `nub-flat` — so it
//! could not exist before that personality did.
//!
//! - `nub_jit_cold` — **the bench target.** Each sample starts with no
//!   compiled code and ends with the program having run: the cost a VM
//!   pays when a work-package arrives, is turned into native code, and
//!   executed once.
//! - `nub_jit_warm` — the same invocation with the compiled image
//!   already cached. The difference between the two rows *is* what the
//!   recompile costs.
//!
//! Publishing is deliberately outside both. Getting a blob into the
//! guest's object store means shipping it across the VM boundary,
//! decoding it and content-hashing it — a storage cost, dominated by
//! hashing, belonging to a different subsystem than the recompiler. It
//! is measured once here and reported to stderr, never folded into a row.
//!
//! Linux x86-64 only, and needs `/dev/kvm`.
//!
//! One sandbox serves every program in the process, because the
//! guest-VA window is a single process-wide reservation that is never
//! released. To measure one program in isolation, filter:
//! `cargo bench -p nub-bench --bench jit -- prime_sieve`.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    eprintln!("the JIT benchmark is Linux x86-64 only");
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
criterion::criterion_main!(imp::benches);

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod imp {
    use std::time::Instant;

    use criterion::{BatchSize, Criterion, criterion_group};
    use nub_bench::{BENCH_GAS, EXIT_HOST_CALL, PROGRAMS, flat_sandbox};

    /// Endpoint 0, matching `interp.rs`'s cold row and jar's
    /// `javm-bench`. Every invocation builds a fresh frame with a fresh
    /// copy-on-write overlay, so the guest's bump arena starts clean and
    /// endpoint 0 is safe to re-enter — unlike the interpreter's
    /// `ProgramInstance`, whose memory persists and which therefore
    /// needs endpoint 2's `reset_heap()`.
    const EP: u8 = 0;

    fn bench_jit(c: &mut Criterion) {
        if !std::path::Path::new("/dev/kvm").exists() {
            eprintln!("skipping: /dev/kvm not present");
            return;
        }
        let nub = flat_sandbox();

        for p in PROGRAMS {
            // Publish once, outside every timed region — see the module
            // docs for why storage is not part of the target.
            let started = Instant::now();
            let hash = nub
                .put_object(p.blob)
                .unwrap_or_else(|e| panic!("[{}] publish: {e}", p.name));
            let publish = started.elapsed();

            // Correctness gate before timing. Gas equality with the
            // interpreter is the strong assertion: it says both backends
            // charge identically instruction for instruction, which is
            // what makes them interchangeable for a metered VM.
            let (value, gas) = invoke(nub, hash, p.name);
            assert_eq!(value, p.expected_value, "[{}] return value", p.name);
            assert_eq!(gas, p.expected_gas, "[{}] gas", p.name);
            eprintln!(
                "[{}] value={value:#x} gas={gas} publish={publish:?} (excluded)",
                p.name,
            );

            let mut group = c.benchmark_group(p.name);

            group.bench_function("nub_jit_cold", |b| {
                b.iter_batched(
                    // Untimed: drop every compiled image, so the
                    // invocation below has to recompile before it can
                    // run. `PerIteration` because one eviction serves
                    // exactly one sample — batching would leave every
                    // sample after the first measuring a warm run.
                    || nub.evict_jit_all().expect("evict_jit_all"),
                    |()| std::hint::black_box(invoke(nub, hash, p.name)),
                    BatchSize::PerIteration,
                )
            });

            group.bench_function("nub_jit_warm", |b| {
                b.iter(|| std::hint::black_box(invoke(nub, hash, p.name)))
            });

            group.finish();
        }
    }

    /// One invocation, returning `(return_value, gas_used)`.
    ///
    /// Panics unless the program halts cleanly, so a benchmark can never
    /// silently measure a trapping program.
    fn invoke(nub: &nub::Nub<nub_flat::Flat>, hash: nub::ObjHash, name: &str) -> (u64, u64) {
        let result = nub
            .invoke_cached(hash, EP, [0; 4], BENCH_GAS)
            .unwrap_or_else(|e| panic!("[{name}] invoke: {e}"));
        assert_eq!(
            result.exit_reason, EXIT_HOST_CALL,
            "[{name}] did not halt cleanly: exit_reason={} exit_arg={}",
            result.exit_reason, result.exit_arg,
        );
        assert_eq!(result.exit_arg, 0, "[{name}] unexpected host call");
        (result.return_value, BENCH_GAS - result.gas_remaining)
    }

    criterion_group!(benches, bench_jit);
}
