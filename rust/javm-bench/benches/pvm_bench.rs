//! PVM benchmarks: byte-PVM interpreter vs JIT recompiler.
//!
//! Each guest crate at `components/benches/<workload>` builds to a
//! single-endpoint Image; this bench loads each Image, runs a sanity
//! check (which primes the cached Hyperlight sandbox), then runs
//! criterion on both backends.
//!
//! Two recompiler arms are reported per workload:
//!
//! - `recompiler_warm` — the JIT cache hits after iteration 1; the
//!   timed body is steady-state execute. Comparable across runs and
//!   to PolkaVM's warm path.
//! - `recompiler_cold` — the JIT cache is evicted before every
//!   invocation; the timed body is **predecode + JIT + execute**.
//!   Models a PolkaVM-shaped workload where each guest invocation
//!   may face a fresh Image hash.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use javm_cap::image::Image;
use ssz::Decode;

macro_rules! bench_workload {
    ($name:ident, $env:literal, $endpoint:literal) => {
        fn $name(c: &mut Criterion) {
            let blob: &[u8] = include_bytes!(env!($env));
            let image = Image::from_ssz_bytes(blob).expect("decode Image");
            let ep: u8 = $endpoint;

            // Build the Cap<Global> graph + precomputed hashes once at
            // bench setup. The iter loop reuses this handle.
            let built = javm_bench::BuiltCaps::for_image(&image, ep);

            // Sanity: interpreter and recompiler must agree. Running
            // each backend once before the timed loop also pays the
            // Hyperlight sandbox boot (~hundreds of ms) so it never
            // lands inside a criterion sample.
            let (interp_val, interp_gas) = javm_bench::run_interpreter(&built);
            eprintln!(
                "[{}] result = {:#x}, interp gas = {}",
                stringify!($name),
                interp_val,
                interp_gas,
            );
            let (recomp_val, recomp_gas) = javm_bench::run_recompiler(&built);
            assert_eq!(
                interp_val,
                recomp_val,
                "{}: interp vs recomp value",
                stringify!($name),
            );
            assert_eq!(
                interp_gas,
                recomp_gas,
                "{}: interp vs recomp gas",
                stringify!($name),
            );
            eprintln!("[{}] recomp gas = {}", stringify!($name), recomp_gas);

            let mut g = c.benchmark_group(stringify!($name));
            g.bench_function("interpreter", |b| {
                b.iter(|| javm_bench::run_interpreter(&built))
            });
            // Both recompiler arms use iter_batched(PerIteration). The
            // timed body covers `put_cap_with_hash` × 4 + `invoke_cached`,
            // i.e. the per-call publish-and-invoke cost real callers pay.
            // The merkle-hash computation that `put_cap` would normally do
            // is amortised away at warmup (`BuiltCaps::for_image` records
            // every hash once) and short-circuits at runtime via the
            // host-side `GuestCacheReader::contains(hash)` check, so the
            // routine measures the realistic publish+invoke, never the
            // merkle. Setup (untimed) holds the mutex and — for cold —
            // does JIT-cache eviction so eviction's ~7 µs RPC doesn't
            // get counted against recompile time.
            g.bench_function("recompiler_warm", |b| {
                b.iter_batched(
                    || javm_bench::nub_hyperlight_lock(),
                    |mut nub| {
                        built.put_into(&mut nub);
                        javm_bench::invoke(&mut *nub, &built)
                    },
                    BatchSize::PerIteration,
                )
            });
            g.bench_function("recompiler_cold", |b| {
                b.iter_batched(
                    || {
                        let mut nub = javm_bench::nub_hyperlight_lock();
                        nub.evict_jit_all().expect("evict_jit_all");
                        nub
                    },
                    |mut nub| {
                        built.put_into(&mut nub);
                        javm_bench::invoke(&mut *nub, &built)
                    },
                    BatchSize::PerIteration,
                )
            });
            g.finish();
        }
    };
}

bench_workload!(prime_sieve, "PRIME_SIEVE_BLOB", 0);
bench_workload!(ed25519, "ED25519_BLOB", 0);
bench_workload!(keccak, "KECCAK_BLOB", 0);
bench_workload!(blake2b, "BLAKE2B_BLOB", 0);
bench_workload!(ecrecover, "ECRECOVER_BLOB", 0);

criterion_group!(benches, prime_sieve, ed25519, keccak, blake2b, ecrecover);
criterion_main!(benches);
