//! PVM benchmarks: byte-PVM interpreter vs JIT recompiler.
//!
//! Each guest crate at `components/benches/<workload>` builds to a
//! single-endpoint Image; this bench loads each Image, builds the
//! shared [`nub::PublishSpec`] ONCE per workload, runs a sanity check
//! (which also primes the Hyperlight sandbox via the cached
//! `OnceLock` and publishes into the cache), then runs criterion on
//! both backends.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use criterion::{Criterion, criterion_group, criterion_main};
use javm_cap::image::Image;
use scale::Decode;

macro_rules! bench_workload {
    ($name:ident, $env:literal, $endpoint:literal) => {
        fn $name(c: &mut Criterion) {
            let blob: &[u8] = include_bytes!(env!($env));
            let image = Image::decode(blob).expect("decode Image").0;
            let ep: u8 = $endpoint;

            // Build the PublishSpec ONCE — re-using across iterations
            // keeps per-iter cost in `invoke_cached` proper, not in
            // bitmask unpack + ro/rw byte clones.
            let spec = javm_bench::build_publish_spec(&image, ep);

            // Sanity: interpreter and recompiler must agree. Running
            // each backend once before the timed loop also pays the
            // Hyperlight sandbox boot (~hundreds of ms) so it never
            // lands inside a criterion sample.
            let (interp_val, interp_gas) = javm_bench::run_interpreter(&spec);
            eprintln!(
                "[{}] result = {:#x}, interp gas = {}",
                stringify!($name),
                interp_val,
                interp_gas,
            );
            let (recomp_val, recomp_gas) = javm_bench::run_recompiler(&spec);
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
                b.iter(|| javm_bench::run_interpreter(&spec))
            });
            g.bench_function("recompiler", |b| {
                b.iter(|| javm_bench::run_recompiler(&spec))
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
