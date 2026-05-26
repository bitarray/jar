//! PVM2 vs PVM bench: warm/cold recompile+execute on the same guest.
//!
//! Only `prime_sieve` is wired today — the other 11 bench guests need
//! x3/x4 rewrite handling in `linker_rv` before lld-emitted ELFs link
//! cleanly. This file captures the comparison numbers for `07-pvm2-
//! bench-stats.md` (Phase 3).

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use javm_cap::image::Image;
use ssz::Decode;

macro_rules! bench_workload {
    ($name:ident, $env:literal, $endpoint:literal, $label:literal) => {
        fn $name(c: &mut Criterion) {
            let blob: &[u8] = include_bytes!(env!($env));
            let image = Image::from_ssz_bytes(blob).expect("decode Image");
            let ep: u8 = $endpoint;
            let built = javm_bench::BuiltCaps::for_image(&image, ep);

            let (val, gas) = javm_bench::run_recompiler(&built);
            eprintln!(
                "[{}] result = {:#x}, gas = {}, code = {}B",
                $label,
                val,
                gas,
                image.code.len(),
            );

            let mut g = c.benchmark_group($label);
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

bench_workload!(prime_sieve_pvm, "PRIME_SIEVE_BLOB", 0, "prime_sieve_pvm");
bench_workload!(prime_sieve_pvm2, "PRIME_SIEVE_PVM2_BLOB", 0, "prime_sieve_pvm2");

criterion_group!(benches, prime_sieve_pvm, prime_sieve_pvm2);
criterion_main!(benches);
