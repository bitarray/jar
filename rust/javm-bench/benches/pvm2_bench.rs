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

// Bench guests that pass the pvm2_smoke comparison check (PVM and
// PVM2 produce identical return_value). Failing guests
// (ed25519/ecrecover/poseidon2_perm/mini_verifier/poly_eval/
// fri_fold_tree) are tracked in docs/pvm-isa/07-pvm2-bench-stats.md
// and excluded here so the bench numbers don't include miscomputed
// runs.
bench_workload!(prime_sieve_pvm, "PRIME_SIEVE_BLOB", 0, "prime_sieve_pvm");
bench_workload!(prime_sieve_pvm2, "PRIME_SIEVE_PVM2_BLOB", 0, "prime_sieve_pvm2");
bench_workload!(keccak_pvm, "KECCAK_BLOB", 0, "keccak_pvm");
bench_workload!(keccak_pvm2, "KECCAK_PVM2_BLOB", 0, "keccak_pvm2");
bench_workload!(blake2b_pvm, "BLAKE2B_BLOB", 0, "blake2b_pvm");
bench_workload!(blake2b_pvm2, "BLAKE2B_PVM2_BLOB", 0, "blake2b_pvm2");
bench_workload!(goldilocks_mul_pvm, "GOLDILOCKS_MUL_BLOB", 0, "goldilocks_mul_pvm");
bench_workload!(goldilocks_mul_pvm2, "GOLDILOCKS_MUL_PVM2_BLOB", 0, "goldilocks_mul_pvm2");
bench_workload!(sub_vm_recurse_pvm, "SUB_VM_RECURSE_BLOB", 0, "sub_vm_recurse_pvm");
bench_workload!(sub_vm_recurse_pvm2, "SUB_VM_RECURSE_PVM2_BLOB", 0, "sub_vm_recurse_pvm2");
bench_workload!(sub_vm_data_recurse_pvm, "SUB_VM_DATA_RECURSE_BLOB", 0, "sub_vm_data_recurse_pvm");
bench_workload!(sub_vm_data_recurse_pvm2, "SUB_VM_DATA_RECURSE_PVM2_BLOB", 0, "sub_vm_data_recurse_pvm2");

criterion_group!(
    benches,
    prime_sieve_pvm,
    prime_sieve_pvm2,
    keccak_pvm,
    keccak_pvm2,
    blake2b_pvm,
    blake2b_pvm2,
    goldilocks_mul_pvm,
    goldilocks_mul_pvm2,
    sub_vm_recurse_pvm,
    sub_vm_recurse_pvm2,
    sub_vm_data_recurse_pvm,
    sub_vm_data_recurse_pvm2,
);
criterion_main!(benches);
