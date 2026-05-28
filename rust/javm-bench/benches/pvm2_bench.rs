//! PVM2 recompile + execute bench. Warm/cold per workload.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use javm_cap::image::Image;
use ssz::Decode;

macro_rules! bench_workload {
    ($name:ident, $env:literal, $endpoint:literal, $label:literal) => {
        fn $name(c: &mut Criterion) {
            // Rebuild the Hyperlight sandbox before each workload so
            // cap-publish state from prior bench functions doesn't
            // accumulate across the sweep — Instance caps with large
            // overlays trigger an indefinite hang in put_cap after
            // ~13 publishes on a single long-lived sandbox.
            javm_bench::reset_nub_hyperlight();

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

bench_workload!(prime_sieve, "PRIME_SIEVE_PVM2_BLOB", 0, "prime_sieve");
bench_workload!(keccak, "KECCAK_PVM2_BLOB", 0, "keccak");
bench_workload!(blake2b, "BLAKE2B_PVM2_BLOB", 0, "blake2b");
bench_workload!(
    goldilocks_mul,
    "GOLDILOCKS_MUL_PVM2_BLOB",
    0,
    "goldilocks_mul"
);
bench_workload!(
    sub_vm_recurse,
    "SUB_VM_RECURSE_PVM2_BLOB",
    0,
    "sub_vm_recurse"
);
bench_workload!(
    sub_vm_data_recurse,
    "SUB_VM_DATA_RECURSE_PVM2_BLOB",
    0,
    "sub_vm_data_recurse"
);
bench_workload!(ed25519, "ED25519_PVM2_BLOB", 0, "ed25519");
bench_workload!(ecrecover, "ECRECOVER_PVM2_BLOB", 0, "ecrecover");
bench_workload!(
    poseidon2_perm,
    "POSEIDON2_PERM_PVM2_BLOB",
    0,
    "poseidon2_perm"
);
bench_workload!(mini_verifier, "MINI_VERIFIER_PVM2_BLOB", 0, "mini_verifier");
bench_workload!(poly_eval, "POLY_EVAL_PVM2_BLOB", 0, "poly_eval");
bench_workload!(fri_fold_tree, "FRI_FOLD_TREE_PVM2_BLOB", 0, "fri_fold_tree");

criterion_group!(
    benches,
    prime_sieve,
    keccak,
    blake2b,
    goldilocks_mul,
    sub_vm_recurse,
    sub_vm_data_recurse,
    ed25519,
    ecrecover,
    poseidon2_perm,
    mini_verifier,
    poly_eval,
    fri_fold_tree,
);
criterion_main!(benches);
