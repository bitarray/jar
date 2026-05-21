//! STARK-shaped PVM benchmarks: byte-PVM interpreter vs JIT recompiler.
//!
//! Five workloads decomposing the cost of one moderate uni-stark
//! verify into its constituent pieces:
//!
//! - `goldilocks_mul` — 100k chained Goldilocks multiplications,
//!   isolates field-arithmetic cost (`u64 * u64 → u128 → mod p_G`).
//! - `poseidon2_perm` — 1k chained Poseidon2-WIDTH8 permutations,
//!   isolates the hash cost.
//! - `mini_verifier` — Fiat-Shamir transcript + FRI fold + AIR
//!   constraint-eval composite (~400 Poseidon2 perms + ~2400
//!   Goldilocks ops per call).
//! - `poly_eval` — Horner's-method evaluation of a degree-4096
//!   polynomial at 64 challenge points (~262k mul-add ops with
//!   sequential L1-resident coefficient reads).
//! - `fri_fold_tree` — 30 queries × 12 levels of merkle-tree walk
//!   with scattered sibling lookups + Poseidon2 mix + Goldilocks
//!   linear-combine fold (64 KiB tree).
//!
//! All three share the no_std hand-written Goldilocks + Poseidon2
//! implementation in `components/benches/goldilocks-poseidon2`,
//! bit-exact with `p3-goldilocks::default_goldilocks_poseidon2_8`.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use criterion::{Criterion, criterion_group, criterion_main};
use javm_cap::image::Image;
use ssz::Decode;

macro_rules! bench_workload {
    ($name:ident, $env:literal, $endpoint:literal) => {
        fn $name(c: &mut Criterion) {
            let blob: &[u8] = include_bytes!(env!($env));
            let image = Image::from_ssz_bytes(blob).expect("decode Image");
            let ep: u8 = $endpoint;

            let built = javm_bench::BuiltCaps::for_image(&image, ep);

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
            g.bench_function("interpreter", |b| b.iter(|| javm_bench::run_interpreter(&built)));
            g.bench_function("recompiler", |b| b.iter(|| javm_bench::run_recompiler(&built)));
            g.finish();
        }
    };
}

bench_workload!(goldilocks_mul, "GOLDILOCKS_MUL_BLOB", 0);
bench_workload!(poseidon2_perm, "POSEIDON2_PERM_BLOB", 0);
bench_workload!(mini_verifier, "MINI_VERIFIER_BLOB", 0);
bench_workload!(poly_eval, "POLY_EVAL_BLOB", 0);
bench_workload!(fri_fold_tree, "FRI_FOLD_TREE_BLOB", 0);

criterion_group!(
    benches,
    goldilocks_mul,
    poseidon2_perm,
    mini_verifier,
    poly_eval,
    fri_fold_tree,
);
criterion_main!(benches);
