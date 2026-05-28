//! Cross-compile each bench guest crate for the PVM2 target,
//! transpile to a SCALE-encoded `Image`, and expose the blob path
//! to the bench harness + examples via per-guest environment variables.
//!
//! The `BUILD_CRATE_GUEST_BUILD` env-var guard prevents infinite
//! recursion when `build-crate` re-invokes cargo for the guest target.

fn main() {
    if std::env::var("BUILD_CRATE_GUEST_BUILD").is_ok() {
        return;
    }
    for (path, crate_name, env) in [
        (
            "../../components/benches/prime-sieve",
            "bench-prime-sieve",
            "PRIME_SIEVE_PVM2_BLOB",
        ),
        (
            "../../components/benches/ed25519",
            "bench-ed25519",
            "ED25519_PVM2_BLOB",
        ),
        (
            "../../components/benches/keccak",
            "bench-keccak",
            "KECCAK_PVM2_BLOB",
        ),
        (
            "../../components/benches/blake2b",
            "bench-blake2b",
            "BLAKE2B_PVM2_BLOB",
        ),
        (
            "../../components/benches/ecrecover",
            "bench-ecrecover",
            "ECRECOVER_PVM2_BLOB",
        ),
        (
            "../../components/benches/goldilocks-mul",
            "bench-goldilocks-mul",
            "GOLDILOCKS_MUL_PVM2_BLOB",
        ),
        (
            "../../components/benches/poseidon2-perm",
            "bench-poseidon2-perm",
            "POSEIDON2_PERM_PVM2_BLOB",
        ),
        (
            "../../components/benches/mini-verifier",
            "bench-mini-verifier",
            "MINI_VERIFIER_PVM2_BLOB",
        ),
        (
            "../../components/benches/poly-eval",
            "bench-poly-eval",
            "POLY_EVAL_PVM2_BLOB",
        ),
        (
            "../../components/benches/fri-fold-tree",
            "bench-fri-fold-tree",
            "FRI_FOLD_TREE_PVM2_BLOB",
        ),
        (
            "../../components/benches/sub-vm-recurse",
            "bench-sub-vm-recurse",
            "SUB_VM_RECURSE_PVM2_BLOB",
        ),
        (
            "../../components/benches/sub-vm-data-recurse",
            "bench-sub-vm-data-recurse",
            "SUB_VM_DATA_RECURSE_PVM2_BLOB",
        ),
    ] {
        let blob = build_javm::build_pvm2(path, crate_name);
        println!("cargo:rustc-env={env}={}", blob.display());
        println!("cargo:rerun-if-changed={path}/src");
        println!("cargo:rerun-if-changed={path}/Cargo.toml");
    }
}
