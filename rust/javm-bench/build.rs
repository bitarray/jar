//! Cross-compile each bench guest crate for the PVM2 target,
//! transpile to a SSZ-encoded `Image`, and expose the blob path
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
            "../../nub/programs/prime-sieve",
            "bench-prime-sieve",
            "PRIME_SIEVE_BLOB",
        ),
        (
            "../../nub/programs/ed25519",
            "bench-ed25519",
            "ED25519_BLOB",
        ),
        ("../../nub/programs/keccak", "bench-keccak", "KECCAK_BLOB"),
        (
            "../../nub/programs/blake2b",
            "bench-blake2b",
            "BLAKE2B_BLOB",
        ),
        (
            "../../nub/programs/ecrecover",
            "bench-ecrecover",
            "ECRECOVER_BLOB",
        ),
        (
            "../../nub/programs/goldilocks-mul",
            "bench-goldilocks-mul",
            "GOLDILOCKS_MUL_BLOB",
        ),
        (
            "../../nub/programs/poseidon2-perm",
            "bench-poseidon2-perm",
            "POSEIDON2_PERM_BLOB",
        ),
        (
            "../../nub/programs/mini-verifier",
            "bench-mini-verifier",
            "MINI_VERIFIER_BLOB",
        ),
        (
            "../../nub/programs/poly-eval",
            "bench-poly-eval",
            "POLY_EVAL_BLOB",
        ),
        (
            "../../nub/programs/fri-fold-tree",
            "bench-fri-fold-tree",
            "FRI_FOLD_TREE_BLOB",
        ),
        (
            "../../components/benches/sub-vm-recurse",
            "bench-sub-vm-recurse",
            "SUB_VM_RECURSE_BLOB",
        ),
        (
            "../../components/benches/sub-vm-data-recurse",
            "bench-sub-vm-data-recurse",
            "SUB_VM_DATA_RECURSE_BLOB",
        ),
        (
            "../../components/benches/pt-cache",
            "bench-pt-cache",
            "PT_CACHE_BLOB",
        ),
        (
            "../../components/tests/sub-vm-reread-recurse",
            "test-sub-vm-reread-recurse",
            "SUB_VM_REREAD_RECURSE_BLOB",
        ),
    ] {
        let blob = build_javm::build(path, crate_name);
        println!("cargo:rustc-env={env}={}", blob.display());
        println!("cargo:rerun-if-changed={path}/src");
        println!("cargo:rerun-if-changed={path}/Cargo.toml");
    }
}
