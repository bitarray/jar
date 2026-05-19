//! Cross-compile each bench guest crate for the JAVM target,
//! transpile to a SCALE-encoded `Image`, and expose the blob path
//! to `benches/pvm_bench.rs` via per-guest environment variables.
//!
//! Mirrors `rust/jar-kernel/build.rs`, repeated once per guest. The
//! `BUILD_CRATE_GUEST_BUILD` env-var guard prevents infinite
//! recursion when `build-crate` re-invokes cargo for the guest
//! target.

fn main() {
    if std::env::var("BUILD_CRATE_GUEST_BUILD").is_ok() {
        return;
    }
    for (path, crate_name, env) in [
        (
            "../../components/benches/prime-sieve",
            "bench-prime-sieve",
            "PRIME_SIEVE_BLOB",
        ),
        (
            "../../components/benches/ed25519",
            "bench-ed25519",
            "ED25519_BLOB",
        ),
        (
            "../../components/benches/keccak",
            "bench-keccak",
            "KECCAK_BLOB",
        ),
        (
            "../../components/benches/blake2b",
            "bench-blake2b",
            "BLAKE2B_BLOB",
        ),
        (
            "../../components/benches/ecrecover",
            "bench-ecrecover",
            "ECRECOVER_BLOB",
        ),
        (
            "../../components/benches/goldilocks-mul",
            "bench-goldilocks-mul",
            "GOLDILOCKS_MUL_BLOB",
        ),
        (
            "../../components/benches/poseidon2-perm",
            "bench-poseidon2-perm",
            "POSEIDON2_PERM_BLOB",
        ),
        (
            "../../components/benches/mini-verifier",
            "bench-mini-verifier",
            "MINI_VERIFIER_BLOB",
        ),
    ] {
        let blob = build_javm::build(path, crate_name);
        println!("cargo:rustc-env={env}={}", blob.display());
        println!("cargo:rerun-if-changed={path}/src");
        println!("cargo:rerun-if-changed={path}/Cargo.toml");
    }
}
