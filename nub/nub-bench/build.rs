//! Cross-compile and link every program in `nub/programs`, exposing
//! each blob's path as a `<NAME>_BLOB` env var for `include_bytes!`.

/// `(crate directory, `[[bin]]` name, env var)` for every program.
const PROGRAMS: &[(&str, &str, &str)] = &[
    (
        "../programs/prime-sieve",
        "bench-prime-sieve",
        "PRIME_SIEVE",
    ),
    ("../programs/ed25519", "bench-ed25519", "ED25519"),
    ("../programs/keccak", "bench-keccak", "KECCAK"),
    ("../programs/blake2b", "bench-blake2b", "BLAKE2B"),
    ("../programs/ecrecover", "bench-ecrecover", "ECRECOVER"),
    (
        "../programs/goldilocks-mul",
        "bench-goldilocks-mul",
        "GOLDILOCKS_MUL",
    ),
    (
        "../programs/poseidon2-perm",
        "bench-poseidon2-perm",
        "POSEIDON2_PERM",
    ),
    (
        "../programs/mini-verifier",
        "bench-mini-verifier",
        "MINI_VERIFIER",
    ),
    ("../programs/poly-eval", "bench-poly-eval", "POLY_EVAL"),
    (
        "../programs/fri-fold-tree",
        "bench-fri-fold-tree",
        "FRI_FOLD_TREE",
    ),
];

fn main() {
    // Recursion guard: this build script runs cargo, and the inner
    // cargo would otherwise re-enter it.
    if std::env::var("BUILD_CRATE_GUEST_BUILD").is_ok() {
        return;
    }

    for (dir, bin, var) in PROGRAMS {
        let blob = nub_build::pvm2::build(dir, bin);
        println!("cargo:rustc-env={var}_BLOB={}", blob.display());
    }

    // The flat personality's guest kernel: a bare-metal x86-64 ELF that
    // boots in the KVM sandbox and drives the JIT. This is what makes
    // the recompiler *executable* here rather than only measurable at
    // emission time.
    let flat_guest = nub_build::build("../nub-flat-guest-x86", "nub-flat-guest-x86", &[]);
    println!(
        "cargo:rustc-env=NUB_FLAT_GUEST_BLOB={}",
        flat_guest.display()
    );
    // The guest blob embeds these; cargo cannot see them through the
    // guest build's separate target dir.
    for dir in [
        "../nub-flat-guest-x86",
        "../nub-flat",
        "../nub-arch-x86",
        "../nub-arch-x86-abi",
        "../nub-recompiler-x86",
        "../nub-exec",
        "../nub-program",
        "../nub-arch-guestbin",
        "../nub-host-common",
        "../nub-host-guest-macro",
    ] {
        println!("cargo:rerun-if-changed={dir}/src");
        println!("cargo:rerun-if-changed={dir}/Cargo.toml");
    }
    println!("cargo:rerun-if-changed=../nub-flat-guest-x86/link.x");

    // The shared field/permutation library every STARK-shaped program
    // links; cargo cannot see it through the guest build's separate
    // target dir.
    println!("cargo:rerun-if-changed=../programs/goldilocks-poseidon2/src");
    println!("cargo:rerun-if-changed=../programs/goldilocks-poseidon2/Cargo.toml");
}
