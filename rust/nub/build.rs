//! Cross-compile the `javm-guest-x86` guest crate for
//! `x86_64-unknown-none` and expose the ELF paths to the host binary
//! via env vars.
//!
//! - Production blob: always built. Exposed as `NUB_ARCH_X86_BLOB`.
//! - Tests + benches blobs: only built when the `test-support`
//!   feature is on (auto-enabled by the self-referencing dev-dep
//!   in `Cargo.toml`). Exposed as `NUB_ARCH_X86_TESTS_BLOB` and
//!   `NUB_ARCH_X86_BENCHES_BLOB`.

fn main() {
    if std::env::var("BUILD_CRATE_GUEST_BUILD").is_ok() {
        return;
    }
    // Forward `nub`'s features that the guest binary needs to know
    // about. Right now: `heap-diag` enables talc allocation counters
    // + the `nub_heap_stats` guest function.
    let mut features: Vec<&str> = Vec::new();
    if std::env::var("CARGO_FEATURE_HEAP_DIAG").is_ok() {
        features.push("heap-diag");
    }

    let prod = nub_build::build("../javm-guest-x86", "javm-guest-x86", &features);
    println!("cargo:rustc-env=NUB_ARCH_X86_BLOB={}", prod.display());

    if std::env::var("CARGO_FEATURE_TEST_SUPPORT").is_ok() {
        let tests = nub_build::build("../javm-guest-x86", "javm-guest-x86-tests", &features);
        println!("cargo:rustc-env=NUB_ARCH_X86_TESTS_BLOB={}", tests.display());
        let benches = nub_build::build("../javm-guest-x86", "javm-guest-x86-benches", &features);
        println!(
            "cargo:rustc-env=NUB_ARCH_X86_BENCHES_BLOB={}",
            benches.display()
        );
    }

    // The guest blob embeds every crate below; cargo can't see the guest
    // crate's path-deps (separate CARGO_TARGET_DIR build), so register their
    // src trees explicitly. nub_build::build already emits rerun for the
    // guest crate's own src/ + Cargo.toml.
    println!("cargo:rerun-if-changed=../javm-guest-x86/link.x");
    println!("cargo:rerun-if-changed=../nub-arch-x86/src");
    println!("cargo:rerun-if-changed=../nub-arch-x86/Cargo.toml");
    println!("cargo:rerun-if-changed=../javm-recompiler-x86/src");
    println!("cargo:rerun-if-changed=../javm-recompiler-x86/Cargo.toml");
    println!("cargo:rerun-if-changed=../javm-exec/src");
    println!("cargo:rerun-if-changed=../javm-exec/Cargo.toml");
    println!("cargo:rerun-if-changed=../javm-cap/src");
    println!("cargo:rerun-if-changed=../javm-cap/Cargo.toml");
    println!("cargo:rerun-if-changed=../nub-arch-x86-abi/src");
    println!("cargo:rerun-if-changed=../nub-host-common/src");
    println!("cargo:rerun-if-changed=../nub-host-guest-macro/src");
    println!("cargo:rerun-if-changed=../nub-arch-guestbin/src");
}
