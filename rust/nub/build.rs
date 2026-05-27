//! Cross-compile `nub-arch-x86` for `x86_64-unknown-none` and
//! expose the ELF paths to the host binary via env vars.
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

    let prod = nub_build::build("../nub-arch-x86", "nub-arch-x86", &features);
    println!("cargo:rustc-env=NUB_ARCH_X86_BLOB={}", prod.display());

    if std::env::var("CARGO_FEATURE_TEST_SUPPORT").is_ok() {
        let tests = nub_build::build("../nub-arch-x86", "nub-arch-x86-tests", &features);
        println!(
            "cargo:rustc-env=NUB_ARCH_X86_TESTS_BLOB={}",
            tests.display()
        );
        let benches = nub_build::build("../nub-arch-x86", "nub-arch-x86-benches", &features);
        println!(
            "cargo:rustc-env=NUB_ARCH_X86_BENCHES_BLOB={}",
            benches.display()
        );
    }

    println!("cargo:rerun-if-changed=../nub-arch-x86/src");
    println!("cargo:rerun-if-changed=../nub-arch-x86/Cargo.toml");
    println!("cargo:rerun-if-changed=../nub-arch-x86/link.x");
    // nub-arch-x86 embeds javm-recompiler-x86 and javm-exec; its build
    // script doesn't know about path-deps via cargo metadata, so register
    // their src trees here explicitly. Without this, changes to the
    // recompiler or exec layer don't trigger a guest blob rebuild and the
    // cached blob goes stale (e.g. gas-cost tweaks in javm-exec wouldn't
    // appear in bench numbers).
    println!("cargo:rerun-if-changed=../javm-recompiler-x86/src");
    println!("cargo:rerun-if-changed=../javm-recompiler-x86/Cargo.toml");
    println!("cargo:rerun-if-changed=../javm-exec/src");
    println!("cargo:rerun-if-changed=../javm-exec/Cargo.toml");
}
