//! Cross-compile `nub-arch-x86` for `x86_64-unknown-none` and
//! expose the ELF path to the host binary via the
//! `NUB_ARCH_X86_BLOB` environment variable.

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
    let elf = nub_build::build("../nub-arch-x86", "nub-arch-x86", &features);
    println!("cargo:rustc-env=NUB_ARCH_X86_BLOB={}", elf.display());
    println!("cargo:rerun-if-changed=../nub-arch-x86/src");
    println!("cargo:rerun-if-changed=../nub-arch-x86/Cargo.toml");
    println!("cargo:rerun-if-changed=../nub-arch-x86/link.x");
}
