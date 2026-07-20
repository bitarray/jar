//! Cross-compile the `javm-guest-x86` guest crate for
//! `x86_64-unknown-none` and expose the ELF paths to the host binary
//! via env vars.
//!
//! - Production blob: always built. Exposed as `JAVM_GUEST_X86_BLOB`.
//! - Tests + benches blobs: only built when the `test-support`
//!   feature is on (auto-enabled by the self-referencing dev-dep
//!   in `Cargo.toml`). Exposed as `JAVM_GUEST_X86_BLOB_TESTS` and
//!   `JAVM_GUEST_X86_BLOB_BENCHES`.

fn main() {
    if std::env::var("BUILD_CRATE_GUEST_BUILD").is_ok() {
        return;
    }
    // Forward `javm`'s features that the guest binary needs to know
    // about. Right now: `heap-diag` enables talc allocation counters
    // + the `nub_heap_stats` guest function.
    let mut features: Vec<&str> = Vec::new();
    if std::env::var("CARGO_FEATURE_HEAP_DIAG").is_ok() {
        features.push("heap-diag");
    }

    let prod = nub_build::build("../javm-guest-x86", "javm-guest-x86", &features);
    println!("cargo:rustc-env=JAVM_GUEST_X86_BLOB={}", prod.display());

    if std::env::var("CARGO_FEATURE_TEST_SUPPORT").is_ok() {
        let tests = nub_build::build("../javm-guest-x86", "javm-guest-x86-tests", &features);
        println!(
            "cargo:rustc-env=JAVM_GUEST_X86_BLOB_TESTS={}",
            tests.display()
        );
        let benches = nub_build::build("../javm-guest-x86", "javm-guest-x86-benches", &features);
        println!(
            "cargo:rustc-env=JAVM_GUEST_X86_BLOB_BENCHES={}",
            benches.display()
        );
    }

    // The guest blob embeds every crate below; cargo can't see the guest
    // crate's path-deps (separate CARGO_TARGET_DIR build), so register their
    // src trees explicitly. nub_build::build already emits rerun for the
    // guest crate's own src/ + Cargo.toml.
    println!("cargo:rerun-if-changed=../javm-guest-x86/link.x");
    println!("cargo:rerun-if-changed=../../nub/nub-arch-x86/src");
    println!("cargo:rerun-if-changed=../../nub/nub-arch-x86/Cargo.toml");
    println!("cargo:rerun-if-changed=../../nub/nub-recompiler-x86/src");
    println!("cargo:rerun-if-changed=../../nub/nub-recompiler-x86/Cargo.toml");
    println!("cargo:rerun-if-changed=../../nub/nub-exec/src");
    println!("cargo:rerun-if-changed=../../nub/nub-exec/Cargo.toml");
    println!("cargo:rerun-if-changed=../javm-cap/src");
    println!("cargo:rerun-if-changed=../javm-cap/Cargo.toml");
    // javm-cap embeds the in-workspace SSZ crates (content hashing /
    // hash_tree_root run guest-side) — an untracked edit here would
    // silently diverge host and guest content hashes.
    println!("cargo:rerun-if-changed=../ssz/src");
    println!("cargo:rerun-if-changed=../ssz/Cargo.toml");
    println!("cargo:rerun-if-changed=../ssz-derive/src");
    println!("cargo:rerun-if-changed=../ssz-derive/Cargo.toml");
    println!("cargo:rerun-if-changed=../../nub/nub-arch-x86-abi/src");
    println!("cargo:rerun-if-changed=../../nub/nub-arch-x86-abi/Cargo.toml");
    println!("cargo:rerun-if-changed=../../nub/nub-host-common/src");
    println!("cargo:rerun-if-changed=../../nub/nub-host-common/Cargo.toml");
    println!("cargo:rerun-if-changed=../../nub/nub-host-guest-macro/src");
    println!("cargo:rerun-if-changed=../../nub/nub-host-guest-macro/Cargo.toml");
    println!("cargo:rerun-if-changed=../../nub/nub-arch-guestbin/src");
    println!("cargo:rerun-if-changed=../../nub/nub-arch-guestbin/Cargo.toml");
    // The guest build resolves through the same workspace: the root
    // manifest's [workspace.dependencies] feed the tracked crates'
    // `workspace = true` deps, and external version bumps land in the
    // shared lockfile. Both change the blob with no tracked src edit.
    println!("cargo:rerun-if-changed=../../Cargo.toml");
    println!("cargo:rerun-if-changed=../../Cargo.lock");
}
