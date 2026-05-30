//! Cross-compile this crate's `main.rs` for the JAVM target, transpile
//! to a SSZ-encoded `Image`, and expose the blob path to the
//! integration test via the `GUEST_TESTS_BLOB` environment variable.
//!
//! Mirrors `rust/jar-kernel/build.rs`. The `BUILD_CRATE_GUEST_BUILD`
//! env-var guard prevents infinite recursion when `build-crate`
//! re-invokes cargo for the guest target.

fn main() {
    if std::env::var("BUILD_CRATE_GUEST_BUILD").is_ok() {
        return;
    }

    let blob = build_javm::build(".", "javm-guest-tests");
    println!("cargo:rustc-env=GUEST_TESTS_BLOB={}", blob.display());
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/main.rs");
    println!("cargo:rerun-if-changed=src/tests");
    println!("cargo:rerun-if-changed=Cargo.toml");

    // Sub-VM lifecycle test guests. The `tests/sub_vm.rs`
    // integration test publishes both Images, derives M's child
    // Instance, CALLs S, and asserts the round-trip.
    for (path, crate_name, env) in [
        (
            "../../components/tests/spawn-parent-m",
            "spawn-parent-m",
            "SPAWN_PARENT_M_BLOB",
        ),
        (
            "../../components/tests/spawn-child-s",
            "spawn-child-s",
            "SPAWN_CHILD_S_BLOB",
        ),
    ] {
        let blob = build_javm::build(path, crate_name);
        println!("cargo:rustc-env={env}={}", blob.display());
        println!("cargo:rerun-if-changed={path}/src");
        println!("cargo:rerun-if-changed={path}/Cargo.toml");
    }
}
