//! Cross-compile this crate's `main.rs` for the JAVM target, transpile
//! to a SCALE-encoded `Image`, and expose the blob path to the
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
}
