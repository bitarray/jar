//! Cross-compile the simple-chain example for the JAVM target,
//! transpile it to a SCALE-encoded `Image`, and expose the blob
//! path to the integration test via the `SIMPLE_CHAIN_BLOB`
//! environment variable.
//!
//! Mirrors `rust/javm-guest-tests/build.rs`. The
//! `BUILD_CRATE_GUEST_BUILD` env-var guard prevents infinite
//! recursion when `build-crate` re-invokes cargo for the guest
//! target.

fn main() {
    if std::env::var("BUILD_CRATE_GUEST_BUILD").is_ok() {
        return;
    }
    let blob = build_javm::build_pvm2("../../components/examples/simple-chain", "simple-chain");
    println!("cargo:rustc-env=SIMPLE_CHAIN_BLOB={}", blob.display());
    println!("cargo:rerun-if-changed=../../components/examples/simple-chain/src/main.rs");
    println!("cargo:rerun-if-changed=../../components/examples/simple-chain/src/lib.rs");
    println!("cargo:rerun-if-changed=../../components/examples/simple-chain/Cargo.toml");
}
