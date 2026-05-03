//! Build the simple-chain PVM blob and expose its path to integration
//! tests.

fn main() {
    let blob = build_javm::build_service("../../components/examples/simple-chain", "simple-chain");
    println!("cargo:rustc-env=SIMPLE_CHAIN_BLOB_PATH={}", blob.display());
}
