fn main() {
    // Don't recurse: build-crate sets JAVM_GUEST_BUILD when spawning guest builds.
    if std::env::var("BUILD_CRATE_GUEST_BUILD").is_ok() {
        return;
    }

    let blob = build_javm::build(".", "javm-guest-tests");
    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(
        format!("{out_dir}/guest_blob.rs"),
        format!(
            "const GUEST_TESTS_BLOB: &[u8] = include_bytes!(\"{}\");\n",
            blob.display(),
        ),
    )
    .unwrap();
}
