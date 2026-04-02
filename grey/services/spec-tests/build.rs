fn main() {
    let minimal = build_javm::build_service("minimal", "spec-minimal");
    let bootstrap = build_javm::build_service("bootstrap", "spec-bootstrap");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(
        format!("{out_dir}/spec_blobs.rs"),
        format!(
            "const MINIMAL_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const BOOTSTRAP_BLOB: &[u8] = include_bytes!(\"{}\");\n",
            minimal.display(),
            bootstrap.display(),
        ),
    )
    .unwrap();
}
