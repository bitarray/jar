fn main() {
    let sample =
        build_javm::build_service("../../services/samples/sample-service", "sample-service");
    let pixels = build_javm::build_service("../../services/pixels-service", "pixels-service");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(
        format!("{out_dir}/service_blobs.rs"),
        format!(
            "const SAMPLE_SERVICE_BLOB: &[u8] = include_bytes!(\"{}\");\n\
             const PIXELS_SERVICE_BLOB: &[u8] = include_bytes!(\"{}\");\n",
            build_javm::include_path(&sample),
            build_javm::include_path(&pixels),
        ),
    )
    .unwrap();
}
