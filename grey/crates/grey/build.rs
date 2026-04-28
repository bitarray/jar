fn main() {
    let sample =
        build_javm::build_service("../../services/samples/sample-service", "sample-service");
    let pixels = build_javm::build_service("../../services/pixels-service", "pixels-service");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    // Use forward slashes in the generated include_bytes! paths so the Rust
    // compiler can parse the string literals correctly on all platforms
    // (Windows paths with backslashes would be misinterpreted as escape sequences).
    let sample_str = sample.to_string_lossy().replace('\\', "/");
    let pixels_str = pixels.to_string_lossy().replace('\\', "/");
    std::fs::write(
        format!("{out_dir}/service_blobs.rs"),
        format!(
            "const SAMPLE_SERVICE_BLOB: &[u8] = include_bytes!(\"{sample_str}\");\n\
             const PIXELS_SERVICE_BLOB: &[u8] = include_bytes!(\"{pixels_str}\");\n",
        ),
    )
    .unwrap();
}
