//! build.rs helper: cross-compile a guest crate and emit a JAVM
//! `Image` blob.
//!
//! The cross-compile is [`nub_build::pvm2::build_elf`]; the JAVM part
//! is the last two lines — wrap the linked program in the cap shape and
//! SSZ-encode it. Consumers `include_bytes!` the returned path.

use std::path::PathBuf;

use ssz::Encode;

/// Emit `cargo:rerun-if-changed` for the cap-wrapping sources, so the
/// blob is rebuilt when the Image format changes. `nub_build::pvm2`
/// watches the linker and program-format sources on its own.
fn watch_transpiler_sources() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let crates_dir = PathBuf::from(&manifest_dir)
        .parent()
        .expect("build-javm must be inside rust/")
        .to_path_buf();

    build_crate::emit_rerun_for_dir(&crates_dir.join("javm-transpiler/src"));
}

/// Build a JAVM `Image` blob from a guest crate, returning the path to
/// the SSZ-encoded `.pvm` file in `OUT_DIR`.
///
/// `Image::code` holds raw RV+C+custom-0 bytes, consumed directly by
/// the recompiler / interpreter.
pub fn build(manifest_dir: &str, bin_name: &str) -> PathBuf {
    watch_transpiler_sources();
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let blob_path = PathBuf::from(&out_dir).join(format!("{bin_name}.pvm"));

    if std::env::var("SKIP_GUEST_BUILD").is_ok() {
        if !blob_path.exists() {
            std::fs::write(&blob_path, b"").ok();
        }
        return blob_path;
    }

    let elf_path = nub_build::pvm2::build_elf(manifest_dir, bin_name);
    let elf_data = std::fs::read(&elf_path).expect("failed to read ELF");
    let image = javm_transpiler::linker::link_elf(&elf_data).expect("failed to link ELF to Image");

    std::fs::write(&blob_path, image.as_ssz_bytes()).expect("failed to write Image blob");
    blob_path
}
