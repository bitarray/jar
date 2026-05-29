use std::path::PathBuf;

use build_crate::{BuildKind, GuestBuild};
use ssz::Encode;

/// PVM2 target spec: RV64EM+C+Zba+Zbs+Zicond. Used by [`build`].
const TARGET_JSON: &str = include_str!("riscv64emc-pvm2.json");
const TARGET_NAME: &str = "riscv64emc-pvm2";

/// Emit `cargo:rerun-if-changed` for transpiler + javm sources so the blob
/// is rebuilt when the transpiler or PVM format changes.
fn watch_transpiler_sources() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let crates_dir = PathBuf::from(&manifest_dir)
        .parent()
        .expect("build-javm must be inside crates/")
        .to_path_buf();

    build_crate::emit_rerun_for_dir(&crates_dir.join("javm-transpiler/src"));
}

/// Build a PVM2 blob from a service crate. The guest is built for the
/// RV+C+Zbb+Zba+Zbs+Zicond target and the ELF is linked via
/// [`javm_transpiler::linker::link_elf`] — `Image::code` holds raw
/// RV+C+custom-0 bytes consumed directly by the recompiler / interpreter.
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

    let resolved = build_crate::resolve_manifest_dir(manifest_dir);
    let target_json_path = build_crate::write_target_json("riscv64emc-pvm2.json", TARGET_JSON);

    let extra_rustflags = vec!["-Cllvm-args=--inline-threshold=265".to_string()];
    let guest = GuestBuild {
        manifest_dir: resolved,
        target_json_path,
        target_dir_name: TARGET_NAME.to_string(),
        build_kind: BuildKind::Bin(bin_name.to_string()),
        extra_rustflags,
        extra_rustc_args: vec![],
        env_overrides: vec![
            (
                "CARGO_PROFILE_RELEASE_OPT_LEVEL".to_string(),
                "3".to_string(),
            ),
            ("CARGO_PROFILE_RELEASE_LTO".to_string(), "true".to_string()),
            (
                "CARGO_PROFILE_RELEASE_CODEGEN_UNITS".to_string(),
                "1".to_string(),
            ),
        ],
        rustc_bootstrap: true,
    };

    let elf_path = guest.build();
    let elf_data = std::fs::read(&elf_path).expect("failed to read ELF");
    let image =
        javm_transpiler::linker::link_elf(&elf_data).expect("failed to link ELF to Cap::Image");
    let encoded = image.as_ssz_bytes();

    std::fs::write(&blob_path, &encoded).expect("failed to write Image blob");
    blob_path
}
