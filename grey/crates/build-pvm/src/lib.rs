use std::path::PathBuf;

use build_crate::{BuildKind, GuestBuild};

const TARGET_JSON: &str = include_str!("riscv64emac-polkavm.json");
const TARGET_NAME: &str = "riscv64emac-polkavm";

/// Build a PolkaVM blob from a service crate.
///
/// - `manifest_dir`: path to the service crate, relative to `CARGO_MANIFEST_DIR`
///
/// Returns the absolute path to the output `.polkavm` blob file.
///
/// The blob is ready to use with `polkavm::Module::new()`.
pub fn build(manifest_dir: &str) -> PathBuf {
    build_with_options(manifest_dir, 65536)
}

/// Build a PolkaVM blob with a custom minimum stack size.
pub fn build_with_options(manifest_dir: &str, min_stack_size: u32) -> PathBuf {
    let resolved = build_crate::resolve_manifest_dir(manifest_dir);

    // Derive blob name from the crate directory name
    let crate_name = resolved.file_name().unwrap().to_str().unwrap().to_string();
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let blob_path = PathBuf::from(&out_dir).join(format!("{crate_name}.polkavm"));

    if std::env::var("SKIP_GUEST_BUILD").is_ok() {
        if !blob_path.exists() {
            std::fs::write(&blob_path, b"").ok();
        }
        return blob_path;
    }

    let target_json_path = build_crate::write_target_json("riscv64emac-polkavm.json", TARGET_JSON);

    let guest = GuestBuild {
        manifest_dir: resolved,
        target_json_path,
        target_dir_name: TARGET_NAME.to_string(),
        build_kind: BuildKind::Lib,
        extra_rustflags: vec![
            "-Zunstable-options".to_string(),
            "-Cpanic=immediate-abort".to_string(),
        ],
        env_overrides: vec![(
            "CARGO_PROFILE_RELEASE_STRIP".to_string(),
            "false".to_string(),
        )],
        rustc_bootstrap: true,
    };

    let elf_path = guest.build();
    let elf_data = std::fs::read(&elf_path).expect("failed to read ELF");

    let mut config = polkavm_linker::Config::default();
    config.set_strip(true);
    config.set_min_stack_size(min_stack_size);
    let blob = polkavm_linker::program_from_elf(
        config,
        polkavm_linker::TargetInstructionSet::JamV1,
        &elf_data,
    )
    .expect("failed to link ELF to PolkaVM blob");

    std::fs::write(&blob_path, &blob).expect("failed to write PolkaVM blob");
    blob_path
}
