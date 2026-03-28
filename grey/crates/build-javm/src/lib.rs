use std::path::PathBuf;

use build_crate::{BuildKind, GuestBuild};

const TARGET_JSON: &str = include_str!("riscv64em-javm.json");
const TARGET_NAME: &str = "riscv64em-javm";

/// Build a Grey PVM blob from a service crate (standard program, single entry point).
///
/// - `manifest_dir`: path to the service crate, relative to `CARGO_MANIFEST_DIR`
/// - `bin_name`: binary target name in the service crate
///
/// Returns the absolute path to the output `.pvm` blob file.
///
/// The blob is ready to use with `javm::program::initialize_program()`.
pub fn build(manifest_dir: &str, bin_name: &str) -> PathBuf {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let blob_path = PathBuf::from(&out_dir).join(format!("{bin_name}.pvm"));

    if std::env::var("SKIP_GUEST_BUILD").is_ok() {
        if !blob_path.exists() {
            std::fs::write(&blob_path, b"").ok();
        }
        return blob_path;
    }

    let resolved = build_crate::resolve_manifest_dir(manifest_dir);
    let target_json_path = build_crate::write_target_json("riscv64em-javm.json", TARGET_JSON);

    // Pass LLVM flags to encourage aggressive inlining and unrolling.
    // More inlining → fewer function calls → fewer jump table entries →
    // fewer gas block transitions in the recompiler → faster compile+exec.
    let extra_rustflags = vec!["-Cllvm-args=--inline-threshold=275".to_string()];
    let guest = GuestBuild {
        manifest_dir: resolved,
        target_json_path,
        target_dir_name: TARGET_NAME.to_string(),
        build_kind: BuildKind::Bin(bin_name.to_string()),
        extra_rustflags,
        env_overrides: vec![],
        rustc_bootstrap: true,
    };

    let elf_path = guest.build();
    let elf_data = std::fs::read(&elf_path).expect("failed to read ELF");
    let blob = grey_transpiler::link_elf(&elf_data).expect("failed to transpile ELF to PVM blob");

    std::fs::write(&blob_path, &blob).expect("failed to write PVM blob");
    blob_path
}

/// Build a Grey PVM blob from a service crate (service program with refine + accumulate).
///
/// Same as [`build`] but uses `link_elf_service` which produces a blob with
/// dual entry points (refine at PC=0, accumulate at PC=5).
pub fn build_service(manifest_dir: &str, bin_name: &str) -> PathBuf {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let blob_path = PathBuf::from(&out_dir).join(format!("{bin_name}.pvm"));

    if std::env::var("SKIP_GUEST_BUILD").is_ok() {
        if !blob_path.exists() {
            std::fs::write(&blob_path, b"").ok();
        }
        return blob_path;
    }

    let resolved = build_crate::resolve_manifest_dir(manifest_dir);
    let target_json_path = build_crate::write_target_json("riscv64em-javm.json", TARGET_JSON);

    let extra_rustflags = vec!["-Cllvm-args=--inline-threshold=275".to_string()];
    let guest = GuestBuild {
        manifest_dir: resolved,
        target_json_path,
        target_dir_name: TARGET_NAME.to_string(),
        build_kind: BuildKind::Bin(bin_name.to_string()),
        extra_rustflags,
        env_overrides: vec![],
        rustc_bootstrap: true,
    };

    let elf_path = guest.build();
    let elf_data = std::fs::read(&elf_path).expect("failed to read ELF");
    let blob = grey_transpiler::link_elf_service(&elf_data)
        .expect("failed to transpile ELF to PVM service blob");

    std::fs::write(&blob_path, &blob).expect("failed to write PVM blob");
    blob_path
}
