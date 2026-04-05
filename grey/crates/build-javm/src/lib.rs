use std::path::PathBuf;

use build_crate::{BuildKind, GuestBuild};

const TARGET_JSON: &str = include_str!("riscv64em-javm.json");
const TARGET_NAME: &str = "riscv64em-javm";

/// Emit `cargo:rerun-if-changed` for transpiler + javm sources so the blob
/// is rebuilt when the transpiler or PVM format changes.
fn watch_transpiler_sources() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let crates_dir = PathBuf::from(&manifest_dir)
        .parent()
        .expect("build-javm must be inside crates/")
        .to_path_buf();

    // Watch transpiler source (affects blob encoding)
    build_crate::emit_rerun_for_dir(&crates_dir.join("grey-transpiler/src"));
    // Watch javm program (affects blob format)
    let javm_src = crates_dir.join("javm/src");
    println!(
        "cargo:rerun-if-changed={}",
        javm_src.join("program.rs").display()
    );
}

/// Build a PVM blob from a service crate (standard program, single entry point).
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
    let target_json_path = build_crate::write_target_json("riscv64em-javm.json", TARGET_JSON);

    let extra_rustflags = vec!["-Cllvm-args=--inline-threshold=275".to_string()];
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
    let blob =
        grey_transpiler::link_elf(&elf_data).expect("failed to transpile ELF to v2 PVM blob");

    std::fs::write(&blob_path, &blob).expect("failed to write PVM blob");
    blob_path
}

/// Build a PVM service blob (single entrypoint, size-optimized profile).
pub fn build_service(manifest_dir: &str, bin_name: &str) -> PathBuf {
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
    let target_json_path = build_crate::write_target_json("riscv64em-javm.json", TARGET_JSON);

    let extra_rustflags = vec!["-Cllvm-args=--inline-threshold=275".to_string()];
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
                "s".to_string(),
            ),
            ("CARGO_PROFILE_RELEASE_LTO".to_string(), "false".to_string()),
        ],
        rustc_bootstrap: true,
    };

    let elf_path = guest.build();
    let elf_data = std::fs::read(&elf_path).expect("failed to read ELF");
    let blob =
        grey_transpiler::link_elf(&elf_data).expect("failed to transpile ELF to v2 PVM blob");

    std::fs::write(&blob_path, &blob).expect("failed to write PVM blob");
    blob_path
}
