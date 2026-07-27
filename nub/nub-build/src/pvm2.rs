//! build.rs helper: cross-compile a guest crate for the PVM2 target and
//! link it into a runnable program.
//!
//! Two entry points, deliberately split:
//!
//! - [`build_elf`] stops at the RV64EMC ELF. A personality that wants
//!   its own container (JAVM wraps the blob in a cap `Image`) calls
//!   this and links the ELF itself.
//! - [`build`] goes all the way to a `.nubp` [`ProgramBlob`] file.
//!
//! The target is `riscv64emc-pvm2`: RV64 embedded (16 registers) with
//! compressed, M, and the Zbb/Zba/Zbs/Zicond/Zicclsm extensions, no
//! atomics, `panic=abort`, PIE. It is a custom target JSON, so the
//! guest build needs `-Zbuild-std` and therefore `RUSTC_BOOTSTRAP=1` —
//! which `build_crate::GuestBuild` sets.
//!
//! [`ProgramBlob`]: nub_program::ProgramBlob

use std::path::PathBuf;

use build_crate::{BuildKind, GuestBuild};

/// PVM2 target spec: RV64EMC + Zbb/Zba/Zbs/Zicond/Zicclsm.
const TARGET_JSON: &str = include_str!("riscv64emc-pvm2.json");
const TARGET_NAME: &str = "riscv64emc-pvm2";
/// File extension for a serialized [`nub_program::ProgramBlob`].
const BLOB_EXT: &str = "nubp";

/// Emit `cargo:rerun-if-changed` for the linker and program-format
/// sources.
///
/// Cargo does re-run a build script when its own executable changes,
/// which covers these transitively — but the coupling is load-bearing
/// enough (a linker change rewrites every blob, and blobs feed pinned
/// gas vectors) to state explicitly.
fn watch_linker_sources() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let nub_dir = PathBuf::from(&manifest_dir)
        .parent()
        .expect("nub-build must live inside nub/")
        .to_path_buf();
    build_crate::emit_rerun_for_dir(&nub_dir.join("nub-linker/src"));
    build_crate::emit_rerun_for_dir(&nub_dir.join("nub-program/src"));
}

/// Cross-compile `bin_name` in `manifest_dir` for `riscv64emc-pvm2` and
/// return the path to the resulting ELF.
///
/// `manifest_dir` is relative to the calling `build.rs`'s
/// `CARGO_MANIFEST_DIR`.
pub fn build_elf(manifest_dir: &str, bin_name: &str) -> PathBuf {
    watch_linker_sources();

    let resolved = build_crate::resolve_manifest_dir(manifest_dir);
    let target_json_path = build_crate::write_target_json("riscv64emc-pvm2.json", TARGET_JSON);

    let guest = GuestBuild {
        manifest_dir: resolved,
        target_json_path,
        target_dir_name: TARGET_NAME.to_string(),
        build_kind: BuildKind::Bin(bin_name.to_string()),
        // Guests are small and hot; a raised inline threshold buys real
        // PVM2 instruction-count reductions. Changing it changes every
        // blob, hence every pinned gas vector.
        extra_rustflags: vec!["-Cllvm-args=--inline-threshold=265".to_string()],
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

    guest.build()
}

/// Cross-compile and link `bin_name` into `$OUT_DIR/<bin_name>.nubp`,
/// returning the blob path.
///
/// Honours `SKIP_GUEST_BUILD` by writing an empty placeholder — CI uses
/// it for jobs that only need the workspace to compile.
pub fn build(manifest_dir: &str, bin_name: &str) -> PathBuf {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let blob_path = PathBuf::from(&out_dir).join(format!("{bin_name}.{BLOB_EXT}"));

    if std::env::var("SKIP_GUEST_BUILD").is_ok() {
        if !blob_path.exists() {
            std::fs::write(&blob_path, b"").ok();
        }
        return blob_path;
    }

    let elf_path = build_elf(manifest_dir, bin_name);
    let elf_data = std::fs::read(&elf_path).expect("failed to read guest ELF");
    let program = nub_linker::link_elf(&elf_data).expect("failed to link guest ELF");
    std::fs::write(&blob_path, program.to_bytes()).expect("failed to write program blob");
    blob_path
}
