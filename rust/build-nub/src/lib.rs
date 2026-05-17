//! build.rs helper: cross-compile a hyperlight guest crate for the
//! stable bare-metal target `x86_64-unknown-none` and return the
//! path to the resulting ELF.
//!
//! Modeled on `build-javm`, but with two simplifications:
//!
//! 1. **No custom target JSON.** We use the upstream stable target
//!    `x86_64-unknown-none` (shipped since Rust 1.71). The
//!    `core`/`alloc`/`compiler_builtins` come pre-built; no
//!    `-Zbuild-std` needed.
//!
//! 2. **No C toolchain.** Hyperlight guests that link picolibc need
//!    a full cross-clang setup (which is why `cargo-hyperlight`
//!    exists). Our guests use `hyperlight-guest-bin` with
//!    `default-features = false`, dropping the picolibc dependency
//!    entirely — pure Rust, no cc-rs, no bindgen.
//!
//! What `cargo-hyperlight` does that we replicate as `RUSTFLAGS`:
//!
//! - `--cfg=hyperlight` + `--check-cfg=cfg(hyperlight)` — the
//!   hyperlight guest crates gate some code on this cfg.
//! - `-Clink-args=-eentrypoint` — make the symbol `entrypoint` the
//!   ELF entry point.
//!
//! What `cargo-hyperlight` does that we skip:
//!
//! - Building the sysroot (`-Zbuild-std`) — unnecessary for stable
//!   `x86_64-unknown-none`.
//! - Setting `CC_…`, `AR_…`, `CFLAGS_…` — unnecessary without C.

use std::path::PathBuf;
use std::process::Command;

const TARGET_TRIPLE: &str = "x86_64-unknown-none";

/// Cross-compile a hyperlight guest crate. Returns the path to the
/// resulting ELF binary, suitable for `include_bytes!` or for
/// passing to `hyperlight_host::GuestBinary::FilePath`.
///
/// `manifest_dir` is relative to the calling `build.rs`'s
/// `CARGO_MANIFEST_DIR`. `bin_name` is the `[[bin]]` name to build.
///
/// Emits `cargo:rerun-if-changed` for the guest crate's `src/` and
/// `Cargo.toml`, plus `cargo:rerun-if-env-changed` for
/// `SKIP_GUEST_BUILD`. Respects the `BUILD_CRATE_GUEST_BUILD` env
/// var as a recursion guard (mirrors `build-javm`).
pub fn build(manifest_dir: &str, bin_name: &str) -> PathBuf {
    let manifest_dir = build_crate::resolve_manifest_dir(manifest_dir);
    let manifest_path = manifest_dir.join("Cargo.toml");

    build_crate::emit_rerun_for_dir(&manifest_dir.join("src"));
    println!("cargo:rerun-if-changed={}", manifest_path.display());
    println!("cargo:rerun-if-env-changed=SKIP_GUEST_BUILD");

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let target_dir = PathBuf::from(&out_dir).join("nub-guest-build");
    let elf_path = target_dir
        .join(TARGET_TRIPLE)
        .join("release")
        .join(bin_name);

    if std::env::var("SKIP_GUEST_BUILD").is_ok() && elf_path.exists() {
        return elf_path;
    }

    let rustflags = [
        "--cfg=hyperlight",
        "--check-cfg=cfg(hyperlight)",
        "-Clink-args=-eentrypoint",
        // Smallest valid panic strategy for no_std bin
        "-Cpanic=abort",
    ]
    .join("\x1f");

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cmd = Command::new(cargo);
    cmd.arg("build")
        .arg("--release")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .arg("--target")
        .arg(TARGET_TRIPLE)
        .arg("--bin")
        .arg(bin_name)
        .env("CARGO_TARGET_DIR", &target_dir)
        .env("BUILD_CRATE_GUEST_BUILD", "1")
        .env("CARGO_ENCODED_RUSTFLAGS", rustflags);

    let output = cmd.output().expect("failed to spawn cargo for nub-guest");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!(
            "nub-guest build failed for {}:\n--- stderr ---\n{}\n--- stdout ---\n{}",
            manifest_dir.display(),
            stderr,
            stdout
        );
    }

    assert!(
        elf_path.exists(),
        "Expected ELF artifact not found at: {}",
        elf_path.display()
    );
    elf_path
}
