//! build.rs helper: cross-compile a nub bare-metal Arch guest crate
//! for a stable bare-metal target (today: `x86_64-unknown-none`) and
//! return the path to the resulting ELF.
//!
//! Today's only consumer is `nub-arch-x86`. As we add more
//! bare-metal Arch backends (e.g. an arm/riscv guest), they live here
//! too — this crate owns the cross-compile recipe for all of nub's
//! bare-metal arch guests.
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
/// `features` is forwarded to cargo as `--features <comma-joined>`;
/// pass `&[]` for no extras.
///
/// Emits `cargo:rerun-if-changed` for the guest crate's `src/` and
/// `Cargo.toml`, plus `cargo:rerun-if-env-changed` for
/// `SKIP_GUEST_BUILD`. Respects the `BUILD_CRATE_GUEST_BUILD` env
/// var as a recursion guard (mirrors `build-javm`).
pub fn build(manifest_dir: &str, bin_name: &str, features: &[&str]) -> PathBuf {
    let manifest_dir = build_crate::resolve_manifest_dir(manifest_dir);
    let manifest_path = manifest_dir.join("Cargo.toml");

    build_crate::emit_rerun_for_dir(&manifest_dir.join("src"));
    println!("cargo:rerun-if-changed={}", manifest_path.display());
    println!("cargo:rerun-if-env-changed=SKIP_GUEST_BUILD");

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let target_dir = PathBuf::from(&out_dir).join("nub-arch-guest-build");
    let elf_path = target_dir
        .join(TARGET_TRIPLE)
        .join("release")
        .join(bin_name);

    if std::env::var("SKIP_GUEST_BUILD").is_ok() && elf_path.exists() {
        return elf_path;
    }

    // Custom linker script placing the kernel at the high "negative
    // 2 GiB" VA. Adjacent to the guest crate's `src/`.
    let link_script = manifest_dir.join("link.x");
    let link_script_arg = format!("-Clink-args=-T{}", link_script.display());
    // Non-PIE: with a fixed link base we don't need relocations, and
    // R_X86_64_RELATIVE entries from a PIE binary would carry the
    // wrong runtime address (the host applies them against the GPA
    // load_addr, not the high GVA).
    let rustflags = [
        "--cfg=hyperlight",
        "--check-cfg=cfg(hyperlight)",
        "-Clink-args=-eentrypoint",
        link_script_arg.as_str(),
        "-Crelocation-model=static",
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
    if !features.is_empty() {
        cmd.arg("--features").arg(features.join(","));
    }

    let output = cmd
        .output()
        .expect("failed to spawn cargo for nub arch guest");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!(
            "nub arch guest build failed for {}:\n--- stderr ---\n{}\n--- stdout ---\n{}",
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
