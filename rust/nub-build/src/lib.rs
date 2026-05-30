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

    // Custom linker script. Adjacent to the guest crate's `src/`.
    let link_script = manifest_dir.join("link.x");
    let link_script_arg = format!("-Clink-args=-T{}", link_script.display());
    // The guest is a PIE (DYN ELF) linked at VA 0. The host loader
    // (`nub-host-kvm/src/mem/elf.rs::load_at`) patches each
    // `R_X86_64_RELATIVE` entry with `runtime_base_va + addend`, where
    // `runtime_base_va = guest_va_base() + KERNEL_OFFSET` from
    // `nub-host-common::layout` — env-overridable on Linux, dynamic
    // on macOS. So the kernel boots wherever the host reserves the
    // per-process GUEST_VA range, no hardcoded link base required.
    let rustflags = [
        "--cfg=hyperlight",
        "--check-cfg=cfg(hyperlight)",
        "-Clink-args=-eentrypoint",
        // Force PIE output (DYN ELF) so absolute references emit
        // `R_X86_64_RELATIVE` entries the host can patch at load
        // time with the runtime base GVA. Without `-pie`, lld
        // produces an EXEC binary with statically-resolved (to 0)
        // absolute references, which would dereference garbage at
        // runtime once mapped at a non-zero kernel base.
        "-Clink-args=-pie",
        link_script_arg.as_str(),
        // PIC (not static): the linker -pie flag produces a DYN ELF
        // with `R_X86_64_RELATIVE` entries for absolute references;
        // the compiler must agree by emitting PIC-style code (so
        // text-segment relocations can be rewritten as RELATIVE).
        "-Crelocation-model=pic",
        // x86_64-unknown-none defaults to the `kernel` code model,
        // which assumes the kernel sits in the high-half
        // (`0xFFFF_FFFF_8000_0000+`) where R_X86_64_32S sign-extension
        // does the right thing. We load the guest at a low-half VA
        // (typically `0x5001_4000_0000`), which is too far above 2 GiB
        // for the small/kernel models — switch to `large` to emit
        // 64-bit absolute relocations everywhere (the linker rewrites
        // them as `R_X86_64_RELATIVE` in the PIE output).
        "-Ccode-model=large",
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
        // NOTE: enabling LTO here (`--config profile.release.lto=…`) fails:
        // the guest forces `-Ccode-model=large` (it loads at a low-half GVA,
        // too far above 2 GiB for the default `kernel` model), but the
        // *precompiled* `core`/`alloc` use the target-default `kernel`
        // model, and LTO (fat *and* thin) refuses to merge modules with
        // conflicting `Code Model` flags (`i32 4` vs `i32 2`). Making LTO
        // work would require rebuilding std with the matching code model via
        // `-Zbuild-std`, i.e. a nightly toolchain (or `RUSTC_BOOTSTRAP=1`) —
        // a departure from this crate's deliberate stable / no-build-std
        // design. Left disabled pending that decision.
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
