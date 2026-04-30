use std::path::{Path, PathBuf};
use std::process::Command;

/// What kind of artifact to build.
pub enum BuildKind {
    /// Build a binary target: `--bin <name>`.
    Bin(String),
    /// Build a library target: `--lib`.
    Lib,
}

/// Configuration for a guest (cross-compiled) cargo build.
///
/// Spawns a separate `cargo build` subprocess with its own `CARGO_TARGET_DIR`
/// to avoid deadlocking with the outer cargo process running build.rs.
pub struct GuestBuild {
    /// Absolute path to the service crate directory (containing Cargo.toml).
    pub manifest_dir: PathBuf,
    /// Absolute path to the target JSON file.
    pub target_json_path: PathBuf,
    /// Name used as subdirectory in cargo's target dir (e.g. "riscv64em-javm").
    /// This is the directory name cargo creates under `target/` for the custom target.
    pub target_dir_name: String,
    /// Whether to build a binary or library.
    pub build_kind: BuildKind,
    /// Extra flags appended to CARGO_ENCODED_RUSTFLAGS.
    pub extra_rustflags: Vec<String>,
    /// Extra arguments passed to rustc after `--` (e.g. `--crate-type cdylib`).
    /// When non-empty, uses `cargo rustc` instead of `cargo build`.
    pub extra_rustc_args: Vec<String>,
    /// Extra environment variables to set (e.g. CARGO_PROFILE_RELEASE_STRIP=false).
    pub env_overrides: Vec<(String, String)>,
    /// Set RUSTC_BOOTSTRAP=1 so stable rustc accepts -Z flags.
    pub rustc_bootstrap: bool,
}

impl GuestBuild {
    /// Run the inner cargo build. Returns the absolute path to the output ELF.
    ///
    /// Emits `cargo:rerun-if-changed` directives for the service source files
    /// and `cargo:rerun-if-env-changed` for `SKIP_GUEST_BUILD`.
    ///
    /// # Panics
    /// Panics if the build fails or the output artifact is not found.
    pub fn build(&self) -> PathBuf {
        // Emit rerun directives — watch all source files recursively
        emit_rerun_for_dir(&self.manifest_dir.join("src"));
        println!(
            "cargo:rerun-if-changed={}",
            self.manifest_dir.join("Cargo.toml").display()
        );
        println!("cargo:rerun-if-env-changed=SKIP_GUEST_BUILD");

        // Check skip flag
        if std::env::var("SKIP_GUEST_BUILD").is_ok() {
            let elf_path = self.output_elf_path();
            if elf_path.exists() {
                return elf_path;
            }
            // No cached ELF — must build
        }

        let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
        let target_dir = PathBuf::from(&out_dir)
            .join("guest-build")
            .join(&self.target_dir_name);

        let manifest_path = self.manifest_dir.join("Cargo.toml");

        let mut cmd = Command::new("cargo");
        // Use `cargo rustc` when we need to pass extra args to rustc (e.g. --crate-type).
        if self.extra_rustc_args.is_empty() {
            cmd.arg("build");
        } else {
            cmd.arg("rustc");
        }
        cmd.arg("--release")
            .arg("--manifest-path")
            .arg(&manifest_path)
            .arg("--target")
            .arg(&self.target_json_path);
        if cargo_supports_json_target_spec() {
            // Rust 1.95 requires an explicit cargo unstable flag when
            // building against a custom target JSON.
            cmd.arg("-Zjson-target-spec");
        }
        cmd.arg("-Zbuild-std=core,alloc");

        match &self.build_kind {
            BuildKind::Bin(name) => {
                cmd.arg("--bin").arg(name);
            }
            BuildKind::Lib => {
                cmd.arg("--lib");
            }
        }

        if !self.extra_rustc_args.is_empty() {
            cmd.arg("--");
            cmd.args(&self.extra_rustc_args);
        }

        // Use separate target dir to avoid deadlock
        cmd.env("CARGO_TARGET_DIR", &target_dir);

        // Signal to nested build.rs scripts that they're inside a guest build.
        // This prevents recursive guest builds (e.g., javm-guest-tests building itself).
        cmd.env("BUILD_CRATE_GUEST_BUILD", "1");

        // Use CARGO_ENCODED_RUSTFLAGS to avoid cache invalidation
        if !self.extra_rustflags.is_empty() {
            let encoded = self.extra_rustflags.join("\x1f");
            cmd.env("CARGO_ENCODED_RUSTFLAGS", &encoded);
        }

        if self.rustc_bootstrap {
            cmd.env("RUSTC_BOOTSTRAP", "1");
        }

        for (key, val) in &self.env_overrides {
            cmd.env(key, val);
        }

        let output = cmd.output().expect("failed to spawn cargo for guest build");

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            panic!(
                "Guest build failed for {}:\n--- stderr ---\n{}\n--- stdout ---\n{}",
                self.manifest_dir.display(),
                stderr,
                stdout
            );
        }

        let elf_path = self.output_elf_path();
        assert!(
            elf_path.exists(),
            "Expected ELF artifact not found at: {}",
            elf_path.display()
        );
        elf_path
    }

    fn output_elf_path(&self) -> PathBuf {
        let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
        let target_dir = PathBuf::from(&out_dir)
            .join("guest-build")
            .join(&self.target_dir_name);

        let artifact_name = match &self.build_kind {
            BuildKind::Bin(name) => name.clone(),
            BuildKind::Lib => {
                // cdylib: lib<name>.elf or lib<name>.so depending on target
                let manifest_path = self.manifest_dir.join("Cargo.toml");
                let contents =
                    std::fs::read_to_string(&manifest_path).expect("failed to read Cargo.toml");

                parse_lib_name(&contents, &self.manifest_dir)
            }
        };

        let release_dir = target_dir.join(&self.target_dir_name).join("release");

        // Try common artifact patterns
        let candidates = match &self.build_kind {
            BuildKind::Bin(_) => vec![
                release_dir.join(format!("{}.elf", artifact_name)),
                release_dir.join(&artifact_name),
            ],
            BuildKind::Lib => vec![
                release_dir.join(format!("{}.elf", artifact_name)),
                release_dir.join(format!("lib{}.elf", artifact_name)),
            ],
        };

        for candidate in &candidates {
            if candidate.exists() {
                return candidate.clone();
            }
        }

        // Return the first candidate as the expected path (for error messages)
        candidates.into_iter().next().unwrap()
    }
}

fn cargo_supports_json_target_spec() -> bool {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let Ok(output) = Command::new(cargo).arg("--version").output() else {
        return false;
    };
    if !output.status.success() {
        return false;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut parts = stdout.split_whitespace();
    let _ = parts.next();
    let Some(version) = parts.next() else {
        return false;
    };

    let mut components = version.split('.');
    let major = components.next().and_then(|part| part.parse::<u64>().ok());
    let minor = components.next().and_then(|part| part.parse::<u64>().ok());

    matches!((major, minor), (Some(major), Some(minor)) if (major, minor) >= (1, 95))
}

/// Parse the library name from a Cargo.toml.
/// Looks for `[lib] name = "..."`, falls back to package name with hyphens replaced.
fn parse_lib_name(contents: &str, manifest_dir: &Path) -> String {
    // Simple parsing: look for [lib] section with name = "..."
    let mut in_lib_section = false;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed == "[lib]" {
            in_lib_section = true;
            continue;
        }
        if trimmed.starts_with('[') {
            in_lib_section = false;
            continue;
        }
        if in_lib_section
            && trimmed.starts_with("name")
            && let Some(name) = extract_toml_string_value(trimmed)
        {
            return name;
        }
    }

    // Fall back to package name
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("name")
            && let Some(name) = extract_toml_string_value(trimmed)
        {
            return name.replace('-', "_");
        }
    }

    // Last resort: directory name
    manifest_dir
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .replace('-', "_")
}

fn extract_toml_string_value(line: &str) -> Option<String> {
    let after_eq = line.split('=').nth(1)?.trim();
    let unquoted = after_eq.trim_matches('"').trim_matches('\'');
    Some(unquoted.to_string())
}

/// Recursively emit `cargo:rerun-if-changed` for all files in a directory.
pub fn emit_rerun_for_dir(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                emit_rerun_for_dir(&path);
            } else {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
}

/// Write a target JSON string to `OUT_DIR/targets/<filename>` and return the path.
pub fn write_target_json(filename: &str, contents: &str) -> PathBuf {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let targets_dir = PathBuf::from(&out_dir).join("targets");
    std::fs::create_dir_all(&targets_dir).expect("failed to create targets dir");
    let path = targets_dir.join(filename);
    std::fs::write(&path, contents).expect("failed to write target JSON");
    path
}

/// Resolve a relative path against CARGO_MANIFEST_DIR.
pub fn resolve_manifest_dir(relative_path: &str) -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let resolved = PathBuf::from(&manifest_dir).join(relative_path);
    assert!(
        resolved.exists(),
        "Service crate not found at: {} (resolved from CARGO_MANIFEST_DIR={})",
        resolved.display(),
        manifest_dir
    );
    std::fs::canonicalize(&resolved).expect("failed to canonicalize path")
}
