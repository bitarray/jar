//! Fan each benchmark kernel out to every engine's artifact family.
//!
//! One kernel crate in `nub/programs/<name>`, four artifacts:
//!
//! | family      | artifact                        | consumed by            |
//! |-------------|---------------------------------|------------------------|
//! | `pvm2`      | `artifacts/pvm2/<n>.nubp`       | nub interp / JIT       |
//! | `native`    | `artifacts/native/<n>.so`       | the `native` floor     |
//! | `wasm32`    | `artifacts/wasm32/<n>.wasm`     | wasmtime, wasmer, wasmi|
//! | `polkavm64` | `artifacts/polkavm64/<n>.polkavm` | polkavm              |
//!
//! Discovery downstream is by directory name, not by inferring a family
//! from a path deep inside `target/`. It also keeps artifacts out of a
//! tree that `cargo clean` churns.
//!
//! A manifest at `artifacts/manifest.json` records how each artifact was
//! built, so the report can state provenance instead of implying that
//! every row saw identical compiler settings (they cannot — each family
//! needs its own).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::Serialize;

/// Kernels to fan out. Names match `nub/programs/<name>`.
const PROGRAMS: &[&str] = &[
    "prime-sieve",
    "ed25519",
    "keccak",
    "blake2b",
    "ecrecover",
    "goldilocks-mul",
    "poseidon2-perm",
    "mini-verifier",
    "poly-eval",
    "fri-fold-tree",
];

const NATIVE_TRIPLE: &str = "x86_64-unknown-linux-gnu";
const WASM_TRIPLE: &str = "wasm32-unknown-unknown";
const POLKAVM_TARGET: &str = "riscv64emac-polkavm";
const POLKAVM_TARGET_JSON: &str = include_str!("../targets/riscv64emac-polkavm.json");

/// Guest stack for the polkavm family, matching the recovered
/// `build-pvm` recipe.
const POLKAVM_MIN_STACK: u32 = 65536;

#[derive(Serialize)]
struct Artifact {
    program: String,
    family: String,
    path: String,
    /// The rustc invocation's distinguishing settings, so the report can
    /// say what each family actually saw.
    target: String,
    rustflags: String,
}

#[derive(Serialize)]
struct Manifest {
    rustc: String,
    artifacts: Vec<Artifact>,
}

fn main() -> Result<()> {
    let root = workspace_root()?;
    let artifacts = root.join("artifacts");

    let mut manifest = Manifest {
        rustc: rustc_version()?,
        artifacts: Vec::new(),
    };

    for program in PROGRAMS {
        eprintln!("=== {program} ===");
        manifest
            .artifacts
            .push(build_pvm2(&root, &artifacts, program)?);
        manifest
            .artifacts
            .push(build_cdylib(&root, &artifacts, program, Family::Native)?);
        manifest
            .artifacts
            .push(build_cdylib(&root, &artifacts, program, Family::Wasm32)?);
        manifest
            .artifacts
            .push(build_polkavm(&root, &artifacts, program)?);
    }

    let path = artifacts.join("manifest.json");
    std::fs::write(&path, serde_json::to_string_pretty(&manifest)?)?;
    eprintln!(
        "\n{} artifacts across {} programs -> {}",
        manifest.artifacts.len(),
        PROGRAMS.len(),
        artifacts.display()
    );
    Ok(())
}

/// `bench-build` lives at `<root>/bench-build`, so its manifest dir's
/// parent is the bench-compare workspace root.
///
/// Baked in at compile time, not read from the environment: this binary
/// *sets* `CARGO_MANIFEST_DIR` for `nub_build`, and it must work when
/// invoked directly rather than through `cargo run`.
fn workspace_root() -> Result<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("bench-build must live inside the bench-compare workspace")?
        .to_path_buf())
}

fn rustc_version() -> Result<String> {
    let out = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
        .arg("--version")
        .output()?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[derive(Clone, Copy)]
enum Family {
    Native,
    Wasm32,
}

impl Family {
    fn triple(self) -> &'static str {
        match self {
            Family::Native => NATIVE_TRIPLE,
            Family::Wasm32 => WASM_TRIPLE,
        }
    }
    fn dir(self) -> &'static str {
        match self {
            Family::Native => "native",
            Family::Wasm32 => "wasm32",
        }
    }
    fn produced_ext(self) -> &'static str {
        match self {
            Family::Native => "so",
            Family::Wasm32 => "wasm",
        }
    }
}

/// The PVM2 family: nub's own recipe, reused rather than reimplemented.
///
/// `nub_build::pvm2` is a build-script helper, so it reads `OUT_DIR`;
/// we supply one. Reusing it is the point — the inline threshold, LTO
/// setting and codegen-units that shape nub's numbers are the ones nub
/// actually ships, not a second guess at them.
fn build_pvm2(root: &Path, artifacts: &Path, program: &str) -> Result<Artifact> {
    let out = artifacts.join("pvm2");
    std::fs::create_dir_all(&out)?;
    // `nub_build::pvm2` scribbles a whole cargo target tree under
    // OUT_DIR, so point it at `target/` and copy only the blob out.
    // Artifacts stay a directory of artifacts.
    let scratch = root.join("target/pvm2-build");
    std::fs::create_dir_all(&scratch)?;

    // Single-threaded, and set before any read of these.
    unsafe {
        std::env::set_var("OUT_DIR", &scratch);
        std::env::set_var("CARGO_MANIFEST_DIR", root);
    }
    let built = nub_build::pvm2::build(
        &format!("../programs/{program}"),
        &format!("bench-{program}"),
    );
    let dest = out.join(format!("{program}.nubp"));
    std::fs::copy(&built, &dest)
        .with_context(|| format!("copy {} -> {}", built.display(), dest.display()))?;
    eprintln!("  pvm2      {}", dest.display());
    Ok(Artifact {
        program: program.into(),
        family: "pvm2".into(),
        path: rel(root, &dest),
        target: "riscv64emc-pvm2".into(),
        rustflags: "-Cllvm-args=--inline-threshold=265 (nub_build::pvm2)".into(),
    })
}

/// The native and wasm families: a plain cdylib build of the wrapper.
///
/// wasm deliberately uses Rust's *default* target features. The old
/// polkavm benchtool forced `-C target-cpu=mvp -C target-feature=-sign-ext`
/// purely so wasm3 would accept the module, which penalises every other
/// wasm engine's memcpy. We do not ship a wasm3 row, so we do not pay
/// that cost.
fn build_cdylib(root: &Path, artifacts: &Path, program: &str, family: Family) -> Result<Artifact> {
    let target_dir = root.join("target/guests");
    let mut cmd = cargo(root);
    cmd.args(["build", "--release", "-p"])
        .arg(format!("guest-{program}"))
        .args(["--target", family.triple()])
        .env("CARGO_TARGET_DIR", &target_dir);

    // Strip the wasm guests, so the size comparison is like-for-like.
    //
    // The workspace root sets `[profile.release] debug = true` for the
    // *harness* — it is what makes the measuring process profilable —
    // but `members` includes `guests/*`, so without this every guest
    // inherits it. That put full DWARF in every `.wasm`: 86-98% of each
    // artifact, and 1.33 MB of ed25519's 1.39 MB. PolkaVM strips at
    // link (`Config::set_strip(true)`) and nub's linker never copies
    // debug info, so leaving wasm unstripped would compare one
    // unstripped format against two stripped ones.
    //
    // Env vars rather than `[profile.release.package.*]` overrides
    // because a per-package override would only reach the thin
    // `guest-*` wrapper crates. Nearly all of that DWARF comes from the
    // kernel crate under `nub/programs/` and its transitive crypto
    // dependencies, which the env var covers and a package override
    // does not.
    //
    // Debug info cannot affect code generation, so this changes only
    // the artifact's size — not what any engine executes.
    if matches!(family, Family::Wasm32) {
        cmd.env("CARGO_PROFILE_RELEASE_DEBUG", "false")
            .env("CARGO_PROFILE_RELEASE_STRIP", "symbols");
    }

    let status = cmd.status()?;
    if !status.success() {
        bail!("{} build failed for {program}", family.dir());
    }

    let stem = format!("guest_{}", program.replace('-', "_"));
    let produced = target_dir
        .join(family.triple())
        .join("release")
        .join(match family {
            Family::Native => format!("lib{stem}.so"),
            Family::Wasm32 => format!("{stem}.wasm"),
        });

    let out = artifacts.join(family.dir());
    std::fs::create_dir_all(&out)?;
    let dest = out.join(format!("{program}.{}", family.produced_ext()));
    std::fs::copy(&produced, &dest)
        .with_context(|| format!("copy {} -> {}", produced.display(), dest.display()))?;
    eprintln!("  {:9} {}", family.dir(), dest.display());

    Ok(Artifact {
        program: program.into(),
        family: family.dir().into(),
        path: rel(root, &dest),
        target: family.triple().into(),
        rustflags: match family {
            Family::Wasm32 => "(default) + CARGO_PROFILE_RELEASE_{DEBUG=false,STRIP=symbols}",
            Family::Native => "(default)",
        }
        .into(),
    })
}

/// The polkavm family: cross-compile to the RV64EMAC polkavm target,
/// then link with `polkavm-linker`.
///
/// Flags recovered verbatim from this repo's deleted `build-pvm`
/// (`23d21225^:rust/build-pvm/src/lib.rs`), including the target JSON,
/// so polkavm is measured the way polkavm expects to be built.
fn build_polkavm(root: &Path, artifacts: &Path, program: &str) -> Result<Artifact> {
    let target_dir = root.join("target/guests");
    let json = root.join("bench-build/targets/riscv64emac-polkavm.json");
    std::fs::create_dir_all(json.parent().unwrap())?;
    std::fs::write(&json, POLKAVM_TARGET_JSON)?;

    let rustflags = ["-Zunstable-options", "-Cpanic=immediate-abort"].join("\x1f");
    let status = cargo(root)
        // `-Zjson-target-spec` is required from Rust 1.95 to pass a
        // custom target JSON at all; `-Zbuild-std` because a custom
        // target has no precompiled core/alloc.
        .args([
            "build",
            "--release",
            "-Zbuild-std=core,alloc",
            "-Zjson-target-spec",
            "-p",
        ])
        .arg(format!("guest-{program}"))
        .arg("--target")
        .arg(&json)
        .env("CARGO_TARGET_DIR", &target_dir)
        .env("RUSTC_BOOTSTRAP", "1")
        .env("CARGO_ENCODED_RUSTFLAGS", &rustflags)
        // The linker needs symbols to find the export table.
        .env("CARGO_PROFILE_RELEASE_STRIP", "false")
        .env("CARGO_PROFILE_RELEASE_OPT_LEVEL", "3")
        .env("CARGO_PROFILE_RELEASE_LTO", "true")
        .env("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "1")
        .status()?;
    if !status.success() {
        bail!("polkavm build failed for {program}");
    }

    let stem = format!("guest_{}", program.replace('-', "_"));
    let elf_dir = target_dir.join(POLKAVM_TARGET).join("release");
    let elf = [
        elf_dir.join(format!("{stem}.elf")),
        elf_dir.join(format!("lib{stem}.elf")),
    ]
    .into_iter()
    .find(|p| p.exists())
    .with_context(|| format!("no polkavm ELF for {program} in {}", elf_dir.display()))?;

    let mut config = polkavm_linker::Config::default();
    config.set_strip(true);
    config.set_min_stack_size(POLKAVM_MIN_STACK);
    let elf_data = std::fs::read(&elf)?;
    let blob = polkavm_linker::program_from_elf(
        config,
        polkavm_linker::TargetInstructionSet::JamV1,
        &elf_data,
    )
    .map_err(|e| anyhow::anyhow!("polkavm link failed for {program}: {e}"))?;

    let out = artifacts.join("polkavm64");
    std::fs::create_dir_all(&out)?;
    let dest = out.join(format!("{program}.polkavm"));
    std::fs::write(&dest, &blob)?;
    eprintln!("  polkavm64 {}", dest.display());

    Ok(Artifact {
        program: program.into(),
        family: "polkavm64".into(),
        path: rel(root, &dest),
        target: POLKAVM_TARGET.into(),
        rustflags: "-Zunstable-options -Cpanic=immediate-abort".into(),
    })
}

fn cargo(root: &Path) -> Command {
    let mut c = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    c.current_dir(root);
    // Never let the parent build's flags leak into a guest build.
    c.env_remove("RUSTFLAGS");
    c.env_remove("CARGO_ENCODED_RUSTFLAGS");
    c
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root).unwrap_or(p).display().to_string()
}

/// Kept for the manifest schema's benefit: families are a closed set.
#[allow(dead_code)]
fn families() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        ("pvm2", "nubp"),
        ("native", "so"),
        ("wasm32", "wasm"),
        ("polkavm64", "polkavm"),
    ])
}
