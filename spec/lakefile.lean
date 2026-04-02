import Lake
open System Lake DSL

package jar where
  version := v!"0.1.0"

require verso from git "https://github.com/leanprover/verso" @ "v4.27.0"
require Cli from git "https://github.com/leanprover/lean4-cli" @ "v4.27.0"

-- Compile crypto-ffi/bridge.c into a static library.
-- The Rust static library (libjar_crypto_ffi.a) must be pre-built via:
--   cd crypto-ffi && cargo build --release
extern_lib jarCryptoFFI (pkg) := do
  let buildDir := pkg.dir / defaultBuildDir / "crypto-ffi"
  let oFile := buildDir / "bridge.o"
  let srcTarget ← inputTextFile <| pkg.dir / "crypto-ffi" / "bridge.c"
  let oTarget ← buildFileAfterDep oFile srcTarget fun srcFile => do
    compileO oFile srcFile #[
      "-I", (← getLeanIncludeDir).toString,
      "-fPIC"
    ]
  let name := nameToStaticLib "jarCryptoFFI"
  buildStaticLib (pkg.staticLibDir / name) #[oTarget]

@[default_target]
lean_lib Jar where
  roots := #[`Jar]
  precompileModules := true
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_lib JarBook where
  roots := #[`JarBook]

lean_exe jarbook where
  root := `JarBookMain
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe jartest where
  root := `Jar.Test.Main
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe jarstf where
  root := `Jar.Test.StfServerMain
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe genreports where
  root := `Jar.Test.GenReports
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

-- ============================================================================
-- Genesis — Proof-of-Intelligence distribution protocol
-- No crypto-ffi dependency — builds without Rust.
-- ============================================================================

lean_lib Genesis where
  roots := #[`Genesis]

lean_exe genesis where
  root := `Genesis.Cli.Main
