import Lake
open System Lake DSL

package jar where
  version := v!"0.1.0"

require verso from git "https://github.com/leanprover/verso" @ "v4.27.0"

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

lean_exe cryptotest where
  root := `Jar.CryptoTest
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe safroletest where
  root := `Jar.Test.SafroleVectors
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe statisticstest where
  root := `Jar.Test.StatisticsVectors

lean_exe authorizationstest where
  root := `Jar.Test.AuthorizationsVectors

lean_exe historytest where
  root := `Jar.Test.HistoryVectors
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe disputestest where
  root := `Jar.Test.DisputesVectors
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe assurancestest where
  root := `Jar.Test.AssurancesVectors
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe preimagestest where
  root := `Jar.Test.PreimagesVectors
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe reportstest where
  root := `Jar.Test.ReportsVectors
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe accumulatetest where
  root := `Jar.Test.AccumulateVectors
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]
