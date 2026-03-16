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
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe cryptotest where
  root := `Jar.CryptoTest
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe safrolejsontest where
  root := `Jar.Test.SafroleJsonMain
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe historyjsontest where
  root := `Jar.Test.HistoryJsonMain
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe statisticsjsontest where
  root := `Jar.Test.StatisticsJsonMain

lean_exe authorizationsjsontest where
  root := `Jar.Test.AuthorizationsJsonMain

lean_exe disputesjsontest where
  root := `Jar.Test.DisputesJsonMain
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe preimagesjsontest where
  root := `Jar.Test.PreimagesJsonMain
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe assurancesjsontest where
  root := `Jar.Test.AssurancesJsonMain
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe reportsjsontest where
  root := `Jar.Test.ReportsJsonMain
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe accumulatejsontest where
  root := `Jar.Test.AccumulateJsonMain
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe propertytest where
  root := `Jar.Test.PropertyMain
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe trietest where
  root := `Jar.Test.TrieTestMain
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe shuffletest where
  root := `Jar.Test.ShuffleTestMain
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

lean_exe codectest where
  root := `Jar.Test.CodecTestMain
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe blocktest where
  root := `Jar.Test.BlockTestMain
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]

lean_exe erasuretest where
  root := `Jar.Test.ErasureTestMain
  moreLinkArgs := #[
    "-L", "crypto-ffi/target/release",
    "-ljar_crypto_ffi",
    "-lpthread", "-ldl", "-lm"
  ]
