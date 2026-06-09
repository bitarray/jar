import Lake
open System Lake DSL

package jar where
  version := v!"0.1.0"

require verso from git "https://github.com/leanprover/verso" @ "v4.27.0"
require Cli from git "https://github.com/leanprover/lean4-cli" @ "v4.27.0"

@[default_target]
lean_lib Jar where
  roots := #[`Jar]
  precompileModules := true

lean_lib JarBook where
  roots := #[`JarBook]

lean_exe jarbook where
  root := `JarBookMain

-- ============================================================================
-- Genesis — Proof-of-Intelligence distribution protocol
-- ============================================================================

lean_lib Genesis where
  roots := #[`Genesis]

lean_exe genesis where
  root := `Genesis.Cli.Main
