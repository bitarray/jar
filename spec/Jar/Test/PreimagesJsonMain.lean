import Jar.Test.PreimagesJson
import Jar.Variant

open Jar Jar.Test.PreimagesJson

private def testVariants : Array JarConfig := #[JarVariant.gp072_tiny.toJarConfig, JarVariant.gp072_full.toJarConfig, JarVariant.jar1.toJarConfig]

def preimagesJsonMain (args : List String) : IO UInt32 := do
  let dir := match args with
    | [d] => d
    | _ => "tests/vectors/preimages"
  let mut exitCode : UInt32 := 0
  for v in testVariants do
    letI := v
    IO.println s!"Running preimages JSON tests ({v.name}) from: {dir}"
    let code ← runJsonTestDir dir
    if code != 0 then exitCode := code
  return exitCode
