import Jar.Test.AssurancesJson
import Jar.Variant

open Jar Jar.Test.AssurancesJson

private def testVariants : Array JarConfig := #[JarVariant.gp072_tiny.toJarConfig, JarVariant.gp072_full.toJarConfig, JarVariant.jar1.toJarConfig]

def assurancesJsonMain (args : List String) : IO UInt32 := do
  let dir := match args with
    | [d] => d
    | _ => "tests/vectors/assurances"
  let mut exitCode : UInt32 := 0
  for v in testVariants do
    letI := v
    IO.println s!"Running assurances JSON tests ({v.name}) from: {dir}"
    let code ← runJsonTestDir dir
    if code != 0 then exitCode := code
  return exitCode
