import Jar.Test.DisputesJson
import Jar.Variant

open Jar Jar.Test.DisputesJson

private def testVariants : Array JamConfig := #[JamVariant.gp072_tiny.toJamConfig, JamVariant.gp072_full.toJamConfig, JamVariant.jar1.toJamConfig]

def disputesJsonMain (args : List String) : IO UInt32 := do
  let dir := match args with
    | [d] => d
    | _ => "tests/vectors/disputes"
  let mut exitCode : UInt32 := 0
  for v in testVariants do
    letI := v
    IO.println s!"Running disputes JSON tests ({v.name}) from: {dir}"
    let code ← runJsonTestDir dir
    if code != 0 then exitCode := code
  return exitCode
