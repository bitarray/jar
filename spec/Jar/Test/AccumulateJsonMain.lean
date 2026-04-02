import Jar.Test.AccumulateJson
import Jar.Variant

open Jar Jar.Test.AccumulateJson

private def testVariants : Array JamConfig := #[JamVariant.gp072_tiny.toJamConfig, JamVariant.gp072_full.toJamConfig, JamVariant.jar1.toJamConfig]

def accumulateJsonMain (args : List String) : IO UInt32 := do
  let (verbose, rest) := match args with
    | "--verbose" :: r => (true, r)
    | r => (false, r)
  let dir := match rest with
    | [d] => d
    | _ => "tests/vectors/accumulate"
  let mut exitCode : UInt32 := 0
  for v in testVariants do
    letI := v
    IO.println s!"Running accumulate JSON tests ({v.name}) from: {dir}"
    let code ← runJsonTestDir dir verbose
    if code != 0 then exitCode := code
  return exitCode
