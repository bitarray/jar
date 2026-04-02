import Jar.Test.StatisticsJson
import Jar.Variant

open Jar Jar.Test.StatisticsJson

private def testVariants : Array JamConfig := #[JamVariant.gp072_tiny.toJamConfig, JamVariant.gp072_full.toJamConfig, JamVariant.jar1.toJamConfig]

def statisticsJsonMain (args : List String) : IO UInt32 := do
  let dir := match args with
    | [d] => d
    | _ => "tests/vectors/statistics"
  let mut exitCode : UInt32 := 0
  for v in testVariants do
    letI := v
    IO.println s!"Running statistics JSON tests ({v.name}) from: {dir}"
    let code ← runJsonTestDir dir
    if code != 0 then exitCode := code
  return exitCode
