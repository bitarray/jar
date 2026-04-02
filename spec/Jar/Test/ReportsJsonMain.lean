import Jar.Test.ReportsJson
import Jar.Variant

open Jar Jar.Test.ReportsJson

private def runForVariant (inst : JamVariant) (dir : String) : IO UInt32 := do
  letI := inst
  IO.println s!"Running reports JSON tests ({inst.toJamConfig.name}) from: {dir}"
  runJsonTestDir dir

def reportsJsonMain (args : List String) : IO UInt32 := do
  let dir := match args with
    | [d] => d
    | _ => "tests/vectors/reports"
  let mut exitCode : UInt32 := 0
  for inst in #[JamVariant.gp072_tiny, JamVariant.gp072_full, JamVariant.jar1] do
    let code ← runForVariant inst dir
    if code != 0 then exitCode := code
  return exitCode
