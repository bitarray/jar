import Jar.Test.ReportsJson
import Jar.Variant

open Jar Jar.Test.ReportsJson

private def runForVariant (inst : JarVariant) (dir : String) : IO UInt32 := do
  letI := inst
  IO.println s!"Running reports JSON tests ({inst.toJarConfig.name}) from: {dir}"
  runJsonTestDir dir

def reportsJsonMain (args : List String) : IO UInt32 := do
  let dir := match args with
    | [d] => d
    | _ => "tests/vectors/reports"
  let mut exitCode : UInt32 := 0
  for inst in #[JarVariant.gp072_tiny, JarVariant.gp072_full, JarVariant.jar1] do
    let code ← runForVariant inst dir
    if code != 0 then exitCode := code
  return exitCode
