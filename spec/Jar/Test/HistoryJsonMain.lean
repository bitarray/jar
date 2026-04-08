import Jar.Test.HistoryJson
import Jar.Variant

open Jar Jar.Test.HistoryJson

private def testVariants : Array JarConfig := #[JarVariant.gp072_tiny.toJarConfig, JarVariant.gp072_full.toJarConfig, JarVariant.jar1.toJarConfig]

def historyJsonMain (args : List String) : IO UInt32 := do
  let dir := match args with
    | [d] => d
    | _ => "tests/vectors/history"
  let mut exitCode : UInt32 := 0
  for v in testVariants do
    letI := v
    IO.println s!"Running history JSON tests ({v.name}) from: {dir}"
    let code ← runJsonTestDir dir
    if code != 0 then exitCode := code
  return exitCode
