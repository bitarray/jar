import Jar.Test.BlockTest
import Jar.Variant

open Jar Jar.Test.BlockTest

def testVariants : Array JamConfig := #[JamVariant.gp072_tiny.toJamConfig]

def main (args : List String) : IO UInt32 := do
  let dir := match args with
    | [d] => d
    | _ => "tests/vectors/blocks/safrole"
  let mut exitCode : UInt32 := 0
  for v in testVariants do
    letI := v
    IO.println s!"Running block tests ({v.name}) from: {dir}"
    let code ← runBlockTestDir dir
    if code != 0 then exitCode := code
  return exitCode
