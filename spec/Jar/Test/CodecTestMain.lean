import Jar.Test.CodecTest
import Jar.Variant

open Jar Jar.Test.CodecTest

def testVariants : Array JamConfig := #[
  JamVariant.gp072_tiny.toJamConfig,
  JamVariant.gp072_full.toJamConfig
]

def main (args : List String) : IO UInt32 := do
  let dir := match args with
    | [d] => d
    | _ => "tests/vectors/codec"
  let mut exitCode : UInt32 := 0
  for v in testVariants do
    letI := v
    IO.println s!"Running codec tests ({v.name})..."
    let code ← runAll dir v.name
    if code != 0 then exitCode := code
  return exitCode
