import Jar.Test.BlockTest
import Jar.Variant

open Jar Jar.Test.BlockTest

def testVariants : Array JamConfig := #[JamVariant.gp072_tiny.toJamConfig]

/-- Traces where each block has full keyvals (independent per-block tests). -/
def independentTraces : Array String := #["safrole", "fallback", "storage_light", "storage", "preimages_light", "preimages"]

/-- Traces where only the first block has keyvals (sequential state threading). -/
def sequentialTraces : Array String := #["conformance_no_forks", "conformance_forks"]

def main (args : List String) : IO UInt32 := do
  let mut exitCode : UInt32 := 0
  match args with
  | ["dump", d] =>
    for v in testVariants do
      letI := v
      IO.println s!"Dumping keyvals ({v.name}) for: {d}"
      let code ← runBlockTestDirDump d
      if code != 0 then exitCode := code
  | [d] =>
    for v in testVariants do
      letI := v
      IO.println s!"Running block tests ({v.name}) from: {d}"
      let code ← runBlockTestDir d
      if code != 0 then exitCode := code
  | _ =>
    for trace in independentTraces do
      let dir := s!"tests/vectors/blocks/{trace}"
      for v in testVariants do
        letI := v
        IO.println s!"Running block tests ({v.name}) from: {dir}"
        let code ← runBlockTestDir dir
        if code != 0 then exitCode := code
    for trace in sequentialTraces do
      let dir := s!"tests/vectors/blocks/{trace}"
      for v in testVariants do
        letI := v
        IO.println s!"Running block tests ({v.name}, sequential) from: {dir}"
        let code ← runBlockTestDirSeq dir
        if code != 0 then exitCode := code
  return exitCode
