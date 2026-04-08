import Jar.Test.BlockTest
import Jar.Variant

open Jar Jar.Test.BlockTest

/-- Traces where each block has full keyvals (independent per-block tests). -/
def independentTraces : Array String := #["safrole", "fallback", "storage_light", "storage", "preimages_light", "preimages"]

/-- Traces where only the first block has keyvals (sequential state threading). -/
def sequentialTraces : Array String := #["conformance_no_forks", "conformance_forks"]

-- Block trace vectors only exist for gp072_tiny.
instance : JarVariant := JarVariant.gp072_tiny

def blockTestMain (_args : List String) : IO UInt32 := do
  let variantName := "gp072_tiny"
  let mut exitCode : UInt32 := 0
  for trace in independentTraces do
    let dir := s!"tests/vectors/blocks/{trace}"
    IO.println s!"Running block tests ({variantName}) from: {dir}"
    let code ← runBlockTestDir dir
    if code != 0 then exitCode := code
  for trace in sequentialTraces do
    let dir := s!"tests/vectors/blocks/{trace}"
    IO.println s!"Running block tests ({variantName}, sequential) from: {dir}"
    let code ← runBlockTestDirSeq dir
    if code != 0 then exitCode := code
  return exitCode
