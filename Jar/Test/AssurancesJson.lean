import Jar.Json
import Jar.Test.Assurances

/-!
# Assurances JSON Test Runner

FromJson instances for assurances test-specific types and a JSON-based test runner.
-/

namespace Jar.Test.AssurancesJson

open Lean (Json ToJson FromJson toJson fromJson?)
open Jar Jar.Json Jar.Test.Assurances

instance : JamConfig where
  config := Config.tiny
  valid := Config.tiny_valid

-- ============================================================================
-- JSON instances for assurances test types
-- ============================================================================

instance : FromJson (Option TAAvailAssignment) where
  fromJson?
    | Json.null => .ok none
    | j => do
      let report ← j.getObjVal? "report"
      let pkgSpec ← report.getObjVal? "package_spec"
      let hash ← @fromJson? Hash _ (← pkgSpec.getObjVal? "hash")
      let coreIndex ← (← report.getObjVal? "core_index").getNat?
      let timeout ← (← j.getObjVal? "timeout").getNat?
      return some { reportPackageHash := hash, coreIndex, timeout }

instance : FromJson TAAssurance where
  fromJson? j := do
    let anchor ← @fromJson? Hash _ (← j.getObjVal? "anchor")
    let bitfield ← @fromJson? ByteArray _ (← j.getObjVal? "bitfield")
    let validatorIndex ← (← j.getObjVal? "validator_index").getNat?
    let signature ← @fromJson? Ed25519Signature _ (← j.getObjVal? "signature")
    return { anchor, bitfield, validatorIndex, signature }

instance : FromJson TAState where
  fromJson? j := do
    let availArr ← j.getObjVal? "avail_assignments"
    let availAssignments ← match availArr with
      | Json.arr items => items.toList.mapM (fromJson? (α := Option TAAvailAssignment)) |>.map Array.mk
      | _ => .error "expected array for avail_assignments"
    let currValidators ← @fromJson? (Array ValidatorKey) _ (← j.getObjVal? "curr_validators")
    return { availAssignments, currValidators }

instance : FromJson TAInput where
  fromJson? j := do
    let assurancesArr ← j.getObjVal? "assurances"
    let assurances ← match assurancesArr with
      | Json.arr items => items.toList.mapM (fromJson? (α := TAAssurance)) |>.map Array.mk
      | _ => .error "expected array for assurances"
    let slot ← (← j.getObjVal? "slot").getNat?
    let parent ← @fromJson? Hash _ (← j.getObjVal? "parent")
    return { assurances, slot, parent }

instance : FromJson TAResult where
  fromJson? j := do
    if let .ok v := j.getObjVal? "ok" then
      let reportedArr ← v.getObjVal? "reported"
      let cores ← match reportedArr with
        | Json.arr items => items.toList.mapM (fun (wr : Json) => do
            let cj ← wr.getObjVal? "core_index"
            cj.getNat?) |>.map Array.mk
        | _ => .error "expected array for reported"
      return .ok cores
    else if let .ok (Json.str e) := j.getObjVal? "err" then
      return .err e
    else
      .error "TAResult: expected 'ok' or 'err'"

-- ============================================================================
-- ToJson instances for STF server output
-- ============================================================================

instance : ToJson TAAvailAssignment where
  toJson a := Json.mkObj [
    ("report", Json.mkObj [
      ("package_spec", Json.mkObj [("hash", toJson a.reportPackageHash)]),
      ("core_index", toJson a.coreIndex)]),
    ("timeout", toJson a.timeout)]

private instance : ToJson (Option TAAvailAssignment) where
  toJson
    | none => Json.null
    | some a => toJson a

instance : ToJson TAResult where
  toJson
    | .ok cores => Json.mkObj [("ok", Json.mkObj [
        ("reported", Json.arr (cores.map fun c => Json.mkObj [("core_index", toJson c)]))])]
    | .err e => Json.mkObj [("err", Json.str e)]

-- ============================================================================
-- JSON Test Runner
-- ============================================================================

/-- Run a single assurances test from separate input/output JSON files. -/
def runJsonTest (inputPath : System.FilePath) : IO Bool := do
  let inputContent ← IO.FS.readFile inputPath
  let inputJson ← IO.ofExcept (Json.parse inputContent)
  let outputPath := System.FilePath.mk (inputPath.toString.replace ".input.json" ".output.json")
  let outputContent ← IO.FS.readFile outputPath
  let outputJson ← IO.ofExcept (Json.parse outputContent)
  let pre ← IO.ofExcept (@fromJson? TAState _ (← IO.ofExcept (inputJson.getObjVal? "pre_state")))
  let input ← IO.ofExcept (@fromJson? TAInput _ (← IO.ofExcept (inputJson.getObjVal? "input")))
  let expectedResult ← IO.ofExcept (@fromJson? TAResult _ (← IO.ofExcept (outputJson.getObjVal? "output")))
  -- post_state avail_assignments
  let postAvailJson ← IO.ofExcept (outputJson.getObjVal? "post_state")
  let postAvailArr ← IO.ofExcept (postAvailJson.getObjVal? "avail_assignments")
  let postAvail ← IO.ofExcept (match postAvailArr with
    | Json.arr items => items.toList.mapM (fromJson? (α := Option TAAvailAssignment)) |>.map Array.mk
    | _ => .error "expected array for post avail_assignments")
  let name := inputPath.fileName.getD (toString inputPath)
  Assurances.runTest name pre input expectedResult postAvail

/-- Run all JSON tests in a directory. -/
def runJsonTestDir (dir : System.FilePath) : IO UInt32 := do
  let entries ← dir.readDir
  let jsonFiles := entries.filter (fun e => e.fileName.endsWith ".input.json")
  let sorted := jsonFiles.qsort (fun a b => a.fileName < b.fileName)
  let mut passed := 0
  let mut failed := 0
  for entry in sorted do
    let ok ← runJsonTest entry.path
    if ok then passed := passed + 1 else failed := failed + 1
  IO.println s!"\nAssurances JSON tests: {passed} passed, {failed} failed, {passed + failed} total"
  return if failed > 0 then 1 else 0

end Jar.Test.AssurancesJson
