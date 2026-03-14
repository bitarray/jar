import Jar.Json
import Jar.Test.History

/-!
# History JSON Test Runner

FromJson instances for history test-specific types and a JSON-based test runner.
-/

namespace Jar.Test.HistoryJson

open Lean (Json ToJson FromJson toJson fromJson?)
open Jar Jar.Json Jar.Test.History

instance : JamConfig where
  config := Config.tiny
  valid := Config.tiny_valid

-- ============================================================================
-- JSON instances for history test types
-- ============================================================================

instance : FromJson ReportedPackage where
  fromJson? j := do
    let hash ← @fromJson? Hash _ (← j.getObjVal? "hash")
    let exportsRoot ← @fromJson? Hash _ (← j.getObjVal? "exports_root")
    return { hash, exportsRoot }

instance : FromJson HistoryEntry where
  fromJson? j := do
    let headerHash ← @fromJson? Hash _ (← j.getObjVal? "header_hash")
    let beefyRoot ← @fromJson? Hash _ (← j.getObjVal? "beefy_root")
    let stateRoot ← @fromJson? Hash _ (← j.getObjVal? "state_root")
    let reported ← @fromJson? (Array ReportedPackage) _ (← j.getObjVal? "reported")
    return { headerHash, beefyRoot, stateRoot, reported }

instance : FromJson (Option Hash) where
  fromJson?
    | Json.null => .ok none
    | j => do pure (some (← @fromJson? Hash _ j))

instance : FromJson FlatHistoryState where
  fromJson? j := do
    let history ← @fromJson? (Array HistoryEntry) _ (← j.getObjVal? "history")
    let mmrObj ← j.getObjVal? "mmr"
    let mmrPeaks ← @fromJson? (Array (Option Hash)) _ (← mmrObj.getObjVal? "peaks")
    return { history, mmrPeaks }

instance : FromJson HistoryInput where
  fromJson? j := do
    let headerHash ← @fromJson? Hash _ (← j.getObjVal? "header_hash")
    let parentStateRoot ← @fromJson? Hash _ (← j.getObjVal? "parent_state_root")
    let accumulateRoot ← @fromJson? Hash _ (← j.getObjVal? "accumulate_root")
    let workPackages ← @fromJson? (Array ReportedPackage) _ (← j.getObjVal? "work_packages")
    return { headerHash, parentStateRoot, accumulateRoot, workPackages }

-- ============================================================================
-- ToJson instances for STF server output
-- ============================================================================

instance : ToJson ReportedPackage where
  toJson r := Json.mkObj [
    ("hash", toJson r.hash),
    ("exports_root", toJson r.exportsRoot)]

instance : ToJson HistoryEntry where
  toJson e := Json.mkObj [
    ("header_hash", toJson e.headerHash),
    ("beefy_root", toJson e.beefyRoot),
    ("state_root", toJson e.stateRoot),
    ("reported", toJson e.reported)]

private instance : ToJson (Option Hash) where
  toJson
    | none => Json.null
    | some h => toJson h

instance : ToJson FlatHistoryState where
  toJson s := Json.mkObj [
    ("history", toJson s.history),
    ("mmr", Json.mkObj [("peaks", toJson s.mmrPeaks)])]

-- ============================================================================
-- JSON Test Runner
-- ============================================================================

/-- Run a single history test from separate input/output JSON files. -/
def runJsonTest (inputPath : System.FilePath) : IO Bool := do
  let inputContent ← IO.FS.readFile inputPath
  let inputJson ← IO.ofExcept (Json.parse inputContent)
  let outputPath := System.FilePath.mk (inputPath.toString.replace ".input.json" ".output.json")
  let outputContent ← IO.FS.readFile outputPath
  let outputJson ← IO.ofExcept (Json.parse outputContent)
  let preStateJson ← IO.ofExcept (inputJson.getObjVal? "pre_state")
  let betaPre ← IO.ofExcept (preStateJson.getObjVal? "beta")
  let pre ← IO.ofExcept (@fromJson? FlatHistoryState _ betaPre)
  let input ← IO.ofExcept (@fromJson? HistoryInput _ (← IO.ofExcept (inputJson.getObjVal? "input")))
  let postStateJson ← IO.ofExcept (outputJson.getObjVal? "post_state")
  let betaPost ← IO.ofExcept (postStateJson.getObjVal? "beta")
  let post ← IO.ofExcept (@fromJson? FlatHistoryState _ betaPost)
  let name := inputPath.fileName.getD (toString inputPath)
  History.runTest name pre input post

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
  IO.println s!"\nHistory JSON tests: {passed} passed, {failed} failed, {passed + failed} total"
  return if failed > 0 then 1 else 0

end Jar.Test.HistoryJson
