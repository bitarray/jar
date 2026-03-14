import Jar.Json
import Jar.Test.Preimages

/-!
# Preimages JSON Test Runner

FromJson instances for preimages test-specific types and a JSON-based test runner.
-/

namespace Jar.Test.PreimagesJson

open Lean (Json ToJson FromJson toJson fromJson?)
open Jar Jar.Json Jar.Test.Preimages

instance : JamConfig where
  config := Config.tiny
  valid := Config.tiny_valid

-- ============================================================================
-- JSON instances for preimages test types
-- ============================================================================

private def parseTPServiceAccount (j : Json) : Except String TPServiceAccount := do
  let serviceId ← (← j.getObjVal? "id").getNat?
  let data ← j.getObjVal? "data"
  -- Extract blob hashes from preimage_blobs
  let blobsJson ← data.getObjVal? "preimage_blobs"
  let blobHashes ← match blobsJson with
    | Json.arr items => items.toList.mapM (fun (item : Json) => do
        @fromJson? Hash _ (← item.getObjVal? "hash")) |>.map Array.mk
    | _ => .error "expected array for preimage_blobs"
  -- Extract requests from preimage_requests
  let reqsJson ← data.getObjVal? "preimage_requests"
  let requests ← match reqsJson with
    | Json.arr items => items.toList.mapM (fun (item : Json) => do
        let key ← item.getObjVal? "key"
        let hash ← @fromJson? Hash _ (← key.getObjVal? "hash")
        let length ← (← key.getObjVal? "length").getNat?
        let value ← item.getObjVal? "value"
        let timeslots ← match value with
          | Json.arr ts => ts.toList.mapM (fun (t : Json) => t.getNat?) |>.map Array.mk
          | _ => .error "expected array for timeslots"
        return ({ hash, length, timeslots } : TPRequest)) |>.map Array.mk
    | _ => .error "expected array for preimage_requests"
  return { serviceId, blobHashes, requests }

def parseTPState (j : Json) : Except String TPState := do
  let accountsJson ← j.getObjVal? "accounts"
  let accounts ← match accountsJson with
    | Json.arr items => items.toList.mapM parseTPServiceAccount |>.map Array.mk
    | _ => .error "expected array for accounts"
  return { accounts }

instance : FromJson TPPreimage where
  fromJson? j := do
    let requester ← (← j.getObjVal? "requester").getNat?
    let blob ← @fromJson? ByteArray _ (← j.getObjVal? "blob")
    return { requester, blob }

instance : FromJson TPInput where
  fromJson? j := do
    let preimagesJson ← j.getObjVal? "preimages"
    let preimages ← match preimagesJson with
      | Json.arr items => items.toList.mapM (fun item =>
          @fromJson? TPPreimage _ item) |>.map Array.mk
      | _ => .error "expected array for preimages"
    let slot ← (← j.getObjVal? "slot").getNat?
    return { preimages, slot }

instance : FromJson TPResult where
  fromJson? j := do
    if let .ok _ := j.getObjVal? "ok" then
      return .ok
    else if let .ok (Json.str e) := j.getObjVal? "err" then
      return .err e
    else
      .error "TPResult: expected 'ok' or 'err'"

-- ============================================================================
-- ToJson instances for STF server output
-- ============================================================================

private def toJsonTPServiceAccount (a : TPServiceAccount) : Json :=
  Json.mkObj [
    ("id", Json.num a.serviceId),
    ("data", Json.mkObj [
      ("preimage_blobs", Json.arr (a.blobHashes.map fun h =>
        Json.mkObj [("hash", toJson h)])),
      ("preimage_requests", Json.arr (a.requests.map fun r =>
        Json.mkObj [
          ("key", Json.mkObj [
            ("hash", toJson r.hash),
            ("length", toJson r.length)]),
          ("value", Json.arr (r.timeslots.map fun t => toJson t))]))])]

def toJsonTPState (s : TPState) : Json :=
  Json.mkObj [("accounts", Json.arr (s.accounts.map toJsonTPServiceAccount))]

instance : ToJson TPResult where
  toJson
    | .ok => Json.mkObj [("ok", Json.mkObj [])]
    | .err e => Json.mkObj [("err", Json.str e)]

-- ============================================================================
-- JSON Test Runner
-- ============================================================================

/-- Run a single preimages test from separate input/output JSON files. -/
def runJsonTest (inputPath : System.FilePath) : IO Bool := do
  let inputContent ← IO.FS.readFile inputPath
  let inputJson ← IO.ofExcept (Json.parse inputContent)
  let outputPath := System.FilePath.mk (inputPath.toString.replace ".input.json" ".output.json")
  let outputContent ← IO.FS.readFile outputPath
  let outputJson ← IO.ofExcept (Json.parse outputContent)
  let pre ← IO.ofExcept (parseTPState (← IO.ofExcept (inputJson.getObjVal? "pre_state")))
  let input ← IO.ofExcept (@fromJson? TPInput _ (← IO.ofExcept (inputJson.getObjVal? "input")))
  let expectedResult ← IO.ofExcept (@fromJson? TPResult _ (← IO.ofExcept (outputJson.getObjVal? "output")))
  let expectedPost ← IO.ofExcept (parseTPState (← IO.ofExcept (outputJson.getObjVal? "post_state")))
  let name := inputPath.fileName.getD (toString inputPath)
  Preimages.runTest name pre input expectedResult expectedPost

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
  IO.println s!"\nPreimages JSON tests: {passed} passed, {failed} failed, {passed + failed} total"
  return if failed > 0 then 1 else 0

end Jar.Test.PreimagesJson
