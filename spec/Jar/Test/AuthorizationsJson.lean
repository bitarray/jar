import Jar.Json
import Jar.Test.Authorizations

/-!
# Authorizations JSON Test Runner

FromJson instances for authorization test types and a JSON-based test runner.
-/

namespace Jar.Test.AuthorizationsJson

open Lean (Json ToJson FromJson toJson fromJson?)
open Jar Jar.Json Jar.Test.Authorizations

variable [JarConfig]

-- ============================================================================
-- JSON instances for authorization test types
-- ============================================================================

instance : FromJson FlatAuthState where
  fromJson? j := do
    let authPools ← @fromJson? (Array (Array Hash)) _ (← j.getObjVal? "auth_pools")
    let authQueues ← @fromJson? (Array (Array Hash)) _ (← j.getObjVal? "auth_queues")
    return { authPools, authQueues }

instance : FromJson AuthUsed where
  fromJson? j := do
    let core ← (← j.getObjVal? "core").getNat?
    let authHash ← @fromJson? Hash _ (← j.getObjVal? "auth_hash")
    return { core, authHash }

instance : FromJson AuthInput where
  fromJson? j := do
    let slot ← (← j.getObjVal? "slot").getNat?
    let auths ← @fromJson? (Array AuthUsed) _ (← j.getObjVal? "auths")
    return { slot, auths }

-- ============================================================================
-- ToJson instances for STF server output
-- ============================================================================

instance : ToJson FlatAuthState where
  toJson s := Json.mkObj [
    ("auth_pools", toJson s.authPools),
    ("auth_queues", toJson s.authQueues)]

-- ============================================================================
-- JSON Test Runner
-- ============================================================================

/-- Run a single authorization test from separate input/output JSON files. -/
def runJsonTest (inputPath : System.FilePath) : IO Bool := do
  let inputContent ← IO.FS.readFile inputPath
  let inputJson ← IO.ofExcept (Json.parse inputContent)
  let outputPath := System.FilePath.mk (inputPath.toString.replace s!".input.{JarConfig.name}.json" s!".output.{JarConfig.name}.json")
  let outputContent ← IO.FS.readFile outputPath
  let outputJson ← IO.ofExcept (Json.parse outputContent)
  let pre ← IO.ofExcept (@fromJson? FlatAuthState _ (← IO.ofExcept (inputJson.getObjVal? "pre_state")))
  let input ← IO.ofExcept (@fromJson? AuthInput _ (← IO.ofExcept (inputJson.getObjVal? "input")))
  let expectedPost ← IO.ofExcept (@fromJson? FlatAuthState _ (← IO.ofExcept (outputJson.getObjVal? "post_state")))
  let name := inputPath.fileName.getD (toString inputPath)
  Authorizations.runTest name pre input expectedPost

/-- Run all JSON tests in a directory. -/
def runJsonTestDir (dir : System.FilePath) : IO UInt32 := do
  let entries ← dir.readDir
  let jsonFiles := entries.filter (fun e => e.fileName.endsWith s!".input.{JarConfig.name}.json")
  let sorted := jsonFiles.qsort (fun a b => a.fileName < b.fileName)
  let mut passed := 0
  let mut failed := 0
  for entry in sorted do
    let ok ← runJsonTest entry.path
    if ok then passed := passed + 1 else failed := failed + 1
  IO.println s!"\nAuthorizations JSON tests: {passed} passed, {failed} failed, {passed + failed} total"
  return if failed > 0 then 1 else 0

end Jar.Test.AuthorizationsJson
