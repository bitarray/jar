/-
  genesis_select_targets CLI

  Input:  {"prId": 42, "indices": [...]}
  Output: {"targets": ["abc123", ...]}
-/

import Genesis.Cli.Common

open Lean (Json ToJson toJson fromJson? FromJson)
open Genesis.Cli

def main : IO UInt32 := runJsonPipe fun j => do
  let prId ← IO.ofExcept (j.getObjValAs? Nat "prId")
  let indices ← IO.ofExcept (j.getObjValAs? (List CommitIndex) "indices")
  let pastIds := indices.map (·.commitHash)
  let targets := selectComparisonTargets pastIds (min rankingSize pastIds.length) prId
  return Json.mkObj [("targets", toJson targets)]
