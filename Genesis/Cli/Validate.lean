/-
  genesis_validate CLI

  Input:  {"indices": [...], "signedCommits": [...]}
  Output: {"valid": bool, "errors": [...]}

  Re-evaluates each signed commit against prior indices and checks
  that the stored CommitIndex matches.
-/

import Genesis.Cli.Common

open Lean (Json ToJson toJson fromJson? FromJson)
open Genesis.Cli

def main : IO UInt32 := runJsonPipe fun j => do
  let indices ← IO.ofExcept (j.getObjValAs? (List CommitIndex) "indices")
  let signedCommits ← IO.ofExcept (j.getObjValAs? (List SignedCommit) "signedCommits")
  if indices.length != signedCommits.length then
    return Json.mkObj [
      ("valid", toJson false),
      ("errors", Json.arr #[Json.str s!"index count ({indices.length}) != commit count ({signedCommits.length})"])
    ]
  let mut errors : Array Json := #[]
  let mut pastIndices : List CommitIndex := []
  for (idx, commit) in indices.zip signedCommits do
    let expected := evaluate pastIndices commit
    -- Compare key fields
    if expected.commitHash != idx.commitHash then
      errors := errors.push (Json.str s!"commit {idx.commitHash}: hash mismatch")
    if expected.score != idx.score then
      errors := errors.push (Json.str s!"commit {idx.commitHash}: score mismatch (expected {repr expected.score}, got {repr idx.score})")
    if expected.weightDelta != idx.weightDelta then
      errors := errors.push (Json.str s!"commit {idx.commitHash}: weightDelta mismatch (expected {expected.weightDelta}, got {idx.weightDelta})")
    if expected.contributor != idx.contributor then
      errors := errors.push (Json.str s!"commit {idx.commitHash}: contributor mismatch")
    pastIndices := pastIndices ++ [idx]
  return Json.mkObj [
    ("valid", toJson errors.isEmpty),
    ("errors", Json.arr errors)
  ]
