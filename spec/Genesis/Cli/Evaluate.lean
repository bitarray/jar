/-
  genesis_evaluate CLI

  Input:  {"commit": {...}, "pastIndices": [...], "ranking": [...] (required for v2)}
  Output: CommitIndex JSON

  For v2 (useRankedTargets), the "ranking" field is REQUIRED.
  Missing ranking for a v2 commit is a fatal error.
-/

import Genesis.Cli.Common

open Lean (Json ToJson toJson fromJson? FromJson)
open Genesis.Cli

def main : IO UInt32 := runJsonPipe fun j => do
  let commit ← IO.ofExcept (j.getObjValAs? SignedCommit "commit")
  let pastIndices ← IO.ofExcept (j.getObjValAs? (List CommitIndex) "pastIndices")
  let v := activeVariant commit.prCreatedAt
  let ranking ← if v.useRankedTargets then
    IO.ofExcept (j.getObjValAs? (List CommitId) "ranking"
      |>.mapError (s!"v2 variant active (useRankedTargets=true) but ranking field missing: " ++ ·))
    |>.map some
  else
    pure none
  let idx := evaluate pastIndices commit ranking
  return toJson idx
