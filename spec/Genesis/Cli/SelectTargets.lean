/-
  genesis_select_targets CLI

  Input:  {"prId": 42, "prCreatedAt": 1774000000, "indices": [...], "ranking": [...] (optional)}
  Output: {"targets": ["abc123", ...]}

  When the active variant has useRankedTargets=true, the "ranking" field is
  required — targets are selected by global quality ranking (v2).
  When useRankedTargets=false, ranking is ignored and time-based buckets (v1) are used.
-/

import Genesis.Cli.Common

open Lean (Json ToJson toJson fromJson? FromJson)
open Genesis.Cli

def main : IO UInt32 := runJsonPipe fun j => do
  let prId ← IO.ofExcept (j.getObjValAs? Nat "prId")
  let prCreatedAt ← IO.ofExcept (j.getObjValAs? Nat "prCreatedAt")
  let indices ← IO.ofExcept (j.getObjValAs? (List CommitIndex) "indices")
  let scoredCommits := indices.map (fun idx => (idx.commitHash, idx.epoch))
  let v := activeVariant prCreatedAt
  letI := v
  let eligible := scoredCommits.filter (fun (_, epoch) => epoch < prCreatedAt)
  if v.useRankedTargets then do
    let ranking ← IO.ofExcept (j.getObjValAs? (List CommitId) "ranking")
    let targets := selectComparisonTargetsRanked ranking scoredCommits
      (min v.rankingSize eligible.length) prId prCreatedAt
    return Json.mkObj [("targets", toJson targets)]
  else
    let targets := selectComparisonTargets scoredCommits
      (min v.rankingSize eligible.length) prId prCreatedAt
    return Json.mkObj [("targets", toJson targets)]
