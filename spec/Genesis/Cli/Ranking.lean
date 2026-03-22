/-
  genesis_ranking CLI

  Computes the global quality ranking using 1/3 quantile reviewer selection
  (Sybil-resistant: same model as score derivation).

  Input:  {"signedCommits": [...], "indices": [...]}
  Output: {"ranking": ["hash1", "hash2", ...]}  (best to worst)

  Reviewer weights are reconstructed from indices at each step.
-/

import Genesis.Cli.Common

open Lean (Json ToJson toJson fromJson? FromJson)
open Genesis.Cli

def main : IO UInt32 := runJsonPipe fun j => do
  let signedCommits ← IO.ofExcept (j.getObjValAs? (List SignedCommit) "signedCommits")
  let indices ← IO.ofExcept (j.getObjValAs? (List CommitIndex) "indices")
  -- Build per-commit weight functions by reconstructing state incrementally
  let (weightFns, _) := signedCommits.zip indices |>.foldl
    (fun (fns, pastIndices) (commit, idx) =>
      let state := reconstructState pastIndices
      letI := activeVariant commit.prCreatedAt
      let fn := (state.reviewerWeight ·)
      (fns ++ [fn], pastIndices ++ [idx])
    ) (([] : List (ContributorId → Nat)), ([] : List CommitIndex))
  -- designWeight is the same across v1/v2; if it ever diverges,
  -- computeRanking would need per-commit variant dispatch for aggregateReviewRanking
  letI := GenesisVariant.v1
  let ranking := computeRanking signedCommits weightFns
  return Json.mkObj [("ranking", toJson ranking)]
