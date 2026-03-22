/-
  genesis_ranking CLI

  Computes the global quality ranking from pairwise review evidence.

  Input:  {"signedCommits": [...]}
  Output: {"ranking": ["hash1", "hash2", ...]}  (best to worst)
-/

import Genesis.Cli.Common

open Lean (Json ToJson toJson fromJson? FromJson)
open Genesis.Cli

def main : IO UInt32 := runJsonPipe fun j => do
  let signedCommits ← IO.ofExcept (j.getObjValAs? (List SignedCommit) "signedCommits")
  -- Use v1 variant for designWeight (same across v1/v2)
  letI := GenesisVariant.v1
  let ranking := computeRanking signedCommits
  return Json.mkObj [("ranking", toJson ranking)]
