/-
  genesis_finalize CLI

  NOTE: Token reward finalization is future work. The reward parameters
  (emission, caps, contributor/reviewer splits) have not been defined yet.
  This tool currently computes only weights from the indices.

  Input:  {"indices": [...]}
  Output: {"note": "...", "weights": [...]}
-/

import Genesis.Cli.Common

open Lean (Json ToJson toJson fromJson? FromJson)
open Genesis.Cli

def main : IO UInt32 := runJsonPipe fun j => do
  let indices ← IO.ofExcept (j.getObjValAs? (List CommitIndex) "indices")
  let weights := finalWeights indices
  let weightsJson := weights.map fun (id, weight) =>
    Json.mkObj [("id", toJson id), ("weight", toJson weight)]
  return Json.mkObj [
    ("note", Json.str "Token reward finalization is future work. Only weights are computed."),
    ("weights", Json.arr weightsJson.toArray)
  ]
