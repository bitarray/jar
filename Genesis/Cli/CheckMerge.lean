/-
  genesis_check_merge CLI

  Input:  {"reviews": [...], "metaReviews": [...], "indices": [...]}
  Output: {"ready": bool, "mergeWeight": N, "rejectWeight": N, "totalWeight": N}
-/

import Genesis.Cli.Common

open Lean (Json ToJson toJson fromJson? FromJson)
open Genesis.Cli

def main : IO UInt32 := runJsonPipe fun j => do
  let reviews ← IO.ofExcept (j.getObjValAs? (List EmbeddedReview) "reviews")
  let metaReviews ← IO.ofExcept (j.getObjValAs? (List MetaReview) "metaReviews")
  let indices ← IO.ofExcept (j.getObjValAs? (List CommitIndex) "indices")
  let state := reconstructState indices
  -- Filter reviews by meta-review
  let approved := filterReviews reviews metaReviews (state.reviewerWeight ·)
  -- Tally weighted merge votes
  let mergeWeight := approved.foldl (fun acc r =>
    if r.verdict == .merge then acc + state.reviewerWeight r.reviewer else acc) 0
  let rejectWeight := approved.foldl (fun acc r =>
    if r.verdict == .notMerge then acc + state.reviewerWeight r.reviewer else acc) 0
  let totalWeight := state.contributors.foldl (fun acc c =>
    if c.isReviewer then acc + c.weight else acc) 0
  let ready : Bool := mergeWeight * 2 > totalWeight
  return Json.mkObj [
    ("ready", toJson ready),
    ("mergeWeight", toJson mergeWeight),
    ("rejectWeight", toJson rejectWeight),
    ("totalWeight", toJson totalWeight)
  ]
