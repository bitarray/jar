/-
  Genesis Protocol — Test Harness

  Direct Lean function tests for Genesis scoring, ranking, and state.
  Each test category calls the spec function and compares against expected output.
-/

import Genesis.Types
import Genesis.Scoring
import Genesis.State
import Genesis.Json

namespace Genesis.Test

open Lean (Json ToJson FromJson toJson fromJson?)
open Genesis.Json

/-! ### Test Utilities -/

def compareJson (name : String) (expected actual : Json) : IO Bool := do
  if expected == actual then
    IO.println s!"  ✓ {name}"
    return true
  else
    IO.eprintln s!"  ✗ {name}"
    IO.eprintln s!"    expected: {expected}"
    IO.eprintln s!"    actual:   {actual}"
    return false

/-! ### Select Targets Tests -/

structure SelectTargetsInput where
  prId : PRId
  prCreatedAt : Epoch
  indices : List CommitIndex
  ranking : Option (List CommitId) := none

structure SelectTargetsOutput where
  targets : List CommitId

def runSelectTargetsTest (input : SelectTargetsInput) : SelectTargetsOutput :=
  let v := activeVariant input.prCreatedAt
  letI := v
  let scoredCommits := input.indices.map fun idx => (idx.commitHash, idx.epoch)
  let eligible := scoredCommits.filter (fun (_, epoch) => epoch < input.prCreatedAt)
  let numTargets := min v.rankingSize eligible.length
  let targets :=
    if v.useRankedTargets then
      match input.ranking with
      | some r => selectComparisonTargetsRanked r scoredCommits numTargets input.prId input.prCreatedAt
      | none => []
    else
      selectComparisonTargets scoredCommits numTargets input.prId input.prCreatedAt
  { targets }

/-! ### Evaluate Tests -/

structure EvaluateInput where
  commit : SignedCommit
  pastIndices : List CommitIndex
  ranking : Option (List CommitId) := none

def runEvaluateTest (input : EvaluateInput) : CommitIndex :=
  evaluate input.pastIndices input.commit input.ranking

/-! ### Check Merge Tests -/

structure CheckMergeInput where
  reviews : List EmbeddedReview
  metaReviews : List MetaReview
  indices : List CommitIndex

structure CheckMergeOutput where
  ready : Bool
  mergeWeight : Nat
  rejectWeight : Nat
  totalWeight : Nat

def runCheckMergeTest (input : CheckMergeInput) : CheckMergeOutput :=
  let state := reconstructState input.indices
  let getWeight := state.reviewerWeight
  let approved := filterReviews input.reviews input.metaReviews getWeight
  let weighted := approved.filter fun r => getWeight r.reviewer > 0
  let mergeWeight := weighted.foldl (fun acc r =>
    if r.verdict == .merge then acc + getWeight r.reviewer else acc) 0
  let rejectWeight := weighted.foldl (fun acc r =>
    if r.verdict == .notMerge then acc + getWeight r.reviewer else acc) 0
  let totalWeight := mergeWeight + rejectWeight
  let ready := totalWeight > 0 && mergeWeight * 2 > totalWeight
  { ready, mergeWeight, rejectWeight, totalWeight }

/-! ### Ranking Tests -/

structure RankingInput where
  signedCommits : List SignedCommit
  indices : List CommitIndex

structure BTScore where
  commit : CommitId
  mu : Int
  sigma2 : Nat
  deriving Repr, BEq

structure RankingOutput where
  ranking : List CommitId
  scores : Option (List BTScore) := none

def runRankingTest (input : RankingInput) : RankingOutput :=
  let contexts := input.signedCommits.zip input.indices |>.map fun (commit, _) =>
    let state := reconstructState (input.indices.takeWhile (·.commitHash != commit.id))
    let v := activeVariant commit.prCreatedAt
    { variant := v, getWeight := state.reviewerWeight : RankingCommitCtx }
  let useBT := contexts.getLast?.map (·.variant.useBradleyTerry) |>.getD false
  if useBT then
    let (ranking, btState) := computeRankingBTWithState input.signedCommits contexts
    let scores := ranking.map fun c =>
      let entry := btLookup btState c
      { commit := c, mu := entry.mu, sigma2 := entry.sigma2 : BTScore }
    { ranking, scores := some scores }
  else
    { ranking := computeRanking input.signedCommits contexts }

/-! ### Finalize Tests -/

structure FinalizeInput where
  indices : List CommitIndex

structure FinalizeOutput where
  weights : List (ContributorId × Nat)

def runFinalizeTest (input : FinalizeInput) : FinalizeOutput :=
  { weights := finalWeights input.indices }

/-! ### Scoring Unit Tests -/

inductive ScoringFunction where
  | percentileFromRanking
  | weightedQuantile

structure ScoringInput where
  function : ScoringFunction
  -- percentileFromRanking fields
  ranking : Option (List CommitId) := none
  currentPR : Option CommitId := none
  -- weightedQuantile fields
  entries : Option (List (Nat × Nat)) := none

structure ScoringOutput where
  result : Nat

def runScoringTest (input : ScoringInput) : ScoringOutput :=
  match input.function with
  | .percentileFromRanking =>
    let ranking := input.ranking.getD []
    let pr := input.currentPR.getD .invalid
    { result := percentileFromRanking ranking pr }
  | .weightedQuantile =>
    let entries := input.entries.getD []
    letI := GenesisVariant.v1
    { result := weightedQuantile entries }

end Genesis.Test
