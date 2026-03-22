/-
  Genesis Protocol — JSON Serialization

  Manual `FromJson`/`ToJson` instances for all Genesis types,
  for interchange between the Lean spec and the GitHub Actions bot.
-/

import Lean.Data.Json
import Lean.Data.Json.FromToJson
import Genesis.Types
import Genesis.Scoring
import Genesis.State

namespace Genesis.Json

open Lean (Json ToJson FromJson toJson fromJson?)

-- ============================================================================
-- Ratio
-- ============================================================================

instance : ToJson Ratio where
  toJson r := Json.mkObj [("num", toJson r.num), ("den", toJson r.den)]

instance : FromJson Ratio where
  fromJson? j := do
    let num ← j.getObjValAs? Nat "num"
    let den ← j.getObjValAs? Nat "den"
    if h : den > 0 then
      return { num := num, den := den, den_pos := h }
    else
      .error "Ratio.den must be > 0"

-- ============================================================================
-- Verdict
-- ============================================================================

instance : ToJson Verdict where
  toJson
    | .merge => Json.str "merge"
    | .notMerge => Json.str "notMerge"

instance : FromJson Verdict where
  fromJson?
    | Json.str "merge" => .ok .merge
    | Json.str "notMerge" => .ok .notMerge
    | j => .error s!"expected \"merge\" or \"notMerge\", got {j}"


-- ============================================================================
-- CommitScore (percentile ranks, 0-100)
-- ============================================================================

instance : ToJson CommitScore where
  toJson s := Json.mkObj [
    ("difficulty", toJson s.difficulty),
    ("novelty", toJson s.novelty),
    ("designQuality", toJson s.designQuality)
  ]

instance : FromJson CommitScore where
  fromJson? j := do
    let difficulty ← j.getObjValAs? Nat "difficulty"
    let novelty ← j.getObjValAs? Nat "novelty"
    let designQuality ← j.getObjValAs? Nat "designQuality"
    return { difficulty, novelty, designQuality }

-- ============================================================================
-- EmbeddedReview
-- ============================================================================

instance : ToJson EmbeddedReview where
  toJson r := Json.mkObj [
    ("reviewer", toJson r.reviewer),
    ("difficultyRanking", toJson r.difficultyRanking),
    ("noveltyRanking", toJson r.noveltyRanking),
    ("designQualityRanking", toJson r.designQualityRanking),
    ("verdict", toJson r.verdict)
  ]

instance : FromJson EmbeddedReview where
  fromJson? j := do
    let reviewer ← j.getObjValAs? String "reviewer"
    let difficultyRanking ← j.getObjValAs? (List String) "difficultyRanking"
    let noveltyRanking ← j.getObjValAs? (List String) "noveltyRanking"
    let designQualityRanking ← j.getObjValAs? (List String) "designQualityRanking"
    let verdict ← j.getObjValAs? Verdict "verdict"
    return { reviewer, difficultyRanking, noveltyRanking, designQualityRanking, verdict }

-- ============================================================================
-- MetaReview
-- ============================================================================

instance : ToJson MetaReview where
  toJson mr := Json.mkObj [
    ("metaReviewer", toJson mr.metaReviewer),
    ("targetReviewer", toJson mr.targetReviewer),
    ("approve", toJson mr.approve)
  ]

instance : FromJson MetaReview where
  fromJson? j := do
    let metaReviewer ← j.getObjValAs? String "metaReviewer"
    let targetReviewer ← j.getObjValAs? String "targetReviewer"
    let approve ← j.getObjValAs? Bool "approve"
    return { metaReviewer, targetReviewer, approve }


-- ============================================================================
-- SignedCommit
-- ============================================================================

instance : ToJson SignedCommit where
  toJson c := Json.mkObj [
    ("id", toJson c.id),
    ("prId", toJson c.prId),
    ("author", toJson c.author),
    ("mergeEpoch", toJson c.mergeEpoch),
    ("prCreatedAt", toJson c.prCreatedAt),
    ("comparisonTargets", toJson c.comparisonTargets),
    ("reviews", toJson c.reviews),
    ("metaReviews", toJson c.metaReviews),
    ("founderOverride", toJson c.founderOverride)
  ]

instance : FromJson SignedCommit where
  fromJson? j := do
    let id ← j.getObjValAs? String "id"
    let prId ← j.getObjValAs? Nat "prId"
    let author ← j.getObjValAs? String "author"
    let mergeEpoch ← j.getObjValAs? Nat "mergeEpoch"
    -- Backward compat: legacy commits without prCreatedAt use mergeEpoch
    let prCreatedAt ← (j.getObjValAs? Nat "prCreatedAt") <|> pure mergeEpoch
    let comparisonTargets ← j.getObjValAs? (List String) "comparisonTargets"
    let reviews ← j.getObjValAs? (List EmbeddedReview) "reviews"
    let metaReviews ← j.getObjValAs? (List MetaReview) "metaReviews"
    let founderOverride ← j.getObjValAs? Bool "founderOverride"
    return { id, prId, author, mergeEpoch, prCreatedAt, comparisonTargets, reviews, metaReviews, founderOverride }

-- ============================================================================
-- Contributor
-- ============================================================================

instance : ToJson Contributor where
  toJson c := Json.mkObj [
    ("id", toJson c.id),
    ("balance", toJson c.balance),
    ("weight", toJson c.weight),
    ("isReviewer", toJson c.isReviewer)
  ]

instance : FromJson Contributor where
  fromJson? j := do
    let id ← j.getObjValAs? String "id"
    let balance ← j.getObjValAs? Nat "balance"
    let weight ← j.getObjValAs? Nat "weight"
    let isReviewer ← j.getObjValAs? Bool "isReviewer"
    return { id, balance, weight, isReviewer }

-- ============================================================================
-- CommitIndex
-- ============================================================================

instance : ToJson CommitIndex where
  toJson idx := Json.mkObj [
    ("commitHash", toJson idx.commitHash),
    ("epoch", toJson idx.epoch),
    ("score", toJson idx.score),
    ("contributor", toJson idx.contributor),
    ("weightDelta", toJson idx.weightDelta),
    ("reviewers", toJson idx.reviewers),
    ("metaReviews", toJson idx.metaReviews),
    ("mergeVotes", toJson idx.mergeVotes),
    ("rejectVotes", toJson idx.rejectVotes),
    ("founderOverride", toJson idx.founderOverride)
  ]

instance : FromJson CommitIndex where
  fromJson? j := do
    let commitHash ← j.getObjValAs? String "commitHash"
    let epoch ← j.getObjValAs? Nat "epoch"
    let score ← j.getObjValAs? CommitScore "score"
    let contributor ← j.getObjValAs? String "contributor"
    let weightDelta ← j.getObjValAs? Nat "weightDelta"
    let reviewers ← j.getObjValAs? (List String) "reviewers"
    let metaReviews ← j.getObjValAs? (List MetaReview) "metaReviews"
    let mergeVotes ← j.getObjValAs? (List String) "mergeVotes"
    let rejectVotes ← j.getObjValAs? (List String) "rejectVotes"
    let founderOverride ← j.getObjValAs? Bool "founderOverride"
    return { commitHash, epoch, score, contributor, weightDelta, reviewers,
             metaReviews, mergeVotes, rejectVotes, founderOverride }

end Genesis.Json
