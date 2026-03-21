/-
  Genesis Protocol — Scoring & Reward Computation

  Scoring is based on rankings of past commits + the current PR.

  Flow:
  1. PR opened → bot selects N comparison targets from hash(prId)
  2. Reviewers rank all N+1 commits (targets + current PR) on 3 dimensions
  3. Reviewers submit detailed comments + merge verdict
  4. Other reviewers meta-review (thumbs up/down) to filter bad reviews
  5. Bot merges when >50% weighted merge votes (or founder override)
  6. Bot records rankings + meta-reviews in the signed merge commit
  7. Spec validates targets, filters reviews by meta-review, derives
     score using weighted lower-quantile

  See Design.lean for deferred features.
-/

import Genesis.Types

/-! ### Configurable Parameters

  These are Lean constants, easy to adjust for experimentation.
-/

/-- Number of past commits a reviewer must rank alongside the current PR.
    Total items ranked = rankingSize + 1 (targets + current PR).
    Higher = more context for scoring, more effort per review.
    Lower = faster reviews, less context. -/
def rankingSize : Nat := 7

/-- Quantile for the weighted quantile scoring function, as num/den.
    The score is the value at this quantile of the weighted distribution.

    - 1/2 (median): safe up to 50% honest. Symmetric.
    - 1/3 (lower third): safe up to 66% honest for inflation.
      Meta-review covers deflation below 50%.
    - 2/5 (lower two-fifths): safe up to 60% honest for inflation.

    Lower quantile = more conservative scoring, higher Sybil resistance. -/
def quantileNum : Nat := 1
def quantileDen : Nat := 3

/-! ### Evaluation Parameters -/

/-- Parameters for the evaluation path (scoring + state reconstruction).
    Reward parameters (emission, caps, splits) are deferred to finalization
    and documented in Design.lean. -/
structure EvalParams where
  /-- Minimum weight to activate as a reviewer. -/
  reviewerThreshold : Nat
  /-- Minimum number of approved reviews required for scoring. -/
  minReviews : Nat
  deriving Repr

def EvalParams.default : EvalParams where
  reviewerThreshold := 500
  minReviews := 1

/-! ### Comparison Target Selection -/

/-- Maps a PR ID to a pseudo-random natural number for target selection. -/
def prIdHash (prId : PRId) : Nat :=
  let a := 2654435761
  (prId * a) % (2^32)

/-- Select comparison targets from past scored commits.
    Divides into buckets, picks one per bucket using hash(prId). -/
def selectComparisonTargets
    (pastCommitIds : List CommitId)
    (numTargets : Nat)
    (prId : PRId) : List CommitId :=
  let n := pastCommitIds.length
  if n == 0 then []
  else
    let k := min numTargets n
    let hash := prIdHash prId
    List.range k |>.map fun i =>
      let bucketStart := n * i / k
      let bucketEnd := n * (i + 1) / k
      let bucketSize := bucketEnd - bucketStart
      if bucketSize == 0 then
        pastCommitIds[bucketStart]!
      else
        let idx := bucketStart + (hash + i * 7) % bucketSize
        pastCommitIds[idx]!

/-- Validate comparison targets in a signed commit. -/
def validateComparisonTargets
    (commit : SignedCommit)
    (pastCommitIds : List CommitId) : Bool :=
  if pastCommitIds.isEmpty then commit.comparisonTargets.isEmpty
  else
    let expected := selectComparisonTargets pastCommitIds
      (min rankingSize pastCommitIds.length) commit.prId
    commit.comparisonTargets == expected

/-! ### Meta-Review Filtering

  Reviews are filtered by meta-reviews (thumbs up/down) before scoring.
  A review is excluded if its net meta-review weight is negative
  (more weighted thumbs-down than thumbs-up).
-/

/-- Compute net meta-review weight for a specific reviewer's review.
    Positive = approved, negative = rejected, zero = no meta-reviews. -/
def metaReviewNet
    (metaReviews : List MetaReview)
    (targetReviewer : ContributorId)
    (getWeight : ContributorId → Nat) : Int :=
  metaReviews.foldl (fun acc (mr : MetaReview) =>
    if mr.targetReviewer == targetReviewer then
      let w := (getWeight mr.metaReviewer : Int)
      if mr.approve then acc + w else acc - w
    else acc
  ) 0

/-- Filter reviews: keep only those with non-negative meta-review net weight.
    Reviews with no meta-reviews are kept (net = 0). -/
def filterReviews
    (reviews : List EmbeddedReview)
    (metaReviews : List MetaReview)
    (getWeight : ContributorId → Nat) : List EmbeddedReview :=
  reviews.filter fun (r : EmbeddedReview) =>
    metaReviewNet metaReviews r.reviewer getWeight ≥ 0

/-! ### Score Derivation from Rankings

  Each reviewer ranks N+1 commits (targets + current PR).
  The score for each dimension is the PR's percentile rank (0-100)
  among the ranked items. Rank 1 of N = 100, rank N of N = 0.

  This is independent of past scores — purely positional. The score
  is always 0-100, making weightDelta predictable and extensible.
-/

/-- Compute the percentile rank (0-100) of the current PR in a ranking.
    Ranking is best-to-worst. Position 0 (first) = 100, last = 0.
    If the PR is not in the ranking, returns 0. -/
def percentileFromRanking
    (ranking : Ranking)
    (currentPR : CommitId) : Nat :=
  let n := ranking.length
  if n ≤ 1 then 100  -- sole item gets 100
  else
    match ranking.findIdx? (· == currentPR) with
    | none => 0
    | some pos => (n - 1 - pos) * 100 / (n - 1)

/-- percentileFromRanking always returns a value ≤ 100. -/
theorem percentileFromRanking_le_100 (ranking : Ranking) (pr : CommitId) :
    percentileFromRanking ranking pr ≤ 100 := by
  simp only [percentileFromRanking]
  split <;> rename_i h
  · -- n ≤ 1: returns 100
    omega
  · -- n > 1: match on findIdx?
    split
    · -- none: returns 0
      omega
    · -- some pos: (n - 1 - pos) * 100 / (n - 1) ≤ 100
      rename_i pos _
      apply Nat.div_le_of_le_mul
      exact Nat.mul_le_mul_right 100 (Nat.sub_le ..)

/-- Derive a score for the current PR from one reviewer's rankings.
    Each dimension is a percentile rank (0-100). -/
def scoreFromReview
    (review : EmbeddedReview)
    (currentPR : CommitId) : CommitScore :=
  { difficulty := percentileFromRanking review.difficultyRanking currentPR,
    novelty := percentileFromRanking review.noveltyRanking currentPR,
    designQuality := percentileFromRanking review.designQualityRanking currentPR }

/-! ### Weighted Lower-Quantile

  The score at the configured quantile of the weighted distribution.
  With quantile = 1/3: the value where 1/3 of weight is below.
  Sybil inflation scores sit at the top and are ignored.
  Safe up to 66% honest for inflation; meta-review covers deflation.
-/

/-- Weighted quantile of a list of (weight, value) pairs.
    Returns the value at the point where `quantileNum/quantileDen`
    of the total weight has been accumulated (walking from low to high). -/
def weightedQuantile (entries : List (Nat × Nat))
    (qNum : Nat := quantileNum) (qDen : Nat := quantileDen) : Nat :=
  if entries.isEmpty then 0
  else
    let sorted := entries.toArray.qsort (fun a b => a.2 < b.2) |>.toList
    let totalWeight := sorted.foldl (fun acc (w, _) => acc + w) 0
    if totalWeight == 0 then 0
    else
      -- Target: first value where cumulative weight ≥ totalWeight * qNum / qDen
      let target := totalWeight * qNum / qDen
      let (_, result) := sorted.foldl (fun (cumWeight, best) (w, v) =>
        let newCum := cumWeight + w
        if cumWeight ≤ target then (newCum, v) else (newCum, best)
      ) (0, sorted.head!.2)
      result

/-- Derive a score for the current PR from all approved reviews.

    For each reviewer, compute the percentile score from their rankings.
    Then take the weighted quantile across all reviewers per dimension.

    Reviews from non-reviewers (weight = 0) are silently ignored. -/
def deriveScore
    (reviews : List EmbeddedReview)
    (currentPR : CommitId)
    (getWeight : ContributorId → Nat) : CommitScore :=
  let weightedScores := reviews.filterMap fun (r : EmbeddedReview) =>
    let w := getWeight r.reviewer
    if w == 0 then none
    else some (w, scoreFromReview r currentPR)
  if weightedScores.isEmpty then { difficulty := 0, novelty := 0, designQuality := 0 }
  else
    let dEntries := weightedScores.map fun (w, s) => (w, s.difficulty)
    let nEntries := weightedScores.map fun (w, s) => (w, s.novelty)
    let qEntries := weightedScores.map fun (w, s) => (w, s.designQuality)
    { difficulty := weightedQuantile dEntries
      novelty := weightedQuantile nEntries
      designQuality := weightedQuantile qEntries }

/-! ### Score Computation -/

/-- Compute the score for a single signed commit.

    Steps:
    1. Validate comparison targets against hash(prId).
    2. Filter reviews by meta-review (exclude thumbed-down reviews).
    3. Check minimum approved reviews from weighted reviewers.
    4. Derive score from rankings using weighted lower-quantile.

    Returns the CommitScore (percentile-based, 0-100 per dimension).
    Reward computation is deferred to finalization (see Design.lean). -/
def commitScore
    (ep : EvalParams)
    (commit : SignedCommit)
    (pastCommitIds : List CommitId)
    (getWeight : ContributorId → Nat)
    : CommitScore :=
  let zeroScore : CommitScore := { difficulty := 0, novelty := 0, designQuality := 0 }
  -- Step 1: Validate comparison targets
  if !validateComparisonTargets commit pastCommitIds then
    zeroScore
  else
    -- Step 2: Filter reviews by meta-review
    let approvedReviews := filterReviews commit.reviews commit.metaReviews getWeight
    -- Step 3: Check minimum approved reviews from weighted reviewers
    let weightedReviews := approvedReviews.filter fun (r : EmbeddedReview) =>
      getWeight r.reviewer > 0
    if weightedReviews.length < ep.minReviews then
      zeroScore
    else
      -- Step 4: Derive score (percentile-based)
      deriveScore weightedReviews commit.id getWeight
