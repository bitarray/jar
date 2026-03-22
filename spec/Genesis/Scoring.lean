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

/-! ### Comparison Target Selection -/

/-- Maps a PR ID to a pseudo-random natural number for target selection. -/
def prIdHash (prId : PRId) : Nat :=
  let a := 2654435761
  (prId * a) % (2^32)

/-- Select comparison targets from past scored commits.
    Only commits merged before prCreatedAt are eligible.
    Divides eligible commits into buckets, picks one per bucket using hash(prId). -/
def selectComparisonTargets
    (scoredCommits : List (CommitId × Epoch))
    (numTargets : Nat)
    (prId : PRId)
    (prCreatedAt : Epoch) : List CommitId :=
  let eligible := scoredCommits.filter (fun (_, epoch) => epoch < prCreatedAt)
  let pastCommitIds := eligible.map (·.1)
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
def weightedQuantile [gv : GenesisVariant] (entries : List (Nat × Nat))
    (qNum : Nat := gv.quantileNum) (qDen : Nat := gv.quantileDen) : Nat :=
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
def deriveScore [GenesisVariant]
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

/-! ### Score Computation (defined after validateComparisonTargets below) -/

/-! ### Global Ranking (v2 target selection)

  Build a global quality ordering from pairwise review evidence.
  Each review's 3 dimension rankings are aggregated into one ordering
  (1×diff + 1×nov + 3×design position). Pairwise wins are accumulated
  across all reviews. Net-wins determines the global rank.
-/

/-- Compute aggregate position for each commit in a review.
    Lower = better. Uses weighted positions: diff + nov + designWeight×design. -/
def aggregateReviewRanking [gv : GenesisVariant]
    (review : EmbeddedReview) : List (CommitId × Nat) :=
  let commits := review.designQualityRanking
  commits.map fun c =>
    let dPos := review.difficultyRanking.findIdx? (· == c) |>.getD review.difficultyRanking.length
    let nPos := review.noveltyRanking.findIdx? (· == c) |>.getD review.noveltyRanking.length
    let qPos := review.designQualityRanking.findIdx? (· == c) |>.getD review.designQualityRanking.length
    (c, dPos + nPos + gv.designWeight * qPos)

/-- Extract pairwise outcomes from a single review.
    Returns list of (winner, loser) pairs. -/
def extractPairwise [GenesisVariant] (review : EmbeddedReview) : List (CommitId × CommitId) :=
  let ranked := aggregateReviewRanking review
  let sorted := ranked.toArray.qsort (fun a b => a.2 < b.2) |>.toList
  let commits := sorted.map (·.1)
  let indexed := commits.zip (List.range commits.length)
  indexed.foldl (fun acc (winner, i) =>
    acc ++ (commits.drop (i + 1)).map (fun loser => (winner, loser))
  ) []

/-- Accumulate pairwise wins from a single review into a map: commitId → set of commitIds it beats. -/
def accumulatePairwiseFromReview [GenesisVariant]
    (review : EmbeddedReview)
    (existing : List (CommitId × List CommitId)) : List (CommitId × List CommitId) :=
  let pairs := extractPairwise review
  pairs.foldl (fun acc (winner, loser) =>
    match acc.find? (fun (c, _) => c == winner) with
    | some (_, losers) =>
      if losers.contains loser then acc
      else acc.map (fun (c, ls) => if c == winner then (c, ls ++ [loser]) else (c, ls))
    | none => acc ++ [(winner, [loser])]
  ) existing

/-- Select the 1/3 quantile reviewer for a commit.
    Mirrors the scoring system's Sybil resistance: sort reviewers by how
    conservatively they ranked the current commit (worst position first),
    walk from most conservative accumulating weight, pick the reviewer
    whose cumulative weight crosses the 1/3 threshold.

    With a single reviewer, always picks that reviewer.
    With 2/3 Sybil inflating, picks an honest conservative reviewer. -/
def selectQuantileReviewer [gv : GenesisVariant]
    (reviews : List EmbeddedReview)
    (getWeight : ContributorId → Nat)
    (commitId : CommitId) : Option EmbeddedReview :=
  -- Filter to weighted reviewers
  let weighted := reviews.filterMap fun r =>
    let w := getWeight r.reviewer
    if w == 0 then none else some (r, w)
  if weighted.isEmpty then none
  else
    -- For each reviewer, find currentPR's position in their aggregate ranking
    -- Higher position = more conservative (ranked it worse)
    let withPos := weighted.map fun (r, w) =>
      let ranked := aggregateReviewRanking r
      let arr := ranked.toArray.qsort (fun a b => a.2 < b.2)
      let commits : List CommitId := arr.toList.map Prod.fst
      let pos := commits.findIdx? (· == commitId) |>.getD commits.length
      (r, w, pos)
    -- Sort by position descending (most conservative first = highest position)
    let sorted := withPos.toArray.qsort (fun (_, _, p1) (_, _, p2) => p1 > p2) |>.toList
    let totalWeight := sorted.foldl (fun acc (_, w, _) => acc + w) 0
    let target := totalWeight * gv.quantileNum / gv.quantileDen
    -- Walk from most conservative, pick at 1/3 threshold
    let (_, result) := sorted.foldl (fun (cumWeight, best) (r, w, _) =>
      let newCum := cumWeight + w
      if cumWeight ≤ target then (newCum, some r) else (newCum, best)
    ) (0, none)
    result

/-- Compute net-wins for each commit: |commits beaten| - |commits lost to|. -/
def computeNetWins (commits : List CommitId)
    (wins : List (CommitId × List CommitId)) : List (CommitId × Int) :=
  commits.map fun c =>
    let beaten := match wins.find? (fun (w, _) => w == c) with
      | some (_, losers) => losers.filter (commits.contains ·) |>.length
      | none => 0
    let lostTo := commits.foldl (fun acc other =>
      match wins.find? (fun (w, _) => w == other) with
      | some (_, losers) => if losers.contains c then acc + 1 else acc
      | none => acc
    ) 0
    (c, (beaten : Int) - (lostTo : Int))

/-- Compute global ranking from signed commits with per-commit weight functions.
    For each commit, selects the 1/3 quantile reviewer (Sybil-resistant) and
    uses only their pairwise evidence. Returns commit hashes best to worst. -/
def computeRanking [GenesisVariant]
    (signedCommits : List SignedCommit)
    (weightFns : List (ContributorId → Nat)) : List CommitId :=
  let allCommitIds := signedCommits.map (·.id)
  -- Accumulate pairwise evidence using quantile-selected reviewer per commit
  let pairwiseWins := signedCommits.zip weightFns |>.foldl
    (fun acc (commit, getWeight) =>
      match selectQuantileReviewer commit.reviews getWeight commit.id with
      | some review => accumulatePairwiseFromReview review acc
      | none => acc  -- no weighted reviewers
    ) ([] : List (CommitId × List CommitId))
  -- Compute net-wins and sort
  let netWins := computeNetWins allCommitIds pairwiseWins
  let indexed := netWins.zip (List.range netWins.length)
  let sorted := indexed.toArray.qsort (fun ((_, nw1), i1) ((_, nw2), i2) =>
    if nw1 != nw2 then nw1 > nw2 else i1 < i2
  ) |>.toList
  sorted.map (fun ((c, _), _) => c)

/-- Select comparison targets using global ranking (v2).
    Sorts eligible commits by their position in the ranking,
    then bucket-selects with hash jitter. -/
def selectComparisonTargetsRanked
    (ranking : List CommitId)
    (eligibleEpochs : List (CommitId × Epoch))
    (numTargets : Nat)
    (prId : PRId)
    (prCreatedAt : Epoch) : List CommitId :=
  let eligible := eligibleEpochs.filter (fun (_, epoch) => epoch < prCreatedAt)
  let eligibleIds := eligible.map (·.1)
  -- Filter ranking to eligible commits, preserving rank order
  let rankedEligible := ranking.filter (eligibleIds.contains ·)
  let n := rankedEligible.length
  if n == 0 then []
  else
    let k := min numTargets n
    let hash := prIdHash prId
    List.range k |>.map fun i =>
      let bucketStart := n * i / k
      let bucketEnd := n * (i + 1) / k
      let bucketSize := bucketEnd - bucketStart
      if bucketSize == 0 then
        rankedEligible[bucketStart]!
      else
        let idx := bucketStart + (hash + i * 7) % bucketSize
        rankedEligible[idx]!

/-! ### Target Validation & Score Computation -/

/-- Validate comparison targets in a signed commit.
    For v1 (useRankedTargets=false): validates against time-based selection.
    For v2 (useRankedTargets=true): validates against rank-based selection. -/
def validateComparisonTargets [gv : GenesisVariant]
    (commit : SignedCommit)
    (scoredCommits : List (CommitId × Epoch))
    (ranking : Option (List CommitId) := none) : Bool :=
  let eligible := scoredCommits.filter (fun (_, epoch) => epoch < commit.prCreatedAt)
  if eligible.isEmpty then commit.comparisonTargets.isEmpty
  else if gv.useRankedTargets then
    match ranking with
    | some r =>
      let expected := selectComparisonTargetsRanked r scoredCommits
        (min gv.rankingSize eligible.length) commit.prId commit.prCreatedAt
      commit.comparisonTargets == expected
    | none => false  -- v2 requires ranking
  else
    let expected := selectComparisonTargets scoredCommits
      (min gv.rankingSize eligible.length) commit.prId commit.prCreatedAt
    commit.comparisonTargets == expected

/-- Compute the score for a single signed commit.
    For v2, ranking is required for target validation. -/
def commitScore [gv : GenesisVariant]
    (commit : SignedCommit)
    (scoredCommits : List (CommitId × Epoch))
    (ranking : Option (List CommitId))
    (getWeight : ContributorId → Nat)
    : CommitScore :=
  let zeroScore : CommitScore := { difficulty := 0, novelty := 0, designQuality := 0 }
  if !(validateComparisonTargets commit scoredCommits ranking) then
    zeroScore
  else
    let approvedReviews := filterReviews commit.reviews commit.metaReviews getWeight
    let weightedReviews := approvedReviews.filter fun (r : EmbeddedReview) =>
      getWeight r.reviewer > 0
    if weightedReviews.length < gv.minReviews then
      zeroScore
    else
      deriveScore weightedReviews commit.id getWeight
