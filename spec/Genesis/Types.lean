/-
  Genesis Protocol — Core Types

  ## Source of Truth

  The sole input is the git commit history of master (force-push disabled).

  ## Reward Model

  Rewards are only calculated on signed commits (by GitHub merge or bot GPG key).

  ## Spec Consistency Rule

  For commit N, any spec version ≥ the spec at commit N-1 must produce the
  same CommitIndex. The spec is backward compatible but NOT necessarily
  forward compatible — older spec versions may not handle newer commits
  (e.g., they lack support for new fields like prCreatedAt).

  In practice: the current spec on master evaluates ALL past commits correctly.
  Spec changes MUST preserve results for all already-scored commits. This is
  enforced by CI (`genesis-replay.sh --verify`).

  Each evaluation produces a list of non-negative, capped balance deltas:
    (+contributor_reward, +reviewer1_reward, +reviewer2_reward, ...)

  Final balance for any contributor = Σ of all their deltas across history.

  ## Scoring Model

  Reviewers rank N past commits + the current PR on three dimensions
  (difficulty, novelty, designQuality). Rankings are constrained —
  inflating one requires deflating another, making bias visible.

  Meta-reviews (thumbs up/down) filter low-quality reviews before scoring.
  Score is derived from the weighted lower-quantile of implied scores,
  providing BFT-like safety up to 66% honest weight.

  Guardrails:
  - No delta can be negative (no transfers/slashing).
  - Contributor reward per commit is capped.
  - Reviewer reward per commit is capped.
  - Worst-case damage from a malicious spec = one commit's capped rewards.
  - Comparison targets are validated at spec time — forged targets → zero reward.

  ## Variant System

  Protocol parameters are grouped in GenesisConfig. The active config is
  selected by epoch via a schedule (genesisSchedule), following the
  blockchain hard-fork pattern. Parameter changes are non-retroactive:
  PRs opened before the activation use the old config.

  GenesisVariant extends GenesisConfig with variant-specific functions
  (like JamVariant extends JamConfig in the JAR spec).
-/

/-! ### Genesis Config & Variant -/

/-- Protocol parameters. Mirrors JamConfig's role in the JAR spec.
    All configurable constants that affect scoring and state reconstruction
    are defined here. Changes take effect via the activation schedule. -/
structure GenesisConfig where
  name : String
  reviewerThreshold : Nat
  minReviews : Nat
  rankingSize : Nat
  quantileNum : Nat
  quantileDen : Nat
  designWeight : Nat
  numWeightedDimensions : Nat
  /-- When true, comparison targets are selected by global quality ranking (v2)
      instead of time-based buckets (v1). Requires ranking.json on genesis-state. -/
  useRankedTargets : Bool
  deriving Repr

/-- Protocol configuration typeclass. All configurable constants are
    direct fields, accessed as GenesisVariant.reviewerThreshold etc.
    Mirrors JamConfig in the JAR spec.
    Future variant-specific functions can be added as fields here
    (like JamVariant.pvmRun extends JamConfig). -/
class GenesisVariant extends GenesisConfig

/-! ### Standard Variants -/

def GenesisConfig.v1 : GenesisConfig where
  name := "genesis_v1"
  reviewerThreshold := 500
  minReviews := 1
  rankingSize := 7
  quantileNum := 1
  quantileDen := 3
  designWeight := 3
  numWeightedDimensions := 5
  useRankedTargets := false

instance GenesisVariant.v1 : GenesisVariant where
  toGenesisConfig := .v1

def GenesisConfig.v2 : GenesisConfig where
  name := "genesis_v2"
  reviewerThreshold := 500
  minReviews := 1
  rankingSize := 7
  quantileNum := 1
  quantileDen := 3
  designWeight := 3
  numWeightedDimensions := 5
  useRankedTargets := true

instance GenesisVariant.v2 : GenesisVariant where
  toGenesisConfig := .v2

/-! ### Core Types -/

/-- GitHub username. -/
abbrev ContributorId := String
/-- Full git commit SHA (40 hex chars). -/
abbrev CommitId := String
abbrev PRId := Nat
abbrev Epoch := Nat
abbrev TokenAmount := Nat

/-- Exact rational arithmetic. No floats. -/
structure Ratio where
  num : Nat
  den : Nat
  den_pos : den > 0 := by omega
  deriving Repr

instance : BEq Ratio where
  beq a b := a.num * b.den == b.num * a.den

/-- Normalize a ratio by dividing both num and den by their GCD. -/
def Ratio.normalize (r : Ratio) : Ratio :=
  let g := Nat.gcd r.num r.den
  if hg : g ≤ 1 then r
  else
    have gpos : g > 0 := by omega
    have h : r.den / g > 0 :=
      Nat.div_pos (Nat.le_of_dvd r.den_pos (Nat.gcd_dvd_right r.num r.den)) gpos
    { num := r.num / g, den := r.den / g, den_pos := h }

def Ratio.mul (a b : Ratio) : Ratio :=
  Ratio.normalize { num := a.num * b.num,
                     den := a.den * b.den,
                     den_pos := Nat.mul_pos a.den_pos b.den_pos }

def Ratio.add (a b : Ratio) : Ratio :=
  Ratio.normalize { num := a.num * b.den + b.num * a.den,
                     den := a.den * b.den,
                     den_pos := Nat.mul_pos a.den_pos b.den_pos }

def Ratio.zero : Ratio where num := 0; den := 1
def Ratio.one : Ratio where num := 1; den := 1
def Ratio.ofNat (n : Nat) : Ratio where num := n; den := 1
def Ratio.toNat (r : Ratio) : Nat := r.num / r.den

instance : Inhabited Ratio where
  default := Ratio.zero

/-- Merge verdict from a reviewer. -/
inductive Verdict where
  | merge
  | notMerge
  deriving Repr, BEq

/-- A ranking of commits on one dimension. The list is ordered from
    best (rank 1) to worst (rank N). Each entry is a CommitId.
    The current PR and all comparison targets must appear exactly once. -/
abbrev Ranking := List CommitId

/-- A review: rankings on three dimensions plus a merge verdict.

    The reviewer ranks all N comparison targets + the current PR
    from best to worst on each dimension. Rankings are constrained:
    inflating one commit requires deflating another.

    If a reviewer submits multiple reviews on a PR, only the last
    one counts (the bot records only the final review per reviewer). -/
structure EmbeddedReview where
  reviewer : ContributorId
  /-- Rankings from best to worst on each dimension.
      Each list must contain exactly the comparison targets + the current PR. -/
  difficultyRanking : Ranking
  noveltyRanking : Ranking
  designQualityRanking : Ranking
  /-- Merge verdict. -/
  verdict : Verdict
  deriving Repr

/-- A meta-review: thumbs up or down on another reviewer's review.
    Low-quality or biased reviews accumulate thumbs down and get
    excluded from scoring. -/
structure MetaReview where
  /-- Who submitted this meta-review. -/
  metaReviewer : ContributorId
  /-- Which reviewer's review is being evaluated. -/
  targetReviewer : ContributorId
  /-- Thumbs up (true) or thumbs down (false). -/
  approve : Bool
  deriving Repr


/-- Score for a single commit, per dimension.
    Each dimension is a percentile rank (0-100) of the current PR
    among the ranked items. 100 = ranked first, 0 = ranked last. -/
structure CommitScore where
  difficulty : Nat
  novelty : Nat
  designQuality : Nat
  deriving Repr, BEq

/-- Combined weighted score from CommitScore.
    designWeight and numWeightedDimensions come from the active variant.
    Result is 0-100 (normalized). -/
def CommitScore.weighted [gv : GenesisVariant] (s : CommitScore) : Nat :=
  (s.difficulty + s.novelty + gv.designWeight * s.designQuality) / gv.numWeightedDimensions

/-- weightDelta is at most 100 when all dimension scores are at most 100 (for v1). -/
theorem CommitScore.weighted_le_100_v1 (s : CommitScore)
    (hd : s.difficulty ≤ 100) (hn : s.novelty ≤ 100) (hq : s.designQuality ≤ 100) :
    (letI := GenesisVariant.v1; s.weighted) ≤ 100 := by
  simp only [weighted, GenesisVariant.v1, GenesisConfig.v1]
  omega

/-- A signed commit and the data needed to compute its rewards. -/
structure SignedCommit where
  id : CommitId
  prId : PRId
  author : ContributorId
  mergeEpoch : Epoch
  /-- PR's created_at timestamp (immutable, set by GitHub at PR open).
      Used to anchor comparison target selection: only commits merged
      before this timestamp are eligible as targets. For legacy commits
      without this field, falls back to mergeEpoch. -/
  prCreatedAt : Epoch
  /-- The comparison targets selected by the bot.
      Validated against hash(prId) + prCreatedAt at spec time. -/
  comparisonTargets : List CommitId
  /-- Reviews: each reviewer's rankings and verdicts. -/
  reviews : List EmbeddedReview
  /-- Meta-reviews: thumbs up/down on reviews. -/
  metaReviews : List MetaReview
  /-- Whether the founder used the escape hatch to merge. -/
  founderOverride : Bool
  deriving Repr

/-- Contributor state — derived from processing the full history. -/
structure Contributor where
  id : ContributorId
  /-- Total tokens earned (monotonically increasing, capped per commit). -/
  balance : TokenAmount
  /-- Sum of weighted commit scores across all authored PRs.
      Linear in individual scores → Sybil-neutral. -/
  weight : Nat
  /-- Whether this contributor has activated as a reviewer. -/
  isReviewer : Bool
  deriving Repr
