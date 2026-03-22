/-
  Genesis Protocol — Execution Model & State

  ## Variant System

  Protocol parameters are grouped in GenesisConfig/GenesisVariant.
  The active variant is selected by epoch via genesisSchedule, following
  the blockchain hard-fork pattern. Parameter changes are non-retroactive:
  each past index is processed under the variant active at its epoch,
  and each commit is scored under the variant active at its prCreatedAt.

  ## Spec Consistency Rule

  The current spec on master evaluates ALL past commits correctly.
  Spec changes (algorithms) must remain backward compatible.
  Parameter changes use the variant schedule — no backward compat needed.
  CI enforces via `genesis-replay.sh --verify`.
-/

import Genesis.Types
import Genesis.Scoring

/-! ### Genesis Constants -/

/-- GPG key fingerprints of trusted commit signers. -/
def trustedSigningKeys : Array String := #[
  "B5690EEEBB952194"  -- GitHub web-flow (2024-01-16, no expiry)
]

/-- The founding reviewer. -/
def founder : ContributorId := "sorpaas"

/-- The genesis commit. Scoring starts for commits AFTER this one. -/
def genesisCommit : CommitId := "4cc102a03d715c6bb2b119d8a3a1c49e4694751f"

/-- Initial weight for the founder. -/
def founderWeight : Nat := 1

/-! ### Activation Schedule -/

/-- Activation schedule. Each entry: (activationEpoch, variant).
    For a given epoch, the active variant is the last entry where
    activationEpoch ≤ epoch. Uses idx.epoch for state reconstruction,
    commit.prCreatedAt for scoring.

    To change a parameter:
    1. PR A: add new GenesisConfig + GenesisVariant instance. Safe (inactive).
    2. PR B: add entry here with a future activation epoch. Must merge before that date. -/
def genesisSchedule : List (Epoch × GenesisVariant) :=
  [ (0, GenesisVariant.v1)
  ]

/-- Resolve the active variant for a given epoch. -/
def activeVariant (epoch : Epoch) : GenesisVariant :=
  let applicable := genesisSchedule.filter (fun (e, _) => e ≤ epoch)
  match applicable.getLast? with
  | some (_, v) => v
  | none => GenesisVariant.v1

/-! ### CommitIndex — Output of evaluating one signed commit -/

/-- The output of evaluating a single signed commit.

    Contains only the raw facts needed for state reconstruction and
    future finalization. Token amounts are NOT stored here — they are
    computed during finalization using the current spec's parameters.
    This allows changing reward splits (e.g., 70/30 → 80/20) without
    re-evaluating history. -/
structure CommitIndex where
  /-- Hash of the signed commit that was evaluated. -/
  commitHash : CommitId
  /-- Epoch / timestamp of the commit. -/
  epoch : Epoch
  /-- The commit's score on each dimension. -/
  score : CommitScore
  /-- Who authored the commit. -/
  contributor : ContributorId
  /-- Weight change for the contributor (= score.weighted, 0-100).
      Needed at each step for reconstructing reviewer weights. -/
  weightDelta : Nat
  /-- Approved reviewers who participated. Their weights can be
      reconstructed from prior indices' weightDeltas. -/
  reviewers : List ContributorId
  /-- Meta-review results: who approved/rejected which reviews. -/
  metaReviews : List MetaReview
  /-- Reviewers who voted to merge. -/
  mergeVotes : List ContributorId
  /-- Reviewers who voted not to merge. -/
  rejectVotes : List ContributorId
  /-- Whether the founder used the escape hatch to force this merge. -/
  founderOverride : Bool
  deriving Repr

/-! ### Intermediate State -/

/-- Intermediate state reconstructed from past indices. -/
structure EvalState where
  /-- Current contributor weights (for reviewer weight lookups). -/
  contributors : List Contributor
  /-- Scored commits with their merge epochs (for comparison target selection). -/
  scoredCommits : List (CommitId × Epoch)

/-- Update or insert a contributor in a list. -/
private def upsertContributor (cs : List Contributor) (updated : Contributor) : List Contributor :=
  if cs.any (fun (c : Contributor) => c.id == updated.id) then
    cs.map (fun (c : Contributor) => if c.id == updated.id then updated else c)
  else
    cs ++ [updated]

/-- Initial evaluation state: founder with initial weight, no scored commits. -/
def initEvalState : EvalState := {
  contributors := [⟨founder, 0, founderWeight, true⟩],
  scoredCommits := []
}

/-! ### Inner functions (use [GenesisVariant] typeclass) -/

section VariantScoped
variable [gv : GenesisVariant]

/-- Process one past index under the current variant's parameters.
    Updates contributor weights and reviewer status. -/
def stepState (state : EvalState) (idx : CommitIndex) : EvalState :=
  let contributors :=
    if idx.weightDelta == 0 then state.contributors
    else
      let existing := state.contributors.find? (fun (c : Contributor) => c.id == idx.contributor)
      let c := existing.getD ⟨idx.contributor, 0, 0, false⟩
      let newWeight := c.weight + idx.weightDelta
      let meetsThreshold := newWeight ≥ gv.reviewerThreshold
      let updated : Contributor := ⟨c.id, c.balance, newWeight, c.isReviewer || meetsThreshold⟩
      upsertContributor state.contributors updated
  let scoredCommits := state.scoredCommits ++ [(idx.commitHash, idx.epoch)]
  { contributors := contributors, scoredCommits := scoredCommits }

/-- Get reviewer weight from an EvalState. -/
def EvalState.reviewerWeight (s : EvalState) (id : ContributorId) : Nat :=
  match s.contributors.find? (fun (c : Contributor) => c.id == id) with
  | some c => if c.isReviewer then c.weight else 0
  | none => 0

/-- Evaluate a single signed commit given pre-built state.
    Uses the current [GenesisVariant] for scoring parameters. -/
def evaluateWithState (state : EvalState) (commit : SignedCommit) : CommitIndex :=
  let score := commitScore commit
    state.scoredCommits (state.reviewerWeight ·)
  let approved := filterReviews commit.reviews commit.metaReviews (state.reviewerWeight ·)
  let approvedReviewers := approved
    |>.filter (fun (r : EmbeddedReview) => state.reviewerWeight r.reviewer > 0)
    |>.map (fun (r : EmbeddedReview) => r.reviewer)
  let mergeVoters := commit.reviews
    |>.filter (fun (r : EmbeddedReview) => r.verdict == .merge)
    |>.map (fun (r : EmbeddedReview) => r.reviewer)
  let rejectVoters := commit.reviews
    |>.filter (fun (r : EmbeddedReview) => r.verdict == .notMerge)
    |>.map (fun (r : EmbeddedReview) => r.reviewer)
  { commitHash := commit.id,
    epoch := commit.mergeEpoch,
    score := score,
    contributor := commit.author,
    weightDelta := score.weighted,
    reviewers := approvedReviewers,
    metaReviews := commit.metaReviews,
    mergeVotes := mergeVoters,
    rejectVotes := rejectVoters,
    founderOverride := commit.founderOverride }

end VariantScoped

/-! ### Outer dispatch (resolves variant per-commit via schedule) -/

/-- Reconstruct state from past indices. Each index is processed under
    the variant active at its epoch (idx.epoch). -/
def reconstructState (pastIndices : List CommitIndex) : EvalState :=
  pastIndices.foldl (fun state idx =>
    letI := activeVariant idx.epoch
    stepState state idx
  ) initEvalState

/-- Evaluate a single signed commit.
    State reconstruction uses per-index variants.
    Scoring uses the variant active at commit.prCreatedAt. -/
def evaluate (pastIndices : List CommitIndex) (commit : SignedCommit) : CommitIndex :=
  let state := reconstructState pastIndices
  letI := activeVariant commit.prCreatedAt
  evaluateWithState state commit

/-- Evaluate a full sequence of signed commits. -/
def evaluateAll (signedCommits : List SignedCommit) : List CommitIndex :=
  signedCommits.foldl (fun indices commit =>
    indices ++ [evaluate indices commit]
  ) []

/-- Final weight for each contributor, computed from all indices.
    Weight = founderWeight + Σ weightDelta for authored commits. -/
def finalWeights (indices : List CommitIndex) : List (ContributorId × Nat) :=
  let addToWeight (acc : List (ContributorId × Nat))
      (id : ContributorId) (amount : Nat) : List (ContributorId × Nat) :=
    if amount == 0 then acc
    else
      match acc.find? (fun (cid, _) => cid == id) with
      | some _ => acc.map (fun (cid, w) => if cid == id then (cid, w + amount) else (cid, w))
      | none => acc ++ [(id, amount)]
  let init := [(founder, founderWeight)]
  indices.foldl (fun acc (idx : CommitIndex) =>
    if idx.weightDelta == 0 then acc
    else addToWeight acc idx.contributor idx.weightDelta
  ) init
