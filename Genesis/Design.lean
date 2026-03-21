/-
  Genesis Protocol — Design Notes & Future Work

  This file documents design decisions, deferred features, and the
  rationale behind them. It is not imported by the protocol spec.

  ## Machine Metrics (Deferred)

  The initial protocol uses purely review-based scoring. Machine metrics
  were designed but deferred because:

  ### Metrics considered

  1. `newDeclarations` / `newTheorems` (counting new defs/theorems)
     - Trivially gameable: `theorem t1 : 1 = 1 := rfl` × 100 inflates the count.
     - Count-based metrics reward quantity over quality.
     - Rejected for initial version.

  2. `proofTermSizeReduced` (simplification of existing proofs)
     - Measured via `Expr.sizeWithoutSharing` (built-in Lean 4 API).
     - Computed by comparing environments before and after a commit.
     - Two-step gaming attack: submit verbose proof, then "simplify" it.
     - Only rewards simplification, not creation — useless at bootstrap
       when there is little existing code to simplify.
     - Deferred. Useful as one component in a mature codebase, not as
       the sole machine metric.

  3. `downstreamDependents` (how many declarations depend on yours)
     - The most honest metric: hard to fake, rewards foundational work.
     - Requires building a reverse dependency index.
     - Problem: unknowable at merge time. The signal is retroactive —
       future commits create the dependencies.
     - Deferred. Should be the primary machine metric once the codebase
       is large enough for the signal to be meaningful.

  ## Reviewer Agreement Decay (Deferred)

  Reviewers whose scores consistently diverge from weighted consensus should
  have their weight decay over time. This catches both incompetent and
  malicious reviewers.

  Deferred because: with a single bootstrap reviewer, there is no consensus
  to compare against. Becomes meaningful once ≥3 independent reviewers exist.

  ## Retroactive Impact Pool (Deferred)

  A fraction of each epoch's emission reserved for retroactive distribution
  to past commits whose downstream dependents grew. This rewards foundational
  work continuously as it proves its value.

  Deferred because: requires `downstreamDependents` tracking, which is itself
  deferred.

  ## Emission Decay (Deferred)

  The initial protocol uses fixed rewards per commit (`RewardParams.emission`).
  This is the simplest secure model for bootstrap.

  Future work: decaying emission curve where emission per epoch follows
  E(t) = E_0 * d^t, with d < 1 (e.g., 0.998 per epoch ≈ 48% annual decay).
  This produces asymptotically decreasing inflation, approaching tail emission.

  Intended pool splits when emission decay is implemented:
  - 60% contribution pool (merged commits by score)
  - 20% impact pool (retroactive, by downstream dependents)
  - 10% review pool (reviewer compensation by agreement)
  - 10% treasury (protocol development, grants)

  Emission decay should be introduced when:
  - Epoch boundaries are formally defined
  - The token has enough usage that inflation control matters
  - The impact pool has a mechanism to distribute to (downstreamDependents)
-/
-- Genesis testnet test PR #4
