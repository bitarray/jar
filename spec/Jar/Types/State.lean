import Jar.Notation
import Jar.Types.Numerics
import Jar.Types.Validators
import Jar.Types.Work
import Jar.Types.Accounts
import Jar.Types.Constants

/-!
# Chain State — Gray Paper §4.2

The complete chain state σ and its component types.
References: `graypaper/text/overview.tex` eq:statecomposition.
            `graypaper/text/recent_history.tex`, `graypaper/text/judgments.tex`,
            `graypaper/text/statistics.tex`, `graypaper/text/authorization.tex`,
            `graypaper/text/accumulation.tex`.
-/

namespace Jar
variable [JarConfig]

-- ============================================================================
-- §10 — Judgments State (eq:disputesspec)
-- ============================================================================

/-- ψ : Judgment state. GP §10.1.
    ψ = ⟨ψ_G, ψ_B, ψ_W, ψ_O⟩ -/
structure JudgmentsState where
  /-- ψ_G : Set of good (valid) work-report hashes. -/
  good : Array Hash
  /-- ψ_B : Set of bad (invalid) work-report hashes. -/
  bad : Array Hash
  /-- ψ_W : Set of wonky (uncertain) work-report hashes. -/
  wonky : Array Hash
  /-- ψ_O : Set of offending validator Ed25519 keys. -/
  offenders : Array Ed25519PublicKey

-- ============================================================================
-- §7 — Recent History (eq:recentspec, eq:recenthistoryspec)
-- ============================================================================

/-- A single entry in the recent block history. GP §7.
    ⟨h, s, b, p⟩ -/
structure RecentBlockInfo where
  /-- h : Header hash. ℍ. -/
  headerHash : Hash
  /-- s : State root. ℍ. -/
  stateRoot : Hash
  /-- b : Accumulation-output log super-peak. ℍ. -/
  accOutputRoot : Hash
  /-- p : Reported work-package hashes. ⟨ℍ→ℍ⟩. -/
  reportedPackages : Dict Hash Hash

/-- β : Recent history state. GP §7.
    Composed of block history and accumulation-output belt.
    β = ⟨β_H, β_B⟩ -/
structure RecentHistory where
  /-- β_H : Recent block infos. ⟦RecentBlockInfo⟧_{:H}. -/
  blocks : Array RecentBlockInfo
  /-- β_B : Accumulation-output belt. ⟦ℍ?⟧. -/
  accOutputBelt : Array (Option Hash)

-- ============================================================================
-- §13 — Statistics (eq:activityspec)
-- ============================================================================

/-- Per-validator activity record. GP §13.1. -/
structure ValidatorRecord where
  /-- b : Blocks produced. -/
  blocks : Nat
  /-- t : Tickets introduced. -/
  tickets : Nat
  /-- p : Preimages introduced (count). -/
  preimageCount : Nat
  /-- d : Preimage data introduced (bytes). -/
  preimageSize : Nat
  /-- g : Reports guaranteed. -/
  guarantees : Nat
  /-- a : Assurances made. -/
  assurances : Nat

/-- Per-core statistics for a block. GP §13.2. -/
structure CoreStatistics where
  /-- d : DA bytes written. -/
  daLoad : Nat
  /-- p : Validators assuring (popularity). -/
  popularity : Nat
  /-- i : Segments imported. -/
  imports : Nat
  /-- x : Extrinsic count. -/
  extrinsicCount : Nat
  /-- z : Extrinsic size. -/
  extrinsicSize : Nat
  /-- e : Segments exported. -/
  exports : Nat
  /-- l : Work bundle size. -/
  bundleSize : Nat
  /-- u : Gas consumed. ℕ_G. -/
  gasUsed : Gas

/-- Per-service statistics for a block. GP §13.2. -/
structure ServiceStatistics where
  /-- p : Preimages provided (count, size). -/
  provided : Nat × Nat
  /-- r : Refinement (count, gas). -/
  refinement : Nat × Gas
  /-- i : Segments imported. -/
  imports : Nat
  /-- x : Extrinsic count. -/
  extrinsicCount : Nat
  /-- z : Extrinsic size. -/
  extrinsicSize : Nat
  /-- e : Segments exported. -/
  exports : Nat
  /-- a : Accumulation (count, gas). -/
  accumulation : Nat × Gas

/-- π : Validator activity statistics. GP §13.
    π = ⟨π_V, π_L, π_C, π_S⟩ -/
structure ActivityStatistics where
  /-- π_V : Current epoch validator stats. ⟦ValidatorRecord⟧_V. -/
  current : Array ValidatorRecord
  /-- π_L : Previous epoch validator stats. ⟦ValidatorRecord⟧_V. -/
  previous : Array ValidatorRecord
  /-- π_C : Core statistics (per-block). ⟦CoreStatistics⟧_C. -/
  coreStats : Array CoreStatistics
  /-- π_S : Service statistics (per-block). ⟨ℕ_S → ServiceStatistics⟩. -/
  serviceStats : Dict ServiceId ServiceStatistics

-- ============================================================================
-- §12 — Accumulation State (eq:accumulatedspec, eq:readyspec)
-- ============================================================================

/-- θ : Most recent accumulation outputs. GP §12.
    ⟦(ℕ_S, ℍ)⟧ -/
abbrev AccumulationOutputs := Array (ServiceId × Hash)

-- ============================================================================
-- §4.2 — Complete State (eq:statecomposition)
-- ============================================================================

/-- σ : Complete chain state. GP eq (6).
    σ ≡ (α, β, θ, γ, δ, η, ι, κ, λ, ρ, τ, ϕ, χ, ψ, π, ω, ξ) -/
structure State where
  /-- α : Authorization pool. ⟦⟦ℍ⟧_{:O}⟧_C.
      Per-core pool of authorized code hashes. -/
  authPool : Array (Array Hash)
  /-- β : Recent block history. -/
  recent : RecentHistory
  /-- θ : Most recent accumulation outputs. -/
  accOutputs : AccumulationOutputs
  /-- γ : Safrole consensus state. -/
  safrole : SafroleState
  /-- δ : Service accounts. ⟨ℕ_S → 𝔸⟩. -/
  services : Dict ServiceId ServiceAccount
  /-- η : Entropy accumulator. ⟦ℍ⟧_4. -/
  entropy : Entropy
  /-- ι : Pending (staging) validator keys for next epoch. ⟦𝕂⟧_V. -/
  pendingValidators : Array ValidatorKey
  /-- κ : Current (active) validator keys. ⟦𝕂⟧_V. -/
  currentValidators : Array ValidatorKey
  /-- λ : Previous validator keys. ⟦𝕂⟧_V. -/
  previousValidators : Array ValidatorKey
  /-- ρ : Pending work reports per core. ⟦PendingReport?⟧_C. -/
  pendingReports : Array (Option PendingReport)
  /-- τ : Current timeslot. ℕ_T. -/
  timeslot : Timeslot
  /-- ϕ : Authorization queue. ⟦⟦ℍ⟧_Q⟧_C.
      Per-core queue of authorized code hashes. -/
  authQueue : Array (Array Hash)
  /-- χ : Privileged service identifiers. -/
  privileged : PrivilegedServices
  /-- ψ : Past judgments. -/
  judgments : JudgmentsState
  /-- π : Validator activity statistics. -/
  statistics : ActivityStatistics
  /-- ω : Accumulation queue (ready work-reports). -/
  accQueue : Array (Array (WorkReport × Array Hash))
  /-- ξ : Accumulated work-package hashes history. -/
  accHistory : Array (Array Hash)

-- ============================================================================
-- §4.1 — State Transition (eq:statetransition)
-- ============================================================================

-- The state transition function Υ is defined in Jar.State:
-- σ' ≡ Υ(σ, B)
-- Υ : State → Block → Option State

end Jar
