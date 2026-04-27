import Jar.Notation
import Jar.Types.Numerics

/-!
# Work Types — Gray Paper §11, §14

Work reports, digests, packages, and availability specifications.
References: `graypaper/text/reporting_assurance.tex` eq:workreport, eq:workcontext,
            eq:avspec, eq:workdigest, eq:workerror.
            `graypaper/text/work_packages_and_reports.tex` eq:workpackage, eq:workitem.
-/

namespace Jar
variable [JarConfig]

-- ============================================================================
-- §11.6 — Work Errors (eq:workerror)
-- ============================================================================

/-- 𝔼 : Work execution error. GP eq (109–111).
    Possible outcomes when refinement fails. -/
inductive WorkError where
  /-- ∞ : Gas exhaustion. -/
  | outOfGas
  /-- ☇ : Exceptional halt. -/
  | panic
  /-- Invalid exports produced. -/
  | badExports
  /-- Code too large. -/
  | oversize
  /-- BAD : Code not available. -/
  | badCode
  /-- BIG : Code exceeds limit. -/
  | bigCode
  deriving BEq

-- ============================================================================
-- §11.4 — Work Digest (eq:workdigest)
-- ============================================================================

/-- Work result: either successful output blob or an error. GP eq (109). -/
inductive WorkResult where
  /-- Successful output blob. -/
  | ok : ByteArray → WorkResult
  /-- Refinement error. -/
  | err : WorkError → WorkResult

/-- 𝔻 : Work digest — the on-chain summary of a single refined work-item.
    GP eq (93–103).
    D = ⟨s, c, y, g, l, u, i, x, z, e⟩ -/
structure WorkDigest where
  /-- s : Service index. ℕ_S. -/
  serviceId : ServiceId
  /-- c : Service code hash at time of refinement. ℍ. -/
  codeHash : Hash
  /-- y : Payload hash. ℍ. -/
  payloadHash : Hash
  /-- g : Gas limit for accumulation. ℕ_G. -/
  gasLimit : Gas
  /-- l : Refinement result (output or error). 𝔹 ∪ 𝔼. -/
  result : WorkResult
  /-- u : Actual gas used during refinement. ℕ_G. -/
  gasUsed : Gas
  /-- i : Number of imported segments. ℕ. -/
  importsCount : Nat
  /-- x : Number of extrinsics. ℕ. -/
  extrinsicsCount : Nat
  /-- z : Total extrinsic size in bytes. ℕ. -/
  extrinsicsSize : Nat
  /-- e : Number of exported segments. ℕ. -/
  exportsCount : Nat

-- ============================================================================
-- §11.3 — Availability Specification (eq:avspec)
-- ============================================================================

/-- 𝕐 : Availability specification for a work-package. GP eq (72–79).
    Y = ⟨p, l, u, e, n⟩ -/
structure AvailabilitySpec [JarConfig] where
  /-- p : Work-package hash. ℍ. -/
  packageHash : Hash
  /-- l : Auditable bundle length. ℕ_L. -/
  bundleLength : BlobLength
  /-- u : Erasure-coding root. ℍ. -/
  erasureRoot : Hash
  /-- e : Exports segment root. ℍ. -/
  segmentRoot : Hash
  /-- n : Number of exported segments. ℕ. -/
  segmentCount : Nat
  /-- v : Number of erasure-coding shards (GP#514). Equals len(κ').
      Defaults to V for backward compatibility with gp072 variants. -/
  erasureShards : Nat := V

-- ============================================================================
-- §11.2 — Refinement Context (eq:workcontext)
-- ============================================================================

/-- ℂ : Refinement context. GP eq (57–66).
    C = ⟨a, s, b, l, t, p⟩ -/
structure RefinementContext where
  /-- a : Anchor block header hash. ℍ. -/
  anchorHash : Hash
  /-- s : Anchor state root. ℍ. -/
  anchorStateRoot : Hash
  /-- b : Anchor accumulation-output log super-peak. ℍ. -/
  anchorBeefyRoot : Hash
  /-- l : Lookup-anchor header hash. ℍ. -/
  lookupAnchorHash : Hash
  /-- t : Lookup-anchor timeslot. ℕ_T. -/
  lookupAnchorTimeslot : Timeslot
  /-- p : Prerequisite work-package hashes. {ℍ} (power set). -/
  prerequisites : Array Hash

-- ============================================================================
-- §11.1 — Work Report (eq:workreport)
-- ============================================================================

/-- ℝ : Work report. GP eq (32–45).
    R = ⟨s, c, x, a, o, l, d, g⟩ -/
structure WorkReport where
  /-- s : Availability specification. 𝕐. -/
  availSpec : AvailabilitySpec
  /-- c : Refinement context. ℂ. -/
  context : RefinementContext
  /-- x : Core index. ℕ_C. -/
  coreIndex : CoreIndex
  /-- a : Authorizer hash. ℍ. -/
  authorizerHash : Hash
  /-- o : Authorization output/trace. 𝔹. -/
  authOutput : ByteArray
  /-- l : Segment root lookup. ⟨ℍ→ℍ⟩. -/
  segmentRootLookup : Dict Hash Hash
  /-- d : Work digests. ⟦𝔻⟧_{1:I}. -/
  digests : Array WorkDigest
  /-- g : Authorization gas used. ℕ_G. -/
  authGasUsed : Gas

-- ============================================================================
-- §11.1 — Reporting State (eq:reportingstate)
-- ============================================================================

/-- Pending report on a core: a work report with its reporting timeslot. -/
structure PendingReport where
  /-- r : The work report. ℝ. -/
  report : WorkReport
  /-- t : Timeslot when reported. ℕ_T. -/
  timeslot : Timeslot

-- ============================================================================
-- §14.2 — Work Package (eq:workpackage)
-- ============================================================================

/-- 𝕎 : Work item. GP eq (77–87).
    W = ⟨s, c, y, g, a, e, i, x⟩ -/
structure WorkItem where
  /-- s : Service index. ℕ_S. -/
  serviceId : ServiceId
  /-- c : Code hash. ℍ. -/
  codeHash : Hash
  /-- y : Payload. 𝔹. -/
  payload : ByteArray
  /-- g : Refinement gas limit. ℕ_G. -/
  gasLimit : Gas
  /-- a : Accumulation gas limit. ℕ_G. -/
  accGasLimit : Gas
  /-- e : Number of exports. ℕ. -/
  exportsCount : Nat
  /-- i : Import segment specifications. ⟦⟨ℍ, ℕ⟩⟧. -/
  imports : Array (Hash × Nat)
  /-- x : Extrinsic data hashes. ⟦⟨ℍ, ℕ⟩⟧. -/
  extrinsics : Array (Hash × Nat)

/-- ℙ : Work package. GP eq (64–74).
    P = ⟨j, h, u, f, c, w⟩ -/
structure WorkPackage where
  /-- j : Authorization token. 𝔹. -/
  authToken : ByteArray
  /-- h : Authorization code host service. ℕ_S. -/
  authCodeHost : ServiceId
  /-- u : Authorization code hash. ℍ. -/
  authCodeHash : Hash
  /-- f : Authorizer configuration blob. 𝔹. -/
  authConfig : ByteArray
  /-- c : Refinement context. ℂ. -/
  context : RefinementContext
  /-- w : Work items. ⟦𝕎⟧_{1:I}. -/
  items : Array WorkItem

-- ============================================================================
-- §14 — Segment type (eq:segment)
-- ============================================================================

/-- 𝕁 : Data segment. GP eq (15.1). 𝕁 ≡ 𝔹_{W_G} = 𝔹_4104. -/
abbrev Segment := OctetSeq W_G

end Jar
