import Jar.Notation
import Jar.Types
import Jar.Crypto

/-!
# Reports Sub-Transition Test Harness

Tests the §11.23-11.42 work report guarantee processing: validation,
signature verification, core assignment checking, and state updates.
-/

namespace Jar.Test.Reports

open Jar Jar.Crypto

instance : JamConfig where
  config := Config.tiny
  valid := Config.tiny_valid

def MAX_ACCUMULATE_GAS : Nat := G_A
def MAX_OUTPUT_PER_ITEM : Nat := 18432
def MAX_SEGMENT_LOOKUPS : Nat := 4

-- ============================================================================
-- Types
-- ============================================================================

/-- Work result discriminant. -/
inductive TRWorkResult where
  | ok (data : ByteArray)
  | outOfGas
  | panic
  | badExports
  | badCode
  | codeOversize
  deriving Inhabited

/-- Work digest (result of refinement). -/
structure TRWorkDigest where
  serviceId : Nat
  codeHash : Hash
  payloadHash : Hash
  accumulateGas : Nat
  result : TRWorkResult
  gasUsed : Nat
  imports : Nat
  extrinsicCount : Nat
  extrinsicSize : Nat
  exports : Nat
  deriving Inhabited

/-- Availability spec (package_spec). -/
structure TRAvailSpec where
  packageHash : Hash
  bundleLength : Nat
  erasureRoot : Hash
  exportsRoot : Hash
  exportsCount : Nat
  deriving Inhabited

/-- Refinement context. -/
structure TRContext where
  anchor : Hash
  stateRoot : Hash
  beefyRoot : Hash
  lookupAnchor : Hash
  lookupAnchorSlot : Nat
  prerequisites : Array Hash
  deriving Inhabited

/-- Work report. -/
structure TRWorkReport where
  packageSpec : TRAvailSpec
  context : TRContext
  coreIndex : Nat
  authorizerHash : Hash
  authGasUsed : Nat
  authOutput : ByteArray
  segmentRootLookup : Array (Hash × Hash)
  results : Array TRWorkDigest
  deriving Inhabited

/-- A guarantee signature. -/
structure TRSignature where
  validatorIndex : Nat
  signature : Ed25519Signature
  deriving Inhabited

/-- A guarantee input. -/
structure TRGuarantee where
  report : TRWorkReport
  slot : Nat
  signatures : Array TRSignature
  reportHash : Hash  -- pre-computed blake2b(encode(report))
  deriving Inhabited

/-- Recent block entry. -/
structure TRRecentBlock where
  headerHash : Hash
  stateRoot : Hash
  beefyRoot : Hash
  reported : Array (Hash × Hash)  -- (package_hash, exports_root)
  deriving Inhabited

/-- Service info needed for validation. -/
structure TRServiceInfo where
  serviceId : Nat
  codeHash : Hash
  minItemGas : Nat
  deriving BEq, Inhabited

/-- Availability assignment. -/
structure TRAvailAssignment where
  packageHash : Hash
  timeout : Nat
  deriving BEq, Inhabited

/-- State for reports sub-transition. -/
structure TRState where
  availAssignments : Array (Option TRAvailAssignment)
  currValidators : Array ValidatorKey
  prevValidators : Array ValidatorKey
  entropy : Array Hash   -- 4 entropy values
  offenders : Array Ed25519PublicKey
  recentBlocks : Array TRRecentBlock
  authPools : Array (Array Hash)  -- per-core authorization pools
  accounts : Array TRServiceInfo

/-- Input to reports sub-transition. -/
structure TRInput where
  guarantees : Array TRGuarantee
  knownPackages : Array Hash
  slot : Nat

-- ============================================================================
-- Result type
-- ============================================================================

inductive TRResult where
  | ok
  | err (msg : String)
  deriving BEq

-- ============================================================================
-- Helpers
-- ============================================================================

def compareByteArrays (a b : ByteArray) : Ordering := Id.run do
  let len := min a.size b.size
  for i in [:len] do
    if a.data[i]! < b.data[i]! then return .lt
    if a.data[i]! > b.data[i]! then return .gt
  compare a.size b.size

def hashIn (h : Hash) (arr : Array Hash) : Bool := arr.any (· == h)
def keyIn (k : Ed25519PublicKey) (arr : Array Ed25519PublicKey) : Bool := arr.any (· == k)

/-- Compute core assignments P(e, t). -/
def computeCoreAssignments (entropy : Hash) (slot : Nat) : Array Nat := Id.run do
  -- Step 1: initial[i] = floor(C * i / V)
  let mut initial : Array Nat := Array.replicate V 0
  for i in [:V] do
    initial := initial.set! i (C * i / V)

  -- Step 2: Shuffle with entropy
  let shuffled := shuffle initial entropy

  -- Step 3: Apply rotation
  let rotOffset := if R_ROTATION > 0 then ((slot % E) / R_ROTATION) else 0
  let mut result := shuffled
  for i in [:V] do
    result := result.set! i ((result[i]! + rotOffset) % C)

  result

-- ============================================================================
-- Reports Sub-Transition (§11.23-11.42)
-- ============================================================================

def reportsTransition
    (pre : TRState) (inp : TRInput)
    : (TRResult × Array (Option TRAvailAssignment)) := Id.run do

  -- eq 11.24: Guarantees sorted by core_index
  for i in [1:inp.guarantees.size] do
    if inp.guarantees[i - 1]!.report.coreIndex ≥ inp.guarantees[i]!.report.coreIndex then
      return (.err "out_of_order_guarantee", pre.availAssignments)

  -- Compute core assignments
  let assignmentM := computeCoreAssignments pre.entropy[2]! inp.slot
  let prevSlot := if inp.slot ≥ R_ROTATION then inp.slot - R_ROTATION else 0
  let prevSameEpoch := prevSlot / E == inp.slot / E
  let prevEntropy := if prevSameEpoch then pre.entropy[2]! else pre.entropy[3]!
  let assignmentMStar := computeCoreAssignments prevEntropy prevSlot

  let mut seenPackages : Array Hash := #[]
  let mut avail := pre.availAssignments

  for guarantee in inp.guarantees do
    let report := guarantee.report
    let core := report.coreIndex

    -- eq 11.25: Valid core index
    if core ≥ C then
      return (.err "bad_core_index", pre.availAssignments)

    -- Core not engaged
    match avail[core]! with
    | some _ => return (.err "core_engaged", pre.availAssignments)
    | none => pure ()

    -- Package not duplicated in batch
    if hashIn report.packageSpec.packageHash seenPackages then
      return (.err "duplicate_package", pre.availAssignments)
    seenPackages := seenPackages.push report.packageSpec.packageHash

    -- Package not in recent blocks
    for block in pre.recentBlocks do
      for (reportedHash, _) in block.reported do
        if reportedHash == report.packageSpec.packageHash then
          return (.err "duplicate_package", pre.availAssignments)

    -- Must have at least one result
    if report.results.size == 0 then
      return (.err "missing_work_results", pre.availAssignments)

    -- Signatures sorted and unique
    for i in [1:guarantee.signatures.size] do
      if guarantee.signatures[i - 1]!.validatorIndex ≥ guarantee.signatures[i]!.validatorIndex then
        return (.err "not_sorted_or_unique_guarantors", pre.availAssignments)

    -- Valid validator indices
    for sig in guarantee.signatures do
      if sig.validatorIndex ≥ V then
        return (.err "bad_validator_index", pre.availAssignments)

    -- Determine rotation
    let currentRot := if R_ROTATION > 0 then inp.slot / R_ROTATION else 0
    let guaranteeRot := if R_ROTATION > 0 then guarantee.slot / R_ROTATION else 0

    -- Not future
    if guarantee.slot > inp.slot then
      return (.err "future_report_slot", pre.availAssignments)

    -- Not before last rotation
    if currentRot > guaranteeRot + 1 then
      return (.err "report_epoch_before_last", pre.availAssignments)

    -- Choose validators and assignment
    let isCurrentRotation := currentRot == guaranteeRot
    let (validators, assignment) := if isCurrentRotation then
      (pre.currValidators, assignmentM)
    else if prevSameEpoch then
      (pre.currValidators, assignmentMStar)
    else
      (pre.prevValidators, assignmentMStar)

    -- No banned validators
    for sig in guarantee.signatures do
      let edKey := validators[sig.validatorIndex]!.ed25519
      if keyIn edKey pre.offenders then
        return (.err "banned_validator", pre.availAssignments)

    -- Enough guarantees (≥ 2)
    if guarantee.signatures.size < 2 then
      return (.err "insufficient_guarantees", pre.availAssignments)

    -- Assignment check
    for sig in guarantee.signatures do
      if assignment[sig.validatorIndex]! != core then
        return (.err "wrong_assignment", pre.availAssignments)

    -- Verify ed25519 signatures
    let message := "jam_guarantee".toUTF8 ++ guarantee.reportHash.data
    for sig in guarantee.signatures do
      let edKey := validators[sig.validatorIndex]!.ed25519
      if !ed25519Verify edKey message sig.signature then
        return (.err "bad_signature", pre.availAssignments)

    -- Anchor in recent blocks
    let anchorBlock := pre.recentBlocks.find? (·.headerHash == report.context.anchor)
    match anchorBlock with
    | none => return (.err "anchor_not_recent", pre.availAssignments)
    | some ab =>
      -- State root must match
      if report.context.stateRoot != ab.stateRoot then
        return (.err "bad_state_root", pre.availAssignments)
      -- Beefy root must match
      if report.context.beefyRoot != ab.beefyRoot then
        return (.err "bad_beefy_mmr_root", pre.availAssignments)

    -- Authorization: authorizer_hash in auth_pools[core]
    if core ≥ pre.authPools.size then
      return (.err "core_unauthorized", pre.availAssignments)
    if !hashIn report.authorizerHash pre.authPools[core]! then
      return (.err "core_unauthorized", pre.availAssignments)

    -- Validate work results
    let mut totalGas : Nat := 0
    for digest in report.results do
      -- Service must exist
      let service := pre.accounts.find? (·.serviceId == digest.serviceId)
      match service with
      | none => return (.err "bad_service_id", pre.availAssignments)
      | some svc =>
        -- Code hash match
        if digest.codeHash != svc.codeHash then
          return (.err "bad_code_hash", pre.availAssignments)
        -- Gas minimum
        if digest.accumulateGas < svc.minItemGas then
          return (.err "service_item_gas_too_low", pre.availAssignments)
      -- Output size
      match digest.result with
      | .ok data =>
        if data.size > MAX_OUTPUT_PER_ITEM then
          return (.err "work_report_too_big", pre.availAssignments)
      | _ => pure ()
      totalGas := totalGas + digest.accumulateGas

    -- Total gas check
    if totalGas > MAX_ACCUMULATE_GAS then
      return (.err "work_report_gas_too_high", pre.availAssignments)

    -- Segment root lookup
    if report.segmentRootLookup.size > MAX_SEGMENT_LOOKUPS then
      return (.err "too_many_dependencies", pre.availAssignments)

    for (lookupHash, lookupRoot) in report.segmentRootLookup do
      let inRecent := pre.recentBlocks.any fun b =>
        b.reported.any fun (h, r) => h == lookupHash && r == lookupRoot
      let inBatch := inp.guarantees.any fun g =>
        g.report.packageSpec.packageHash == lookupHash &&
        g.report.packageSpec.exportsRoot == lookupRoot
      if !inRecent && !inBatch then
        return (.err "segment_root_lookup_invalid", pre.availAssignments)

    -- Prerequisites
    for prereq in report.context.prerequisites do
      let inKnown := hashIn prereq inp.knownPackages
      let inBatch := inp.guarantees.any fun g =>
        g.report.packageSpec.packageHash == prereq
      if !inKnown && !inBatch then
        return (.err "dependency_missing", pre.availAssignments)

    -- Place in availability
    avail := avail.set! core (some { packageHash := report.packageSpec.packageHash, timeout := inp.slot })

  (.ok, avail)

-- ============================================================================
-- Test Runner
-- ============================================================================

def runTest (name : String) (pre : TRState) (inp : TRInput)
    (expectedResult : TRResult) (postAvail : Array (Option TRAvailAssignment))
    : IO Bool := do
  let (result, newAvail) := reportsTransition pre inp
  let mut ok := true

  if result != expectedResult then
    ok := false
    match result, expectedResult with
    | .err got, .err expected =>
      IO.println s!"  result: expected err '{expected}', got err '{got}'"
    | .err got, .ok =>
      IO.println s!"  result: expected ok, got err '{got}'"
    | .ok, .err expected =>
      IO.println s!"  result: expected err '{expected}', got ok"
    | .ok, .ok => pure ()

  if newAvail != postAvail then
    ok := false
    IO.println s!"  avail mismatch:"
    for i in [:newAvail.size] do
      if i < postAvail.size then
        if newAvail[i]! != postAvail[i]! then
          IO.println s!"    [{i}]: expected {if postAvail[i]!.isSome then "Some" else "None"}, got {if newAvail[i]!.isSome then "Some" else "None"}"

  if ok then
    IO.println s!"  ✓ {name}"
  else
    IO.println s!"  ✗ {name}"
  return ok

end Jar.Test.Reports
