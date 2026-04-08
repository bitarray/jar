import Jar.Notation
import Jar.Types
import Jar.Crypto

/-!
# Assurances Sub-Transition Test Harness

Tests the §11.3 availability assurances processing: signature verification,
bitfield counting, and work report availability determination.
-/

namespace Jar.Test.Assurances

open Jar Jar.Crypto

variable [JarConfig]

/-- Super-majority threshold: (V * 2 / 3) + 1 -/
def ASSURANCE_THRESHOLD : Nat := (V * 2 / 3) + 1

-- ============================================================================
-- Types
-- ============================================================================

/-- Availability assignment: a work report pending availability. -/
structure TAAvailAssignment where
  reportPackageHash : Hash   -- package_spec.hash identifies the report
  coreIndex : Nat
  timeout : Nat              -- timeslot when report was placed
  deriving BEq, Inhabited

/-- An assurance from a validator. -/
structure TAAssurance where
  anchor : Hash
  bitfield : ByteArray  -- one bit per core
  validatorIndex : Nat
  signature : Ed25519Signature
  deriving Inhabited

/-- Pre/post state for assurances sub-transition. -/
structure TAState where
  availAssignments : Array (Option TAAvailAssignment)  -- one per core
  currValidators : Array ValidatorKey

/-- Input to the assurances sub-transition. -/
structure TAInput where
  assurances : Array TAAssurance
  slot : Nat
  parent : Hash

-- ============================================================================
-- Result type
-- ============================================================================

inductive TAResult where
  | ok (reportedCores : Array Nat)  -- core indices of reported work reports
  | err (msg : String)
  deriving BEq

-- ============================================================================
-- Helpers
-- ============================================================================

/-- Check if bit `idx` is set in a bitfield byte array. -/
def bitfieldBit (bf : ByteArray) (idx : Nat) : Bool :=
  let byteIdx := idx / 8
  let bitIdx := idx % 8
  if byteIdx < bf.size then
    (bf.data[byteIdx]! &&& (1 <<< bitIdx.toUInt8)) != 0
  else
    false

-- ============================================================================
-- Assurances Sub-Transition (§11.3)
-- ============================================================================

def assurancesTransition
    (pre : TAState) (inp : TAInput)
    : (TAResult × Array (Option TAAvailAssignment)) := Id.run do

  -- Step 1: Validate validator indices
  for a in inp.assurances do
    if a.validatorIndex >= pre.currValidators.size then
      return (.err "bad_validator_index", pre.availAssignments)

  -- Step 2: Assurances sorted and unique by validator index
  for i in [1:inp.assurances.size] do
    if inp.assurances[i - 1]!.validatorIndex ≥ inp.assurances[i]!.validatorIndex then
      return (.err "not_sorted_or_unique_assurers", pre.availAssignments)

  -- Step 3: All anchors must match parent
  for a in inp.assurances do
    if a.anchor != inp.parent then
      return (.err "bad_attestation_parent", pre.availAssignments)

  -- Step 4: Verify ed25519 signatures
  -- Message: "jam_available" ++ blake2b(parent_hash ++ bitfield)
  for a in inp.assurances do
    let key := pre.currValidators[a.validatorIndex]!.ed25519
    let payload := inp.parent.data ++ a.bitfield
    let payloadHash := blake2b payload
    let message := "jam_available".toUTF8 ++ payloadHash.data
    if !ed25519Verify key message a.signature then
      return (.err "bad_signature", pre.availAssignments)

  -- Step 5: Bits may only be set for cores with pending reports
  for a in inp.assurances do
    for c in [:C] do
      if bitfieldBit a.bitfield c then
        match pre.availAssignments[c]! with
        | none => return (.err "core_not_engaged", pre.availAssignments)
        | some _ => pure ()

  -- Step 6: Count assurance bits per core
  let mut counts : Array Nat := Array.replicate C 0
  for a in inp.assurances do
    for c in [:C] do
      if bitfieldBit a.bitfield c then
        counts := counts.set! c (counts[c]! + 1)

  -- Step 7: Determine reported cores (those with enough assurances)
  let mut reportedCores : Array Nat := #[]
  for c in [:C] do
    if counts[c]! >= ASSURANCE_THRESHOLD then
      match pre.availAssignments[c]! with
      | some assignment => reportedCores := reportedCores.push assignment.coreIndex
      | none => pure ()

  -- Step 8: Clear available and timed-out reports
  let mut avail := pre.availAssignments
  for c in [:C] do
    match avail[c]! with
    | none => pure ()
    | some assignment =>
      let isAvailable := counts[c]! >= ASSURANCE_THRESHOLD
      let isTimedOut := inp.slot >= assignment.timeout + U_TIMEOUT
      if isAvailable || isTimedOut then
        avail := avail.set! c none

  (.ok reportedCores, avail)

-- ============================================================================
-- Test Runner
-- ============================================================================

def runTest (name : String) (pre : TAState) (inp : TAInput)
    (expectedResult : TAResult) (postAvail : Array (Option TAAvailAssignment))
    : IO Bool := do
  let (result, newAvail) := assurancesTransition pre inp
  let mut ok := true

  if result != expectedResult then
    ok := false
    match result, expectedResult with
    | .err got, .err expected =>
      IO.println s!"  result: expected err '{expected}', got err '{got}'"
    | .ok got, .ok expected =>
      IO.println s!"  result: expected ok (cores {expected}), got ok (cores {got})"
    | .err got, .ok _ =>
      IO.println s!"  result: expected ok, got err '{got}'"
    | .ok _, .err expected =>
      IO.println s!"  result: expected err '{expected}', got ok"

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

end Jar.Test.Assurances
