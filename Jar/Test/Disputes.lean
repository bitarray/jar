import Jar.Notation
import Jar.Types
import Jar.Crypto

/-!
# Disputes Sub-Transition Test Harness

Tests the §10 disputes processing: verdict validation, culprits,
faults, signature verification, and offender detection.
-/

namespace Jar.Test.Disputes

open Jar Jar.Crypto

instance : JamConfig where
  config := Config.tiny
  valid := Config.tiny_valid

/-- Super-majority threshold: (V * 2 / 3) + 1 -/
def SUPER_MAJORITY : Nat := (V * 2 / 3) + 1
/-- One-third threshold: V / 3 -/
def ONE_THIRD : Nat := V / 3

-- ============================================================================
-- Types matching test vector JSON (prefixed to avoid collision with Jar types)
-- ============================================================================

structure TDVote where
  vote : Bool
  index : Nat
  signature : Ed25519Signature
  deriving Inhabited

structure TDVerdict where
  target : Hash
  age : Nat
  votes : Array TDVote
  deriving Inhabited

structure TDCulprit where
  target : Hash
  key : Ed25519PublicKey
  signature : Ed25519Signature
  deriving Inhabited

structure TDFault where
  target : Hash
  vote : Bool
  key : Ed25519PublicKey
  signature : Ed25519Signature
  deriving Inhabited

structure TDInput where
  verdicts : Array TDVerdict
  culprits : Array TDCulprit
  faults : Array TDFault

structure TDJudgments where
  good : Array Hash
  bad : Array Hash
  wonky : Array Hash
  offenders : Array Ed25519PublicKey
  deriving BEq

structure TDState where
  psi : TDJudgments
  rho : Array Bool
  tau : Timeslot
  kappa : Array ValidatorKey
  lambda : Array ValidatorKey

-- ============================================================================
-- Result type
-- ============================================================================

inductive TDResult where
  | ok (offendersMark : Array Ed25519PublicKey)
  | err (msg : String)
  deriving BEq

-- ============================================================================
-- Helpers
-- ============================================================================

/-- Lexicographic compare of two ByteArrays. Returns .lt, .eq, or .gt. -/
def compareByteArrays (a b : ByteArray) : Ordering := Id.run do
  let len := min a.size b.size
  for i in [:len] do
    if a.data[i]! < b.data[i]! then return .lt
    if a.data[i]! > b.data[i]! then return .gt
  compare a.size b.size

def isSortedUniqueVotes (xs : Array TDVote) : Bool := Id.run do
  for i in [1:xs.size] do
    if xs[i - 1]!.index ≥ xs[i]!.index then return false
  true

def isSortedUniqueHashes (xs : Array Hash) : Bool := Id.run do
  for i in [1:xs.size] do
    if compareByteArrays xs[i - 1]!.data xs[i]!.data != .lt then return false
  true

def isSortedUniqueKeys (xs : Array Ed25519PublicKey) : Bool := Id.run do
  for i in [1:xs.size] do
    if compareByteArrays xs[i - 1]!.data xs[i]!.data != .lt then return false
  true

def hashIn (h : Hash) (arr : Array Hash) : Bool := arr.any (· == h)
def keyIn (k : Ed25519PublicKey) (arr : Array Ed25519PublicKey) : Bool := arr.any (· == k)

-- ============================================================================
-- Disputes Sub-Transition (§10)
-- ============================================================================

def disputesTransition
    (pre : TDState) (inp : TDInput)
    : (TDResult × TDJudgments) := Id.run do
  let currentEpoch := pre.tau.toNat / E

  -- eq 10.10: Votes within each verdict sorted by index
  for v in inp.verdicts do
    if !isSortedUniqueVotes v.votes then
      return (.err "judgements_not_sorted_unique", pre.psi)

  -- eq 10.7: Verdicts sorted by target hash
  let verdictHashes := inp.verdicts.map (·.target)
  if !isSortedUniqueHashes verdictHashes then
    return (.err "verdicts_not_sorted_unique", pre.psi)

  -- eq 10.9: No verdict target already judged
  for v in inp.verdicts do
    if hashIn v.target pre.psi.good || hashIn v.target pre.psi.bad || hashIn v.target pre.psi.wonky then
      return (.err "already_judged", pre.psi)

  -- eq 10.4: Validate judgment age
  for v in inp.verdicts do
    if v.age != currentEpoch && v.age + 1 != currentEpoch then
      if !(v.age == currentEpoch) then
        return (.err "bad_judgement_age", pre.psi)

  -- eq 10.3: Verify judgment signatures
  for v in inp.verdicts do
    let validators := if v.age == currentEpoch then pre.kappa else pre.lambda
    for (j : TDVote) in v.votes do
      if j.index >= validators.size then
        return (.err "bad_signature", pre.psi)
      let key := validators[j.index]!.ed25519
      let domain := if j.vote then "jam_valid".toUTF8 else "jam_invalid".toUTF8
      let message := domain ++ v.target.data
      if !ed25519Verify key message j.signature then
        return (.err "bad_signature", pre.psi)

  -- eq 10.12: Validate vote split
  for v in inp.verdicts do
    let positive := v.votes.filter (fun (j : TDVote) => j.vote) |>.size
    if !(positive == SUPER_MAJORITY || positive == 0 || positive == ONE_THIRD) then
      return (.err "bad_vote_split", pre.psi)

  -- Tentatively classify verdicts (needed for culprit/fault validation)
  let mut good := pre.psi.good
  let mut bad := pre.psi.bad
  let mut wonky := pre.psi.wonky
  for v in inp.verdicts do
    let positive := v.votes.filter (fun (j : TDVote) => j.vote) |>.size
    if positive == SUPER_MAJORITY then good := good.push v.target
    else if positive == 0 then bad := bad.push v.target
    else wonky := wonky.push v.target

  -- eq 10.8: Culprits sorted by key
  if !isSortedUniqueKeys (inp.culprits.map (fun (c : TDCulprit) => c.key)) then
    return (.err "culprits_not_sorted_unique", pre.psi)

  -- eq 10.8: Faults sorted by key
  if !isSortedUniqueKeys (inp.faults.map (fun (f : TDFault) => f.key)) then
    return (.err "faults_not_sorted_unique", pre.psi)

  -- eq 10.14: Bad verdicts need ≥ 2 culprits
  for v in inp.verdicts do
    let positive := v.votes.filter (fun (j : TDVote) => j.vote) |>.size
    if positive == 0 then
      let count := inp.culprits.filter (fun (c : TDCulprit) => c.target == v.target) |>.size
      if count < 2 then
        return (.err "not_enough_culprits", pre.psi)

  -- eq 10.13: Good verdicts need ≥ 1 fault
  for v in inp.verdicts do
    let positive := v.votes.filter (fun (j : TDVote) => j.vote) |>.size
    if positive == SUPER_MAJORITY then
      let count := inp.faults.filter (fun (f : TDFault) => f.target == v.target) |>.size
      if count < 1 then
        return (.err "not_enough_faults", pre.psi)

  -- Build allowed keys
  let allKeys := (pre.kappa.map (·.ed25519)) ++ (pre.lambda.map (·.ed25519))

  -- eq 10.5: Validate culprits
  let mut offenders := pre.psi.offenders
  let mut offendersMark : Array Ed25519PublicKey := #[]

  for culprit in inp.culprits do
    if !hashIn culprit.target bad then
      return (.err "culprits_verdict_not_bad", pre.psi)
    if !allKeys.any (· == culprit.key) then
      return (.err "bad_guarantor_key", pre.psi)
    if keyIn culprit.key pre.psi.offenders then
      return (.err "offender_already_reported", pre.psi)
    let message := "jam_guarantee".toUTF8 ++ culprit.target.data
    if !ed25519Verify culprit.key message culprit.signature then
      return (.err "bad_signature", pre.psi)
    offenders := offenders.push culprit.key
    offendersMark := offendersMark.push culprit.key

  -- eq 10.6: Validate faults
  for fault in inp.faults do
    let isBad := hashIn fault.target bad
    let isGood := hashIn fault.target good
    if !isBad && !isGood then
      return (.err "fault_verdict_wrong", pre.psi)
    if isBad && !fault.vote then
      return (.err "fault_verdict_wrong", pre.psi)
    if isGood && fault.vote then
      return (.err "fault_verdict_wrong", pre.psi)
    if !allKeys.any (· == fault.key) then
      return (.err "bad_auditor_key", pre.psi)
    if keyIn fault.key pre.psi.offenders then
      return (.err "offender_already_reported", pre.psi)
    let domain := if fault.vote then "jam_valid".toUTF8 else "jam_invalid".toUTF8
    let message := domain ++ fault.target.data
    if !ed25519Verify fault.key message fault.signature then
      return (.err "bad_signature", pre.psi)
    offenders := offenders.push fault.key
    offendersMark := offendersMark.push fault.key

  -- Sort offenders in psi by key (offendersMark keeps insertion order)
  let sortKey (a b : Ed25519PublicKey) : Bool := compareByteArrays a.data b.data == .lt
  let sortedOffenders := offenders.qsort sortKey

  (.ok offendersMark, { good, bad, wonky, offenders := sortedOffenders })

-- ============================================================================
-- Test Runner
-- ============================================================================

def runTest (name : String) (pre : TDState) (inp : TDInput)
    (expectedResult : TDResult) (postPsi : TDJudgments) : IO Bool := do
  let (result, newPsi) := disputesTransition pre inp
  let mut ok := true

  if result != expectedResult then
    ok := false
    match result, expectedResult with
    | .err got, .err expected =>
      IO.println s!"  result: expected err '{expected}', got err '{got}'"
    | .ok got, .ok expected =>
      IO.println s!"  result: expected ok ({expected.size} offenders), got ok ({got.size} offenders)"
    | .err got, .ok _ =>
      IO.println s!"  result: expected ok, got err '{got}'"
    | .ok _, .err expected =>
      IO.println s!"  result: expected err '{expected}', got ok"

  if newPsi != postPsi then
    ok := false
    IO.println s!"  psi mismatch:"
    if newPsi.good != postPsi.good then
      IO.println s!"    good: expected {postPsi.good.size}, got {newPsi.good.size}"
    if newPsi.bad != postPsi.bad then
      IO.println s!"    bad: expected {postPsi.bad.size}, got {newPsi.bad.size}"
    if newPsi.wonky != postPsi.wonky then
      IO.println s!"    wonky: expected {postPsi.wonky.size}, got {newPsi.wonky.size}"
    if newPsi.offenders != postPsi.offenders then
      IO.println s!"    offenders: expected {postPsi.offenders.size}, got {newPsi.offenders.size}"

  if ok then
    IO.println s!"  ✓ {name}"
  else
    IO.println s!"  ✗ {name}"
  return ok

end Jar.Test.Disputes
