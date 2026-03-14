import Plausible
import Jar.Json
import Jar.Codec
import Jar.Test.Arbitrary

/-!
# Property-Based Tests for Jar

Tests codec and JSON serialization properties using random generation.
-/

namespace Jar.Test.Properties

open Lean (Json ToJson FromJson toJson fromJson?)
open Plausible Plausible.Arbitrary Plausible.Gen
open Jar Jar.Json Jar.Codec

instance : JamConfig where
  config := Config.tiny
  valid := Config.tiny_valid

-- ============================================================================
-- Test harness: run N random instances and check a property
-- ============================================================================

/-- Run a property check over N random instances. -/
def checkProp (name : String) (gen : Gen α) (prop : α → Bool)
    (n : Nat := 100) : IO Bool := do
  for i in List.range n do
    let val ← Gen.run gen (i % 50 + 1)
    if !prop val then
      IO.println s!"  FAIL: {name} (instance {i})"
      return false
  IO.println s!"  PASS: {name} ({n} instances)"
  return true

-- ============================================================================
-- JSON roundtrip: toJson then fromJson? then toJson = original JSON
-- ============================================================================

/-- Check JSON roundtrip via JSON equality: toJson(fromJson?(toJson(x))) == toJson(x). -/
def jsonRoundtrip [ToJson α] [FromJson α] (x : α) : Bool :=
  let j := toJson x
  match @fromJson? α _ j with
  | .ok y => toJson y == j
  | .error _ => false

-- ============================================================================
-- Codec properties
-- ============================================================================

/-- encodeFixedNat l x produces exactly l bytes. -/
def fixedNatLengthProp (l x : Nat) : Bool :=
  (encodeFixedNat l x).size == l

/-- decodeFixedNat (encodeFixedNat l x) == x for x < 2^(8*l). -/
def fixedNatRoundtripProp (l x : Nat) : Bool :=
  let encoded := encodeFixedNat l x
  let decoded := decodeFixedNat encoded
  decoded == x % (2^(8*l))

/-- encodeNat x produces 1-9 bytes. -/
def natLengthProp (x : Nat) : Bool :=
  let encoded := encodeNat x
  encoded.size ≥ 1 && encoded.size ≤ 9

/-- encodeNat is deterministic. -/
def natDeterministicProp (x : Nat) : Bool :=
  encodeNat x == encodeNat x

/-- Encoding a non-negative value produces non-empty output. -/
def encodeNatNonEmpty (x : Nat) : Bool :=
  (encodeNat x).size > 0

-- ============================================================================
-- Encoding length properties for structures
-- ============================================================================

/-- WorkDigest encoding is non-empty. -/
def workDigestEncodeNonEmpty (wd : WorkDigest) : Bool :=
  (encodeWorkDigest wd).size > 0

/-- AvailabilitySpec encoding is deterministic. -/
def availSpecEncodeDeterministic (a : AvailabilitySpec) : Bool :=
  encodeAvailSpec a == encodeAvailSpec a

/-- WorkReport encoding is non-empty and deterministic. -/
def workReportEncodeProp (wr : WorkReport) : Bool :=
  let e1 := encodeWorkReport wr
  let e2 := encodeWorkReport wr
  e1.size > 0 && e1 == e2

-- ============================================================================
-- Hex encoding roundtrip
-- ============================================================================

/-- Hex encode then decode is identity for ByteArray. -/
def hexRoundtripProp (bs : ByteArray) : Bool :=
  match hexToBytes (bytesToHex bs) with
  | .ok bs' => bs == bs'
  | .error _ => false

-- ============================================================================
-- Run all property tests
-- ============================================================================

def runAll : IO UInt32 := do
  IO.println "Running property-based tests...\n"
  let mut passed : Nat := 0
  let mut failed : Nat := 0

  -- Hex roundtrip
  IO.println "── Hex encoding ──"
  if ← checkProp "hex roundtrip (ByteArray)" (arbitrary : Gen ByteArray) hexRoundtripProp
  then passed := passed + 1 else failed := failed + 1

  -- Codec: encodeFixedNat / decodeFixedNat
  IO.println "\n── Fixed-width integer codec ──"
  for (name, l) in [("1", 1), ("2", 2), ("4", 4), ("8", 8)] do
    if ← checkProp s!"encodeFixedNat {name} length"
        Gen.chooseNat (fun x => fixedNatLengthProp l x)
    then passed := passed + 1 else failed := failed + 1
    if ← checkProp s!"decodeFixedNat∘encodeFixedNat {name} roundtrip"
        Gen.chooseNat (fun x => fixedNatRoundtripProp l x)
    then passed := passed + 1 else failed := failed + 1

  -- Codec: encodeNat
  IO.println "\n── Variable-length natural codec ──"
  if ← checkProp "encodeNat length 1-9" Gen.chooseNat natLengthProp
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "encodeNat non-empty" Gen.chooseNat encodeNatNonEmpty
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "encodeNat deterministic" Gen.chooseNat natDeterministicProp
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "encodeNat(0) = [0]" (pure 0) (fun x => encodeNat x == ByteArray.mk #[0])
  then passed := passed + 1 else failed := failed + 1

  -- JSON roundtrips: primitives
  IO.println "\n── JSON roundtrips: primitive types ──"
  if ← checkProp "JSON roundtrip ByteArray"
      (arbitrary : Gen ByteArray) (jsonRoundtrip (α := ByteArray))
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "JSON roundtrip Hash"
      (arbitrary : Gen Hash) (jsonRoundtrip (α := Hash))
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "JSON roundtrip UInt32 (Timeslot)"
      (arbitrary : Gen UInt32) (jsonRoundtrip (α := Timeslot))
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "JSON roundtrip UInt64 (Gas)"
      (arbitrary : Gen UInt64) (jsonRoundtrip (α := Gas))
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "JSON roundtrip UInt32 (ServiceId)"
      (arbitrary : Gen UInt32) (jsonRoundtrip (α := ServiceId))
  then passed := passed + 1 else failed := failed + 1

  -- JSON roundtrips: work types
  IO.println "\n── JSON roundtrips: work types ──"
  if ← checkProp "JSON roundtrip WorkError"
      (arbitrary : Gen WorkError) (jsonRoundtrip (α := WorkError))
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "JSON roundtrip WorkResult"
      (arbitrary : Gen WorkResult) (jsonRoundtrip (α := WorkResult))
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "JSON roundtrip WorkDigest"
      (arbitrary : Gen WorkDigest) (jsonRoundtrip (α := WorkDigest))
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "JSON roundtrip AvailabilitySpec"
      (arbitrary : Gen AvailabilitySpec) (jsonRoundtrip (α := AvailabilitySpec))
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "JSON roundtrip RefinementContext"
      (arbitrary : Gen RefinementContext) (jsonRoundtrip (α := RefinementContext))
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "JSON roundtrip WorkReport"
      (arbitrary : Gen WorkReport) (jsonRoundtrip (α := WorkReport))
  then passed := passed + 1 else failed := failed + 1

  -- JSON roundtrips: validator types
  IO.println "\n── JSON roundtrips: validator types ──"
  if ← checkProp "JSON roundtrip ValidatorKey"
      (arbitrary : Gen ValidatorKey) (jsonRoundtrip (α := ValidatorKey))
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "JSON roundtrip Ticket"
      (arbitrary : Gen Ticket) (jsonRoundtrip (α := Ticket))
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "JSON roundtrip SealKeySeries"
      (arbitrary : Gen SealKeySeries) (jsonRoundtrip (α := SealKeySeries))
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "JSON roundtrip EpochMarker"
      (arbitrary : Gen EpochMarker) (jsonRoundtrip (α := EpochMarker))
  then passed := passed + 1 else failed := failed + 1

  -- JSON roundtrips: state types
  IO.println "\n── JSON roundtrips: state types ──"
  if ← checkProp "JSON roundtrip JudgmentsState"
      (arbitrary : Gen JudgmentsState) (jsonRoundtrip (α := JudgmentsState))
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "JSON roundtrip Entropy"
      (arbitrary : Gen Entropy) (jsonRoundtrip (α := Entropy))
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "JSON roundtrip SafroleState"
      (arbitrary : Gen SafroleState) (jsonRoundtrip (α := SafroleState))
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "JSON roundtrip PrivilegedServices"
      (arbitrary : Gen PrivilegedServices) (jsonRoundtrip (α := PrivilegedServices))
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "JSON roundtrip DeferredTransfer"
      (arbitrary : Gen DeferredTransfer) (jsonRoundtrip (α := DeferredTransfer))
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "JSON roundtrip ValidatorRecord"
      (arbitrary : Gen ValidatorRecord) (jsonRoundtrip (α := ValidatorRecord))
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "JSON roundtrip CoreStatistics"
      (arbitrary : Gen CoreStatistics) (jsonRoundtrip (α := CoreStatistics))
  then passed := passed + 1 else failed := failed + 1

  -- Codec: structure encoding
  IO.println "\n── Codec: structure encoding ──"
  if ← checkProp "WorkDigest encode non-empty"
      (arbitrary : Gen WorkDigest) workDigestEncodeNonEmpty
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "AvailabilitySpec encode deterministic"
      (arbitrary : Gen AvailabilitySpec) availSpecEncodeDeterministic
  then passed := passed + 1 else failed := failed + 1
  if ← checkProp "WorkReport encode non-empty & deterministic"
      (arbitrary : Gen WorkReport) workReportEncodeProp
  then passed := passed + 1 else failed := failed + 1

  IO.println s!"\nProperty tests: {passed} passed, {failed} failed, {passed + failed} total"
  return if failed > 0 then 1 else 0

end Jar.Test.Properties
