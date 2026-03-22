import Jar.Notation
import Jar.Types

/-!
# Statistics Sub-Transition Test Harness

Tests the §13.1 validator statistics update: blocks, tickets, preimages,
guarantees, and assurances counting.
-/

namespace Jar.Test.Statistics

open Jar

variable [JamConfig]

-- ============================================================================
-- Flattened Statistics State (matches test vector JSON shape)
-- ============================================================================

/-- Per-validator activity record matching test vector shape. -/
structure FlatValidatorRecord where
  blocks : Nat
  tickets : Nat
  preImages : Nat
  preImagesSize : Nat
  guarantees : Nat
  assurances : Nat
  deriving Repr, BEq, Inhabited

/-- Flattened statistics state matching test vector pre_state / post_state. -/
structure FlatStatisticsState where
  valsCurrStats : Array FlatValidatorRecord
  valsLastStats : Array FlatValidatorRecord
  slot : Timeslot
  deriving Repr, BEq

-- ============================================================================
-- Simplified Input (matches test vector input shape)
-- ============================================================================

/-- Simplified extrinsic data — only what statistics needs. -/
structure StatsExtrinsic where
  ticketCount : Nat
  /-- Preimage blob sizes (for counting and summing). -/
  preimageSizes : Array Nat
  /-- Guarantee credential validator indices. -/
  guaranteeSigners : Array (Array Nat)
  /-- Assurance validator indices. -/
  assuranceValidators : Array Nat

/-- Input for the statistics sub-transition. -/
structure StatsInput where
  slot : Timeslot
  authorIndex : Nat
  extrinsic : StatsExtrinsic

-- ============================================================================
-- Statistics Sub-Transition (§13.1 — Validator Statistics only)
-- ============================================================================

/-- Zero-valued validator record. -/
def FlatValidatorRecord.zero : FlatValidatorRecord :=
  { blocks := 0, tickets := 0, preImages := 0,
    preImagesSize := 0, guarantees := 0, assurances := 0 }

/-- Compute the statistics sub-transition.
    This implements §13.1 of the Gray Paper (validator-level statistics). -/
def statisticsTransition
    (pre : FlatStatisticsState) (inp : StatsInput) : FlatStatisticsState :=
  let epochChanged := pre.slot / E.toUInt32 != inp.slot / E.toUInt32
  let (cur, prev) := if epochChanged then
      (Array.replicate V FlatValidatorRecord.zero, pre.valsCurrStats)
    else (pre.valsCurrStats, pre.valsLastStats)

  -- §13.1: Block author stats — increment blocks for author
  let authorIdx := inp.authorIndex
  let cur := if authorIdx < cur.size then
    let r := cur[authorIdx]!
    cur.set! authorIdx { r with blocks := r.blocks + 1 }
  else cur

  -- §13.1: Ticket stats — credit author for all tickets
  let cur := if inp.extrinsic.ticketCount > 0 then
    if authorIdx < cur.size then
      let r := cur[authorIdx]!
      cur.set! authorIdx { r with tickets := r.tickets + inp.extrinsic.ticketCount }
    else cur
  else cur

  -- §13.1: Preimage stats — credit author for all preimages
  let cur := if inp.extrinsic.preimageSizes.size > 0 then
    let totalSize := inp.extrinsic.preimageSizes.foldl (· + ·) 0
    if authorIdx < cur.size then
      let r := cur[authorIdx]!
      cur.set! authorIdx { r with
        preImages := r.preImages + inp.extrinsic.preimageSizes.size
        preImagesSize := r.preImagesSize + totalSize }
    else cur
  else cur

  -- §13.1: Guarantee stats — credit each guarantor validator
  let cur := inp.extrinsic.guaranteeSigners.foldl (init := cur) fun (c : Array FlatValidatorRecord) (signers : Array Nat) =>
    signers.foldl (init := c) fun (c' : Array FlatValidatorRecord) vi =>
      if vi < c'.size then
        let r := c'[vi]!
        c'.set! vi { r with guarantees := r.guarantees + 1 }
      else c'

  -- §13.1: Assurance stats — credit each assuring validator
  let cur := inp.extrinsic.assuranceValidators.foldl (init := cur) fun (c : Array FlatValidatorRecord) vi =>
    if vi < c.size then
      let r := c[vi]!
      c.set! vi { r with assurances := r.assurances + 1 }
    else c

  { valsCurrStats := cur
    valsLastStats := prev
    slot := pre.slot }  -- slot is not updated by statistics sub-transition

-- ============================================================================
-- Test Runner
-- ============================================================================

/-- Compare two FlatValidatorRecord arrays field by field, reporting mismatches. -/
def compareRecordArrays (label : String)
    (expected actual : Array FlatValidatorRecord) : IO Bool := do
  let mut ok := true
  if expected.size != actual.size then
    IO.println s!"  {label}: size mismatch: expected {expected.size}, got {actual.size}"
    return false
  for i in [:expected.size] do
    let exp : FlatValidatorRecord := expected[i]!
    let act : FlatValidatorRecord := actual[i]!
    if exp != act then
      ok := false
      IO.println s!"  {label}[{i}] mismatch:"
      if exp.blocks != act.blocks then
        IO.println s!"    blocks: expected {exp.blocks}, got {act.blocks}"
      if exp.tickets != act.tickets then
        IO.println s!"    tickets: expected {exp.tickets}, got {act.tickets}"
      if exp.preImages != act.preImages then
        IO.println s!"    preImages: expected {exp.preImages}, got {act.preImages}"
      if exp.preImagesSize != act.preImagesSize then
        IO.println s!"    preImagesSize: expected {exp.preImagesSize}, got {act.preImagesSize}"
      if exp.guarantees != act.guarantees then
        IO.println s!"    guarantees: expected {exp.guarantees}, got {act.guarantees}"
      if exp.assurances != act.assurances then
        IO.println s!"    assurances: expected {exp.assurances}, got {act.assurances}"
  return ok

/-- Run a single statistics test case. Returns true on pass. -/
def runTest (name : String) (pre : FlatStatisticsState) (inp : StatsInput)
    (post : FlatStatisticsState) : IO Bool := do
  let result := statisticsTransition pre inp
  let mut ok := true

  let currOk ← compareRecordArrays "vals_curr_stats" post.valsCurrStats result.valsCurrStats
  if !currOk then ok := false

  let lastOk ← compareRecordArrays "vals_last_stats" post.valsLastStats result.valsLastStats
  if !lastOk then ok := false

  if ok then
    IO.println s!"  ✓ {name}"
  else
    IO.println s!"  ✗ {name}"
  return ok

end Jar.Test.Statistics
