import Jar.Notation
import Jar.Types
import Jar.Crypto

/-!
# History Sub-Transition Test Harness

Tests the §7 recent block history update: parent state root fixup,
MMR append, beefy root computation, and sliding window.
-/

namespace Jar.Test.History

open Jar Jar.Crypto

variable [JamConfig]

-- ============================================================================
-- Flattened History State (matches test vector JSON shape)
-- ============================================================================

/-- A reported work package: (hash, exports_root). -/
structure ReportedPackage where
  hash : Hash
  exportsRoot : Hash
  deriving BEq

/-- A single entry in recent block history. -/
structure HistoryEntry where
  headerHash : Hash
  beefyRoot : Hash
  stateRoot : Hash
  reported : Array ReportedPackage
  deriving BEq, Inhabited

/-- Flattened history state: history entries + MMR peaks. -/
structure FlatHistoryState where
  history : Array HistoryEntry
  mmrPeaks : Array (Option Hash)
  deriving BEq

-- ============================================================================
-- Input
-- ============================================================================

/-- Input for the history sub-transition. -/
structure HistoryInput where
  headerHash : Hash
  parentStateRoot : Hash
  accumulateRoot : Hash
  workPackages : Array ReportedPackage

-- ============================================================================
-- MMR Operations (using Keccak-256 per §7 / Appendix E)
-- ============================================================================

/-- Append a leaf to an MMR, merging peaks as needed (eq E.8). -/
def mmrAppend (peaks : Array (Option Hash)) (leaf : Hash) : Array (Option Hash) :=
  let rec go (ps : Array (Option Hash)) (carry : Hash) (i : Nat) : Array (Option Hash) :=
    if i >= ps.size then
      ps.push (some carry)
    else
      match ps[i]! with
      | none => ps.set! i (some carry)
      | some existing =>
        -- Merge: H_K(existing ++ carry)
        let combined := existing.data ++ carry.data
        let merged : Hash := keccak256 combined
        go (ps.set! i none) merged (i + 1)
  go peaks leaf 0

/-- Compute MMR super-peak MR (eq E.10).
    MR([]) = H_0, MR([h]) = h, MR(h) = H_K("peak" ++ MR(h[..n-1]) ++ h[n-1]) -/
def mmrSuperPeak (peaks : Array (Option Hash)) : Hash :=
  let nonNone := peaks.filterMap id
  -- Iterative: fold from left, combining accumulator with each peak
  -- MR([]) = H_0, MR([h]) = h, MR(h) = H_K("peak" ++ MR(h[..n-1]) ++ h[n-1])
  match nonNone.size with
  | 0 => Hash.zero
  | _ =>
    let init : Hash := nonNone[0]!
    nonNone.foldl (init := init) (start := 1) fun acc peak =>
      let data := "peak".toUTF8 ++ acc.data ++ peak.data
      keccak256 data

-- ============================================================================
-- History Sub-Transition (§7)
-- ============================================================================

/-- Compute the history sub-transition.
    1. Fix parent state root on previous entry
    2. MMR append of accumulate_root
    3. Compute beefy_root as MMR super-peak
    4. Append new entry
    5. Keep last H entries -/
def historyTransition
    (pre : FlatHistoryState) (inp : HistoryInput) : FlatHistoryState :=
  -- Step 1: fix up previous entry's state_root
  let history := if pre.history.size > 0 then
    let last := pre.history[pre.history.size - 1]!
    pre.history.set! (pre.history.size - 1) { last with stateRoot := inp.parentStateRoot }
  else pre.history

  -- Step 2: MMR append
  let peaks := mmrAppend pre.mmrPeaks inp.accumulateRoot

  -- Step 3: compute beefy root
  let beefyRoot := mmrSuperPeak peaks

  -- Step 4: append new entry
  let entry : HistoryEntry := {
    headerHash := inp.headerHash
    beefyRoot := beefyRoot
    stateRoot := Hash.zero
    reported := inp.workPackages
  }
  let history := history.push entry

  -- Step 5: keep last H entries
  let history := if history.size > H_RECENT then
    history.extract (history.size - H_RECENT) history.size
  else history

  { history := history, mmrPeaks := peaks }

-- ============================================================================
-- Test Runner
-- ============================================================================

/-- Display a Hash as hex (first 8 bytes). -/
def hashToHexShort (h : Hash) : String :=
  let bytes := h.data.data
  let showByte (b : UInt8) : String :=
    let hi := b.toNat / 16
    let lo := b.toNat % 16
    let hexChar (n : Nat) : Char :=
      if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)
    String.ofList [hexChar hi, hexChar lo]
  String.join (bytes.toList.take 8 |>.map showByte) ++ "..."

/-- Run a single history test case. Returns true on pass. -/
def runTest (name : String) (pre : FlatHistoryState) (inp : HistoryInput)
    (post : FlatHistoryState) : IO Bool := do
  let result := historyTransition pre inp
  let mut ok := true

  -- Compare history entries
  if result.history.size != post.history.size then
    IO.println s!"  history size: expected {post.history.size}, got {result.history.size}"
    ok := false
  else
    for i in [:result.history.size] do
      let r : HistoryEntry := result.history[i]!
      let e : HistoryEntry := post.history[i]!
      if r != e then
        ok := false
        IO.println s!"  history[{i}] mismatch:"
        if r.headerHash != e.headerHash then
          IO.println s!"    headerHash: expected {hashToHexShort e.headerHash}, got {hashToHexShort r.headerHash}"
        if r.beefyRoot != e.beefyRoot then
          IO.println s!"    beefyRoot: expected {hashToHexShort e.beefyRoot}, got {hashToHexShort r.beefyRoot}"
        if r.stateRoot != e.stateRoot then
          IO.println s!"    stateRoot: expected {hashToHexShort e.stateRoot}, got {hashToHexShort r.stateRoot}"
        if r.reported != e.reported then
          IO.println s!"    reported: expected {e.reported.size} pkgs, got {r.reported.size} pkgs"

  -- Compare MMR peaks
  if result.mmrPeaks.size != post.mmrPeaks.size then
    IO.println s!"  mmr peaks size: expected {post.mmrPeaks.size}, got {result.mmrPeaks.size}"
    ok := false
  else
    for i in [:result.mmrPeaks.size] do
      let r := result.mmrPeaks[i]!
      let e := post.mmrPeaks[i]!
      if r != e then
        ok := false
        let rStr := match r with | some h => hashToHexShort h | none => "none"
        let eStr := match e with | some h => hashToHexShort h | none => "none"
        IO.println s!"  mmr[{i}]: expected {eStr}, got {rStr}"

  if ok then
    IO.println s!"  ✓ {name}"
  else
    IO.println s!"  ✗ {name}"
  return ok

end Jar.Test.History
