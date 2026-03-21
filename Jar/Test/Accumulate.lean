import Jar.Notation
import Jar.Types
import Jar.Codec
import Jar.Crypto
import Jar.PVM
import Jar.PVM.Decode
import Jar.PVM.Memory
import Jar.PVM.Instructions
import Jar.PVM.Interpreter
import Jar.Accumulation

/-!
# Accumulate Sub-Transition Test Harness

Tests the §12 accumulation pipeline: report partitioning, dependency resolution,
PVM accumulation, ready queue management, and output hash computation.
-/

namespace Jar.Test.Accumulate

open Jar Jar.Crypto Jar.Accumulation

variable [JamConfig]

/-- Build config blob for tiny config, matching Rust Config::tiny().encode_config_blob().
    Format: B_I(8) B_L(8) B_S(8) C(2) D(4) E(4) G_A(8) G_I(8) G_R(8) G_T(8)
            H(2) I(2) J(2) K(2) L(4) N(2) O(2) P(2) Q(2) R(2) T(2) U(2) V(2)
            W_A(4) W_B(4) W_C(4) W_E(4) W_M(4) W_P(4) W_R(4) W_T(4) W_X(4) Y(4) = 134 bytes -/
def buildTinyConfigBlob : ByteArray :=
  let e8 (n : Nat) := Codec.encodeFixedNat 8 n
  let e4 (n : Nat) := Codec.encodeFixedNat 4 n
  let e2 (n : Nat) := Codec.encodeFixedNat 2 n
  -- Constants from Rust Config::tiny() + grey-types constants
  e8 10          -- B_I
  ++ e8 1        -- B_L
  ++ e8 100      -- B_S
  ++ e2 2        -- C (core_count = 2)
  ++ e4 32       -- D (preimage_expunge_period = 32)
  ++ e4 12       -- E (epoch_length = 12)
  ++ e8 10000000 -- G_A
  ++ e8 50000000 -- G_I
  ++ e8 1000000000 -- G_R (gas_refine = 1_000_000_000)
  ++ e8 20000000 -- G_T (gas_total_accumulation = 20_000_000)
  ++ e2 8        -- H (recent_history_size = 8)
  ++ e2 16       -- I (MAX_WORK_ITEMS = 16)
  ++ e2 8        -- J (MAX_DEPENDENCY_ITEMS = 8)
  ++ e2 3        -- K (max_tickets_per_block = 3)
  ++ e4 14400    -- L (MAX_LOOKUP_ANCHOR_AGE = 14400)
  ++ e2 3        -- N (tickets_per_validator = 3)
  ++ e2 8        -- O (auth_pool_size = 8)
  ++ e2 6        -- P (SLOT_PERIOD_SECONDS = 6)
  ++ e2 80       -- Q (auth_queue_size = 80)
  ++ e2 4        -- R (rotation_period_val = 4)
  ++ e2 128      -- T (MAX_WORK_PACKAGE_EXTRINSICS = 128)
  ++ e2 5        -- U (availability_timeout = 5)
  ++ e2 6        -- V (validators_count = 6)
  ++ e4 64000    -- W_A
  ++ e4 13791360 -- W_B
  ++ e4 4000000  -- W_C
  ++ e4 684      -- W_E
  ++ e4 3072     -- W_M
  ++ e4 1026     -- W_P (erasure_pieces_per_segment = 1026)
  ++ e4 49152    -- W_R
  ++ e4 128      -- W_T
  ++ e4 3072     -- W_X
  ++ e4 10       -- Y (ticket_submission_end_val = 10)

-- ============================================================================
-- Types for test vector state
-- ============================================================================

/-- Service statistics record for accumulation tests. -/
structure TAServiceStats where
  serviceId : Nat
  providedCount : Nat
  providedSize : Nat
  refinementCount : Nat
  refinementGasUsed : Nat
  imports : Nat
  extrinsicCount : Nat
  extrinsicSize : Nat
  exports : Nat
  accumulateCount : Nat
  accumulateGasUsed : Nat
  deriving BEq, Inhabited

/-- Privileges in test vector format. -/
structure TAPrivileges where
  bless : Nat
  assign : Array Nat
  designate : Nat
  register : Nat
  alwaysAcc : Array (Nat × Nat)  -- (service_id, gas)
  deriving BEq, Inhabited

/-- Ready record: report with dependencies. -/
structure TAReadyRecord where
  report : WorkReport
  dependencies : Array Hash

/-- State for accumulate sub-transition. -/
structure TAState where
  slot : Nat
  entropy : Hash
  readyQueue : Array (Array TAReadyRecord)  -- E slots
  accumulated : Array (Array Hash)          -- E slots
  privileges : TAPrivileges
  statistics : Array TAServiceStats
  accounts : Dict ServiceId ServiceAccount

/-- Input to accumulate sub-transition. -/
structure TAInput where
  slot : Nat
  reports : Array WorkReport

-- ============================================================================
-- Dependency computation
-- ============================================================================

/-- Compute dependencies for a work report: prerequisites ∪ segment_root_lookup keys. -/
def computeDependencies (report : WorkReport) : Array Hash := Id.run do
  let mut deps : Array Hash := #[]
  for prereq in report.context.prerequisites do
    if !deps.any (· == prereq) then
      deps := deps.push prereq
  for (pkgHash, _) in report.segmentRootLookup.entries do
    if !deps.any (· == pkgHash) then
      deps := deps.push pkgHash
  deps

-- ============================================================================
-- Report partitioning (eq 12.4-12.5)
-- ============================================================================

/-- Partition reports into immediate (no deps) and queued (with deps). -/
def partitionReports (reports : Array WorkReport)
    : Array WorkReport × Array TAReadyRecord := Id.run do
  let mut immediate : Array WorkReport := #[]
  let mut queued : Array TAReadyRecord := #[]
  for report in reports do
    let deps := computeDependencies report
    if deps.size == 0 then
      immediate := immediate.push report
    else
      queued := queued.push { report, dependencies := deps }
  (immediate, queued)

-- ============================================================================
-- Queue editing (eq 12.7)
-- ============================================================================

/-- Edit queue: remove entries whose package hash is accumulated,
    strip fulfilled dependencies. -/
def editQueue (queue : Array TAReadyRecord) (accumulated : Array Hash)
    : Array TAReadyRecord := Id.run do
  let mut result : Array TAReadyRecord := #[]
  for rr in queue do
    if !accumulated.any (· == rr.report.availSpec.packageHash) then
      let deps := rr.dependencies.filter fun d => !accumulated.any (· == d)
      result := result.push { rr with dependencies := deps }
  result

-- ============================================================================
-- Queue resolution (eq 12.8)
-- ============================================================================

/-- Resolve queue: recursively find reports with empty dependencies. -/
partial def resolveQueue (queue : Array TAReadyRecord) : Array WorkReport := Id.run do
  let ready := queue.filter (·.dependencies.size == 0)
  if ready.size == 0 then return #[]
  let readyReports := ready.map (·.report)
  let readyHashes := readyReports.map (·.availSpec.packageHash)
  let remaining := editQueue (queue.filter (·.dependencies.size > 0)) readyHashes
  readyReports ++ resolveQueue remaining

-- ============================================================================
-- Compute accumulatable reports (eq 12.10-12.12)
-- ============================================================================

/-- Compute R* = immediate + resolved queue entries. -/
def computeAccumulatable (immediate : Array WorkReport)
    (readyQueue : Array (Array TAReadyRecord))
    (newQueued : Array TAReadyRecord)
    (epochLength : Nat) (slotIndex : Nat) : Array WorkReport := Id.run do
  -- Gather all queued entries from ready queue (rotated from slotIndex)
  let mut allQueued : Array TAReadyRecord := #[]
  for i in [:epochLength] do
    let idx := (slotIndex + i) % epochLength
    if idx < readyQueue.size then
      for rr in readyQueue[idx]! do
        allQueued := allQueued.push rr
  -- Add new queued
  allQueued := allQueued ++ newQueued
  -- Edit with immediate hashes
  let immediateHashes := immediate.map (·.availSpec.packageHash)
  let edited := editQueue allQueued immediateHashes
  -- Resolve
  immediate ++ resolveQueue edited

-- ============================================================================
-- Keccak Merkle tree for output hash (Appendix E with H_K)
-- ============================================================================

/-- Keccak merkle node N(v, H_K). -/
partial def keccakMerkleNode (leaves : Array ByteArray) : ByteArray :=
  match leaves.size with
  | 0 => Hash.zero.data
  | 1 => leaves[0]!
  | n =>
    let mid := (n + 1) / 2
    let left := keccakMerkleNode (leaves.extract 0 mid)
    let right := keccakMerkleNode (leaves.extract mid n)
    let input := "node".toUTF8 ++ left ++ right
    (keccak256 input).data

/-- Keccak merkle root M_B(v, H_K). -/
def keccakMerkleRoot (leaves : Array ByteArray) : Hash :=
  if leaves.size == 1 then
    keccak256 leaves[0]!
  else
    Hash.mk! (keccakMerkleNode leaves)

/-- Compute output hash from (service_id, yield_hash) pairs. -/
def computeOutputHash (outputs : Array (ServiceId × Hash)) : Hash :=
  if outputs.size == 0 then Hash.zero
  else
    let sorted := outputs.qsort (fun a b => a.1 < b.1)
    let leaves := sorted.map fun (sid, h) =>
      Codec.encodeFixedNat 4 sid.toNat ++ h.data
    keccakMerkleRoot leaves

-- ============================================================================
-- Update ready queue (eq 12.34)
-- ============================================================================

/-- Update ready queue after accumulation. -/
def updateReadyQueue (readyQueue : Array (Array TAReadyRecord))
    (newQueued : Array TAReadyRecord) (accumulatedHashes : Array Hash)
    (epochLength : Nat) (preSlot : Nat) (postSlot : Nat)
    : Array (Array TAReadyRecord) := Id.run do
  let mut rq := readyQueue

  -- Clear positions from prev_slot+1 to current_slot (inclusive)
  let slotsAdvanced := min (postSlot - preSlot) epochLength
  for i in [:slotsAdvanced] do
    let clearIdx := (preSlot + 1 + i) % epochLength
    if clearIdx < rq.size then
      rq := rq.set! clearIdx #[]

  -- Edit remaining with accumulated hashes
  for i in [:epochLength] do
    if i < rq.size then
      rq := rq.set! i (editQueue rq[i]! accumulatedHashes)

  -- Insert new queued at current slot index
  let insertIdx := postSlot % epochLength
  if insertIdx < rq.size then
    -- Also edit new queued with accumulated hashes
    let editedNew := editQueue newQueued accumulatedHashes
    rq := rq.set! insertIdx (rq[insertIdx]! ++ editedNew)

  rq

-- ============================================================================
-- Shift accumulated history (eq 12.32)
-- ============================================================================

/-- Shift accumulated history, recording new package hashes. -/
def shiftAccumulated (accumulated : Array (Array Hash))
    (accumulatable : Array WorkReport) (n : Nat)
    : Array (Array Hash) := Id.run do
  if accumulated.size == 0 then return accumulated
  -- Shift left by 1
  let mut acc := accumulated.extract 1 accumulated.size
  -- Compute new hashes from accumulated reports (sorted, matching Rust)
  let newHashes := (accumulatable.extract 0 n).map (·.availSpec.packageHash)
  let newHashes := newHashes.qsort (fun a b => a.data.data.toList < b.data.data.toList)
  acc := acc.push newHashes
  acc

-- ============================================================================
-- Update statistics
-- ============================================================================

/-- Update service statistics with accumulation results.
    GP eq:accumulationstatisticsdef:
    - G(s) = total gas used for service s across all rounds
    - N(s) = number of work-item digests with service_id=s in accumulated reports -/
def updateStatistics (stats : Array TAServiceStats)
    (gasUsage : Dict ServiceId Gas) (accumulatable : Array WorkReport) (n : Nat)
    : Array TAServiceStats := Id.run do
  let mut result := stats
  -- Compute N(s) for each service: count work-item digests in first n reports
  let reports := accumulatable.extract 0 n
  for (sid, gas) in gasUsage.entries do
    let itemCount := reports.foldl (init := 0) fun acc r =>
      acc + r.digests.foldl (init := 0) fun acc2 d =>
        acc2 + if d.serviceId == sid then 1 else 0
    -- GP: only include if G(s) + N(s) ≠ 0
    if gas.toNat + itemCount == 0 then
      pure ()
    else
      match result.findIdx? (·.serviceId == sid.toNat) with
      | some idx =>
        let s := result[idx]!
        result := result.set! idx { s with
          accumulateCount := s.accumulateCount + itemCount
          accumulateGasUsed := s.accumulateGasUsed + gas.toNat }
      | none =>
        result := result.push {
          serviceId := sid.toNat
          providedCount := 0
          providedSize := 0
          refinementCount := 0
          refinementGasUsed := 0
          imports := 0
          extrinsicCount := 0
          extrinsicSize := 0
          exports := 0
          accumulateCount := itemCount
          accumulateGasUsed := gas.toNat }
  result

-- ============================================================================
-- Main accumulate transition
-- ============================================================================

/-- Run the full accumulate sub-transition. -/
def accumulateTransition (pre : TAState) (inp : TAInput)
    : Hash × TAState := Id.run do
  let epochLength := E
  let slotIndex := inp.slot % epochLength

  -- Step 1: Partition input reports
  let (immediate, newQueued) := partitionReports inp.reports

  -- Step 1b: Compute accumulated union and edit new queued
  let accumulatedUnion := pre.accumulated.foldl (init := #[]) fun acc slot =>
    acc ++ slot
  let editedNewQueued := editQueue newQueued accumulatedUnion

  -- Step 2: Compute accumulatable reports
  let accumulatable := computeAccumulatable immediate pre.readyQueue
    editedNewQueued epochLength slotIndex

  -- Step 3: Build PartialState from test state
  let ps : PartialState := {
    accounts := pre.accounts
    stagingKeys := #[]
    authQueue := #[]
    manager := UInt32.ofNat pre.privileges.bless
    assigners := pre.privileges.assign.map UInt32.ofNat
    designator := UInt32.ofNat pre.privileges.designate
    registrar := UInt32.ofNat pre.privileges.register
    alwaysAccumulate := pre.privileges.alwaysAcc.foldl (init := Dict.empty) fun acc (sid, gas) =>
      acc.insert (UInt32.ofNat sid) (UInt64.ofNat gas)
  }

  -- Step 4: Compute gas budget
  let alwaysGas := pre.privileges.alwaysAcc.foldl (init := 0) fun acc (_, g) => acc + g
  let _gasBudget := max G_T (G_A * C + alwaysGas)

  -- Step 5: Build free gas map from always_acc
  let freeGasMap := pre.privileges.alwaysAcc.foldl (init := Dict.empty (K := ServiceId) (V := Gas))
    fun acc (sid, gas) => acc.insert (UInt32.ofNat sid) (UInt64.ofNat gas)

  -- Step 6: Run accumulation pipeline
  -- Build tiny config blob matching Rust's Config::tiny().encode_config_blob()
  let tinyConfigBlob := buildTinyConfigBlob
  let result := accseq (UInt64.ofNat G_T)
    accumulatable #[] ps freeGasMap (UInt32.ofNat inp.slot) pre.entropy tinyConfigBlob
  let n := result.1
  let ps' := result.2.1
  let yields := result.2.2.1
  let gasMap := result.2.2.2.1
  let _countMap := result.2.2.2.2.1


  -- Step 7: Compute output hash
  let outputHash := computeOutputHash yields

  -- Step 8: Update last_accumulation_slot for accumulated services
  let mut accounts := ps'.accounts
  for (sid, _) in gasMap.entries do
    match accounts.lookup sid with
    | some acct =>
      accounts := accounts.insert sid { acct with lastAccumulation := UInt32.ofNat inp.slot }
    | none => pure ()

  -- Step 9: Compute statistics fresh — GP eq:accumulationstatisticsdef
  -- Statistics are per-block, not carried forward from pre_state
  let newStats := updateStatistics #[] gasMap accumulatable n

  -- Step 10: Shift accumulated
  let newAccumulated := shiftAccumulated pre.accumulated accumulatable n

  -- Step 11: Update ready queue
  let accHashes := match newAccumulated.back? with
    | some h => h
    | none => #[]
  let newReadyQueue := updateReadyQueue pre.readyQueue editedNewQueued
    accHashes epochLength pre.slot inp.slot

  -- Step 12: Update privileges
  let newPrivileges : TAPrivileges := {
    bless := ps'.manager.toNat
    assign := ps'.assigners.map (·.toNat)
    designate := ps'.designator.toNat
    register := ps'.registrar.toNat
    alwaysAcc := (ps'.alwaysAccumulate.entries.map fun (sid, gas) => (sid.toNat, gas.toNat)).toArray
  }

  let postState : TAState := {
    slot := inp.slot
    entropy := pre.entropy
    readyQueue := newReadyQueue
    accumulated := newAccumulated
    privileges := newPrivileges
    statistics := newStats
    accounts := accounts
  }

  (outputHash, postState)

-- ============================================================================
-- Test Runner
-- ============================================================================

/-- Compare two hash arrays. -/
def hashArrayEq (a b : Array Hash) : Bool :=
  a.size == b.size && (Array.range a.size).all fun i => a[i]! == b[i]!

def runTest (name : String) (pre : TAState) (inp : TAInput)
    (expectedHash : Hash) (post : TAState) : IO Bool := do
  let (outputHash, result) := accumulateTransition pre inp
  let mut ok := true

  -- Check output hash
  if outputHash != expectedHash then
    ok := false
    IO.println s!"  output hash mismatch"

  -- Check slot
  if result.slot != post.slot then
    ok := false
    IO.println s!"  slot: expected {post.slot}, got {result.slot}"

  -- Check accumulated
  if result.accumulated.size != post.accumulated.size then
    ok := false
    IO.println s!"  accumulated length: expected {post.accumulated.size}, got {result.accumulated.size}"
  else
    for i in [:result.accumulated.size] do
      if !hashArrayEq result.accumulated[i]! post.accumulated[i]! then
        ok := false
        IO.println s!"  accumulated[{i}]: expected {post.accumulated[i]!.size} hashes, got {result.accumulated[i]!.size} hashes"
        for j in [:min result.accumulated[i]!.size post.accumulated[i]!.size] do
          if result.accumulated[i]![j]! != post.accumulated[i]![j]! then
            IO.println s!"    [{j}] differs"

  -- Check ready queue
  if result.readyQueue.size != post.readyQueue.size then
    ok := false
    IO.println s!"  readyQueue length: expected {post.readyQueue.size}, got {result.readyQueue.size}"
  else
    for i in [:result.readyQueue.size] do
      if result.readyQueue[i]!.size != post.readyQueue[i]!.size then
        ok := false
        IO.println s!"  readyQueue[{i}]: expected {post.readyQueue[i]!.size} entries, got {result.readyQueue[i]!.size} entries"

  -- Check privileges
  if result.privileges != post.privileges then
    ok := false
    IO.println s!"  privileges mismatch"

  -- Check accounts
  let postAccounts := post.accounts.entries
  for (sid, expAcct) in postAccounts do
    match result.accounts.lookup sid with
    | some gotAcct =>
      if gotAcct.balance != expAcct.balance then
        ok := false
        IO.println s!"  account[{sid}].balance: expected {expAcct.balance}, got {gotAcct.balance}"
      if gotAcct.storage.size != expAcct.storage.size then
        ok := false
        IO.println s!"  account[{sid}].storage: expected {expAcct.storage.size} entries, got {gotAcct.storage.size}"
      if gotAcct.creationSlot != expAcct.creationSlot then
        ok := false
        IO.println s!"  account[{sid}].creationSlot: expected {expAcct.creationSlot}, got {gotAcct.creationSlot}"
    | none =>
      ok := false
      IO.println s!"  account[{sid}] missing"

  -- Check statistics
  let gotStatsSorted := result.statistics.qsort (fun a b => a.serviceId < b.serviceId)
  let expStatsSorted := post.statistics.qsort (fun a b => a.serviceId < b.serviceId)
  if gotStatsSorted.size != expStatsSorted.size then
    ok := false
    IO.println s!"  statistics length: expected {expStatsSorted.size}, got {gotStatsSorted.size}"
  else
    for i in [:gotStatsSorted.size] do
      let got := gotStatsSorted[i]!
      let exp := expStatsSorted[i]!
      if got.serviceId != exp.serviceId then
        ok := false
        IO.println s!"  statistics[{i}].serviceId: expected {exp.serviceId}, got {got.serviceId}"
      if got.accumulateCount != exp.accumulateCount then
        ok := false
        IO.println s!"  statistics[{got.serviceId}].accumulateCount: expected {exp.accumulateCount}, got {got.accumulateCount}"
      if got.accumulateGasUsed != exp.accumulateGasUsed then
        ok := false
        IO.println s!"  statistics[{got.serviceId}].accumulateGasUsed: expected {exp.accumulateGasUsed}, got {got.accumulateGasUsed}"

  if ok then
    IO.println s!"  ✓ {name}"
  else
    IO.println s!"  ✗ {name}"
  return ok

end Jar.Test.Accumulate
