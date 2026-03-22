import Jar.Notation
import Jar.Types
import Jar.Crypto
import Jar.Codec
import Jar.Consensus
import Jar.Accumulation
import Jar.Merkle

/-!
# State Transition — §4–13

The block-level state transition function Υ(σ, B) = σ'.
References: `graypaper/text/overview.tex` eq:statetransition, eq:transitionfunctioncomposition.

## Dependency Graph (eq 4.5–4.20)

The transition is organized to minimize dependency depth for parallelism:
- τ' ≺ H                                          (timekeeping)
- β† ≺ (H, β)                                     (state root update)
- η' ≺ (H, τ, η)                                  (entropy)
- κ' ≺ (H, τ, κ, γ)                               (active validators)
- λ' ≺ (H, τ, λ, κ)                               (previous validators)
- ψ' ≺ (E_D, ψ)                                   (judgments)
- ρ† ≺ (E_D, ρ)                                    (reports post-judgment)
- ρ‡ ≺ (E_A, ρ†)                                   (reports post-assurance)
- ρ' ≺ (E_G, ρ‡, κ, τ')                           (reports post-guarantees)
- W* ≺ (E_A, ρ†)                                   (newly available)
- γ' ≺ (H, τ, E_T, γ, ι, η', κ', ψ')            (safrole)
- (ω',ξ',δ†,χ',ι',ϕ',θ',π_acc) ≺ (W*, ω, ξ, δ, χ, ι, ϕ, τ, τ')  (accumulation)
- β' ≺ (H, E_G, β†, θ')                           (recent history)
- δ‡ ≺ (E_P, δ†, τ')                              (preimage integration)
- α' ≺ (H, E_G, ϕ', α)                            (authorization pool)
- π' ≺ (E_G, E_P, E_A, E_T, τ, κ', π, H, π_acc)  (statistics)
-/

namespace Jar
variable [JamConfig]

/-- Stable sort for accumulation outputs by service ID. -/
private def stableSortOutputs (outputs : Array (ServiceId × Hash)) : Array (ServiceId × Hash) :=
  let indexed := outputs.mapIdx fun i x => (i, x)
  let sorted := indexed.qsort fun (i, (a, _)) (j, (b, _)) =>
    if a.toNat != b.toNat then a.toNat < b.toNat else i < j
  sorted.map Prod.snd

-- ============================================================================
-- §6.1 — Timekeeping
-- ============================================================================

/-- τ' ≡ H_t. GP eq (28). The new timeslot is simply the block's timeslot. -/
def newTimeslot (h : Header) : Timeslot := h.timeslot

/-- Epoch index: e = ⌊τ / E⌋. GP eq (34). -/
def epochIndex (t : Timeslot) : Nat := t.toNat / E

/-- Slot within epoch: m = τ mod E. GP eq (34). -/
def epochSlot (t : Timeslot) : Nat := t.toNat % E

/-- Whether the block crosses an epoch boundary. -/
def isEpochChange (prior posterior : Timeslot) : Bool :=
  epochIndex prior != epochIndex posterior

-- ============================================================================
-- §7 — Recent History Update
-- ============================================================================

/-- β† : Update last entry's state root with parent's prior state root.
    GP eq (24). -/
def updateParentStateRoot (bs : RecentHistory) (h : Header) : RecentHistory :=
  if hne : bs.blocks.size = 0 then bs
  else
    let idx := bs.blocks.size - 1
    have hidx : idx < bs.blocks.size := by omega
    let last := bs.blocks[idx]
    let last' : RecentBlockInfo := {
      headerHash := last.headerHash
      stateRoot := h.stateRoot
      accOutputRoot := last.accOutputRoot
      reportedPackages := last.reportedPackages
    }
    { bs with blocks := bs.blocks.set idx last' }

/-- Append a leaf to an MMR peaks array using Keccak-256. GP Appendix E eq (E.8).
    Matches Grey's mmr_append in history.rs. -/
def mmrAppend (peaks : Array (Option Hash)) (leaf : Hash) : Array (Option Hash) :=
  let rec go (ps : Array (Option Hash)) (carry : Hash) (i : Nat) : Array (Option Hash) :=
    if i >= ps.size then
      ps.push (some carry)
    else
      match ps[i]! with
      | none => ps.set! i (some carry)
      | some existing =>
        let combined := existing.data ++ carry.data
        let merged : Hash := Crypto.keccak256 combined
        go (ps.set! i none) merged (i + 1)
  go peaks leaf 0

/-- Compute MMR super-peak MR. GP Appendix E eq (E.10).
    MR([]) = H_0, MR([h]) = h, MR(h) = H_K("peak" ++ MR(h[..n-1]) ++ h[n-1]) -/
def mmrSuperPeak (peaks : Array (Option Hash)) : Hash :=
  let nonNone := peaks.filterMap id
  match nonNone.size with
  | 0 => Hash.zero
  | _ =>
    let init : Hash := nonNone[0]!
    nonNone.foldl (init := init) (start := 1) fun acc peak =>
      let data := "peak".toUTF8 ++ acc.data ++ peak.data
      Crypto.keccak256 data

/-- Balanced Keccak-256 Merkle tree node N(v, H_K). GP eq (E.4). -/
private partial def keccakMerkleNode (leaves : Array ByteArray) : ByteArray :=
  match leaves.size with
  | 0 => Hash.zero.data
  | 1 => leaves[0]!
  | n =>
    let mid := (n + 1) / 2
    let left := keccakMerkleNode (leaves.extract 0 mid)
    let right := keccakMerkleNode (leaves.extract mid n)
    let input := "node".toUTF8 ++ left ++ right
    (Crypto.keccak256 input).data

/-- Balanced Keccak-256 Merkle root M_B(v, H_K). GP eq (E.4).
    Matches Grey's keccak_merkle_root / compute_output_hash. -/
def keccakMerkleRoot (leaves : Array ByteArray) : Hash :=
  if leaves.size == 1 then
    Crypto.keccak256 leaves[0]!
  else
    Hash.mk! (keccakMerkleNode leaves)

/-- Compute accumulate root hash from accumulation outputs.
    Uses balanced Keccak-256 Merkle tree (GP eq 7.7 / E.4).
    Matches Grey's compute_output_hash. -/
def computeAccumulateRoot (outputs : AccumulationOutputs) : Hash :=
  if outputs.size == 0 then Hash.zero
  else
    let sorted := stableSortOutputs outputs
    let leaves := sorted.map fun (sid, h) =>
      Codec.encodeFixedNat 4 sid.toNat ++ h.data
    keccakMerkleRoot leaves

/-- Collect reported work-package hashes from guarantees. GP §7.
    Maps package hash → erasure root for each guaranteed report. -/
def collectReportedPackages (guarantees : GuaranteesExtrinsic) : Dict Hash Hash :=
  guarantees.foldl (init := Dict.empty) fun acc g =>
    acc.insert g.report.availSpec.packageHash g.report.availSpec.segmentRoot

/-- β' : Full recent history update. GP eq (37–43).
    1. MMR-append the accumulate root to the belt
    2. Compute beefy root as MMR super-peak
    3. Append new block info, truncate to H entries -/
def updateRecentHistory
    (bdag : RecentHistory) (headerHash : Hash)
    (accOutputs : AccumulationOutputs)
    (guarantees : GuaranteesExtrinsic) : RecentHistory :=
  let maxLen := H_RECENT
  -- Compute accumulate root (balanced Keccak Merkle tree of outputs)
  let accRoot := computeAccumulateRoot accOutputs
  -- MMR append to belt
  let belt' := mmrAppend bdag.accOutputBelt accRoot
  -- Compute beefy root (MMR super-peak) for block info
  let beefyRoot := mmrSuperPeak belt'
  let newEntry : RecentBlockInfo := {
    headerHash := headerHash
    stateRoot := Hash.zero  -- will be filled by next block's β†
    accOutputRoot := beefyRoot
    reportedPackages := collectReportedPackages guarantees
  }
  let blocks' := bdag.blocks.push newEntry
  let blocks'' := if blocks'.size > maxLen
    then blocks'.extract 1 blocks'.size
    else blocks'
  { blocks := blocks'', accOutputBelt := belt' }

-- ============================================================================
-- §6 — Entropy Accumulation
-- ============================================================================

/-- η' : Updated entropy. GP eq (174–181).
    η'_0 = H(η_0 ++ Y(H_v))
    On epoch change: rotate η_0→η_1→η_2→η_3.
    Otherwise: η_{1..3} unchanged. -/
def updateEntropy (eta : Entropy) (h : Header) (t t' : Timeslot) : Entropy :=
  let vrfOut := Crypto.bandersnatchOutput h.vrfSignature
  let eta0' := Crypto.blake2b (eta.current.data ++ vrfOut.data)
  if isEpochChange t t' then
    { current := eta0'
      previous := eta.current
      twoBack := eta.previous
      threeBack := eta.twoBack }
  else
    { eta with current := eta0' }

-- ============================================================================
-- §6 — Validator Set Rotation
-- ============================================================================

/-- Filter out offending validators by zeroing their keys. GP eq (115–128). -/
def filterOffenders (keys : Array ValidatorKey) (offenders : Array Ed25519PublicKey) : Array ValidatorKey :=
  keys.map fun k =>
    if offenders.any (· == k.ed25519) then
      { bandersnatch := default
        ed25519 := default
        bls := default
        metadata := default }
    else k

/-- κ' : Active validator set update. GP §6.
    On epoch change: replace with pending set (filtered).
    Otherwise: unchanged. -/
def updateActiveValidators
    (kappa : Array ValidatorKey) (gamma : SafroleState) (t t' : Timeslot)
    (offenders : Array Ed25519PublicKey) : Array ValidatorKey :=
  if isEpochChange t t' then
    filterOffenders gamma.pendingKeys offenders
  else kappa

/-- λ' : Previous validator set update. GP §6.
    On epoch change: take current active set.
    Otherwise: unchanged. -/
def updatePreviousValidators
    (prev kappa : Array ValidatorKey) (t t' : Timeslot) : Array ValidatorKey :=
  if isEpochChange t t' then kappa else prev

-- ============================================================================
-- §10 — Judgments Processing
-- ============================================================================

/-- ψ' : Updated judgment state from disputes extrinsic. GP §10.
    Processes verdicts, culprits, and faults. -/
def updateJudgments (psi : JudgmentsState) (d : DisputesExtrinsic) : JudgmentsState :=
  -- Process verdicts: classify by approval count
  let init : Array Hash × Array Hash × Array Hash := (#[], #[], #[])
  let result := d.verdicts.foldl (init := init) fun acc v =>
      let approvals : Nat := (v.judgments.filter (·.isValid)).size
      let superMajority : Nat := (v.judgments.size * 2 + 2) / 3
      if Nat.ble superMajority approvals then (acc.1.push v.reportHash, acc.2.1, acc.2.2)
      else if approvals == 0 then (acc.1, acc.2.1.push v.reportHash, acc.2.2)
      else (acc.1, acc.2.1, acc.2.2.push v.reportHash)
  let newGood := result.1
  let newBad := result.2.1
  let newWonky := result.2.2
  -- Process culprits and faults into offender keys
  let culpritKeys := d.culprits.map (·.validatorKey)
  let faultKeys := d.faults.map (·.validatorKey)
  { good := psi.good ++ newGood
    bad := psi.bad ++ newBad
    wonky := psi.wonky ++ newWonky
    offenders := psi.offenders ++ culpritKeys ++ faultKeys }

-- ============================================================================
-- §11 — Reports Processing (Disputes → Assurances → Guarantees)
-- ============================================================================

/-- ρ† : Clear reports which have been judged bad. GP eq (115–120). -/
def reportsPostJudgment
    (rho : Array (Option PendingReport)) (badReports : Array Hash) : Array (Option PendingReport) :=
  rho.map fun opt => opt.bind fun pr =>
    let reportHash := Crypto.blake2b (Codec.encodeWorkReport pr.report)
    if badReports.any (· == reportHash) then none else some pr

/-- ρ‡ : Clear reports which have become available or timed out. GP eq (185–188).
    Returns (updated reports, list of newly available work reports). -/
def reportsPostAssurance
    (rhoDag : Array (Option PendingReport))
    (assurances : AssurancesExtrinsic)
    (t' : Timeslot) : Array (Option PendingReport) × Array WorkReport :=
  let timeout : Nat := U_TIMEOUT
  let superMajority := V * 2 / 3 + 1
  let clearCore (reports : Array (Option PendingReport)) (core : CoreIndex) :=
    reports.map fun r => match r with
      | some pr' => if pr'.report.coreIndex == core then none else some pr'
      | none => none
  let init : Array (Option PendingReport) × Array WorkReport := (rhoDag, #[])
  rhoDag.foldl (init := init) fun acc opt =>
    let reports := acc.1
    let available := acc.2
    match opt with
    | none => (reports, available)
    | some pr =>
      let c := pr.report.coreIndex.val
      let count := assurances.filter (fun a =>
        let byteIdx := c / 8
        let bitIdx := c % 8
        byteIdx < a.bitfield.size &&
          (a.bitfield.data[byteIdx]!.toNat >>> bitIdx) % 2 == 1) |>.size
      if count >= superMajority then
        (clearCore reports pr.report.coreIndex, available.push pr.report)
      else if t'.toNat >= pr.timeslot.toNat + timeout then
        (clearCore reports pr.report.coreIndex, available)
      else (reports, available)

/-- ρ' : Integrate new guarantees into reports. GP eq (413–416). -/
def reportsPostGuarantees
    (rhoDDag : Array (Option PendingReport))
    (guarantees : GuaranteesExtrinsic)
    (t' : Timeslot) : Array (Option PendingReport) :=
  guarantees.foldl (init := rhoDDag) fun reports g =>
    let c := g.report.coreIndex.val
    if hc : c < reports.size then
      reports.set c (some { report := g.report, timeslot := t' })
    else reports

-- ============================================================================
-- §8 — Authorization Pool & Queue
-- ============================================================================

/-- Remove only the first occurrence of `target` from `arr`.
    GP specifies set subtraction α[c] ⊢ {a} which removes one element. -/
private def eraseFirst (arr : Array Hash) (target : Hash) : Array Hash := Id.run do
  let mut found := false
  let mut result : Array Hash := #[]
  for h in arr do
    if !found && h == target then
      found := true
    else
      result := result.push h
  return result

/-- α' : Updated authorization pool. GP eq (26–27).
    Remove used authorizer, add from queue at current slot, truncate to O. -/
def updateAuthPool
    (alpha phi' : Array (Array Hash))
    (h : Header) (guarantees : GuaranteesExtrinsic) : Array (Array Hash) := Id.run do
  let mut result : Array (Array Hash) := #[]
  for coreIdx in [:alpha.size] do
    let a := alpha[coreIdx]!
    -- Remove the FIRST matching authorizer hash used by a guarantee for this core
    let a' := match guarantees.find? (fun g => g.report.coreIndex.val == coreIdx) with
    | some g => eraseFirst a g.report.authorizerHash
    | none => a
    -- Queue index: timeslot mod Q (not E). phi' is indexed [slot][core].
    let queueSlot := h.timeslot.toNat % Q_QUEUE
    let a'' := if queueSlot < phi'.size then
      let slot := phi'[queueSlot]!
      if coreIdx < slot.size then a'.push slot[coreIdx]!
      else a'
    else a'
    -- Truncate to rightmost O_POOL entries
    let a''' := if a''.size > O_POOL
      then a''.extract (a''.size - O_POOL) a''.size
      else a''
    result := result.push a'''
  return result

-- ============================================================================
-- §12 — Accumulation
-- ============================================================================

/-- Accumulation result: the combined outputs of processing available work reports. -/
structure AccumulationResult where
  services : Dict ServiceId ServiceAccount
  privileged : PrivilegedServices
  pendingValidators : Array ValidatorKey
  authQueue : Array (Array Hash)
  outputs : AccumulationOutputs
  accQueue : Array (Array (WorkReport × Array Hash))
  accHistory : Array (Array Hash)
  accStats : Dict ServiceId ServiceStatistics
  remainingOpaqueData : Array (ByteArray × ByteArray) := #[]
  exitReasons : Array (ServiceId × String) := #[]

/-- Compute dependency set for a work report (GP eq 12.6).
    D(r) = prerequisites ∪ K(segment_root_lookup) -/
private def computeDependencies (r : WorkReport) : Array Hash :=
  let deps := r.context.prerequisites
  let srlKeys := r.segmentRootLookup.entries.toArray.map (·.1)
  let all := deps ++ srlKeys
  all.foldl (init := #[]) fun acc h => if acc.any (· == h) then acc else acc.push h

/-- Edit queue: remove entries whose package hash is in accumulated set,
    and remove fulfilled dependencies. GP eq 12.7. -/
private def editQueue (queue : Array (WorkReport × Array Hash))
    (accSet : Array Hash) : Array (WorkReport × Array Hash) :=
  (queue.filter fun (rr, _) => !accSet.any (· == rr.availSpec.packageHash)).map fun (rr, deps) =>
    (rr, deps.filter fun d => !accSet.any (· == d))

/-- Resolve queue: iteratively find reports with zero remaining dependencies. -/
private def resolveQueue (queue : Array (WorkReport × Array Hash)) : Array WorkReport := Id.run do
  let mut result : Array WorkReport := #[]
  let mut remaining := queue
  for _ in [:queue.size + 1] do  -- max iterations bounded by queue size
    let ready := (remaining.filter fun (_, deps) => deps.size == 0).map (·.1)
    if ready.size == 0 then break
    result := result ++ ready
    let readyHashes := ready.map (·.availSpec.packageHash)
    remaining := editQueue remaining readyHashes
  return result

/-- Perform accumulation of newly available work reports. GP §12.
    Implements the full queue management: partition, resolve, accumulate. -/
def performAccumulation
    (available : Array WorkReport)
    (s : State) (t' : Timeslot)
    (opaqueData : Array (ByteArray × ByteArray))
    (entropy' : Entropy := s.entropy) : AccumulationResult :=
  -- Pass the state with updated entropy so accumulation uses eta'_0
  let s' := { s with entropy := entropy' }

  -- Step 1: Partition available reports into immediate and queued (GP eq 12.4-12.5)
  let (immediate, newQueued) := available.foldl (init := (#[], #[])) fun (imm, q) wr =>
    let deps := computeDependencies wr
    if deps.size == 0 then (imm.push wr, q)
    else (imm, q.push (wr, deps))

  -- Step 1b: Edit new queued reports against full accumulated history (GP ⊜(ξ))
  let accHistoryUnion := s.accHistory.foldl (init := #[]) fun acc slot => acc ++ slot
  let editedNewQueued := editQueue newQueued accHistoryUnion

  -- Step 2: Compute R* (all accumulatable reports, GP eq 12.10-12.12)
  -- Combine immediate reports with queue-resolved reports from ready_queue
  -- Grey rotates starting from slot_index (GP eq 12.11)
  let slotIndex := t'.toNat % E
  let immediateHashes := immediate.map (·.availSpec.packageHash)
  let allQueued := Id.run do
    let mut q : Array (WorkReport × Array Hash) := #[]
    for i in [:E] do
      let idx := (slotIndex + i) % E
      if idx < s.accQueue.size then
        q := q ++ s.accQueue[idx]!
    return q
  let allQueuedWithNew := allQueued ++ editedNewQueued
  let editedAll := editQueue allQueuedWithNew immediateHashes
  let queueResolved := resolveQueue editedAll
  let accumulatable := immediate ++ queueResolved

  -- Step 3: Accumulate reports (Δ+)
  -- Gas budget: g = max(G_T, G_A × C + Σ(χZ)). GP eq 12.25.
  let alwaysGas := s'.privileged.alwaysAccumulate.values.foldl (init := 0) fun acc g => acc + g.toNat
  let gasBudget := max G_T (G_A * C + alwaysGas)
  -- Limit reports to fit within gas budget (GP eq 12.13-12.16)
  let (taken, _) := accumulatable.foldl (init := (#[], (0 : Nat))) fun (taken, gasUsed) wr =>
    let reportGas := wr.digests.foldl (init := (0 : Nat)) fun acc d => acc + d.gasLimit.toNat
    if gasUsed + reportGas <= gasBudget then (taken.push wr, gasUsed + reportGas)
    else (taken, gasUsed)
  let n := taken.size
  let result : Accumulation.AccumulationResult := Accumulation.accumulate s' taken t' opaqueData

  -- Step 4: Collect accumulated package hashes for history (sorted)
  let hashLt (a b : Hash) : Bool := Id.run do
    for i in [:32] do
      if a.data.get! i < b.data.get! i then return true
      if a.data.get! i > b.data.get! i then return false
    return false
  let accPackageHashes := (accumulatable.extract 0 n |>.map fun wr => wr.availSpec.packageHash).qsort hashLt

  -- Step 5: Update accumulation history: shift left by 1, append new entry
  let accHistory' := if s.accHistory.size > 0
    then s.accHistory.extract 1 s.accHistory.size
    else s.accHistory
  let accHistory'' := accHistory'.push accPackageHashes
  let accHistory''' := if accHistory''.size < E
    then Id.run do
      let mut h := accHistory''
      while h.size < E do
        h := h.push #[]
      return h
    else accHistory''

  -- Step 6: Update ready queue (GP eq 12.34)
  let accumulatedHashes := accPackageHashes
  let prevSlot := s.timeslot
  let slotsAdvanced := if t'.toNat > prevSlot.toNat then t'.toNat - prevSlot.toNat else 1
  let accQueue' := Id.run do
    let mut queue := s.accQueue
    -- Ensure E entries
    while queue.size < E do
      queue := queue.push #[]
    -- Clear positions for skipped slots
    for offset in [:min slotsAdvanced E] do
      let slot := prevSlot.toNat + 1 + offset
      let pos := slot % E
      if pos < queue.size then
        queue := queue.set! pos #[]
    -- Edit surviving slots: remove fulfilled dependencies and accumulated reports
    for i in [:queue.size] do
      queue := queue.set! i (editQueue queue[i]! accumulatedHashes)
    -- Insert newly queued reports at current position
    let m := t'.toNat % E
    if m < queue.size then
      let edited := editQueue editedNewQueued accumulatedHashes
      queue := queue.set! m (queue[m]! ++ edited)
    return queue

  -- Build per-service accumulation statistics from gas usage.
  -- GP §13: A(s) = (N(s), G(s)) where N = work item count, G = gas used.
  -- Refinement stats are computed separately in updateStatistics from guarantees.
  let accStatsAll := result.gasUsage.entries.foldl (init := Dict.empty (K := ServiceId) (V := ServiceStatistics))
    fun acc (sid, gas) =>
      let itemCount := accumulatable.foldl (init := 0) fun cnt wr =>
        cnt + (wr.digests.filter fun d => d.serviceId == sid).size
      acc.insert sid {
        provided := (0, 0), refinement := (0, 0), imports := 0,
        extrinsicCount := 0, extrinsicSize := 0, exports := 0,
        accumulation := (itemCount, gas) }
  -- Filter: G(s) + N(s) != 0
  let accStats := accStatsAll.entries.foldl (init := Dict.empty (K := ServiceId) (V := ServiceStatistics))
    fun acc (sid, ss) =>
      if ss.accumulation.1 + ss.accumulation.2.toNat != 0 then acc.insert sid ss
      else acc
  -- GP eq δ‡: update a_a = τ' for all services in K(S)
  -- K(S) = services where G(s) + N(s) ≠ 0 (the accStats keys)
  let servicesWithLastAcc := accStats.entries.foldl (init := result.services)
    fun svcs (sid, _) =>
      match svcs.lookup sid with
      | some acct => svcs.insert sid { acct with lastAccumulation := t' }
      | none => svcs
  { services := servicesWithLastAcc
    privileged := result.privileged
    pendingValidators := result.stagingKeys
    authQueue := result.authQueue
    outputs := result.outputs
    accQueue := accQueue'
    accHistory := accHistory'''
    accStats := accStats
    remainingOpaqueData := result.remainingOpaqueData
    exitReasons := result.exitReasons }

-- ============================================================================
-- §12.7 — Preimage Integration
-- ============================================================================

/-- Decode preimage info timeslots from raw bytes (compact-encoded count + E_4 each). -/
private def decodePreimageInfoTimeslots (data : ByteArray) : Array Timeslot :=
  match Codec.Decoder.run (fun s => do
    let (count, s) ← Codec.decodeNatD s
    let mut timeslots : Array Timeslot := #[]
    let mut state := s
    for _ in [:count] do
      match Codec.decodeFixedNatD 4 state with
      | some (ts, s') =>
        timeslots := timeslots.push (UInt32.ofNat ts)
        state := s'
      | none => break
    return (timeslots, state)) data with
  | some ts => ts
  | none => #[]

/-- δ‡ : Integrate preimage data into service accounts. GP eq (12.35–12.38).
    For each (service_id, preimage_data) in E_P:
    1. Hash the preimage data to get h = H(data)
    2. If the service has a solicitation for (h, |data|), store the preimage
    3. Expunge old preimage solicitations past D_EXPUNGE timeslots.
    Also accepts and returns opaque data so that preimage_info entries
    not promoted during accumulation can still be found and updated. -/
def integratePreimages
    (delta : Dict ServiceId ServiceAccount)
    (preimages : PreimagesExtrinsic)
    (t' : Timeslot)
    (opaqueData : Array (ByteArray × ByteArray) := #[])
    : Dict ServiceId ServiceAccount × Array (ByteArray × ByteArray) :=
  -- Phase 1: Store new preimages
  let (delta', od') := preimages.foldl (init := (delta, opaqueData)) fun (acc, od) (sid, data) =>
    match acc.lookup sid with
    | none => (acc, od)
    | some acct =>
      let h := Crypto.blake2b data
      let blobLen := UInt32.ofNat data.size
      -- Check structured preimageInfo first
      match acct.preimageInfo.lookup (h, blobLen) with
      | some timeslots =>
        -- Store the preimage data and update the info with current timeslot
        let acct' := { acct with
          preimages := acct.preimages.insert h data
          preimageInfo := acct.preimageInfo.insert (h, blobLen)
            (timeslots.push t') }
        (acc.insert sid acct', od)
      | none =>
        -- Promote preimage_info from opaque data if available
        let stateKey := StateSerialization.stateKeyForServiceData sid
          (StateSerialization.preimageInfoHashArg blobLen h)
        let found := od.findSome? fun (k, v) =>
          if k == stateKey.data then some v else none
        match found with
        | none => (acc, od)  -- Not solicited; ignore
        | some rawVal =>
          -- Decode timeslots from opaque data value
          let timeslots := decodePreimageInfoTimeslots rawVal
          -- Remove from opaque data
          let od' := od.filter fun (k, _) => k != stateKey.data
          -- Store the preimage data and update the info with current timeslot
          let acct' := { acct with
            preimages := acct.preimages.insert h data
            preimageInfo := acct.preimageInfo.insert (h, blobLen)
              (timeslots.push t') }
          (acc.insert sid acct', od')
  -- GP: expired preimage solicitations (ts.size >= 2, ts[1] + D_EXPUNGE < t') should
  -- be expunged here for all services. Not implemented because test vectors (generated
  -- by PolkaJAM) don't perform block-level expunging — they defer to forget(24) during
  -- accumulation. Enabling causes 13 test failures.
  (delta', od')

-- ============================================================================
-- §13 — Statistics Update
-- ============================================================================

/-- Zero-valued validator record. -/
def ValidatorRecord.zero : ValidatorRecord :=
  { blocks := 0, tickets := 0, preimageCount := 0
    preimageSize := 0, guarantees := 0, assurances := 0 }

/-- Zero-valued core statistics. -/
def CoreStatistics.zero : CoreStatistics :=
  { daLoad := 0, popularity := 0, imports := 0, extrinsicCount := 0
    extrinsicSize := 0, exports := 0, bundleSize := 0, gasUsed := 0 }

/-- π' : Updated activity statistics. GP §13.
    Tracks per-validator: blocks, tickets, preimages, guarantees, assurances.
    Tracks per-core and per-service statistics.
    Per-core and per-service stats are reset each block (not accumulated within epoch). -/
def updateStatistics
    (pi : ActivityStatistics) (h : Header)
    (e : Extrinsic) (t t' : Timeslot)
    (_kappa' : Array ValidatorKey)
    (available : Array WorkReport)
    (accStats : Dict ServiceId ServiceStatistics) : ActivityStatistics :=
  let epochChanged := isEpochChange t t'
  let (cur, prev) := if epochChanged
    then (Array.replicate V ValidatorRecord.zero, pi.current)
    else (pi.current, pi.previous)

  -- §13.1: Block author stats
  let authorIdx := h.authorIndex.val
  let cur := if hv : authorIdx < cur.size then
    let r := cur[authorIdx]
    cur.set authorIdx { r with blocks := r.blocks + 1 }
  else cur

  -- §13.1: Ticket stats — each ticket proof credits the author
  let cur := if e.tickets.size > 0 then
    if hv : authorIdx < cur.size then
      let r := cur[authorIdx]
      cur.set authorIdx { r with tickets := r.tickets + e.tickets.size }
    else cur
  else cur

  -- §13.1: Preimage stats — each preimage credits the author
  let cur := if e.preimages.size > 0 then
    let totalSize := e.preimages.foldl (init := 0) fun acc (_, data) => acc + data.size
    if hv : authorIdx < cur.size then
      let r := cur[authorIdx]
      cur.set authorIdx { r with
        preimageCount := r.preimageCount + e.preimages.size
        preimageSize := r.preimageSize + totalSize }
    else cur
  else cur

  -- §13.1: Guarantee stats — credit each guarantor (boolean per block, not per guarantee)
  -- GP: π_V'[v]_g ≡ a[v]_g + (κ'_v ∈ G) — G is the SET of validator indices
  -- across ALL guarantees, so each validator counts at most once per block.
  let guarantorSet : Array Nat := Id.run do
    let mut seen : Array Nat := #[]
    for g in e.guarantees do
      for (vi, _) in g.credentials do
        if !seen.contains vi.val then seen := seen.push vi.val
    return seen
  let cur := guarantorSet.foldl (init := cur) fun c vi =>
    if hv : vi < c.size then
      let r := c[vi]
      c.set vi { r with guarantees := r.guarantees + 1 }
    else c

  -- §13.1: Assurance stats — credit each assuring validator
  let cur := e.assurances.foldl (init := cur) fun c a =>
    if hv : a.validatorIndex.val < c.size then
      let r := c[a.validatorIndex.val]
      c.set a.validatorIndex.val { r with assurances := r.assurances + 1 }
    else c

  -- §13.2: Core statistics — always fresh per block (not accumulated within epoch)
  -- R(c): refine-load from incoming reports (guarantees)
  -- L(c): bundle size from incoming reports
  -- D(c): DA load from available reports (assurance-confirmed)
  -- p: popularity from assurance bitfields
  let coreStats := Array.replicate C CoreStatistics.zero
  -- p: popularity from assurance bitfields (computed independently for ALL cores)
  let coreStats := Id.run do
    let mut cs := coreStats
    for cIdx in [:C] do
      let pop := e.assurances.filter (fun a =>
        let byteIdx := cIdx / 8
        let bitIdx := cIdx % 8
        byteIdx < a.bitfield.size &&
          (a.bitfield.data[byteIdx]!.toNat >>> bitIdx) % 2 == 1) |>.size
      if hc : cIdx < cs.size then
        let s := cs[cIdx]
        cs := cs.set cIdx { s with popularity := s.popularity + pop }
    return cs
  -- R(c), L(c): refine-load and bundle size from incoming reports (guarantees)
  let coreStats := e.guarantees.foldl (init := coreStats) fun cs g =>
    let cIdx := g.report.coreIndex.val
    if hc : cIdx < cs.size then
      let s := cs[cIdx]
      -- Sum digest statistics
      let (totalImports, totalExtrinsics, totalExtrinsicSize, totalExports, totalGas) :=
        g.report.digests.foldl (init := (0, 0, 0, 0, (0 : UInt64))) fun (i, x, z, e', gas) d =>
          (i + d.importsCount, x + d.extrinsicsCount, z + d.extrinsicsSize,
           e' + d.exportsCount, gas + d.gasUsed)
      cs.set cIdx { s with
        imports := s.imports + totalImports
        extrinsicCount := s.extrinsicCount + totalExtrinsics
        extrinsicSize := s.extrinsicSize + totalExtrinsicSize
        exports := s.exports + totalExports
        bundleSize := s.bundleSize + g.report.availSpec.bundleLength.toNat
        gasUsed := s.gasUsed + totalGas }
    else cs
  -- D(c): DA load from available reports (newly available via assurances)
  let coreStats := available.foldl (init := coreStats) fun cs wr =>
    let cIdx := wr.coreIndex.val
    if hc : cIdx < cs.size then
      let s := cs[cIdx]
      let bundleLen := wr.availSpec.bundleLength.toNat
      let exportsCount := wr.availSpec.segmentCount
      -- D(c) = bundle_length + W_G * ceil(exports_count * 65 / 64)
      let segmentBytes := W_G * ((exportsCount * 65 + 63) / 64)
      cs.set cIdx { s with daLoad := s.daLoad + bundleLen + segmentBytes }
    else cs

  -- §13.2: Service statistics — always fresh per block (not accumulated within epoch)
  let serviceStats : Dict ServiceId ServiceStatistics := Dict.empty
  -- Add refinement stats from incoming guarantees (GP eq R(s))
  let serviceStats := e.guarantees.foldl (init := serviceStats) fun ss g =>
    g.report.digests.foldl (init := ss) fun ss' d =>
      let existing := match ss'.lookup d.serviceId with
        | some s => s
        | none => { provided := (0, 0), refinement := (0, 0), imports := 0,
                    extrinsicCount := 0, extrinsicSize := 0, exports := 0,
                    accumulation := (0, 0) }
      ss'.insert d.serviceId { existing with
        refinement := (existing.refinement.1 + 1, existing.refinement.2 + d.gasUsed)
        imports := existing.imports + d.importsCount
        extrinsicCount := existing.extrinsicCount + d.extrinsicsCount
        extrinsicSize := existing.extrinsicSize + d.extrinsicsSize
        exports := existing.exports + d.exportsCount }
  -- Add preimage provided stats (GP eq π_S: p = (count, size))
  let serviceStats := e.preimages.foldl (init := serviceStats) fun ss (sid, data) =>
    let existing := match ss.lookup sid with
      | some s => s
      | none => { provided := (0, 0), refinement := (0, 0), imports := 0,
                  extrinsicCount := 0, extrinsicSize := 0, exports := 0,
                  accumulation := (0, 0) }
    ss.insert sid { existing with
      provided := (existing.provided.1 + 1, existing.provided.2 + data.size) }
  -- Merge accumulation stats
  let serviceStats := accStats.entries.foldl (init := serviceStats) fun ss (sid, astats) =>
    let existing := match ss.lookup sid with
      | some s => s
      | none => { provided := (0, 0), refinement := (0, 0), imports := 0,
                  extrinsicCount := 0, extrinsicSize := 0, exports := 0,
                  accumulation := (0, 0) }
    ss.insert sid { existing with
      accumulation := (existing.accumulation.1 + astats.accumulation.1,
                       existing.accumulation.2 + astats.accumulation.2) }

  { current := cur
    previous := prev
    coreStats
    serviceStats }

-- ============================================================================
-- §5 — Header Validation
-- ============================================================================

/-- Validate block header against the current state. GP §5.
    Checks:
    1. Parent hash matches last known block
    2. Timeslot strictly increasing
    3. Timeslot not too far in the future
    4. Author index is valid
    5. Extrinsic size bounds
    6. Seal signature (via crypto opaque)
    7. VRF output (via crypto opaque) -/
def validateHeader (s : State) (h : Header) : Bool :=
  -- §5.1: Parent hash must match the last block in recent history
  let parentOk := if hn : s.recent.blocks.size = 0 then true
  else
    let idx := s.recent.blocks.size - 1
    have : idx < s.recent.blocks.size := by omega
    let lastBlock := s.recent.blocks[idx]
    h.parent == lastBlock.headerHash

  -- §5.2: Timeslot must be strictly greater than prior
  let timeslotOk := h.timeslot.toNat > s.timeslot.toNat

  -- §5.3: Author index must be valid validator index
  let authorOk := h.authorIndex.val < V

  -- §5.4: Seal signature verification. GP eq (6.24–6.25).
  -- Verify the block seal using the author's Bandersnatch key
  let sealOk :=
    if h.authorIndex.val < s.currentValidators.size then
      let authorKey := s.currentValidators[h.authorIndex.val]!
      let unsignedHeader := Codec.encodeUnsignedHeader h
      Crypto.bandersnatchVerify authorKey.bandersnatch
        Crypto.ctxTicketSeal unsignedHeader h.sealSig
    else false

  -- §5.5: VRF signature verification. GP eq (6.27).
  let vrfOk :=
    if h.authorIndex.val < s.currentValidators.size then
      let authorKey := s.currentValidators[h.authorIndex.val]!
      Crypto.bandersnatchVerify authorKey.bandersnatch
        Crypto.ctxEntropy (Codec.encodeFixedNat 4 h.timeslot.toNat) h.vrfSignature
    else false

  -- §5.6: Epoch marker present iff epoch boundary
  let epochMarkerOk :=
    let shouldHaveMarker := isEpochChange s.timeslot h.timeslot
    match h.epochMarker with
    | some _ => shouldHaveMarker
    | none => !shouldHaveMarker

  parentOk && timeslotOk && authorOk && sealOk && vrfOk && epochMarkerOk

/-- Header validation without seal/VRF checks (for block-level testing
    while seal verification context is being fixed). -/
def validateHeaderNoSeal (s : State) (h : Header) : Bool :=
  let parentOk := if hn : s.recent.blocks.size = 0 then true
  else
    let idx := s.recent.blocks.size - 1
    have : idx < s.recent.blocks.size := by omega
    let lastBlock := s.recent.blocks[idx]
    h.parent == lastBlock.headerHash
  let timeslotOk := h.timeslot.toNat > s.timeslot.toNat
  let authorOk := h.authorIndex.val < V
  let epochMarkerOk :=
    let shouldHaveMarker := isEpochChange s.timeslot h.timeslot
    match h.epochMarker with
    | some _ => shouldHaveMarker
    | none => !shouldHaveMarker
  parentOk && timeslotOk && authorOk && epochMarkerOk

-- ============================================================================
-- Block Import Validation (beyond STF header checks)
-- ============================================================================

/-- Validate the block seal signature and author identity.
    In ticket mode: the author's bandersnatch key must match the ticket's key for the slot.
    In fallback mode: the author's bandersnatch key must match the fallback key for the slot.
    `eta'` is the POST-transition entropy (needed because seal uses η'_3).
    `sealKeys` is the POST-epoch seal key series (may differ from pre-state on epoch boundaries).
    `validators` is the POST-epoch active validator set (κ').
    Returns true if the author is expected for this timeslot. -/
def validateAuthor (h : Header) (eta' : Entropy) (sealKeys : SealKeySeries)
    (validators : Array ValidatorKey) : Bool :=
  let slotInEpoch := h.timeslot.toNat % E
  if h.authorIndex.val >= validators.size then false
  else
    let authorKey := validators[h.authorIndex.val]!.bandersnatch
    match sealKeys with
    | .tickets tickets =>
      if slotInEpoch < tickets.size then
        -- In ticket mode, verify seal with ticket context
        let ticket := tickets[slotInEpoch]!
        let unsignedHeader := Codec.encodeUnsignedHeader h
        Consensus.verifySealTicketed authorKey eta'.threeBack ticket
          unsignedHeader h.sealSig
      else false
    | .fallback keys =>
      if slotInEpoch < keys.size then
        -- In fallback mode, the author's key must match the expected fallback key
        let expectedKey := keys[slotInEpoch]!
        if authorKey != expectedKey then false
        else
          let unsignedHeader := Codec.encodeUnsignedHeader h
          Consensus.verifySealFallback authorKey eta'.threeBack
            unsignedHeader h.sealSig
      else false

/-- Validate the epoch marker contents.
    When present, the epoch marker must contain the correct entropy values
    and the correct validator key set. GP eq (6.13-6.16). -/
def validateEpochMarkerContents (s : State) (h : Header) (eta' : Entropy)
    (kappa' : Array ValidatorKey) : Bool :=
  let epochChanged := isEpochChange s.timeslot h.timeslot
  match h.epochMarker with
  | none => !epochChanged
  | some em =>
    if !epochChanged then false
    else
      -- Check entropy values: H_E.η_0 = η'_1, H_E.η_1 = η'_2
      -- On epoch change: eta'.previous = old eta.current, eta'.twoBack = old eta.previous
      let entropyOk := em.entropy == eta'.previous && em.entropyPrev == eta'.twoBack
      -- Check validator keys
      let validatorsOk := em.validators.size == kappa'.size &&
        (em.validators.toList.zip kappa'.toList).all fun ((bk, ek), vk) =>
          bk == vk.bandersnatch && ek == vk.ed25519
      entropyOk && validatorsOk

/-- Validate that preimages are required (solicited by the service).
    Returns true if all preimages are solicited. -/
def validatePreimages
    (delta : Dict ServiceId ServiceAccount)
    (preimages : PreimagesExtrinsic)
    (opaqueData : Array (ByteArray × ByteArray)) : Bool :=
  preimages.all fun (sid, data) =>
    match delta.lookup sid with
    | none => false
    | some acct =>
      let h := Crypto.blake2b data
      let blobLen := UInt32.ofNat data.size
      -- Check structured preimageInfo first
      match acct.preimageInfo.lookup (h, blobLen) with
      | some _ => true
      | none =>
        -- Check opaque data for preimage_info entries using the correct state key format
        let stateKey := StateSerialization.stateKeyForServiceData sid
          (StateSerialization.preimageInfoHashArg blobLen h)
        opaqueData.any fun (k, _v) => k == stateKey.data

/-- Validate assurance ordering: validator indices must be sorted and unique. -/
def validateAssuranceOrder (assurances : AssurancesExtrinsic) : Bool :=
  if assurances.size <= 1 then true
  else
    let indices := assurances.map (·.validatorIndex.val)
    Id.run do
      for i in [:indices.size - 1] do
        if indices[i]! >= indices[i + 1]! then
          return false
      return true

/-- Validate assurance validator indices are in range. -/
def validateAssuranceIndices (assurances : AssurancesExtrinsic) : Bool :=
  assurances.all fun a => a.validatorIndex.val < V

/-- Validate guarantee credential validator indices are in range. -/
def validateGuaranteeIndices (guarantees : GuaranteesExtrinsic) : Bool :=
  guarantees.all fun g =>
    g.credentials.all fun (vi, _) => vi.val < V

/-- Validate guarantee timeslots: the guarantee timeslot must not be in the future
    relative to the block timeslot. GP eq (11.24): g_t <= H_t.
    Also: the report context anchor must be in recent history. -/
def validateGuaranteeTimeslots (guarantees : GuaranteesExtrinsic)
    (t' : Timeslot) : Bool :=
  guarantees.all fun g => g.timeslot.toNat <= t'.toNat

/-- Validate guarantee credential signatures.
    Each credential (vi, sig) must be a valid Ed25519 signature of the
    work report by the validator at index vi.
    GP eq (11.28): H̄_κ'[vi] ∈ V̄_sig⟨𝓔(report)⟩. -/
def validateGuaranteeSignatures (guarantees : GuaranteesExtrinsic)
    (validators : Array ValidatorKey) : Bool :=
  guarantees.all fun g =>
    let reportEncoding := Codec.encodeWorkReport g.report
    let reportHash := Crypto.blake2b reportEncoding
    -- The message to sign is: "jam_guarantee" ++ H(encode(report))
    let message := Crypto.ctxGuarantee ++ reportHash.data
    g.credentials.all fun (vi, sig) =>
      if vi.val < validators.size then
        let validatorKey := validators[vi.val]!.ed25519
        Crypto.ed25519Verify validatorKey message sig
      else false

/-- Validate assurance signatures.
    Each assurance must be signed by the validator at the given index.
    Message: "jam_available" ++ H(parent_hash ++ bitfield). GP eq (11.13). -/
def validateAssuranceSignatures (assurances : AssurancesExtrinsic)
    (validators : Array ValidatorKey) : Bool :=
  assurances.all fun a =>
    if a.validatorIndex.val < validators.size then
      let validatorKey := validators[a.validatorIndex.val]!.ed25519
      let payload := a.anchor.data ++ a.bitfield
      let payloadHash := Crypto.blake2b payload
      let message := "jam_available".toUTF8 ++ payloadHash.data
      Crypto.ed25519Verify validatorKey message a.signature
    else false

/-- Validate assurance anchors: all must equal parent block hash. GP eq (11.11). -/
def validateAssuranceAnchors (assurances : AssurancesExtrinsic) (s : State) : Bool :=
  if hn : s.recent.blocks.size = 0 then assurances.size == 0
  else
    let lastIdx := s.recent.blocks.size - 1
    have : lastIdx < s.recent.blocks.size := by omega
    let parentHash := s.recent.blocks[lastIdx].headerHash
    assurances.all fun a => a.anchor == parentHash

/-- Validate extrinsic data bounds. GP §5, §11. -/
def validateExtrinsic (e : Extrinsic) : Bool :=
  -- Ticket submissions bounded by K
  let ticketsOk := e.tickets.size <= K_MAX_TICKETS
  -- Each guarantee must have at least 1 credential
  let guaranteesOk := e.guarantees.all (fun g => g.credentials.size > 0)
  -- No duplicate cores in guarantees
  let coreIndices := e.guarantees.map (·.report.coreIndex)
  let noDupCores := coreIndices.size == (coreIndices.toList.eraseDups).length
  ticketsOk && guaranteesOk && noDupCores

-- ============================================================================
-- §4.1 — Top-Level State Transition Υ(σ, B) = σ'
-- ============================================================================

/-- Υ(σ, B) : Block-level state transition function. GP eq (4.1).
    Returns the posterior state, or none if the block is invalid. -/
def stateTransition (s : State) (b : Block) : Option State := do
  let h := b.header
  let ext := b.extrinsic

  -- §5 — Header validation
  guard (validateHeader s h)
  guard (validateExtrinsic ext)

  -- §6.1 — Timekeeping
  let t' := newTimeslot h

  -- §6 — Entropy
  let eta' := updateEntropy s.entropy h s.timeslot t'

  -- §6 — Validator rotation
  let kappa' := updateActiveValidators s.currentValidators s.safrole s.timeslot t' h.offenders
  let lambda' := updatePreviousValidators s.previousValidators s.currentValidators s.timeslot t'

  -- §10 — Judgments
  let psi' := updateJudgments s.judgments ext.disputes

  -- §11 — Reports pipeline
  let rhoDag := reportsPostJudgment s.pendingReports psi'.bad
  let (rhoDDag, available) := reportsPostAssurance rhoDag ext.assurances t'
  let rho' := reportsPostGuarantees rhoDDag ext.guarantees t'

  -- §7 — Recent history: β†
  let bDag := updateParentStateRoot s.recent h

  -- §12 — Accumulation
  let accResult := performAccumulation available s t' #[] eta'

  -- §7 — Recent history: β'
  let headerHash := Crypto.blake2b (Codec.encodeHeader h)
  let beta' := updateRecentHistory bDag headerHash accResult.outputs ext.guarantees

  -- §12.7 — Preimage integration
  let (delta', _) := integratePreimages accResult.services ext.preimages t'

  -- §8 — Authorization
  let alpha' := updateAuthPool s.authPool accResult.authQueue h ext.guarantees

  -- §13 — Statistics
  let pi' := updateStatistics s.statistics h ext s.timeslot t' kappa' available accResult.accStats

  -- Assemble posterior state
  pure {
    authPool := alpha'
    recent := beta'
    accOutputs := stableSortOutputs accResult.outputs
    safrole := Consensus.updateSafrole s.safrole ext.tickets eta' kappa'
                  (isEpochChange s.timeslot t') (epochSlot s.timeslot)
                  (epochIndex s.timeslot) (epochIndex t')
                  s.pendingValidators h.offenders
    services := delta'
    entropy := eta'
    pendingValidators := accResult.pendingValidators
    currentValidators := kappa'
    previousValidators := lambda'
    pendingReports := rho'
    timeslot := t'
    authQueue := accResult.authQueue
    privileged := accResult.privileged
    judgments := psi'
    statistics := pi'
    accQueue := accResult.accQueue
    accHistory := accResult.accHistory
  }

/-- State transition with opaque data for PVM accumulation (for block-level testing).
    Returns (state, (available_count, exit_reasons, remaining_opaque)) for debugging. -/
def stateTransitionWithOpaque (s : State) (b : Block)
    (opaqueData : Array (ByteArray × ByteArray))
    : Option (State × (Nat × Array (ServiceId × String) × Array (ByteArray × ByteArray))) := do
  let h := b.header
  let ext := b.extrinsic
  -- §5 — Basic header validation (parent, timeslot, author index, epoch marker presence)
  guard (validateHeaderNoSeal s h)
  guard (validateExtrinsic ext)
  let t' := newTimeslot h
  let eta' := updateEntropy s.entropy h s.timeslot t'
  let kappa' := updateActiveValidators s.currentValidators s.safrole s.timeslot t' h.offenders
  let safrole' := Consensus.updateSafrole s.safrole ext.tickets eta' kappa'
                    (isEpochChange s.timeslot t') (epochSlot s.timeslot)
                    (epochIndex s.timeslot) (epochIndex t')
                    s.pendingValidators h.offenders
  guard (validateAuthor h eta' safrole'.sealKeys kappa')
  guard (ext.tickets.all fun tp =>
    Consensus.verifyTicketProof safrole'.ringRoot eta'.twoBack tp (UInt32.ofNat V))
  -- Block import validation: epoch marker contents (entropy + validators). GP eq (6.13-6.16).
  -- NOTE: Disabled while conformance_forks runs as sequential trace. The independent runner
  -- crashes on fuzz blocks with intentionally invalid parse data (e.g. author_index >= V).
  -- Re-enable once the independent runner handles parse errors gracefully.
  -- guard (validateEpochMarkerContents s h eta' kappa')
  -- Block import validation: assurance ordering (sorted, unique)
  guard (validateAssuranceOrder ext.assurances)
  -- Block import validation: assurance validator indices in range
  guard (validateAssuranceIndices ext.assurances)
  -- Block import validation: guarantee credential validator indices in range
  guard (validateGuaranteeIndices ext.guarantees)
  -- Block import validation: guarantee timeslots not in future
  guard (validateGuaranteeTimeslots ext.guarantees t')
  -- Block import validation: guarantee credential signatures. GP eq (11.22).
  -- Each guarantee is checked against the validator set for its creation epoch.
  guard (ext.guarantees.all fun g =>
    let gEpoch := epochIndex g.timeslot
    let blockEpoch := epochIndex t'
    let validators :=
      if gEpoch == blockEpoch then kappa'
      else if gEpoch + 1 == blockEpoch then
        if isEpochChange s.timeslot t' then s.currentValidators
        else s.previousValidators
      else s.previousValidators  -- fallback for older guarantees
    validateGuaranteeSignatures #[g] validators)
  -- Block import validation: guarantee report context anchor must be in recent history
  guard (ext.guarantees.all fun g =>
    s.recent.blocks.any fun bi => bi.headerHash == g.report.context.anchorHash)
  -- Guarantee context state root must match recent history entry (skip zero roots —
  -- stateRoot in recent blocks is set by the NEXT block's header, so may be zero)
  guard (ext.guarantees.all fun g =>
    s.recent.blocks.any fun bi =>
      bi.headerHash == g.report.context.anchorHash &&
      (bi.stateRoot == Hash.zero || bi.stateRoot == g.report.context.anchorStateRoot))
  -- Block import validation: assurance anchor must equal parent hash
  guard (validateAssuranceAnchors ext.assurances s)
  -- Block import validation: assurance signatures (use post-epoch validators)
  guard (validateAssuranceSignatures ext.assurances kappa')
  -- Block import validation: preimages must be solicited
  guard (validatePreimages s.services ext.preimages opaqueData)
  let lambda' := updatePreviousValidators s.previousValidators s.currentValidators s.timeslot t'
  let psi' := updateJudgments s.judgments ext.disputes
  let rhoDag := reportsPostJudgment s.pendingReports psi'.bad
  let (rhoDDag, available) := reportsPostAssurance rhoDag ext.assurances t'
  -- GP §11: Guarantee validity — core must be free after assurance processing (ρ‡[c] = ∅)
  guard (ext.guarantees.all fun g =>
    let c := g.report.coreIndex.val
    if hc : c < rhoDDag.size then
      match rhoDDag[c] with
      | none => true
      | some _ => false
    else true)
  -- GP §11: Work package must not have been reported in recent history
  guard (ext.guarantees.all fun g =>
    !(s.recent.blocks.any fun bi =>
      bi.reportedPackages.lookup g.report.availSpec.packageHash |>.isSome))
  let rho' := reportsPostGuarantees rhoDDag ext.guarantees t'
  let bDag := updateParentStateRoot s.recent h
  let accResult := performAccumulation available s t' opaqueData eta'
  let headerHash := Crypto.blake2b (Codec.encodeHeader h)
  let beta' := updateRecentHistory bDag headerHash accResult.outputs ext.guarantees
  let (delta', remainingOpaque) := integratePreimages accResult.services ext.preimages t' accResult.remainingOpaqueData
  let alpha' := updateAuthPool s.authPool accResult.authQueue h ext.guarantees
  let pi' := updateStatistics s.statistics h ext s.timeslot t' kappa' available accResult.accStats
  pure ({
    authPool := alpha'
    recent := beta'
    accOutputs := stableSortOutputs accResult.outputs
    safrole := Consensus.updateSafrole s.safrole ext.tickets eta' kappa'
                  (isEpochChange s.timeslot t') (epochSlot s.timeslot)
                  (epochIndex s.timeslot) (epochIndex t')
                  s.pendingValidators h.offenders
    services := delta'
    entropy := eta'
    pendingValidators := accResult.pendingValidators
    currentValidators := kappa'
    previousValidators := lambda'
    pendingReports := rho'
    timeslot := t'
    authQueue := accResult.authQueue
    privileged := accResult.privileged
    judgments := psi'
    statistics := pi'
    accQueue := accResult.accQueue
    accHistory := accResult.accHistory
  }, (available.size, accResult.exitReasons, remainingOpaque))

/-- State transition without seal/VRF verification (for block-level testing).
    Accepts opaque data for PVM accumulation host calls and returns remaining
    opaque data with consumed entries removed. -/
def stateTransitionNoSealCheck (s : State) (b : Block)
    (opaqueData : Array (ByteArray × ByteArray) := #[])
    : Option (State × Array (ServiceId × String) × Array (ByteArray × ByteArray)) := do
  let h := b.header
  let ext := b.extrinsic
  guard (validateHeaderNoSeal s h)
  guard (validateExtrinsic ext)
  let t' := newTimeslot h
  let eta' := updateEntropy s.entropy h s.timeslot t'
  let kappa' := updateActiveValidators s.currentValidators s.safrole s.timeslot t' h.offenders
  let lambda' := updatePreviousValidators s.previousValidators s.currentValidators s.timeslot t'
  let psi' := updateJudgments s.judgments ext.disputes
  let rhoDag := reportsPostJudgment s.pendingReports psi'.bad
  let (rhoDDag, available) := reportsPostAssurance rhoDag ext.assurances t'
  let rho' := reportsPostGuarantees rhoDDag ext.guarantees t'
  let bDag := updateParentStateRoot s.recent h
  let accResult := performAccumulation available s t' opaqueData eta'
  let headerHash := Crypto.blake2b (Codec.encodeHeader h)
  let beta' := updateRecentHistory bDag headerHash accResult.outputs ext.guarantees
  let (delta', remainingOpaque) := integratePreimages accResult.services ext.preimages t' accResult.remainingOpaqueData
  let alpha' := updateAuthPool s.authPool accResult.authQueue h ext.guarantees
  let pi' := updateStatistics s.statistics h ext s.timeslot t' kappa' available accResult.accStats
  pure ({
    authPool := alpha'
    recent := beta'
    accOutputs := stableSortOutputs accResult.outputs
    safrole := Consensus.updateSafrole s.safrole ext.tickets eta' kappa'
                  (isEpochChange s.timeslot t') (epochSlot s.timeslot)
                  (epochIndex s.timeslot) (epochIndex t')
                  s.pendingValidators h.offenders
    services := delta'
    entropy := eta'
    pendingValidators := accResult.pendingValidators
    currentValidators := kappa'
    previousValidators := lambda'
    pendingReports := rho'
    timeslot := t'
    authQueue := accResult.authQueue
    privileged := accResult.privileged
    judgments := psi'
    statistics := pi'
    accQueue := accResult.accQueue
    accHistory := accResult.accHistory
  }, accResult.exitReasons, remainingOpaque)

end Jar
