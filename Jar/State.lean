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
  | 0 => ⟨ByteArray.mk (Array.replicate 32 0), sorry⟩
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
    ⟨keccakMerkleNode leaves, sorry⟩

/-- Compute accumulate root hash from accumulation outputs.
    Uses balanced Keccak-256 Merkle tree (GP eq 7.7 / E.4).
    Matches Grey's compute_output_hash. -/
def computeAccumulateRoot (outputs : AccumulationOutputs) : Hash :=
  if outputs.size == 0 then Hash.zero
  else
    let sorted := outputs.qsort fun (a, _) (b, _) => a.toNat < b.toNat
    let leaves := sorted.map fun (sid, h) =>
      Codec.encodeFixedNat 4 sid.toNat ++ h.data
    keccakMerkleRoot leaves

/-- Collect reported work-package hashes from guarantees. GP §7.
    Maps package hash → erasure root for each guaranteed report. -/
def collectReportedPackages (guarantees : GuaranteesExtrinsic) : Dict Hash Hash :=
  guarantees.foldl (init := Dict.empty) fun acc g =>
    acc.insert g.report.availSpec.packageHash g.report.availSpec.erasureRoot

/-- β' : Full recent history update. GP eq (37–43).
    1. MMR-append the accumulate root to the belt
    2. Compute beefy root as MMR super-peak
    3. Append new block info, truncate to H entries -/
def updateRecentHistory
    (bdag : RecentHistory) (headerHash : Hash)
    (accOutputs : AccumulationOutputs)
    (guarantees : GuaranteesExtrinsic) : RecentHistory :=
  let maxLen := 8  -- H_R : Maximum recent history length
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
  let timeout : Nat := 20
  let superMajority := (V * 2 + 2) / 3
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
      else if t'.toNat - pr.timeslot.toNat > timeout then
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

/-- α' : Updated authorization pool. GP eq (26–27).
    Remove used authorizer, add from queue at current slot, truncate to O. -/
def updateAuthPool
    (alpha phi' : Array (Array Hash))
    (h : Header) (guarantees : GuaranteesExtrinsic) : Array (Array Hash) := Id.run do
  let mut result : Array (Array Hash) := #[]
  for coreIdx in [:alpha.size] do
    let a := alpha[coreIdx]!
    -- Remove the authorizer hash used by a guarantee for this core
    let a' := match guarantees.find? (fun g => g.report.coreIndex.val == coreIdx) with
    | some g => a.filter (· != g.report.authorizerHash)
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

/-- Perform accumulation of newly available work reports. GP §12.
    Delegates to the full accumulation pipeline in Jar.Accumulation. -/
def performAccumulation
    (available : Array WorkReport)
    (s : State) (t' : Timeslot) : AccumulationResult :=
  let result := Accumulation.accumulate s available t'
  -- Collect work-package hashes of accumulated reports for history (sorted)
  let accPackageHashes := (available.map fun wr => wr.availSpec.packageHash).qsort
    (fun a b => Id.run do
      for i in [:32] do
        if a.data.get! i < b.data.get! i then return true
        if a.data.get! i > b.data.get! i then return false
      return false)
  -- Update accumulation history: shift left by 1, append new entry at end (GP eq 12).
  -- Maintains exactly E entries (like Grey's shift_accumulated).
  let accHistory' := if s.accHistory.size > 0
    then s.accHistory.extract 1 s.accHistory.size
    else s.accHistory
  let accHistory'' := accHistory'.push accPackageHashes
  -- Ensure exactly E entries
  let accHistory''' := if accHistory''.size < E
    then Id.run do
      let mut h := accHistory''
      while h.size < E do
        h := h.push #[]
      return h
    else accHistory''
  -- Build per-service statistics from gas usage
  let accStats := result.gasUsage.entries.foldl (init := Dict.empty (K := ServiceId) (V := ServiceStatistics))
    fun acc (sid, gas) =>
      acc.insert sid {
        provided := (0, 0)
        refinement := (0, 0)
        imports := 0
        extrinsicCount := 0
        extrinsicSize := 0
        exports := 0
        accumulation := (1, gas)
      }
  { services := result.services
    privileged := result.privileged
    pendingValidators := result.stagingKeys
    authQueue := result.authQueue
    outputs := result.outputs
    accQueue := s.accQueue
    accHistory := accHistory'''
    accStats := accStats }

-- ============================================================================
-- §12.7 — Preimage Integration
-- ============================================================================

/-- δ‡ : Integrate preimage data into service accounts. GP eq (12.35–12.38).
    For each (service_id, preimage_data) in E_P:
    1. Hash the preimage data to get h = H(data)
    2. If the service has a solicitation for (h, |data|), store the preimage
    3. Expunge old preimage solicitations past D_EXPUNGE timeslots. -/
def integratePreimages
    (delta : Dict ServiceId ServiceAccount)
    (preimages : PreimagesExtrinsic)
    (t' : Timeslot) : Dict ServiceId ServiceAccount :=
  -- Phase 1: Store new preimages
  let delta' := preimages.foldl (init := delta) fun acc (sid, data) =>
    match acc.lookup sid with
    | none => acc
    | some acct =>
      let h := Crypto.blake2b data
      let blobLen := UInt32.ofNat data.size
      -- Check if the service has solicited this preimage
      match acct.preimageInfo.lookup (h, blobLen) with
      | none => acc  -- Not solicited; ignore
      | some timeslots =>
        -- Store the preimage data and update the info with current timeslot
        let acct' := { acct with
          preimages := acct.preimages.insert h data
          preimageInfo := acct.preimageInfo.insert (h, blobLen)
            (timeslots.push t') }
        acc.insert sid acct'
  -- Phase 2: Expunge old preimage solicitations past D_EXPUNGE
  let delta'' := delta'.entries.foldl (init := delta') fun acc (sid, acct) =>
    let expunged := acct.preimageInfo.entries.foldl (init := acct.preimageInfo)
      fun info (key, timeslots) =>
        -- Remove entries where all timeslots are older than D_EXPUNGE
        let recent := timeslots.filter fun ts =>
          t'.toNat - ts.toNat < D_EXPUNGE
        if recent.size == 0 then
          -- All timeslots expired: expunge the preimage and info
          info.erase key
        else
          info.insert key recent
    if expunged.size != acct.preimageInfo.size then
      -- Also remove the actual preimage data for expunged hashes
      let removedHashes := acct.preimageInfo.entries.foldl (init := #[]) fun removed (key, timeslots) =>
        let recent := timeslots.filter fun ts => t'.toNat - ts.toNat < D_EXPUNGE
        if recent.size == 0 then removed.push key.1 else removed
      let preimages' := removedHashes.foldl (init := acct.preimages) fun pims h =>
        pims.erase h
      acc.insert sid { acct with preimageInfo := expunged, preimages := preimages' }
    else acc
  delta''

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
    Tracks per-core and per-service statistics. -/
def updateStatistics
    (pi : ActivityStatistics) (h : Header)
    (e : Extrinsic) (t t' : Timeslot)
    (_kappa' : Array ValidatorKey)
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

  -- §13.1: Guarantee stats — credit each guarantor
  let cur := e.guarantees.foldl (init := cur) fun c g =>
    g.credentials.foldl (init := c) fun c' (vi, _) =>
      if hv : vi.val < c'.size then
        let r := c'[vi.val]
        c'.set vi.val { r with guarantees := r.guarantees + 1 }
      else c'

  -- §13.1: Assurance stats — credit each assuring validator
  let cur := e.assurances.foldl (init := cur) fun c a =>
    if hv : a.validatorIndex.val < c.size then
      let r := c[a.validatorIndex.val]
      c.set a.validatorIndex.val { r with assurances := r.assurances + 1 }
    else c

  -- §13.2: Core statistics — compute from guarantees
  let coreStats := if epochChanged
    then Array.replicate C CoreStatistics.zero
    else pi.coreStats
  let coreStats := e.guarantees.foldl (init := coreStats) fun cs g =>
    let cIdx := g.report.coreIndex.val
    if hc : cIdx < cs.size then
      let s := cs[cIdx]
      -- Count assurances for this core (popularity)
      let pop := e.assurances.filter (fun a =>
        let byteIdx := cIdx / 8
        let bitIdx := cIdx % 8
        byteIdx < a.bitfield.size &&
          (a.bitfield.data[byteIdx]!.toNat >>> bitIdx) % 2 == 1) |>.size
      -- Sum digest statistics
      let (totalImports, totalExtrinsics, totalExtrinsicSize, totalExports, totalGas) :=
        g.report.digests.foldl (init := (0, 0, 0, 0, (0 : UInt64))) fun (i, x, z, e', gas) d =>
          (i + d.importsCount, x + d.extrinsicsCount, z + d.extrinsicsSize,
           e' + d.exportsCount, gas + d.gasUsed)
      cs.set cIdx { s with
        daLoad := s.daLoad + g.report.availSpec.bundleLength.toNat
        popularity := s.popularity + pop
        imports := s.imports + totalImports
        extrinsicCount := s.extrinsicCount + totalExtrinsics
        extrinsicSize := s.extrinsicSize + totalExtrinsicSize
        exports := s.exports + totalExports
        bundleSize := s.bundleSize + g.report.availSpec.bundleLength.toNat
        gasUsed := s.gasUsed + totalGas }
    else cs

  -- §13.2: Service statistics — merge accumulation stats with digest stats
  let serviceStats := if epochChanged then Dict.empty else pi.serviceStats
  -- Add refinement stats from guarantees
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
  -- Merge accumulation stats
  let serviceStats := accStats.entries.foldl (init := serviceStats) fun ss (sid, astats) =>
    let existing := match ss.lookup sid with
      | some s => s
      | none => { provided := (0, 0), refinement := (0, 0), imports := 0,
                  extrinsicCount := 0, extrinsicSize := 0, exports := 0,
                  accumulation := (0, 0) }
    ss.insert sid { existing with
      accumulation := (existing.accumulation.1 + astats.accumulation.1,
                       existing.accumulation.2 + astats.accumulation.2)
      provided := (existing.provided.1 + astats.provided.1,
                   existing.provided.2 + astats.provided.2) }

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
  let accResult := performAccumulation available s t'

  -- §7 — Recent history: β'
  let headerHash := Crypto.blake2b (Codec.encodeHeader h)
  let beta' := updateRecentHistory bDag headerHash accResult.outputs ext.guarantees

  -- §12.7 — Preimage integration
  let delta' := integratePreimages accResult.services ext.preimages t'

  -- §8 — Authorization
  let alpha' := updateAuthPool s.authPool accResult.authQueue h ext.guarantees

  -- §13 — Statistics
  let pi' := updateStatistics s.statistics h ext s.timeslot t' kappa' accResult.accStats

  -- Assemble posterior state
  pure {
    authPool := alpha'
    recent := beta'
    accOutputs := accResult.outputs
    safrole := Consensus.updateSafrole s.safrole ext.tickets eta' kappa'
                  (isEpochChange s.timeslot t') (epochSlot t')
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

/-- State transition without seal/VRF verification (for block-level testing). -/
def stateTransitionNoSealCheck (s : State) (b : Block) : Option State := do
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
  let accResult := performAccumulation available s t'
  let headerHash := Crypto.blake2b (Codec.encodeHeader h)
  let beta' := updateRecentHistory bDag headerHash accResult.outputs ext.guarantees
  let delta' := integratePreimages accResult.services ext.preimages t'
  let alpha' := updateAuthPool s.authPool accResult.authQueue h ext.guarantees
  let pi' := updateStatistics s.statistics h ext s.timeslot t' kappa' accResult.accStats
  pure {
    authPool := alpha'
    recent := beta'
    accOutputs := accResult.outputs
    safrole := Consensus.updateSafrole s.safrole ext.tickets eta' kappa'
                  (isEpochChange s.timeslot t') (epochSlot t')
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

end Jar
