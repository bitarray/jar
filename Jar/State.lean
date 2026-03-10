import Jar.Notation
import Jar.Types
import Jar.Crypto
import Jar.Codec
import Jar.Consensus
import Jar.Accumulation

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
    have hidx : idx < bs.blocks.size := Nat.sub_one_lt hne
    let last := bs.blocks[idx]
    let last' : RecentBlockInfo := {
      headerHash := last.headerHash
      stateRoot := h.stateRoot
      accOutputRoot := last.accOutputRoot
      reportedPackages := last.reportedPackages
    }
    { bs with blocks := bs.blocks.set idx last' }

/-- β' : Full recent history update. GP eq (37–43).
    Appends new block info, truncates to max history length. -/
def updateRecentHistory
    (bdag : RecentHistory) (headerHash : Hash) : RecentHistory :=
  let maxLen := 8  -- H_R : Maximum recent history length
  let newEntry : RecentBlockInfo := {
    headerHash := headerHash
    stateRoot := Hash.zero  -- will be filled by next block's β†
    accOutputRoot := Hash.zero  -- TODO: compute from accumulation outputs
    reportedPackages := Dict.empty
  }
  let blocks' := bdag.blocks.push newEntry
  let blocks'' := if blocks'.size > maxLen
    then blocks'.extract 1 blocks'.size
    else blocks'
  { bdag with blocks := blocks'' }

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
    Remove used authorizer, add from queue at current slot. -/
def updateAuthPool
    (alpha phi' : Array (Array Hash))
    (h : Header) (guarantees : GuaranteesExtrinsic) : Array (Array Hash) :=
  alpha.mapIdx fun c a =>
    let a' := match guarantees.find? (fun g => g.report.coreIndex.val == c) with
    | some g => a.filter (· != g.report.authorizerHash)
    | none => a
    let m := epochSlot h.timeslot
    if hc : c < phi'.size then
      let queueEntry := phi'[c]
      if hm : m < queueEntry.size then a'.push queueEntry[m]
      else a'
    else a'

-- ============================================================================
-- §12 — Accumulation (skeleton)
-- ============================================================================

/-- Accumulation result: the combined outputs of processing available work reports.
    Full implementation requires PVM execution. -/
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
  { services := result.services
    privileged := result.privileged
    pendingValidators := result.stagingKeys
    authQueue := result.authQueue
    outputs := result.outputs
    accQueue := s.accQueue  -- Queue management handled separately
    accHistory := s.accHistory
    accStats := Dict.empty }  -- Gas stats mapped separately

-- ============================================================================
-- §12.7 — Preimage Integration
-- ============================================================================

/-- δ‡ : Integrate preimage data into service accounts. GP eq (12.35–12.38). -/
def integratePreimages
    (delta : Dict ServiceId ServiceAccount)
    (_preimages : PreimagesExtrinsic)
    (_t' : Timeslot) : Dict ServiceId ServiceAccount :=
  -- TODO: store preimage data in the service's preimage store
  delta

-- ============================================================================
-- §13 — Statistics Update (skeleton)
-- ============================================================================

/-- Zero-valued validator record. -/
def ValidatorRecord.zero : ValidatorRecord :=
  { blocks := 0, tickets := 0, preimageCount := 0
    preimageSize := 0, guarantees := 0, assurances := 0 }

/-- π' : Updated activity statistics. GP §13. -/
def updateStatistics
    (pi : ActivityStatistics) (h : Header)
    (_e : Extrinsic) (t t' : Timeslot)
    (_kappa' : Array ValidatorKey)
    (_accStats : Dict ServiceId ServiceStatistics) : ActivityStatistics :=
  let epochChanged := isEpochChange t t'
  let (cur, prev) := if epochChanged
    then (Array.mkArray V ValidatorRecord.zero, pi.current)
    else (pi.current, pi.previous)
  -- Increment block author stats
  let authorIdx := h.authorIndex.val
  let cur' := if hv : authorIdx < cur.size then
    let r := cur[authorIdx]
    cur.set authorIdx { r with blocks := r.blocks + 1 }
  else cur
  { current := cur'
    previous := prev
    coreStats := pi.coreStats
    serviceStats := pi.serviceStats }

-- ============================================================================
-- §4.1 — Top-Level State Transition Υ(σ, B) = σ'
-- ============================================================================

/-- Υ(σ, B) : Block-level state transition function. GP eq (4.1).
    Returns the posterior state, or none if the block is invalid. -/
def stateTransition (s : State) (b : Block) : Option State := do
  let h := b.header
  let ext := b.extrinsic

  -- §6.1 — Timekeeping
  let t' := newTimeslot h
  guard (t'.toNat > s.timeslot.toNat)

  -- §6 — Entropy
  let eta' := updateEntropy s.entropy h s.timeslot t'

  -- §6 — Validator rotation
  let kappa' := updateActiveValidators s.currentValidators s.safrole s.timeslot t' #[]
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
  let beta' := updateRecentHistory bDag headerHash

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

end Jar
