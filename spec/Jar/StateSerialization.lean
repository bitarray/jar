import Jar.Notation
import Jar.Types
import Jar.Codec
import Jar.Crypto
import Jar.Merkle

/-!
# State Serialization T(sigma) -- Gray Paper Appendix D, eq D.2

Maps State to Merkle trie key-value pairs (31-byte keys -> variable-length values).
Matches the encoding in Grey's `crates/grey-merkle/src/state_serial.rs`.

## State Component Indices
- C(1)  : alpha  -- authorization pool
- C(2)  : phi    -- authorization queue
- C(3)  : beta   -- recent block history
- C(4)  : gamma  -- Safrole consensus state
- C(5)  : psi    -- judgments
- C(6)  : eta    -- entropy
- C(7)  : iota   -- pending validators
- C(8)  : kappa  -- current validators
- C(9)  : lambda -- previous validators
- C(10) : rho    -- pending reports
- C(11) : tau    -- timeslot
- C(12) : chi    -- privileged services
- C(13) : pi     -- statistics
- C(14) : omega  -- accumulation queue
- C(15) : xi     -- accumulation history
- C(16) : theta  -- accumulation outputs
- C(255, s) : service account metadata
- C(s, h) : service storage/preimage data
-/

namespace Jar.StateSerialization
open Jar.Codec
variable [JamConfig]

-- Instances needed for this module
instance : Inhabited CoreStatistics where
  default := { daLoad := 0, popularity := 0, imports := 0, extrinsicCount := 0,
               extrinsicSize := 0, exports := 0, bundleSize := 0, gasUsed := 0 }

instance : Inhabited ValidatorRecord where
  default := { blocks := 0, tickets := 0, preimageCount := 0,
               preimageSize := 0, guarantees := 0, assurances := 0 }

/-- Lexicographic comparison for ByteArray. -/
private def byteArrayLt (a b : ByteArray) : Bool :=
  let n := min a.size b.size
  go a b 0 n
where
  go (a b : ByteArray) (i n : Nat) : Bool :=
    if i >= n then a.size < b.size
    else if a.get! i < b.get! i then true
    else if a.get! i > b.get! i then false
    else go a b (i + 1) n

-- ============================================================================
-- State Key Constructors -- Appendix D eq D.1
-- ============================================================================

/-- C(i) : State key from component index. GP eq D.1.
    31-byte key with index at position 0. -/
def stateKeyFromIndex (i : UInt8) : OctetSeq 31 :=
  let arr := (ByteArray.mk (Array.replicate 31 0)).set! 0 i
  OctetSeq.mk! arr 31

/-- C(i, s) : State key for service-indexed component. GP eq D.1.
    The service ID bytes (LE) are interleaved at positions 0,1,3,5,7 of the key. -/
def stateKeyForService (i : UInt8) (serviceId : ServiceId) : OctetSeq 31 :=
  let s := encodeFixedNat 4 serviceId.toNat
  let arr := ByteArray.mk (Array.replicate 31 0)
  let arr := arr.set! 0 i
  let arr := arr.set! 1 (s.get! 0)
  let arr := arr.set! 3 (s.get! 1)
  let arr := arr.set! 5 (s.get! 2)
  let arr := arr.set! 7 (s.get! 3)
  OctetSeq.mk! arr 31

/-- C(s, h) : State key for service data (storage/preimage entries). GP eq D.1.
    Interleaves E_4(s) with H(h). -/
def stateKeyForServiceData (serviceId : ServiceId) (h : ByteArray) : OctetSeq 31 :=
  let s := encodeFixedNat 4 serviceId.toNat
  let a := Crypto.blake2b h
  let arr := ByteArray.mk (Array.replicate 31 0)
  let arr := arr.set! 0 (s.get! 0)
  let arr := arr.set! 1 (a.data.get! 0)
  let arr := arr.set! 2 (s.get! 1)
  let arr := arr.set! 3 (a.data.get! 1)
  let arr := arr.set! 4 (s.get! 2)
  let arr := arr.set! 5 (a.data.get! 2)
  let arr := arr.set! 6 (s.get! 3)
  let arr := arr.set! 7 (a.data.get! 3)
  let arr := Id.run do
    let mut r := arr
    for i in [:23] do
      r := r.set! (8 + i) (a.data.get! (4 + i))
    return r
  OctetSeq.mk! arr 31

/-- Construct the h argument for storage entries: E_4(2^32-1) ++ k. -/
def storageHashArg (storageKey : ByteArray) : ByteArray :=
  encodeFixedNat 4 (2^32 - 1) ++ storageKey

/-- Construct the h argument for preimage lookup entries: E_4(2^32-2) ++ hash. -/
def preimageHashArg (hash : Hash) : ByteArray :=
  encodeFixedNat 4 (2^32 - 2) ++ hash.data

/-- Construct the h argument for preimage info entries: E_4(l) ++ hash. -/
def preimageInfoHashArg (length : BlobLength) (hash : Hash) : ByteArray :=
  encodeFixedNat 4 length.toNat ++ hash.data

/-- Extract service ID from a C(s, h) key. Bytes at positions 0,2,4,6. -/
def extractServiceIdFromDataKey (key : ByteArray) : ServiceId :=
  if key.size < 7 then 0
  else
    let b0 := key.get! 0
    let b1 := key.get! 2
    let b2 := key.get! 4
    let b3 := key.get! 6
    UInt32.ofNat (b0.toNat + b1.toNat * 256 + b2.toNat * 65536 + b3.toNat * 16777216)

-- ============================================================================
-- Serialization Helpers
-- ============================================================================

/-- Encode a ValidatorKey (336 bytes = 32 + 32 + 144 + 128). -/
private def encodeValidatorKey (vk : ValidatorKey) : ByteArray :=
  vk.bandersnatch.data ++ vk.ed25519.data ++ vk.bls.data ++ vk.metadata.data

-- ============================================================================
-- Work Report Serialization (State Context)
-- ============================================================================

/-- Encode a WorkResult for state context. Same as block codec. -/
private def encodeWorkResultState (r : WorkResult) : ByteArray :=
  match r with
  | .ok data => ByteArray.mk #[0] ++ encodeLengthPrefixed data
  | .err .outOfGas => ByteArray.mk #[1]
  | .err .panic => ByteArray.mk #[2]
  | .err .badExports => ByteArray.mk #[3]
  | .err .badCode => ByteArray.mk #[4]
  | .err .bigCode => ByteArray.mk #[5]
  | .err .oversize => ByteArray.mk #[5]

/-- Encode a WorkDigest for state context (fixed-width RefineLoad fields).
    Matches Grey's serialize_work_digest_state. -/
private def encodeWorkDigestState (d : WorkDigest) : ByteArray :=
  encodeFixedNat 4 d.serviceId.toNat
  ++ d.codeHash.data
  ++ d.payloadHash.data
  ++ encodeFixedNat 8 d.gasLimit.toNat
  ++ encodeWorkResultState d.result
  ++ encodeFixedNat 8 d.gasUsed.toNat
  ++ encodeFixedNat 2 d.importsCount
  ++ encodeFixedNat 2 d.extrinsicsCount
  ++ encodeFixedNat 4 d.extrinsicsSize
  ++ encodeFixedNat 2 d.exportsCount

/-- Encode an AvailabilitySpec for state context. -/
private def encodeAvailSpecState (a : AvailabilitySpec) : ByteArray :=
  a.packageHash.data
  ++ encodeFixedNat 4 a.bundleLength.toNat
  ++ a.erasureRoot.data
  ++ a.segmentRoot.data
  ++ encodeFixedNat 2 a.segmentCount

/-- Encode a RefinementContext for state context. -/
private def encodeRefinementContextState (c : RefinementContext) : ByteArray :=
  c.anchorHash.data
  ++ c.anchorStateRoot.data
  ++ c.anchorBeefyRoot.data
  ++ c.lookupAnchorHash.data
  ++ encodeFixedNat 4 c.lookupAnchorTimeslot.toNat
  ++ encodeCountPrefixedArray (fun h => h.data) c.prerequisites

/-- Encode a WorkReport for state context (fixed-width numerics).
    In state context:
    - core_index: E_2 (NOT compact)
    - auth_gas_used: E_8 (NOT compact) -/
private def encodeWorkReportState (wr : WorkReport) : ByteArray :=
  encodeAvailSpecState wr.availSpec
  ++ encodeRefinementContextState wr.context
  ++ encodeFixedNat 2 wr.coreIndex.val
  ++ wr.authorizerHash.data
  ++ encodeFixedNat 8 wr.authGasUsed.toNat
  ++ encodeLengthPrefixed wr.authOutput
  ++ encodeCountPrefixedArray (fun (k, v) => k.data ++ v.data)
      (wr.segmentRootLookup.entries.toArray.qsort fun (a, _) (b, _) => byteArrayLt a.data b.data)
  ++ encodeCountPrefixedArray encodeWorkDigestState wr.digests

-- ============================================================================
-- Component Serializers
-- ============================================================================

/-- C(1): alpha auth_pool. -/
private def serializeAuthPool (authPool : Array (Array Hash)) : ByteArray := Id.run do
  let mut buf := ByteArray.empty
  for coreIdx in [:C] do
    let hashes := if coreIdx < authPool.size then authPool[coreIdx]! else #[]
    buf := buf ++ encodeNat hashes.size
    for h in hashes do
      buf := buf ++ h.data
  return buf

/-- C(2): phi auth_queue. -/
private def serializeAuthQueue (authQueue : Array (Array Hash)) : ByteArray := Id.run do
  let mut buf := ByteArray.empty
  for slotIdx in [:Q_QUEUE] do
    let slot := if slotIdx < authQueue.size then authQueue[slotIdx]! else #[]
    for coreIdx in [:C] do
      let hash := if coreIdx < slot.size then slot[coreIdx]! else Hash.zero
      buf := buf ++ hash.data
  return buf

/-- C(3): beta recent_blocks. -/
private def serializeRecentBlocks (recent : RecentHistory) : ByteArray := Id.run do
  let mut buf := ByteArray.empty
  buf := buf ++ encodeNat recent.blocks.size
  for info in recent.blocks do
    buf := buf ++ info.headerHash.data
    buf := buf ++ info.accOutputRoot.data
    buf := buf ++ info.stateRoot.data
    let pkgs := info.reportedPackages.entries.toArray.qsort fun (a, _) (b, _) => byteArrayLt a.data b.data
    buf := buf ++ encodeNat pkgs.size
    for (k, v) in pkgs do
      buf := buf ++ k.data
      buf := buf ++ v.data
  buf := buf ++ encodeNat recent.accOutputBelt.size
  for entry in recent.accOutputBelt do
    match entry with
    | some hash =>
      buf := buf ++ ByteArray.mk #[1]
      buf := buf ++ hash.data
    | none =>
      buf := buf ++ ByteArray.mk #[0]
  return buf

/-- C(4): gamma safrole. -/
private def serializeSafrole (safrole : SafroleState) : ByteArray := Id.run do
  let mut buf := ByteArray.empty
  for key in safrole.pendingKeys do
    buf := buf ++ encodeValidatorKey key
  buf := buf ++ safrole.ringRoot.data
  match safrole.sealKeys with
  | .tickets tickets =>
    buf := buf ++ ByteArray.mk #[0]
    for ticket in tickets do
      buf := buf ++ ticket.id.data
      buf := buf ++ ByteArray.mk #[UInt8.ofNat ticket.attempt]
    for _ in List.range (E - tickets.size) do
      buf := buf ++ (Hash.zero).data
      buf := buf ++ ByteArray.mk #[0]
  | .fallback keys =>
    buf := buf ++ ByteArray.mk #[1]
    for key in keys do
      buf := buf ++ key.data
    for _ in List.range (E - keys.size) do
      buf := buf ++ ByteArray.mk (Array.replicate 32 0)
  buf := buf ++ encodeNat safrole.ticketAccumulator.size
  for ticket in safrole.ticketAccumulator do
    buf := buf ++ ticket.id.data
    buf := buf ++ ByteArray.mk #[UInt8.ofNat ticket.attempt]
  return buf

/-- C(5): psi judgments. -/
private def serializeJudgments (j : JudgmentsState) : ByteArray := Id.run do
  let mut buf := ByteArray.empty
  buf := buf ++ encodeNat j.good.size
  for h in j.good do buf := buf ++ h.data
  buf := buf ++ encodeNat j.bad.size
  for h in j.bad do buf := buf ++ h.data
  buf := buf ++ encodeNat j.wonky.size
  for h in j.wonky do buf := buf ++ h.data
  buf := buf ++ encodeNat j.offenders.size
  for k in j.offenders do buf := buf ++ k.data
  return buf

/-- C(6): eta entropy. -/
private def serializeEntropy (e : Entropy) : ByteArray :=
  e.current.data ++ e.previous.data ++ e.twoBack.data ++ e.threeBack.data

/-- C(7,8,9): validator keys. -/
private def serializeValidators (validators : Array ValidatorKey) : ByteArray := Id.run do
  let mut buf := ByteArray.empty
  for key in validators do
    buf := buf ++ encodeValidatorKey key
  return buf

/-- C(10): rho pending_reports. -/
private def serializePendingReports (reports : Array (Option PendingReport)) : ByteArray := Id.run do
  let mut buf := ByteArray.empty
  for report in reports do
    match report with
    | none => buf := buf ++ ByteArray.mk #[0]
    | some pr =>
      buf := buf ++ ByteArray.mk #[1]
      buf := buf ++ Codec.encodeWorkReport pr.report
      buf := buf ++ encodeFixedNat 4 pr.timeslot.toNat
  return buf

/-- C(12): chi privileged. -/
private def serializePrivileged (priv : PrivilegedServices) : ByteArray := Id.run do
  let mut buf := ByteArray.empty
  buf := buf ++ encodeFixedNat 4 priv.manager.toNat
  for sid in priv.assigners do
    buf := buf ++ encodeFixedNat 4 sid.toNat
  buf := buf ++ encodeFixedNat 4 priv.designator.toNat
  buf := buf ++ encodeFixedNat 4 priv.registrar.toNat
  let zEntries := priv.alwaysAccumulate.entries.toArray.qsort fun (a, _) (b, _) => a.toNat < b.toNat
  buf := buf ++ encodeNat zEntries.size
  for (sid, gas) in zEntries do
    buf := buf ++ encodeFixedNat 4 sid.toNat
    buf := buf ++ encodeFixedNat 8 gas.toNat
  -- jar1 (coinless): serialize quotaService after always-accumulate entries
  if JamConfig.hostcallVersion == 1 then
    buf := buf ++ encodeFixedNat 4 priv.quotaService.toNat
  return buf

/-- Encode V validator records with E_4. -/
private def serializeValidatorRecords (records : Array ValidatorRecord) (count : Nat)
    : ByteArray := Id.run do
  let mut buf := ByteArray.empty
  for i in [:count] do
    let r : ValidatorRecord :=
      if i < records.size then records[i]! else
      { blocks := 0, tickets := 0, preimageCount := 0,
        preimageSize := 0, guarantees := 0, assurances := 0 }
    buf := buf ++ encodeFixedNat 4 r.blocks
    buf := buf ++ encodeFixedNat 4 r.tickets
    buf := buf ++ encodeFixedNat 4 r.preimageCount
    buf := buf ++ encodeFixedNat 4 r.preimageSize
    buf := buf ++ encodeFixedNat 4 r.guarantees
    buf := buf ++ encodeFixedNat 4 r.assurances
  return buf

/-- C(13): pi statistics. -/
private def serializeStatistics (stats : ActivityStatistics) : ByteArray := Id.run do
  let mut buf := ByteArray.empty
  buf := buf ++ serializeValidatorRecords stats.current V
  buf := buf ++ serializeValidatorRecords stats.previous V
  for coreIdx in [:C] do
    let cs : CoreStatistics :=
      if coreIdx < stats.coreStats.size then stats.coreStats[coreIdx]! else
      { daLoad := 0, popularity := 0, imports := 0, extrinsicCount := 0,
        extrinsicSize := 0, exports := 0, bundleSize := 0, gasUsed := 0 }
    buf := buf ++ encodeNat cs.daLoad
    buf := buf ++ encodeNat cs.popularity
    buf := buf ++ encodeNat cs.imports
    buf := buf ++ encodeNat cs.extrinsicCount
    buf := buf ++ encodeNat cs.extrinsicSize
    buf := buf ++ encodeNat cs.exports
    buf := buf ++ encodeNat cs.bundleSize
    buf := buf ++ encodeNat cs.gasUsed.toNat
  let sEntries := stats.serviceStats.entries.toArray.qsort fun (a, _) (b, _) => a.toNat < b.toNat
  buf := buf ++ encodeNat sEntries.size
  for (sid, ss) in sEntries do
    buf := buf ++ encodeFixedNat 4 sid.toNat
    buf := buf ++ encodeNat ss.provided.1
    buf := buf ++ encodeNat ss.provided.2
    buf := buf ++ encodeNat ss.refinement.1
    buf := buf ++ encodeNat ss.refinement.2.toNat
    buf := buf ++ encodeNat ss.imports
    buf := buf ++ encodeNat ss.extrinsicCount
    buf := buf ++ encodeNat ss.extrinsicSize
    buf := buf ++ encodeNat ss.exports
    buf := buf ++ encodeNat ss.accumulation.1
    buf := buf ++ encodeNat ss.accumulation.2.toNat
  return buf

/-- C(14): omega accumulation_queue. -/
private def serializeAccumulationQueue
    (queue : Array (Array (WorkReport × Array Hash))) : ByteArray := Id.run do
  let mut buf := ByteArray.empty
  for slot in queue do
    buf := buf ++ encodeNat slot.size
    for (report, deps) in slot do
      buf := buf ++ Codec.encodeWorkReport report
      buf := buf ++ encodeNat deps.size
      for h in deps do
        buf := buf ++ h.data
  return buf

/-- C(15): xi accumulation_history. -/
private def serializeAccumulationHistory (history : Array (Array Hash)) : ByteArray := Id.run do
  let mut buf := ByteArray.empty
  for slot in history do
    buf := buf ++ encodeNat slot.size
    for h in slot do
      buf := buf ++ h.data
  return buf

/-- C(16): theta accumulation_outputs. -/
private def serializeAccumulationOutputs (outputs : AccumulationOutputs) : ByteArray := Id.run do
  let mut buf := ByteArray.empty
  buf := buf ++ encodeNat outputs.size
  for (sid, hash) in outputs do
    buf := buf ++ encodeFixedNat 4 sid.toNat
    buf := buf ++ hash.data
  return buf

/-- C(255, s): Service account metadata.
    Field layout (matches Grey's serialize_service_account_with_id):
    E(0) ++ a_c ++ E_8(b, g, m, o, f) ++ E_4(i, r, a, p)
    where o = totalFootprint, f = gratis, i = itemCount,
    a = lastAccumulation (last_activity), p = parentServiceId. -/
private def serializeServiceAccount (account : ServiceAccount) (_sid : ServiceId)
    : ByteArray := Id.run do
  let mut buf := ByteArray.empty
  -- Use preserved totalFootprint/itemCount/parentServiceId values.
  -- These are maintained incrementally during accumulation host calls
  -- (write updates itemCount and totalFootprint, solicit/forget update preimageInfo counts).
  let footprint := account.totalFootprint
  let itemCount := account.itemCount.toNat  -- a_i: item count
  let preimCount := account.parentServiceId -- a_p: parent service ID
  -- Serialize econ fields at their original wire positions.
  -- serializeEcon returns 16 bytes: [first_field(8) ++ second_field(8)]
  -- For BalanceEcon: first=balance, second=gratis
  -- For QuotaEcon: first=quotaItems, second=quotaBytes
  let econBytes := @EconModel.serializeEcon JamConfig.EconType JamConfig.TransferType _ account.econ
  let econFirst := econBytes.extract 0 8    -- balance or quotaItems
  let econSecond := econBytes.extract 8 16  -- gratis or quotaBytes
  buf := buf ++ ByteArray.mk #[0]  -- version
  buf := buf ++ account.codeHash.data
  buf := buf ++ econFirst                                    -- was: balance
  buf := buf ++ encodeFixedNat 8 account.minAccGas.toNat
  buf := buf ++ encodeFixedNat 8 account.minOnTransferGas.toNat
  buf := buf ++ encodeFixedNat 8 footprint
  buf := buf ++ econSecond                                   -- was: gratis
  buf := buf ++ encodeFixedNat 4 itemCount
  buf := buf ++ encodeFixedNat 4 account.creationSlot.toNat
  buf := buf ++ encodeFixedNat 4 account.lastAccumulation.toNat
  buf := buf ++ encodeFixedNat 4 preimCount
  return buf

-- ============================================================================
-- Full State Serialization
-- ============================================================================

/-- T(sigma) : Serialize the full state into sorted (key, value) pairs. -/
def serializeState (state : State) : Array (OctetSeq 31 × ByteArray) := Id.run do
  let mut kvs : Array (OctetSeq 31 × ByteArray) := #[]
  kvs := kvs.push (stateKeyFromIndex 1, serializeAuthPool state.authPool)
  kvs := kvs.push (stateKeyFromIndex 2, serializeAuthQueue state.authQueue)
  kvs := kvs.push (stateKeyFromIndex 3, serializeRecentBlocks state.recent)
  kvs := kvs.push (stateKeyFromIndex 4, serializeSafrole state.safrole)
  kvs := kvs.push (stateKeyFromIndex 5, serializeJudgments state.judgments)
  kvs := kvs.push (stateKeyFromIndex 6, serializeEntropy state.entropy)
  kvs := kvs.push (stateKeyFromIndex 7, serializeValidators state.pendingValidators)
  kvs := kvs.push (stateKeyFromIndex 8, serializeValidators state.currentValidators)
  kvs := kvs.push (stateKeyFromIndex 9, serializeValidators state.previousValidators)
  kvs := kvs.push (stateKeyFromIndex 10, serializePendingReports state.pendingReports)
  kvs := kvs.push (stateKeyFromIndex 11, encodeFixedNat 4 state.timeslot.toNat)
  kvs := kvs.push (stateKeyFromIndex 12, serializePrivileged state.privileged)
  kvs := kvs.push (stateKeyFromIndex 13, serializeStatistics state.statistics)
  kvs := kvs.push (stateKeyFromIndex 14, serializeAccumulationQueue state.accQueue)
  kvs := kvs.push (stateKeyFromIndex 15, serializeAccumulationHistory state.accHistory)
  kvs := kvs.push (stateKeyFromIndex 16, serializeAccumulationOutputs state.accOutputs)
  for (serviceId, account) in state.services.entries.toArray do
    kvs := kvs.push (stateKeyForService 255 serviceId,
                      serializeServiceAccount account serviceId)
    for (storageKey, value) in account.storage.entries.toArray do
      let h := storageHashArg storageKey
      kvs := kvs.push (stateKeyForServiceData serviceId h, value)
    for (hash, blobData) in account.preimages.entries.toArray do
      let h := preimageHashArg hash
      kvs := kvs.push (stateKeyForServiceData serviceId h, blobData)
    for ((hash, length), timeslots) in account.preimageInfo.entries.toArray do
      let h := preimageInfoHashArg length hash
      let mut val := ByteArray.empty
      val := val ++ encodeNat timeslots.size
      for t in timeslots do
        val := val ++ encodeFixedNat 4 t.toNat
      kvs := kvs.push (stateKeyForServiceData serviceId h, val)
  let sorted := kvs.qsort fun (k1, _) (k2, _) => byteArrayLt k1.data k2.data
  return sorted

-- ============================================================================
-- Deserialization Helpers (using Codec.Decoder monad)
-- ============================================================================

/-- Key classification for deserialization. -/
private inductive KeyType where
  | component (idx : UInt8)
  | serviceAccount (sid : ServiceId)
  | serviceData

/-- Classify a 31-byte state key. -/
private def classifyKey (key : ByteArray) : KeyType :=
  if key.size < 31 then .serviceData  -- malformed key
  else if key.get! 0 == 255 then
    if key.get! 2 == 0 && key.get! 4 == 0 && key.get! 6 == 0 &&
       (Id.run do
         let mut allZero := true
         for i in [8:31] do
           if key.get! i != 0 then allZero := false
         return allZero) then
      let sid := UInt32.ofNat (
        (key.get! 1).toNat +
        (key.get! 3).toNat * 256 +
        (key.get! 5).toNat * 65536 +
        (key.get! 7).toNat * 16777216)
      .serviceAccount sid
    else .serviceData
  else if (Id.run do
    let mut allZero := true
    for i in [1:31] do
      if key.get! i != 0 then allZero := false
    return allZero) then
    .component (key.get! 0)
  else .serviceData

-- ============================================================================
-- Component Decoders
-- ============================================================================

/-- Decode auth pool: C arrays of compact-prefixed hashes. -/
private def deserializeAuthPoolD (coreCount : Nat) : Decoder (Array (Array Hash)) :=
  go coreCount #[]
where
  go : Nat → Array (Array Hash) → Decoder (Array (Array Hash))
    | 0, acc => Decoder.pure acc
    | n + 1, acc => fun s =>
      match decodeNatD s with
      | none => none
      | some (count, s') =>
        match Decoder.replicateD count decodeHashD s' with
        | none => none
        | some (hashes, s'') => go n (acc.push hashes) s''

/-- Decode auth queue: Q x C x 32 bytes. -/
private def deserializeAuthQueueD (q : Nat) (c : Nat) : Decoder (Array (Array Hash)) :=
  go q #[]
where
  go : Nat → Array (Array Hash) → Decoder (Array (Array Hash))
    | 0, acc => Decoder.pure acc
    | n + 1, acc => fun s =>
      match Decoder.replicateD c decodeHashD s with
      | none => none
      | some (slot, s') => go n (acc.push slot) s'

/-- Decode recent blocks. -/
private def deserializeRecentBlocksD : Decoder RecentHistory := fun s => do
  let (headerCount, s) ← decodeNatD s
  let (blocks, s) ← goHeaders headerCount #[] s
  let (beltCount, s) ← decodeNatD s
  let (belt, s) ← goBelt beltCount #[] s
  return ({ blocks, accOutputBelt := belt }, s)
where
  goHeaders : Nat → Array RecentBlockInfo → DecodeState → Option (Array RecentBlockInfo × DecodeState)
    | 0, acc, s => some (acc, s)
    | n + 1, acc, s => do
      let (headerHash, s) ← decodeHashD s
      let (accOutputRoot, s) ← decodeHashD s
      let (stateRoot, s) ← decodeHashD s
      let (pkgCount, s) ← decodeNatD s
      let (pkgs, s) ← goPkgs pkgCount Dict.empty s
      goHeaders n (acc.push { headerHash, accOutputRoot, stateRoot, reportedPackages := pkgs }) s
  goPkgs : Nat → Dict Hash Hash → DecodeState → Option (Dict Hash Hash × DecodeState)
    | 0, acc, s => some (acc, s)
    | n + 1, acc, s => do
      let (k, s) ← decodeHashD s
      let (v, s) ← decodeHashD s
      goPkgs n (acc.insert k v) s
  goBelt : Nat → Array (Option Hash) → DecodeState → Option (Array (Option Hash) × DecodeState)
    | 0, acc, s => some (acc, s)
    | n + 1, acc, s => do
      let (disc, s) ← Decoder.readByte s
      if disc.toNat == 0 then
        goBelt n (acc.push none) s
      else if disc.toNat == 1 then do
        let (h, s) ← decodeHashD s
        goBelt n (acc.push (some h)) s
      else none

/-- Decode a ValidatorKey from 336 bytes. -/
private def decodeValidatorKeyD : Decoder ValidatorKey := fun s => do
  let (bander, s) ← decodeOctetSeqD 32 s
  let (ed, s) ← decodeOctetSeqD 32 s
  let (bls, s) ← decodeOctetSeqD 144 s
  let (md, s) ← decodeOctetSeqD 128 s
  return ({ bandersnatch := bander, ed25519 := ed, bls := bls, metadata := md }, s)

/-- Decode Safrole state. -/
private def deserializeSafroleD (v e : Nat) : Decoder SafroleState := fun s => do
  let (pendingKeys, s) ← Decoder.replicateD v decodeValidatorKeyD s
  let (ringRoot, s) ← decodeOctetSeqD 144 s
  let (disc, s) ← Decoder.readByte s
  let (sealKeys, s) ← (match disc.toNat with
    | 0 => do
      let (tickets, s) ← goTickets e #[] s
      some (SealKeySeries.tickets tickets, s)
    | 1 => do
      let (keys, s) ← Decoder.replicateD e (decodeOctetSeqD 32) s
      some (SealKeySeries.fallback keys, s)
    | _ => none : Option (SealKeySeries × DecodeState))
  let (taCount, s) ← decodeNatD s
  let (ticketAccumulator, s) ← goTickets taCount #[] s
  return ({ pendingKeys, ringRoot, sealKeys, ticketAccumulator }, s)
where
  goTickets : Nat → Array Ticket → DecodeState → Option (Array Ticket × DecodeState)
    | 0, acc, s => some (acc, s)
    | n + 1, acc, s => do
      let (id, s) ← decodeHashD s
      let (attempt, s) ← Decoder.readByte s
      goTickets n (acc.push { id, attempt := attempt.toNat }) s

/-- Decode judgments state. -/
private def deserializeJudgmentsD : Decoder JudgmentsState := fun s => do
  let (goodCount, s) ← decodeNatD s
  let (good, s) ← Decoder.replicateD goodCount decodeHashD s
  let (badCount, s) ← decodeNatD s
  let (bad, s) ← Decoder.replicateD badCount decodeHashD s
  let (wonkyCount, s) ← decodeNatD s
  let (wonky, s) ← Decoder.replicateD wonkyCount decodeHashD s
  let (offenderCount, s) ← decodeNatD s
  let (offenders, s) ← Decoder.replicateD offenderCount (decodeOctetSeqD 32) s
  return ({ good, bad, wonky, offenders }, s)

/-- Decode validators (fixed count). -/
private def deserializeValidatorsD (count : Nat) : Decoder (Array ValidatorKey) :=
  Decoder.replicateD count decodeValidatorKeyD

/-- Decode a WorkDigest from state context (fixed-width RefineLoad fields). -/
private def deserializeWorkDigestStateD : Decoder WorkDigest := fun s => do
  let (serviceId, s) ← decodeFixedNatD 4 s
  let (codeHash, s) ← decodeHashD s
  let (payloadHash, s) ← decodeHashD s
  let (gasLimit, s) ← decodeFixedNatD 8 s
  let (result, s) ← decodeWorkResultD s
  -- RefineLoad fields: compact (standard block codec)
  let (gasUsed, s) ← decodeNatD s
  let (importsCount, s) ← decodeNatD s
  let (extrinsicsCount, s) ← decodeNatD s
  let (extrinsicsSize, s) ← decodeNatD s
  let (exportsCount, s) ← decodeNatD s
  return ({
    serviceId := UInt32.ofNat serviceId
    codeHash, payloadHash
    gasLimit := UInt64.ofNat gasLimit
    result
    gasUsed := UInt64.ofNat gasUsed
    importsCount, extrinsicsCount, extrinsicsSize, exportsCount
  }, s)

/-- Decode a WorkReport from state context (fixed-width numerics). -/
private def deserializeWorkReportStateD : Decoder WorkReport := fun s => do
  -- AvailabilitySpec
  let (packageHash, s) ← decodeHashD s
  let (bundleLength, s) ← decodeFixedNatD 4 s
  let (erasureRoot, s) ← decodeHashD s
  let (segmentRoot, s) ← decodeHashD s
  let (segmentCount, s) ← decodeFixedNatD 2 s
  let availSpec : AvailabilitySpec := {
    packageHash, bundleLength := UInt32.ofNat bundleLength,
    erasureRoot, segmentRoot, segmentCount }
  -- RefinementContext
  let (anchorHash, s) ← decodeHashD s
  let (anchorStateRoot, s) ← decodeHashD s
  let (anchorBeefyRoot, s) ← decodeHashD s
  let (lookupAnchorHash, s) ← decodeHashD s
  let (lookupAnchorTimeslot, s) ← decodeFixedNatD 4 s
  let (prerequisites, s) ← decodeCountPrefixedArrayD decodeHashD s
  let context : RefinementContext := {
    anchorHash, anchorStateRoot, anchorBeefyRoot, lookupAnchorHash,
    lookupAnchorTimeslot := UInt32.ofNat lookupAnchorTimeslot, prerequisites }
  -- core_index: compact (standard block codec)
  let (coreIndexNat, s) ← decodeNatD s
  let (authorizerHash, s) ← decodeHashD s
  -- auth_gas_used: compact (standard block codec)
  let (authGasUsed, s) ← decodeNatD s
  let (authOutput, s) ← decodeLengthPrefixedD s
  let (srlArr, s) ← decodeCountPrefixedArrayD (fun s => do
    let (k, s) ← decodeHashD s
    let (v, s) ← decodeHashD s
    return ((k, v), s)) s
  let (digestCount, s) ← decodeNatD s
  let (digests, s) ← Decoder.replicateD digestCount deserializeWorkDigestStateD s
  if h : coreIndexNat < C then
    return ({
      availSpec, context
      coreIndex := ⟨coreIndexNat, h⟩
      authorizerHash
      authGasUsed := UInt64.ofNat authGasUsed
      authOutput
      segmentRootLookup := ⟨srlArr.toList⟩
      digests
    }, s)
  else none

/-- Decode pending reports: C entries. -/
private def deserializePendingReportsD (coreCount : Nat)
    : Decoder (Array (Option PendingReport)) :=
  go coreCount #[]
where
  go : Nat → Array (Option PendingReport) → Decoder (Array (Option PendingReport))
    | 0, acc => Decoder.pure acc
    | n + 1, acc => fun s => do
      let (disc, s) ← Decoder.readByte s
      match disc.toNat with
      | 0 => go n (acc.push none) s
      | 1 => do
        let (report, s) ← deserializeWorkReportStateD s
        let (timeslot, s) ← decodeFixedNatD 4 s
        go n (acc.push (some { report, timeslot := UInt32.ofNat timeslot })) s
      | _ => none

/-- Decode privileged services. -/
private def deserializePrivilegedD (coreCount : Nat) : Decoder PrivilegedServices := fun s => do
  let (manager, s) ← decodeFixedNatD 4 s
  let (assigners, s) ← goAssigners coreCount #[] s
  let (designator, s) ← decodeFixedNatD 4 s
  let (registrar, s) ← decodeFixedNatD 4 s
  let (zCount, s) ← decodeNatD s
  let (alwaysAccumulate, s) ← goZ zCount Dict.empty s
  -- jar1 (coinless): read quotaService after always-accumulate entries
  let (quotaService, s) ←
    if JamConfig.hostcallVersion == 1 then do
      let (qs, s) ← decodeFixedNatD 4 s
      pure (UInt32.ofNat qs, s)
    else pure (0, s)
  return ({
    manager := UInt32.ofNat manager
    assigners
    designator := UInt32.ofNat designator
    registrar := UInt32.ofNat registrar
    alwaysAccumulate
    quotaService
  }, s)
where
  goAssigners : Nat → Array ServiceId → DecodeState → Option (Array ServiceId × DecodeState)
    | 0, acc, s => some (acc, s)
    | n + 1, acc, s => do
      let (sid, s) ← decodeFixedNatD 4 s
      goAssigners n (acc.push (UInt32.ofNat sid)) s
  goZ : Nat → Dict ServiceId Gas → DecodeState → Option (Dict ServiceId Gas × DecodeState)
    | 0, acc, s => some (acc, s)
    | n + 1, acc, s => do
      let (sid, s) ← decodeFixedNatD 4 s
      let (gas, s) ← decodeFixedNatD 8 s
      goZ n (acc.insert (UInt32.ofNat sid) (UInt64.ofNat gas)) s

/-- Decode validator record (E_4 fields). -/
private def decodeValidatorRecordD : Decoder ValidatorRecord := fun s => do
  let (blocks, s) ← decodeFixedNatD 4 s
  let (tickets, s) ← decodeFixedNatD 4 s
  let (preimageCount, s) ← decodeFixedNatD 4 s
  let (preimageSize, s) ← decodeFixedNatD 4 s
  let (guarantees, s) ← decodeFixedNatD 4 s
  let (assurances, s) ← decodeFixedNatD 4 s
  return ({ blocks, tickets, preimageCount, preimageSize, guarantees, assurances }, s)

/-- Decode statistics. -/
private def deserializeStatisticsD (v c : Nat) : Decoder ActivityStatistics := fun s => do
  let (current, s) ← Decoder.replicateD v decodeValidatorRecordD s
  let (previous, s) ← Decoder.replicateD v decodeValidatorRecordD s
  let (coreStats, s) ← goCores c #[] s
  let (sCount, s) ← decodeNatD s
  let (serviceStats, s) ← goServices sCount Dict.empty s
  return ({ current, previous, coreStats, serviceStats }, s)
where
  goCores : Nat → Array CoreStatistics → DecodeState →
      Option (Array CoreStatistics × DecodeState)
    | 0, acc, s => some (acc, s)
    | n + 1, acc, s => do
      let (daLoad, s) ← decodeNatD s
      let (popularity, s) ← decodeNatD s
      let (imports, s) ← decodeNatD s
      let (extrinsicCount, s) ← decodeNatD s
      let (extrinsicSize, s) ← decodeNatD s
      let (exports, s) ← decodeNatD s
      let (bundleSize, s) ← decodeNatD s
      let (gasUsed, s) ← decodeNatD s
      goCores n (acc.push {
        daLoad, popularity, imports, extrinsicCount,
        extrinsicSize, exports, bundleSize, gasUsed := UInt64.ofNat gasUsed
      }) s
  goServices : Nat → Dict ServiceId ServiceStatistics → DecodeState →
      Option (Dict ServiceId ServiceStatistics × DecodeState)
    | 0, acc, s => some (acc, s)
    | n + 1, acc, s => do
      let (sid, s) ← decodeFixedNatD 4 s
      let (providedCount, s) ← decodeNatD s
      let (providedSize, s) ← decodeNatD s
      let (refinementCount, s) ← decodeNatD s
      let (refinementGas, s) ← decodeNatD s
      let (imports, s) ← decodeNatD s
      let (extrinsicCount, s) ← decodeNatD s
      let (extrinsicSize, s) ← decodeNatD s
      let (exports, s) ← decodeNatD s
      let (accCount, s) ← decodeNatD s
      let (accGas, s) ← decodeNatD s
      goServices n (acc.insert (UInt32.ofNat sid) {
        provided := (providedCount, providedSize)
        refinement := (refinementCount, UInt64.ofNat refinementGas)
        imports, extrinsicCount, extrinsicSize, exports
        accumulation := (accCount, UInt64.ofNat accGas)
      }) s

/-- Decode accumulation queue: E slots. -/
private def deserializeAccumulationQueueD (epochLen : Nat)
    : Decoder (Array (Array (WorkReport × Array Hash))) :=
  go epochLen #[]
where
  go : Nat → Array (Array (WorkReport × Array Hash)) →
      Decoder (Array (Array (WorkReport × Array Hash)))
    | 0, acc => Decoder.pure acc
    | n + 1, acc => fun s => do
      let (innerCount, s) ← decodeNatD s
      let (inner, s) ← goInner innerCount #[] s
      go n (acc.push inner) s
  goInner : Nat → Array (WorkReport × Array Hash) → DecodeState →
      Option (Array (WorkReport × Array Hash) × DecodeState)
    | 0, acc, s => some (acc, s)
    | n + 1, acc, s => do
      let (report, s) ← deserializeWorkReportStateD s
      let (depCount, s) ← decodeNatD s
      let (deps, s) ← Decoder.replicateD depCount decodeHashD s
      goInner n (acc.push (report, deps)) s

/-- Decode accumulation history: E slots. -/
private def deserializeAccumulationHistoryD (epochLen : Nat)
    : Decoder (Array (Array Hash)) :=
  go epochLen #[]
where
  go : Nat → Array (Array Hash) → Decoder (Array (Array Hash))
    | 0, acc => Decoder.pure acc
    | n + 1, acc => fun s => do
      let (count, s) ← decodeNatD s
      let (hashes, s) ← Decoder.replicateD count decodeHashD s
      go n (acc.push hashes) s

/-- Decode accumulation outputs. -/
private def deserializeAccumulationOutputsD : Decoder AccumulationOutputs := fun s => do
  let (count, s) ← decodeNatD s
  goOutputs count #[] s
where
  goOutputs : Nat → AccumulationOutputs → DecodeState →
      Option (AccumulationOutputs × DecodeState)
    | 0, acc, s => some (acc, s)
    | n + 1, acc, s => do
      let (sid, s) ← decodeFixedNatD 4 s
      let (hash, s) ← decodeHashD s
      goOutputs n (acc.push (UInt32.ofNat sid, hash)) s

/-- Decode service account metadata. -/
private def deserializeServiceAccountD : Decoder ServiceAccount := fun s => do
  let (_version, s) ← Decoder.readByte s
  let (codeHash, s) ← decodeHashD s
  -- Read first econ field (8 bytes): balance or quotaItems
  let (econFirst, s) ← decodeFixedNatD 8 s
  let (minAccGas, s) ← decodeFixedNatD 8 s
  let (minOnTransferGas, s) ← decodeFixedNatD 8 s
  let (totalFootprint, s) ← decodeFixedNatD 8 s
  -- Read second econ field (8 bytes): gratis or quotaBytes
  let (econSecond, s) ← decodeFixedNatD 8 s
  let (accumCounter, s) ← decodeFixedNatD 4 s
  let (lastAccumulation, s) ← decodeFixedNatD 4 s
  let (lastActivity, s) ← decodeFixedNatD 4 s
  let (preimageCount, s) ← decodeFixedNatD 4 s
  -- Reconstruct econ from the two fields via deserializeEcon
  let econBytes := Codec.encodeFixedNat 8 econFirst ++ Codec.encodeFixedNat 8 econSecond
  let econ : JamConfig.EconType := match @EconModel.deserializeEcon JamConfig.EconType JamConfig.TransferType _ econBytes 0 with
    | some (e, _) => e
    | none => default  -- Should not happen with valid data
  return ({
    storage := Dict.empty
    preimages := Dict.empty
    preimageInfo := Dict.empty
    econ
    codeHash
    minAccGas := UInt64.ofNat minAccGas
    minOnTransferGas := UInt64.ofNat minOnTransferGas
    itemCount := UInt32.ofNat accumCounter
    creationSlot := UInt32.ofNat lastAccumulation
    lastAccumulation := UInt32.ofNat lastActivity
    totalFootprint := totalFootprint
    parentServiceId := preimageCount
  }, s)

-- ============================================================================
-- Full State Deserialization
-- ============================================================================

/-- Deserialize state from key-value pairs (inverse of serializeState).
    Returns the State and a list of opaque service data KV pairs (storage,
    preimage data whose blake2b-hashed keys cannot be reversed). -/
def deserializeState (kvs : Array (ByteArray × ByteArray))
    : Option (State × Array (ByteArray × ByteArray)) := Id.run do
  let mut state : State := {
    authPool := #[]
    recent := { blocks := #[], accOutputBelt := #[] }
    accOutputs := #[]
    safrole := {
      pendingKeys := #[]
      ringRoot := default
      sealKeys := .fallback #[]
      ticketAccumulator := #[]
    }
    services := Dict.empty
    entropy := { current := default, previous := default,
                 twoBack := default, threeBack := default }
    pendingValidators := #[]
    currentValidators := #[]
    previousValidators := #[]
    pendingReports := #[]
    timeslot := 0
    authQueue := #[]
    privileged := {
      manager := 0
      assigners := #[]
      designator := 0
      registrar := 0
      alwaysAccumulate := Dict.empty
    }
    judgments := { good := #[], bad := #[], wonky := #[], offenders := #[] }
    statistics := {
      current := #[]
      previous := #[]
      coreStats := #[]
      serviceStats := Dict.empty
    }
    accQueue := #[]
    accHistory := #[]
  }

  let mut opaqueData : Array (ByteArray × ByteArray) := #[]
  let mut failed := false

  for (key, value) in kvs do
    if failed then break
    let key31 := if key.size >= 31 then key.extract 0 31
                 else key ++ ByteArray.mk (Array.replicate (31 - key.size) 0)
    match classifyKey key31 with
    | .component idx =>
      match idx.toNat with
      | 1 =>
        match Decoder.run (deserializeAuthPoolD C) value with
        | some pool => state := { state with authPool := pool }
        | none => failed := true
      | 2 =>
        match Decoder.run (deserializeAuthQueueD Q_QUEUE C) value with
        | some queue => state := { state with authQueue := queue }
        | none => failed := true
      | 3 =>
        match Decoder.run deserializeRecentBlocksD value with
        | some recent => state := { state with recent := recent }
        | none => failed := true
      | 4 =>
        match Decoder.run (deserializeSafroleD V E) value with
        | some saf => state := { state with safrole := saf }
        | none => failed := true
      | 5 =>
        match Decoder.run deserializeJudgmentsD value with
        | some j => state := { state with judgments := j }
        | none => failed := true
      | 6 =>
        if value.size < 128 then failed := true
        else state := { state with entropy := {
          current := Hash.mk! (value.extract 0 32)
          previous := Hash.mk! (value.extract 32 64)
          twoBack := Hash.mk! (value.extract 64 96)
          threeBack := Hash.mk! (value.extract 96 128)
        }}
      | 7 =>
        match Decoder.run (deserializeValidatorsD (value.size / 336)) value with
        | some vs => state := { state with pendingValidators := vs }
        | none => failed := true
      | 8 =>
        match Decoder.run (deserializeValidatorsD (value.size / 336)) value with
        | some vs => state := { state with currentValidators := vs }
        | none => failed := true
      | 9 =>
        match Decoder.run (deserializeValidatorsD (value.size / 336)) value with
        | some vs => state := { state with previousValidators := vs }
        | none => failed := true
      | 10 =>
        match Decoder.run (deserializePendingReportsD C) value with
        | some reps => state := { state with pendingReports := reps }
        | none => failed := true
      | 11 =>
        if value.size < 4 then failed := true
        else state := { state with
          timeslot := UInt32.ofNat (decodeFixedNat (value.extract 0 4)) }
      | 12 =>
        match Decoder.run (deserializePrivilegedD C) value with
        | some priv => state := { state with privileged := priv }
        | none => failed := true
      | 13 =>
        match Decoder.run (deserializeStatisticsD V C) value with
        | some stats => state := { state with statistics := stats }
        | none => failed := true
      | 14 =>
        match Decoder.run (deserializeAccumulationQueueD E) value with
        | some q => state := { state with accQueue := q }
        | none => failed := true
      | 15 =>
        match Decoder.run (deserializeAccumulationHistoryD E) value with
        | some h => state := { state with accHistory := h }
        | none => failed := true
      | 16 =>
        match Decoder.run deserializeAccumulationOutputsD value with
        | some out => state := { state with accOutputs := out }
        | none => failed := true
      | _ => pure ()
    | .serviceAccount sid =>
      match Decoder.run deserializeServiceAccountD value with
      | some acct => state := { state with services := state.services.insert sid acct }
      | none => failed := true
    | .serviceData =>
      opaqueData := opaqueData.push (key, value)

  if failed then return none
  return some (state, opaqueData)

-- ============================================================================
-- State Root Computation
-- ============================================================================

/-- Compute the state Merkle root M_sigma(sigma). GP Appendix D eq D.2. -/
def computeStateRoot (state : State) : Hash :=
  Jar.Merkle.trieRoot (serializeState state)

end Jar.StateSerialization
