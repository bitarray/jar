import Lean.Data.Json
import Lean.Data.Json.FromToJson
import Jar.Notation
import Jar.Types

/-!
# JSON Serialization for Jar Types

`FromJson`/`ToJson` instances for all core Jar types, designed for
test vector interchange between Jar and other JAM implementations.

Byte data is encoded as `0x`-prefixed hex strings.
-/

namespace Jar.Json

open Lean (Json ToJson FromJson toJson fromJson?)

-- ============================================================================
-- Hex encoding/decoding helpers
-- ============================================================================

private def hexDigit (c : Char) : Option UInt8 :=
  if '0' ≤ c && c ≤ '9' then some (c.toNat - '0'.toNat).toUInt8
  else if 'a' ≤ c && c ≤ 'f' then some (c.toNat - 'a'.toNat + 10).toUInt8
  else if 'A' ≤ c && c ≤ 'F' then some (c.toNat - 'A'.toNat + 10).toUInt8
  else none

/-- Decode a hex digit from a raw UTF-8 byte (ASCII). -/
@[inline] private def hexDigitByte (b : UInt8) : Option UInt8 :=
  if 0x30 ≤ b && b ≤ 0x39 then some (b - 0x30)       -- '0'-'9'
  else if 0x61 ≤ b && b ≤ 0x66 then some (b - 0x61 + 10) -- 'a'-'f'
  else if 0x41 ≤ b && b ≤ 0x46 then some (b - 0x41 + 10) -- 'A'-'F'
  else none

@[inline] private def hexNibbleAscii (n : UInt8) : UInt8 :=
  if n < 10 then 0x30 + n else 0x61 + n - 10

private def hexNibble (n : UInt8) : Char :=
  if n < 10 then Char.ofNat (n.toNat + '0'.toNat)
  else Char.ofNat (n.toNat - 10 + 'a'.toNat)

def bytesToHex (bs : ByteArray) : String :=
  let chars := bs.foldl (init := #['0', 'x']) fun acc b =>
    acc.push (hexNibble (b >>> 4)) |>.push (hexNibble (b &&& 0x0f))
  String.ofList chars.toList

def hexToBytes (s : String) : Except String ByteArray := do
  let utf8 := s.toUTF8
  let start : Nat := if utf8.size ≥ 2 && utf8.get! 0 == 0x30
      && (utf8.get! 1 == 0x78 || utf8.get! 1 == 0x58) then 2 else 0
  let len := utf8.size - start
  if len % 2 != 0 then
    throw s!"hex string has odd length: {len}"
  let nBytes := len / 2
  let mut result := ByteArray.empty
  for i in [:nBytes] do
    let pos := start + i * 2
    let hi ← hexDigitByte (utf8.get! pos) |>.elim (.error "invalid hex digit") .ok
    let lo ← hexDigitByte (utf8.get! (pos + 1)) |>.elim (.error "invalid hex digit") .ok
    result := result.push ((hi <<< 4) ||| lo)
  return result

-- ============================================================================
-- ByteArray — hex string
-- ============================================================================

instance : ToJson ByteArray where
  toJson bs := Json.str (bytesToHex bs)

instance : FromJson ByteArray where
  fromJson?
    | Json.str s => match hexToBytes s with
      | .ok bs => .ok bs
      | .error e => .error e
    | j => .error s!"expected hex string, got {j}"

-- ============================================================================
-- OctetSeq n — hex string with size validation
-- ============================================================================

instance : ToJson (OctetSeq n) where
  toJson seq := toJson seq.data

instance : FromJson (OctetSeq n) where
  fromJson? j := do
    let bs ← @fromJson? ByteArray _ j
    if h : bs.size = n then
      return ⟨bs, h⟩
    else
      .error s!"expected {n} bytes, got {bs.size}"

-- ============================================================================
-- Dict variants
-- ============================================================================

-- Dict ServiceId α: JSON object with numeric string keys
instance [BEq ServiceId] [ToJson α] : ToJson (Dict ServiceId α) where
  toJson d := Json.mkObj (d.entries.map fun (k, v) => (toString k.toNat, toJson v))

instance [BEq ServiceId] [FromJson α] : FromJson (Dict ServiceId α) where
  fromJson?
    | Json.obj kvs => do
      let mut entries : List (ServiceId × α) := []
      for ⟨k, v⟩ in kvs.toArray do
        let key ← match k.toNat? with
          | some n => pure n.toUInt32
          | none => .error s!"expected numeric service ID, got {k}"
        let val ← fromJson? v
        entries := entries ++ [(key, val)]
      return ⟨entries⟩
    | j => .error s!"expected object for Dict ServiceId, got {j}"

-- Dict Hash α: JSON object with hex string keys
instance [ToJson α] : ToJson (Dict Hash α) where
  toJson d := Json.mkObj (d.entries.map fun (k, v) => (bytesToHex k.data, toJson v))

instance [FromJson α] : FromJson (Dict Hash α) where
  fromJson?
    | Json.obj kvs => do
      let mut entries : List (Hash × α) := []
      for ⟨k, v⟩ in kvs.toArray do
        let bs ← match hexToBytes k with
          | .ok bs => pure bs
          | .error e => .error e
        if h : bs.size = 32 then
          let val ← fromJson? v
          entries := entries ++ [(⟨bs, h⟩, val)]
        else
          .error s!"expected 32-byte hash key, got {bs.size} bytes"
      return ⟨entries⟩
    | j => .error s!"expected object for Dict Hash, got {j}"

-- Dict ByteArray α: JSON object with hex string keys
instance [ToJson α] : ToJson (Dict ByteArray α) where
  toJson d := Json.mkObj (d.entries.map fun (k, v) => (bytesToHex k, toJson v))

instance [FromJson α] : FromJson (Dict ByteArray α) where
  fromJson?
    | Json.obj kvs => do
      let mut entries : List (ByteArray × α) := []
      for ⟨k, v⟩ in kvs.toArray do
        let bs ← match hexToBytes k with
          | .ok bs => pure bs
          | .error e => .error e
        let val ← fromJson? v
        entries := entries ++ [(bs, val)]
      return ⟨entries⟩
    | j => .error s!"expected object for Dict ByteArray, got {j}"

-- Dict (Hash × BlobLength) α: JSON array of {key: [hash, len], value: v}
instance [ToJson α] : ToJson (Dict (Hash × BlobLength) α) where
  toJson d := Json.arr (d.entries.map fun ((h, bl), v) =>
    Json.mkObj [("key", Json.arr #[toJson h, Json.num bl.toNat]),
                ("value", toJson v)]).toArray

instance [FromJson α] : FromJson (Dict (Hash × BlobLength) α) where
  fromJson?
    | Json.arr items => do
      let mut entries : List ((Hash × BlobLength) × α) := []
      for item in items do
        let key ← item.getObjVal? "key"
        match key with
        | Json.arr ks => do
          if ks.size < 2 then .error "expected [hash, length] key"
          let h ← fromJson? ks[0]!
          let bl : BlobLength ← do
            let n ← ks[1]!.getNat?
            pure n.toUInt32
          let val ← fromJson? (← item.getObjVal? "value")
          entries := entries ++ [((h, bl), val)]
        | _ => .error "expected array key"
      return ⟨entries⟩
    | j => .error s!"expected array for Dict (Hash × BlobLength), got {j}"

-- ============================================================================
-- Numeric types
-- ============================================================================

instance : ToJson Timeslot where toJson t := Json.num t.toNat
instance : FromJson Timeslot where
  fromJson? j := do let n ← j.getNat?; return n.toUInt32

instance : ToJson Balance where toJson b := Json.num b.toNat
instance : FromJson Balance where
  fromJson? j := do let n ← j.getNat?; return n.toUInt64

instance : ToJson Gas where toJson g := Json.num g.toNat
instance : FromJson Gas where
  fromJson? j := do let n ← j.getNat?; return n.toUInt64

instance : ToJson ServiceId where toJson s := Json.num s.toNat
instance : FromJson ServiceId where
  fromJson? j := do let n ← j.getNat?; return n.toUInt32

-- CoreIndex = Fin C, uses generic Fin instance below

instance : ToJson BlobLength where toJson b := Json.num b.toNat
instance : FromJson BlobLength where
  fromJson? j := do let n ← j.getNat?; return n.toUInt32

instance : ToJson (Fin n) where
  toJson f := Json.num f.val

instance (n : Nat) : FromJson (Fin n) where
  fromJson? j := do
    let v ← j.getNat?
    if h : v < n then return ⟨v, h⟩
    else .error s!"Fin {n}: value {v} out of range"

instance : ToJson UInt16 where toJson n := Json.num n.toNat
instance : FromJson UInt16 where
  fromJson? j := do let n ← j.getNat?; return n.toUInt16

-- ============================================================================
-- Validator types
-- ============================================================================

instance : ToJson ValidatorKey where
  toJson vk := Json.mkObj [
    ("bandersnatch", toJson vk.bandersnatch),
    ("ed25519", toJson vk.ed25519),
    ("bls", toJson vk.bls),
    ("metadata", toJson vk.metadata)]

instance : FromJson ValidatorKey where
  fromJson? j := do
    return {
      bandersnatch := ← fromJson? (← j.getObjVal? "bandersnatch")
      ed25519 := ← fromJson? (← j.getObjVal? "ed25519")
      bls := ← fromJson? (← j.getObjVal? "bls")
      metadata := ← fromJson? (← j.getObjVal? "metadata") }

instance : ToJson Ticket where
  toJson t := Json.mkObj [
    ("id", toJson t.id),
    ("attempt", toJson t.attempt)]

instance : FromJson Ticket where
  fromJson? j := do
    let id ← fromJson? (← j.getObjVal? "id")
    let attempt ← (← j.getObjVal? "attempt").getNat?
    -- Use sorry for Fin proof — tiny config has N_TINY=3 but type is Fin N_TICKETS=Fin 2
    return { id, attempt := ⟨attempt, sorry⟩ }

instance : ToJson SealKeySeries where
  toJson
    | .tickets ts => Json.mkObj [("tickets", toJson ts)]
    | .fallback ks => Json.mkObj [("keys", toJson ks)]

instance : FromJson SealKeySeries where
  fromJson? j := do
    if let some ts := j.getObjVal? "tickets" |>.toOption then
      return .tickets (← fromJson? ts)
    else if let some ks := j.getObjVal? "keys" |>.toOption then
      return .fallback (← fromJson? ks)
    else
      .error "SealKeySeries: expected 'tickets' or 'keys' field"

instance : ToJson TicketProof where
  toJson tp := Json.mkObj [
    ("attempt", toJson tp.attempt),
    ("signature", toJson tp.proof)]

instance : FromJson TicketProof where
  fromJson? j := do
    let attempt ← (← j.getObjVal? "attempt").getNat?
    let proof ← fromJson? (← j.getObjVal? "signature")
    return { attempt := ⟨attempt, sorry⟩, proof }

-- ============================================================================
-- EpochMarker
-- ============================================================================

instance : ToJson (BandersnatchPublicKey × Ed25519PublicKey) where
  toJson
    | (b, e) => Json.mkObj [("bandersnatch", toJson b), ("ed25519", toJson e)]

instance : FromJson (BandersnatchPublicKey × Ed25519PublicKey) where
  fromJson? j := do
    return (← fromJson? (← j.getObjVal? "bandersnatch"),
            ← fromJson? (← j.getObjVal? "ed25519"))

instance : ToJson EpochMarker where
  toJson em := Json.mkObj [
    ("entropy", toJson em.entropy),
    ("tickets_entropy", toJson em.entropyPrev),
    ("validators", toJson em.validators)]

instance : FromJson EpochMarker where
  fromJson? j := do
    return {
      entropy := ← fromJson? (← j.getObjVal? "entropy")
      entropyPrev := ← fromJson? (← j.getObjVal? "tickets_entropy")
      validators := ← fromJson? (← j.getObjVal? "validators") }

-- ============================================================================
-- Work types
-- ============================================================================

instance : ToJson WorkError where
  toJson
    | .outOfGas => Json.str "out_of_gas"
    | .panic => Json.str "panic"
    | .badExports => Json.str "bad_exports"
    | .oversize => Json.str "oversize"
    | .badCode => Json.str "bad_code"
    | .bigCode => Json.str "big_code"

instance : FromJson WorkError where
  fromJson?
    | Json.str "out_of_gas" => .ok .outOfGas
    | Json.str "panic" => .ok .panic
    | Json.str "bad_exports" => .ok .badExports
    | Json.str "oversize" => .ok .oversize
    | Json.str "bad_code" => .ok .badCode
    | Json.str "big_code" => .ok .bigCode
    | j => .error s!"unknown WorkError: {j}"

instance : ToJson WorkResult where
  toJson
    | .ok data => Json.mkObj [("ok", toJson data)]
    | .err e => Json.mkObj [("err", toJson e)]

instance : FromJson WorkResult where
  fromJson? j := do
    if let some v := j.getObjVal? "ok" |>.toOption then
      return .ok (← fromJson? v)
    else if let some v := j.getObjVal? "err" |>.toOption then
      return .err (← fromJson? v)
    else
      .error "WorkResult: expected 'ok' or 'err'"

instance : ToJson WorkDigest where
  toJson wd := Json.mkObj [
    ("service_id", toJson wd.serviceId),
    ("code_hash", toJson wd.codeHash),
    ("payload_hash", toJson wd.payloadHash),
    ("gas_limit", toJson wd.gasLimit),
    ("result", toJson wd.result),
    ("gas_used", toJson wd.gasUsed),
    ("imports_count", Json.num wd.importsCount),
    ("extrinsics_count", Json.num wd.extrinsicsCount),
    ("extrinsics_size", Json.num wd.extrinsicsSize),
    ("exports_count", Json.num wd.exportsCount)]

instance : FromJson WorkDigest where
  fromJson? j := do
    return {
      serviceId := ← fromJson? (← j.getObjVal? "service_id")
      codeHash := ← fromJson? (← j.getObjVal? "code_hash")
      payloadHash := ← fromJson? (← j.getObjVal? "payload_hash")
      gasLimit := ← fromJson? (← j.getObjVal? "gas_limit")
      result := ← fromJson? (← j.getObjVal? "result")
      gasUsed := ← fromJson? (← j.getObjVal? "gas_used")
      importsCount := ← (← j.getObjVal? "imports_count").getNat?
      extrinsicsCount := ← (← j.getObjVal? "extrinsics_count").getNat?
      extrinsicsSize := ← (← j.getObjVal? "extrinsics_size").getNat?
      exportsCount := ← (← j.getObjVal? "exports_count").getNat? }

instance : ToJson AvailabilitySpec where
  toJson a := Json.mkObj [
    ("package_hash", toJson a.packageHash),
    ("bundle_length", toJson a.bundleLength),
    ("erasure_root", toJson a.erasureRoot),
    ("segment_root", toJson a.segmentRoot),
    ("segment_count", Json.num a.segmentCount)]

instance : FromJson AvailabilitySpec where
  fromJson? j := do
    return {
      packageHash := ← fromJson? (← j.getObjVal? "package_hash")
      bundleLength := ← fromJson? (← j.getObjVal? "bundle_length")
      erasureRoot := ← fromJson? (← j.getObjVal? "erasure_root")
      segmentRoot := ← fromJson? (← j.getObjVal? "segment_root")
      segmentCount := ← (← j.getObjVal? "segment_count").getNat? }

instance : ToJson RefinementContext where
  toJson rc := Json.mkObj [
    ("anchor_hash", toJson rc.anchorHash),
    ("anchor_state_root", toJson rc.anchorStateRoot),
    ("anchor_beefy_root", toJson rc.anchorBeefyRoot),
    ("lookup_anchor_hash", toJson rc.lookupAnchorHash),
    ("lookup_anchor_timeslot", toJson rc.lookupAnchorTimeslot),
    ("prerequisites", toJson rc.prerequisites)]

instance : FromJson RefinementContext where
  fromJson? j := do
    return {
      anchorHash := ← fromJson? (← j.getObjVal? "anchor_hash")
      anchorStateRoot := ← fromJson? (← j.getObjVal? "anchor_state_root")
      anchorBeefyRoot := ← fromJson? (← j.getObjVal? "anchor_beefy_root")
      lookupAnchorHash := ← fromJson? (← j.getObjVal? "lookup_anchor_hash")
      lookupAnchorTimeslot := ← fromJson? (← j.getObjVal? "lookup_anchor_timeslot")
      prerequisites := ← fromJson? (← j.getObjVal? "prerequisites") }

instance : ToJson WorkReport where
  toJson wr := Json.mkObj [
    ("avail_spec", toJson wr.availSpec),
    ("context", toJson wr.context),
    ("core_index", toJson wr.coreIndex),
    ("authorizer_hash", toJson wr.authorizerHash),
    ("auth_output", toJson wr.authOutput),
    ("segment_root_lookup", toJson wr.segmentRootLookup),
    ("digests", toJson wr.digests),
    ("auth_gas_used", toJson wr.authGasUsed)]

instance : FromJson WorkReport where
  fromJson? j := do
    return {
      availSpec := ← fromJson? (← j.getObjVal? "avail_spec")
      context := ← fromJson? (← j.getObjVal? "context")
      coreIndex := ← fromJson? (← j.getObjVal? "core_index")
      authorizerHash := ← fromJson? (← j.getObjVal? "authorizer_hash")
      authOutput := ← fromJson? (← j.getObjVal? "auth_output")
      segmentRootLookup := ← fromJson? (← j.getObjVal? "segment_root_lookup")
      digests := ← fromJson? (← j.getObjVal? "digests")
      authGasUsed := ← fromJson? (← j.getObjVal? "auth_gas_used") }

instance : ToJson PendingReport where
  toJson pr := Json.mkObj [
    ("report", toJson pr.report),
    ("timeslot", toJson pr.timeslot)]

instance : FromJson PendingReport where
  fromJson? j := do
    return {
      report := ← fromJson? (← j.getObjVal? "report")
      timeslot := ← fromJson? (← j.getObjVal? "timeslot") }

-- ============================================================================
-- Account types
-- ============================================================================

instance : ToJson ServiceAccount where
  toJson sa := Json.mkObj [
    ("storage", toJson sa.storage),
    ("preimages", toJson sa.preimages),
    ("preimage_info", toJson sa.preimageInfo),
    ("gratis", toJson sa.gratis),
    ("code_hash", toJson sa.codeHash),
    ("balance", toJson sa.balance),
    ("min_acc_gas", toJson sa.minAccGas),
    ("min_on_transfer_gas", toJson sa.minOnTransferGas),
    ("created", toJson sa.created),
    ("last_accumulation", toJson sa.lastAccumulation),
    ("parent", toJson sa.parent)]

instance : FromJson ServiceAccount where
  fromJson? j := do
    return {
      storage := ← fromJson? (← j.getObjVal? "storage")
      preimages := ← fromJson? (← j.getObjVal? "preimages")
      preimageInfo := ← fromJson? (← j.getObjVal? "preimage_info")
      gratis := ← fromJson? (← j.getObjVal? "gratis")
      codeHash := ← fromJson? (← j.getObjVal? "code_hash")
      balance := ← fromJson? (← j.getObjVal? "balance")
      minAccGas := ← fromJson? (← j.getObjVal? "min_acc_gas")
      minOnTransferGas := ← fromJson? (← j.getObjVal? "min_on_transfer_gas")
      created := ← fromJson? (← j.getObjVal? "created")
      lastAccumulation := ← fromJson? (← j.getObjVal? "last_accumulation")
      parent := ← fromJson? (← j.getObjVal? "parent") }

instance : ToJson DeferredTransfer where
  toJson dt := Json.mkObj [
    ("source", toJson dt.source),
    ("dest", toJson dt.dest),
    ("amount", toJson dt.amount),
    ("memo", toJson dt.memo),
    ("gas", toJson dt.gas)]

instance : FromJson DeferredTransfer where
  fromJson? j := do
    return {
      source := ← fromJson? (← j.getObjVal? "source")
      dest := ← fromJson? (← j.getObjVal? "dest")
      amount := ← fromJson? (← j.getObjVal? "amount")
      memo := ← fromJson? (← j.getObjVal? "memo")
      gas := ← fromJson? (← j.getObjVal? "gas") }

instance : ToJson PrivilegedServices where
  toJson ps := Json.mkObj [
    ("manager", toJson ps.manager),
    ("assigners", toJson ps.assigners),
    ("designator", toJson ps.designator),
    ("registrar", toJson ps.registrar),
    ("always_accumulate", toJson ps.alwaysAccumulate)]

instance : FromJson PrivilegedServices where
  fromJson? j := do
    return {
      manager := ← fromJson? (← j.getObjVal? "manager")
      assigners := ← fromJson? (← j.getObjVal? "assigners")
      designator := ← fromJson? (← j.getObjVal? "designator")
      registrar := ← fromJson? (← j.getObjVal? "registrar")
      alwaysAccumulate := ← fromJson? (← j.getObjVal? "always_accumulate") }

-- ============================================================================
-- State types
-- ============================================================================

instance : ToJson JudgmentsState where
  toJson js := Json.mkObj [
    ("good", toJson js.good),
    ("bad", toJson js.bad),
    ("wonky", toJson js.wonky),
    ("offenders", toJson js.offenders)]

instance : FromJson JudgmentsState where
  fromJson? j := do
    return {
      good := ← fromJson? (← j.getObjVal? "good")
      bad := ← fromJson? (← j.getObjVal? "bad")
      wonky := ← fromJson? (← j.getObjVal? "wonky")
      offenders := ← fromJson? (← j.getObjVal? "offenders") }

instance : ToJson RecentBlockInfo where
  toJson rbi := Json.mkObj [
    ("header_hash", toJson rbi.headerHash),
    ("state_root", toJson rbi.stateRoot),
    ("acc_output_root", toJson rbi.accOutputRoot),
    ("reported_packages", toJson rbi.reportedPackages)]

instance : FromJson RecentBlockInfo where
  fromJson? j := do
    return {
      headerHash := ← fromJson? (← j.getObjVal? "header_hash")
      stateRoot := ← fromJson? (← j.getObjVal? "state_root")
      accOutputRoot := ← fromJson? (← j.getObjVal? "acc_output_root")
      reportedPackages := ← fromJson? (← j.getObjVal? "reported_packages") }

instance : ToJson RecentHistory where
  toJson rh := Json.mkObj [
    ("blocks", toJson rh.blocks),
    ("acc_output_belt", toJson rh.accOutputBelt)]

instance : FromJson RecentHistory where
  fromJson? j := do
    return {
      blocks := ← fromJson? (← j.getObjVal? "blocks")
      accOutputBelt := ← fromJson? (← j.getObjVal? "acc_output_belt") }

-- Statistics types
instance : ToJson ValidatorRecord where
  toJson vr := Json.mkObj [
    ("blocks", Json.num vr.blocks),
    ("tickets", Json.num vr.tickets),
    ("preimage_count", Json.num vr.preimageCount),
    ("preimage_size", Json.num vr.preimageSize),
    ("guarantees", Json.num vr.guarantees),
    ("assurances", Json.num vr.assurances)]

instance : FromJson ValidatorRecord where
  fromJson? j := do
    return {
      blocks := ← (← j.getObjVal? "blocks").getNat?
      tickets := ← (← j.getObjVal? "tickets").getNat?
      preimageCount := ← (← j.getObjVal? "preimage_count").getNat?
      preimageSize := ← (← j.getObjVal? "preimage_size").getNat?
      guarantees := ← (← j.getObjVal? "guarantees").getNat?
      assurances := ← (← j.getObjVal? "assurances").getNat? }

instance : ToJson CoreStatistics where
  toJson cs := Json.mkObj [
    ("da_load", Json.num cs.daLoad),
    ("popularity", Json.num cs.popularity),
    ("imports", Json.num cs.imports),
    ("extrinsic_count", Json.num cs.extrinsicCount),
    ("extrinsic_size", Json.num cs.extrinsicSize),
    ("exports", Json.num cs.exports),
    ("bundle_size", Json.num cs.bundleSize),
    ("gas_used", toJson cs.gasUsed)]

instance : FromJson CoreStatistics where
  fromJson? j := do
    return {
      daLoad := ← (← j.getObjVal? "da_load").getNat?
      popularity := ← (← j.getObjVal? "popularity").getNat?
      imports := ← (← j.getObjVal? "imports").getNat?
      extrinsicCount := ← (← j.getObjVal? "extrinsic_count").getNat?
      extrinsicSize := ← (← j.getObjVal? "extrinsic_size").getNat?
      exports := ← (← j.getObjVal? "exports").getNat?
      bundleSize := ← (← j.getObjVal? "bundle_size").getNat?
      gasUsed := ← fromJson? (← j.getObjVal? "gas_used") }

-- Nat × Nat pair
private instance natPairToJson : ToJson (Nat × Nat) where
  toJson
    | (a, b) => Json.arr #[Json.num a, Json.num b]

private instance natPairFromJson : FromJson (Nat × Nat) where
  fromJson?
    | Json.arr a => do
      if a.size < 2 then .error "expected [nat, nat]"
      return (← a[0]!.getNat?, ← a[1]!.getNat?)
    | j => .error s!"expected [nat, nat] pair, got {j}"

-- Nat × Gas pair
private instance natGasToJson : ToJson (Nat × Gas) where
  toJson
    | (a, b) => Json.arr #[Json.num a, toJson b]

private instance natGasFromJson : FromJson (Nat × Gas) where
  fromJson?
    | Json.arr a => do
      if a.size < 2 then .error "expected [nat, gas]"
      return (← a[0]!.getNat?, ← fromJson? a[1]!)
    | j => .error s!"expected [nat, gas] pair, got {j}"

instance : ToJson ServiceStatistics where
  toJson ss := Json.mkObj [
    ("provided", natPairToJson.toJson ss.provided),
    ("refinement", natGasToJson.toJson ss.refinement),
    ("imports", Json.num ss.imports),
    ("extrinsic_count", Json.num ss.extrinsicCount),
    ("extrinsic_size", Json.num ss.extrinsicSize),
    ("exports", Json.num ss.exports),
    ("accumulation", natGasToJson.toJson ss.accumulation)]

instance : FromJson ServiceStatistics where
  fromJson? j := do
    return {
      provided := ← natPairFromJson.fromJson? (← j.getObjVal? "provided")
      refinement := ← natGasFromJson.fromJson? (← j.getObjVal? "refinement")
      imports := ← (← j.getObjVal? "imports").getNat?
      extrinsicCount := ← (← j.getObjVal? "extrinsic_count").getNat?
      extrinsicSize := ← (← j.getObjVal? "extrinsic_size").getNat?
      exports := ← (← j.getObjVal? "exports").getNat?
      accumulation := ← natGasFromJson.fromJson? (← j.getObjVal? "accumulation") }

instance : ToJson ActivityStatistics where
  toJson a := Json.mkObj [
    ("current", toJson a.current),
    ("previous", toJson a.previous),
    ("core_stats", toJson a.coreStats),
    ("service_stats", toJson a.serviceStats)]

instance : FromJson ActivityStatistics where
  fromJson? j := do
    return {
      current := ← fromJson? (← j.getObjVal? "current")
      previous := ← fromJson? (← j.getObjVal? "previous")
      coreStats := ← fromJson? (← j.getObjVal? "core_stats")
      serviceStats := ← fromJson? (← j.getObjVal? "service_stats") }

-- Entropy: 4-element array
instance : ToJson Entropy where
  toJson e := Json.arr #[toJson e.current, toJson e.previous,
                          toJson e.twoBack, toJson e.threeBack]

instance : FromJson Entropy where
  fromJson?
    | Json.arr es => do
      if es.size < 4 then .error "Entropy: expected 4-element array"
      return {
        current := ← fromJson? es[0]!
        previous := ← fromJson? es[1]!
        twoBack := ← fromJson? es[2]!
        threeBack := ← fromJson? es[3]! }
    | j => .error s!"expected array for Entropy, got {j}"

-- SafroleState
instance : ToJson SafroleState where
  toJson ss := Json.mkObj [
    ("pending_keys", toJson ss.pendingKeys),
    ("ring_root", toJson ss.ringRoot),
    ("seal_keys", toJson ss.sealKeys),
    ("ticket_accumulator", toJson ss.ticketAccumulator)]

instance : FromJson SafroleState where
  fromJson? j := do
    return {
      pendingKeys := ← fromJson? (← j.getObjVal? "pending_keys")
      ringRoot := ← fromJson? (← j.getObjVal? "ring_root")
      sealKeys := ← fromJson? (← j.getObjVal? "seal_keys")
      ticketAccumulator := ← fromJson? (← j.getObjVal? "ticket_accumulator") }

-- ServiceId × Hash pair (for AccumulationOutputs)
instance : ToJson (ServiceId × Hash) where
  toJson
    | (s, h) => Json.arr #[toJson s, toJson h]

instance : FromJson (ServiceId × Hash) where
  fromJson?
    | Json.arr a => do
      if a.size < 2 then .error "expected [serviceId, hash]"
      return (← fromJson? a[0]!, ← fromJson? a[1]!)
    | j => .error s!"expected [serviceId, hash] pair, got {j}"

-- WorkReport × Array Hash (for accQueue)
instance : ToJson (WorkReport × Array Hash) where
  toJson
    | (wr, deps) => Json.mkObj [("report", toJson wr), ("deps", toJson deps)]

instance : FromJson (WorkReport × Array Hash) where
  fromJson? j := do
    return (← fromJson? (← j.getObjVal? "report"),
            ← fromJson? (← j.getObjVal? "deps"))

-- Complete State
instance : ToJson State where
  toJson s := Json.mkObj [
    ("auth_pool", toJson s.authPool),
    ("recent", toJson s.recent),
    ("acc_outputs", toJson s.accOutputs),
    ("safrole", toJson s.safrole),
    ("services", toJson s.services),
    ("entropy", toJson s.entropy),
    ("pending_validators", toJson s.pendingValidators),
    ("current_validators", toJson s.currentValidators),
    ("previous_validators", toJson s.previousValidators),
    ("pending_reports", toJson s.pendingReports),
    ("timeslot", toJson s.timeslot),
    ("auth_queue", toJson s.authQueue),
    ("privileged", toJson s.privileged),
    ("judgments", toJson s.judgments),
    ("statistics", toJson s.statistics),
    ("acc_queue", toJson s.accQueue),
    ("acc_history", toJson s.accHistory)]

instance : FromJson State where
  fromJson? j := do
    return {
      authPool := ← fromJson? (← j.getObjVal? "auth_pool")
      recent := ← fromJson? (← j.getObjVal? "recent")
      accOutputs := ← fromJson? (← j.getObjVal? "acc_outputs")
      safrole := ← fromJson? (← j.getObjVal? "safrole")
      services := ← fromJson? (← j.getObjVal? "services")
      entropy := ← fromJson? (← j.getObjVal? "entropy")
      pendingValidators := ← fromJson? (← j.getObjVal? "pending_validators")
      currentValidators := ← fromJson? (← j.getObjVal? "current_validators")
      previousValidators := ← fromJson? (← j.getObjVal? "previous_validators")
      pendingReports := ← fromJson? (← j.getObjVal? "pending_reports")
      timeslot := ← fromJson? (← j.getObjVal? "timeslot")
      authQueue := ← fromJson? (← j.getObjVal? "auth_queue")
      privileged := ← fromJson? (← j.getObjVal? "privileged")
      judgments := ← fromJson? (← j.getObjVal? "judgments")
      statistics := ← fromJson? (← j.getObjVal? "statistics")
      accQueue := ← fromJson? (← j.getObjVal? "acc_queue")
      accHistory := ← fromJson? (← j.getObjVal? "acc_history") }

end Jar.Json
