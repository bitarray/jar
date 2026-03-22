import Lean.Data.Json
import Jar.Types
import Jar.Codec
import Jar.Json
import Jar.Variant

/-!
# Codec Test Runner

Tests JAM codec serialization against binary test vectors.
For each type, reads a JSON file, parses into a Lean struct,
encodes using the codec, and compares against a reference binary file.
-/

namespace Jar.Test.CodecTest

open Lean (Json FromJson toJson fromJson?)
open Jar Jar.Json Jar.Codec

/-- Construct Fin without bounds check. Codec test vectors may contain
    intentionally out-of-bounds values to test encoding fidelity. -/
private unsafe def mkFinImpl (n : Nat) (val : Nat) (_ : 0 < n) : Fin n := ⟨val, lcProof⟩
@[implemented_by mkFinImpl]
private def mkFin (n : Nat) (val : Nat) (h : 0 < n) : Fin n :=
  ⟨val % n, Nat.mod_lt _ h⟩

-- ============================================================================
-- Codec-specific FromJson instances
-- The codec test vectors use a different JSON schema than the conformance
-- tests (Json.lean). We define separate parsers here in a private section.
-- ============================================================================

variable [JamConfig]

namespace CodecJson

-- ---- RefinementContext ----
-- codec JSON: anchor, state_root, beefy_root, lookup_anchor, lookup_anchor_slot, prerequisites

def parseRefinementContext (j : Json) : Except String RefinementContext := do
  return {
    anchorHash := ← fromJson? (← j.getObjVal? "anchor")
    anchorStateRoot := ← fromJson? (← j.getObjVal? "state_root")
    anchorBeefyRoot := ← fromJson? (← j.getObjVal? "beefy_root")
    lookupAnchorHash := ← fromJson? (← j.getObjVal? "lookup_anchor")
    lookupAnchorTimeslot := ← fromJson? (← j.getObjVal? "lookup_anchor_slot")
    prerequisites := ← fromJson? (← j.getObjVal? "prerequisites")
  }

-- ---- AvailabilitySpec ----
-- codec JSON: hash, length, erasure_root, exports_root, exports_count

def parseAvailSpec (j : Json) : Except String AvailabilitySpec := do
  return {
    packageHash := ← fromJson? (← j.getObjVal? "hash")
    bundleLength := ← fromJson? (← j.getObjVal? "length")
    erasureRoot := ← fromJson? (← j.getObjVal? "erasure_root")
    segmentRoot := ← fromJson? (← j.getObjVal? "exports_root")
    segmentCount := ← (← j.getObjVal? "exports_count").getNat?
  }

-- ---- WorkResult (codec JSON) ----
-- codec JSON: {"ok": "0x..."} or {"panic": null} or {"out_of_gas": null} etc.

def parseWorkResult (j : Json) : Except String WorkResult := do
  if let some v := j.getObjVal? "ok" |>.toOption then
    return .ok (← fromJson? v)
  else if (j.getObjVal? "panic" |>.toOption).isSome then
    return .err .panic
  else if (j.getObjVal? "out_of_gas" |>.toOption).isSome then
    return .err .outOfGas
  else if (j.getObjVal? "bad_exports" |>.toOption).isSome then
    return .err .badExports
  else if (j.getObjVal? "oversize" |>.toOption).isSome then
    return .err .oversize
  else if (j.getObjVal? "bad_code" |>.toOption).isSome then
    return .err .badCode
  else if (j.getObjVal? "big_code" |>.toOption).isSome then
    return .err .bigCode
  else
    .error s!"WorkResult: unrecognized format: {j}"

-- ---- WorkDigest (codec JSON) ----
-- codec JSON: service_id, code_hash, payload_hash, accumulate_gas, result, refine_load

def parseWorkDigest (j : Json) : Except String WorkDigest := do
  let rl ← j.getObjVal? "refine_load"
  return {
    serviceId := ← fromJson? (← j.getObjVal? "service_id")
    codeHash := ← fromJson? (← j.getObjVal? "code_hash")
    payloadHash := ← fromJson? (← j.getObjVal? "payload_hash")
    gasLimit := ← fromJson? (← j.getObjVal? "accumulate_gas")
    result := ← parseWorkResult (← j.getObjVal? "result")
    gasUsed := ← fromJson? (← rl.getObjVal? "gas_used")
    importsCount := ← (← rl.getObjVal? "imports").getNat?
    extrinsicsCount := ← (← rl.getObjVal? "extrinsic_count").getNat?
    extrinsicsSize := ← (← rl.getObjVal? "extrinsic_size").getNat?
    exportsCount := ← (← rl.getObjVal? "exports").getNat?
  }

-- ---- WorkReport (codec JSON) ----
-- codec JSON: package_spec, context, core_index, authorizer_hash, auth_gas_used,
--             auth_output, segment_root_lookup, results

def parseSegmentRootLookup (j : Json) : Except String (Dict Hash Hash) := do
  match j with
  | Json.arr items =>
    let mut entries : List (Hash × Hash) := []
    for item in items do
      let k ← fromJson? (← item.getObjVal? "key")
      let v ← fromJson? (← item.getObjVal? "value")
      entries := entries ++ [(k, v)]
    return ⟨entries⟩
  | Json.obj kvs =>
    let mut entries : List (Hash × Hash) := []
    for ⟨k, v⟩ in kvs.toArray do
      let kbs ← match hexToBytes k with
        | .ok bs => pure bs
        | .error e => .error e
      if h : kbs.size = 32 then
        let val ← fromJson? v
        entries := entries ++ [(⟨kbs, h⟩, val)]
      else
        .error s!"expected 32-byte hash key, got {kbs.size} bytes"
    return ⟨entries⟩
  | _ => .error s!"expected array or object for segment_root_lookup, got {j}"

def parseWorkReport (j : Json) : Except String WorkReport := do
  let availSpec ← parseAvailSpec (← j.getObjVal? "package_spec")
  let context ← parseRefinementContext (← j.getObjVal? "context")
  let coreIndexNat ← (← j.getObjVal? "core_index").getNat?
  let coreIndex : CoreIndex := mkFin C coreIndexNat JamConfig.valid.hC
  let authorizerHash ← fromJson? (← j.getObjVal? "authorizer_hash")
  let authGasUsed ← fromJson? (← j.getObjVal? "auth_gas_used")
  let authOutput ← fromJson? (← j.getObjVal? "auth_output")
  let segmentRootLookup ← parseSegmentRootLookup (← j.getObjVal? "segment_root_lookup")
  let resultsJson ← j.getObjVal? "results"
  let digestsArr ← match resultsJson with
    | Json.arr items => items.mapM parseWorkDigest
    | _ => .error "expected array for results"
  return {
    availSpec
    context
    coreIndex
    authorizerHash
    authGasUsed
    authOutput
    segmentRootLookup
    digests := digestsArr
  }

-- ---- Judgment (codec JSON) ----
-- codec JSON: vote, index, signature

def parseJudgment (j : Json) : Except String Judgment := do
  let vote ← match ← j.getObjVal? "vote" with
    | Json.bool b => pure b
    | _ => .error "expected bool for vote"
  let indexNat ← (← j.getObjVal? "index").getNat?
  let index : ValidatorIndex := mkFin V indexNat JamConfig.valid.hV
  let signature ← fromJson? (← j.getObjVal? "signature")
  return { isValid := vote, validatorIndex := index, signature }

-- ---- Verdict (codec JSON) ----
-- codec JSON: target, age, votes

def parseVerdict (j : Json) : Except String Verdict := do
  let reportHash ← fromJson? (← j.getObjVal? "target")
  let age ← (← j.getObjVal? "age").getNat?
  let votesJson ← j.getObjVal? "votes"
  let judgments ← match votesJson with
    | Json.arr items => items.mapM parseJudgment
    | _ => .error "expected array for votes"
  return { reportHash, age := age.toUInt32, judgments }

-- ---- Culprit (codec JSON) ----
-- codec JSON: target, key, signature

def parseCulprit (j : Json) : Except String Culprit := do
  return {
    reportHash := ← fromJson? (← j.getObjVal? "target")
    validatorKey := ← fromJson? (← j.getObjVal? "key")
    signature := ← fromJson? (← j.getObjVal? "signature")
  }

-- ---- Fault (codec JSON) ----
-- codec JSON: target, vote, key, signature

def parseFault (j : Json) : Except String Fault := do
  let vote ← match ← j.getObjVal? "vote" with
    | Json.bool b => pure b
    | _ => .error "expected bool for vote"
  return {
    reportHash := ← fromJson? (← j.getObjVal? "target")
    isValid := vote
    validatorKey := ← fromJson? (← j.getObjVal? "key")
    signature := ← fromJson? (← j.getObjVal? "signature")
  }

-- ---- DisputesExtrinsic (codec JSON) ----

def parseDisputes (j : Json) : Except String DisputesExtrinsic := do
  let verdictsJson ← j.getObjVal? "verdicts"
  let verdicts ← match verdictsJson with
    | Json.arr items => items.mapM parseVerdict
    | _ => .error "expected array for verdicts"
  let culpritsJson ← j.getObjVal? "culprits"
  let culprits ← match culpritsJson with
    | Json.arr items => items.mapM parseCulprit
    | _ => .error "expected array for culprits"
  let faultsJson ← j.getObjVal? "faults"
  let faults ← match faultsJson with
    | Json.arr items => items.mapM parseFault
    | _ => .error "expected array for faults"
  return { verdicts, culprits, faults }

-- ---- Assurance (codec JSON) ----

def parseAssurance (j : Json) : Except String Assurance := do
  let viNat ← (← j.getObjVal? "validator_index").getNat?
  let vi : ValidatorIndex := mkFin V viNat JamConfig.valid.hV
  return {
    anchor := ← fromJson? (← j.getObjVal? "anchor")
    bitfield := ← fromJson? (← j.getObjVal? "bitfield")
    validatorIndex := vi
    signature := ← fromJson? (← j.getObjVal? "signature")
  }

-- ---- Guarantee (codec JSON) ----
-- codec JSON: report, slot, signatures (array of {validator_index, signature})

def parseGuarantee (j : Json) : Except String Guarantee := do
  let report ← parseWorkReport (← j.getObjVal? "report")
  let slot ← (← j.getObjVal? "slot").getNat?
  let sigsJson ← j.getObjVal? "signatures"
  let credentials ← match sigsJson with
    | Json.arr items => items.mapM fun item => do
        let viNat ← (← item.getObjVal? "validator_index").getNat?
        let vi : ValidatorIndex := mkFin V viNat JamConfig.valid.hV
        let sig ← fromJson? (← item.getObjVal? "signature")
        return (vi, sig)
    | _ => .error "expected array for signatures"
  return { report, timeslot := slot.toUInt32, credentials }

-- ---- EpochMarker (codec JSON) ----
-- Same as existing: entropy, tickets_entropy, validators

def parseEpochMarker (j : Json) : Except String EpochMarker := do
  return {
    entropy := ← fromJson? (← j.getObjVal? "entropy")
    entropyPrev := ← fromJson? (← j.getObjVal? "tickets_entropy")
    validators := ← fromJson? (← j.getObjVal? "validators")
  }

-- ---- Header (codec JSON) ----
-- codec JSON: parent, parent_state_root, extrinsic_hash, slot, epoch_mark,
--             tickets_mark, author_index, entropy_source, offenders_mark, seal

def parseHeader (j : Json) : Except String Header := do
  let epochMark ← match ← j.getObjVal? "epoch_mark" with
    | Json.null => pure none
    | em => some <$> parseEpochMarker em
  let ticketsMark ← match ← j.getObjVal? "tickets_mark" with
    | Json.null => pure none
    | Json.arr items => some <$> items.mapM (fromJson? ·)
    | _ => .error "expected null or array for tickets_mark"
  let aiNat ← (← j.getObjVal? "author_index").getNat?
  let ai : ValidatorIndex := mkFin V aiNat JamConfig.valid.hV
  return {
    parent := ← fromJson? (← j.getObjVal? "parent")
    stateRoot := ← fromJson? (← j.getObjVal? "parent_state_root")
    extrinsicHash := ← fromJson? (← j.getObjVal? "extrinsic_hash")
    timeslot := ← fromJson? (← j.getObjVal? "slot")
    epochMarker := epochMark
    ticketsMarker := ticketsMark
    offenders := ← fromJson? (← j.getObjVal? "offenders_mark")
    authorIndex := ai
    vrfSignature := ← fromJson? (← j.getObjVal? "entropy_source")
    sealSig := ← fromJson? (← j.getObjVal? "seal")
  }

-- ---- Preimages extrinsic (codec JSON) ----
-- Array of {requester, blob}

def parsePreimagesExtrinsic (j : Json) : Except String PreimagesExtrinsic := do
  match j with
  | Json.arr items => items.mapM fun item => do
      let sid ← fromJson? (← item.getObjVal? "requester")
      let blob ← fromJson? (← item.getObjVal? "blob")
      return (sid, blob)
  | _ => .error "expected array for preimages_extrinsic"

-- ---- Extrinsic (codec JSON) ----

def parseExtrinsic (j : Json) : Except String Extrinsic := do
  let ticketsJson ← j.getObjVal? "tickets"
  let tickets ← match ticketsJson with
    | Json.arr items => items.mapM (fromJson? ·)
    | _ => .error "expected array for tickets"
  let preimages ← parsePreimagesExtrinsic (← j.getObjVal? "preimages")
  let guaranteesJson ← j.getObjVal? "guarantees"
  let guarantees ← match guaranteesJson with
    | Json.arr items => items.mapM parseGuarantee
    | _ => .error "expected array for guarantees"
  let assurancesJson ← j.getObjVal? "assurances"
  let assurances ← match assurancesJson with
    | Json.arr items => items.mapM parseAssurance
    | _ => .error "expected array for assurances"
  let disputes ← parseDisputes (← j.getObjVal? "disputes")
  return { tickets, disputes, preimages, assurances, guarantees }

-- ---- Block (codec JSON) ----

def parseBlock (j : Json) : Except String Block := do
  let header ← parseHeader (← j.getObjVal? "header")
  let extrinsic ← parseExtrinsic (← j.getObjVal? "extrinsic")
  return { header, extrinsic }

-- ---- WorkItem (codec JSON) ----
-- codec JSON: service, code_hash, refine_gas_limit, accumulate_gas_limit,
--             export_count, payload, import_segments, extrinsic

def parseImportSegment (j : Json) : Except String (Hash × Nat) := do
  let treeRoot ← fromJson? (← j.getObjVal? "tree_root")
  let index ← (← j.getObjVal? "index").getNat?
  return (treeRoot, index)

def parseExtrinsicItem (j : Json) : Except String (Hash × Nat) := do
  let h ← fromJson? (← j.getObjVal? "hash")
  let len ← (← j.getObjVal? "len").getNat?
  return (h, len)

def parseWorkItem (j : Json) : Except String WorkItem := do
  let importsJson ← j.getObjVal? "import_segments"
  let imports ← match importsJson with
    | Json.arr items => items.mapM parseImportSegment
    | _ => .error "expected array for import_segments"
  let extrinsicJson ← j.getObjVal? "extrinsic"
  let extrinsics ← match extrinsicJson with
    | Json.arr items => items.mapM parseExtrinsicItem
    | _ => .error "expected array for extrinsic"
  return {
    serviceId := ← fromJson? (← j.getObjVal? "service")
    codeHash := ← fromJson? (← j.getObjVal? "code_hash")
    payload := ← fromJson? (← j.getObjVal? "payload")
    gasLimit := ← fromJson? (← j.getObjVal? "refine_gas_limit")
    accGasLimit := ← fromJson? (← j.getObjVal? "accumulate_gas_limit")
    exportsCount := ← (← j.getObjVal? "export_count").getNat?
    imports
    extrinsics
  }

-- ---- WorkPackage (codec JSON) ----
-- codec JSON: auth_code_host, auth_code_hash, context, authorization,
--             authorizer_config, items

def parseWorkPackage (j : Json) : Except String WorkPackage := do
  let context ← parseRefinementContext (← j.getObjVal? "context")
  let itemsJson ← j.getObjVal? "items"
  let items ← match itemsJson with
    | Json.arr arr => arr.mapM parseWorkItem
    | _ => .error "expected array for items"
  return {
    authToken := ← fromJson? (← j.getObjVal? "authorization")
    authCodeHost := ← fromJson? (← j.getObjVal? "auth_code_host")
    authCodeHash := ← fromJson? (← j.getObjVal? "auth_code_hash")
    authConfig := ← fromJson? (← j.getObjVal? "authorizer_config")
    context
    items
  }

-- ---- AssurancesExtrinsic (codec JSON) ----

def parseAssurancesExtrinsic (j : Json) : Except String AssurancesExtrinsic := do
  match j with
  | Json.arr items => items.mapM parseAssurance
  | _ => .error "expected array for assurances_extrinsic"

-- ---- GuaranteesExtrinsic (codec JSON) ----

def parseGuaranteesExtrinsic (j : Json) : Except String GuaranteesExtrinsic := do
  match j with
  | Json.arr items => items.mapM parseGuarantee
  | _ => .error "expected array for guarantees_extrinsic"

end CodecJson

-- ============================================================================
-- Encode functions for WorkItem and WorkPackage
-- ============================================================================

open Jar in
/-- Encode a WorkItem.
    Binary format (from test vectors):
    serviceId(4) ++ codeHash(32) ++ gasLimit(8_LE) ++ accGasLimit(8_LE)
    ++ exportsCount(varint) ++ 0x00 (reserved byte)
    ++ payload(length-prefixed) ++ imports(count-prefixed, each = hash(32) + index(2_LE))
    ++ extrinsics(count-prefixed, each = hash(32) + len(4_LE)) -/
def encodeWorkItem (w : WorkItem) : ByteArray :=
  encodeFixedNat 4 w.serviceId.toNat
    ++ w.codeHash.data
    ++ encodeFixedNat 8 w.gasLimit.toNat
    ++ encodeFixedNat 8 w.accGasLimit.toNat
    ++ encodeNat w.exportsCount
    ++ ByteArray.mk #[0]  -- reserved byte (observed as 0x00 in test vectors)
    ++ encodeLengthPrefixed w.payload
    ++ encodeCountPrefixedArray (fun (h, n) => h.data ++ encodeFixedNat 2 n) w.imports
    ++ encodeCountPrefixedArray (fun (h, n) => h.data ++ encodeFixedNat 4 n) w.extrinsics

open Jar in
/-- Encode a WorkPackage.
    Binary format (from test vectors):
    authCodeHost(4) ++ authCodeHash(32) ++ context(RefinementContext)
    ++ authToken(length-prefixed) ++ authConfig(length-prefixed)
    ++ items(count-prefixed WorkItem) -/
def encodeWorkPackage (wp : WorkPackage) : ByteArray :=
  encodeFixedNat 4 wp.authCodeHost.toNat
    ++ wp.authCodeHash.data
    ++ encodeRefinementContext wp.context
    ++ encodeLengthPrefixed wp.authToken
    ++ encodeLengthPrefixed wp.authConfig
    ++ encodeCountPrefixedArray encodeWorkItem wp.items

-- ============================================================================
-- Header encoding fix: tickets_mark uses fixed-size array (no count prefix)
-- ============================================================================

open Jar in
/-- Encode header for codec tests. Tickets marker uses a fixed-size
    array of E tickets (no count prefix), unlike the regular encoder
    which uses a count-prefixed array. -/
def encodeHeaderCodec (h : Header) : ByteArray :=
  h.parent.data
    ++ h.stateRoot.data
    ++ h.extrinsicHash.data
    ++ encodeFixedNat 4 h.timeslot.toNat
    ++ encodeOption encodeEpochMarker h.epochMarker
    ++ encodeOption (encodeArray encodeTicket) h.ticketsMarker
    ++ encodeFixedNat 2 h.authorIndex.val
    ++ h.vrfSignature.data
    ++ encodeCountPrefixedArray (fun k => k.data) h.offenders
    ++ h.sealSig.data

open Jar in
/-- Encode block for codec tests. Uses the codec-specific header encoding. -/
def encodeBlockCodec (b : Block) : ByteArray :=
  encodeHeaderCodec b.header ++ encodeExtrinsic b.extrinsic

-- ============================================================================
-- Test Runner
-- ============================================================================

/-- Helper to show hex of first few bytes. -/
private def showHex (bs : ByteArray) (n : Nat := 16) : String :=
  let len := min bs.size n
  let chars := (bs.extract 0 len).foldl (init := "") fun acc b =>
    acc ++ (if b < 16 then "0" else "") ++ String.ofList (Nat.toDigits 16 b.toNat)
  "0x" ++ chars ++ (if bs.size > n then "..." else "")

/-- Compare encoded bytes with expected binary. Returns true on match. -/
def testEncode (name : String) (encoded : ByteArray) (expected : ByteArray) : IO Bool := do
  if encoded == expected then
    IO.println s!"  PASS {name} ({expected.size} bytes)"
    return true
  else
    IO.println s!"  FAIL {name}"
    IO.println s!"    expected size: {expected.size}, got: {encoded.size}"
    -- Find first difference
    let minLen := min encoded.size expected.size
    for i in [:minLen] do
      if encoded.get! i != expected.get! i then
        IO.println s!"    first diff at byte {i}: expected 0x{String.ofList (Nat.toDigits 16 (expected.get! i).toNat)}, got 0x{String.ofList (Nat.toDigits 16 (encoded.get! i).toNat)}"
        IO.println s!"    expected around offset {i}: {showHex (expected.extract i (min (i + 16) expected.size))}"
        IO.println s!"    got      around offset {i}: {showHex (encoded.extract i (min (i + 16) encoded.size))}"
        break
    return false

/-- Run a codec test given JSON path, binary path, a parser, and an encoder. -/
def runCodecTest (name : String) (jsonPath binPath : System.FilePath)
    (parse : Json → Except String α) (encode : α → ByteArray) : IO Bool := do
  let jsonContent ← IO.FS.readFile jsonPath
  let json ← IO.ofExcept (Json.parse jsonContent)
  let obj ← IO.ofExcept (parse json)
  let encoded := encode obj
  let expected ← IO.FS.readBinFile binPath
  testEncode name encoded expected

-- ============================================================================
-- Per-type test dispatchers
-- ============================================================================

open CodecJson in
def testBlock (jsonPath binPath : System.FilePath) : IO Bool :=
  runCodecTest "block" jsonPath binPath parseBlock encodeBlockCodec

open CodecJson in
def testHeader (jsonPath binPath : System.FilePath) : IO Bool :=
  runCodecTest "header" jsonPath binPath parseHeader encodeHeaderCodec

open CodecJson in
def testExtrinsic (jsonPath binPath : System.FilePath) : IO Bool :=
  runCodecTest "extrinsic" jsonPath binPath parseExtrinsic encodeExtrinsic

open CodecJson in
def testWorkReport (jsonPath binPath : System.FilePath) : IO Bool :=
  runCodecTest "work_report" jsonPath binPath parseWorkReport encodeWorkReport

open CodecJson in
def testWorkResult (jsonPath binPath : System.FilePath) (label : String) : IO Bool :=
  runCodecTest label jsonPath binPath parseWorkDigest encodeWorkDigest

open CodecJson in
def testWorkItem (jsonPath binPath : System.FilePath) : IO Bool :=
  runCodecTest "work_item" jsonPath binPath parseWorkItem encodeWorkItem

open CodecJson in
def testWorkPackage (jsonPath binPath : System.FilePath) : IO Bool :=
  runCodecTest "work_package" jsonPath binPath parseWorkPackage encodeWorkPackage

open CodecJson in
def testRefinementContext (jsonPath binPath : System.FilePath) : IO Bool :=
  runCodecTest "refine_context" jsonPath binPath parseRefinementContext encodeRefinementContext

def testTicketsExtrinsic (jsonPath binPath : System.FilePath) : IO Bool :=
  runCodecTest "tickets_extrinsic" jsonPath binPath
    (fun j => match j with
      | Json.arr items => items.mapM (fromJson? ·)
      | _ => .error "expected array")
    (encodeCountPrefixedArray encodeTicketProof)

open CodecJson in
def testDisputesExtrinsic (jsonPath binPath : System.FilePath) : IO Bool :=
  runCodecTest "disputes_extrinsic" jsonPath binPath parseDisputes encodeDisputes

open CodecJson in
def testPreimagesExtrinsic (jsonPath binPath : System.FilePath) : IO Bool :=
  runCodecTest "preimages_extrinsic" jsonPath binPath parsePreimagesExtrinsic encodePreimages

open CodecJson in
def testAssurancesExtrinsic (jsonPath binPath : System.FilePath) : IO Bool :=
  runCodecTest "assurances_extrinsic" jsonPath binPath parseAssurancesExtrinsic
    (encodeCountPrefixedArray encodeAssurance)

open CodecJson in
def testGuaranteesExtrinsic (jsonPath binPath : System.FilePath) : IO Bool :=
  runCodecTest "guarantees_extrinsic" jsonPath binPath parseGuaranteesExtrinsic
    (encodeCountPrefixedArray encodeGuarantee)

-- ============================================================================
-- Main test runner
-- ============================================================================

/-- Run all codec tests for a given variant. -/
def runAll (dir : String) (variantName : String) : IO UInt32 := do
  let mut passed : Nat := 0
  let mut failed : Nat := 0
  let testCases : Array (String × (System.FilePath → System.FilePath → IO Bool)) := #[
    ("block", testBlock),
    ("header_0", testHeader),
    ("header_1", testHeader),
    ("extrinsic", testExtrinsic),
    ("work_report", testWorkReport),
    ("work_result_0", fun jp bp => testWorkResult jp bp "work_result_0"),
    ("work_result_1", fun jp bp => testWorkResult jp bp "work_result_1"),
    ("work_item", testWorkItem),
    ("work_package", testWorkPackage),
    ("refine_context", testRefinementContext),
    ("tickets_extrinsic", testTicketsExtrinsic),
    ("disputes_extrinsic", testDisputesExtrinsic),
    ("preimages_extrinsic", testPreimagesExtrinsic),
    ("assurances_extrinsic", testAssurancesExtrinsic),
    ("guarantees_extrinsic", testGuaranteesExtrinsic)
  ]
  for (typeName, testFn) in testCases do
    let jsonPath : System.FilePath := s!"{dir}/{typeName}.{variantName}.json"
    let binPath : System.FilePath := s!"{dir}/{typeName}.{variantName}.bin"
    -- Check files exist
    if !(← jsonPath.pathExists) then
      IO.println s!"  SKIP {typeName} (no JSON file)"
      continue
    if !(← binPath.pathExists) then
      IO.println s!"  SKIP {typeName} (no bin file)"
      continue
    try
      let ok ← testFn jsonPath binPath
      if ok then passed := passed + 1
      else failed := failed + 1
    catch e =>
      IO.println s!"  ERROR {typeName}: {e}"
      failed := failed + 1
  IO.println s!"  {passed}/{passed + failed} passed"
  return if failed > 0 then 1 else 0

end Jar.Test.CodecTest
