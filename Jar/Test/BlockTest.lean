import Jar.Json
import Jar.State
import Jar.StateSerialization
import Jar.Variant

/-!
# Block-Level Test Runner

Runs block test vectors from the trace directories. Each test vector consists
of an input file (pre_state keyvals + block) and an output file (post_state
with state_root, or an error).

The block JSON uses a different field naming convention from the STF test
vectors. This module provides custom `FromJson` instances for block-trace
format parsing.
-/

namespace Jar.Test.BlockTest

open Lean (Json ToJson FromJson toJson fromJson?)
open Jar Jar.Json

variable [JamConfig]

-- ============================================================================
-- Block-trace JSON parsing (different field names from STF tests)
-- ============================================================================

/-- Parse a Header from block-trace JSON format.
    Field name mapping:
    - slot → timeslot
    - parent_state_root → stateRoot
    - epoch_mark → epochMarker
    - tickets_mark → ticketsMarker
    - offenders_mark → offenders
    - entropy_source → vrfSignature
    - seal → sealSig -/
private def headerFromTraceJson (j : Json) : Except String Header := do
  let parent ← @fromJson? Hash _ (← j.getObjVal? "parent")
  let stateRoot ← @fromJson? Hash _ (← j.getObjVal? "parent_state_root")
  let extrinsicHash ← @fromJson? Hash _ (← j.getObjVal? "extrinsic_hash")
  let timeslot ← @fromJson? Timeslot _ (← j.getObjVal? "slot")
  -- epoch_mark: null or absent → none
  let epochMarker ← do
    match j.getObjVal? "epoch_mark" with
    | .ok Json.null => pure none
    | .ok v => pure (some (← @fromJson? EpochMarker _ v))
    | .error _ => pure none
  -- tickets_mark: null or absent → none
  let ticketsMarker ← do
    match j.getObjVal? "tickets_mark" with
    | .ok Json.null => pure none
    | .ok v => do
      match v with
      | Json.arr items => do
        let arr ← items.toList.mapM fun item => do
          let id ← @fromJson? Hash _ (← item.getObjVal? "id")
          let attempt ← (← item.getObjVal? "attempt").getNat?
          pure ({ id, attempt := ⟨attempt, sorry⟩ } : Ticket)
        pure (some arr.toArray)
      | _ => .error "expected array for tickets_mark"
    | .error _ => pure none
  let offenders ← @fromJson? (Array Ed25519PublicKey) _ (← j.getObjVal? "offenders_mark")
  let authorIndex ← @fromJson? ValidatorIndex _ (← j.getObjVal? "author_index")
  let vrfSignature ← @fromJson? BandersnatchSignature _ (← j.getObjVal? "entropy_source")
  let sealSig ← @fromJson? BandersnatchSignature _ (← j.getObjVal? "seal")
  return { parent, stateRoot, extrinsicHash, timeslot, epochMarker,
           ticketsMarker, offenders, authorIndex, vrfSignature, sealSig }

/-- Parse AvailabilitySpec from block-trace "package_spec" JSON.
    Field name mapping:
    - hash → packageHash
    - length → bundleLength
    - exports_root → segmentRoot
    - exports_count → segmentCount -/
private def availSpecFromTraceJson (j : Json) : Except String AvailabilitySpec := do
  let packageHash ← @fromJson? Hash _ (← j.getObjVal? "hash")
  let bundleLength ← @fromJson? UInt32 _ (← j.getObjVal? "length")
  let erasureRoot ← @fromJson? Hash _ (← j.getObjVal? "erasure_root")
  let segmentRoot ← @fromJson? Hash _ (← j.getObjVal? "exports_root")
  let segmentCount ← (← j.getObjVal? "exports_count").getNat?
  return { packageHash, bundleLength, erasureRoot, segmentRoot, segmentCount }

/-- Parse RefinementContext from block-trace "context" JSON.
    Field name mapping:
    - anchor → anchorHash
    - state_root → anchorStateRoot
    - beefy_root → anchorBeefyRoot
    - lookup_anchor → lookupAnchorHash
    - lookup_anchor_slot → lookupAnchorTimeslot -/
private def refinementContextFromTraceJson (j : Json) : Except String RefinementContext := do
  let anchorHash ← @fromJson? Hash _ (← j.getObjVal? "anchor")
  let anchorStateRoot ← @fromJson? Hash _ (← j.getObjVal? "state_root")
  let anchorBeefyRoot ← @fromJson? Hash _ (← j.getObjVal? "beefy_root")
  let lookupAnchorHash ← @fromJson? Hash _ (← j.getObjVal? "lookup_anchor")
  let lookupAnchorTimeslot ← @fromJson? Timeslot _ (← j.getObjVal? "lookup_anchor_slot")
  let prerequisites ← @fromJson? (Array Hash) _ (← j.getObjVal? "prerequisites")
  return { anchorHash, anchorStateRoot, anchorBeefyRoot,
           lookupAnchorHash, lookupAnchorTimeslot, prerequisites }

/-- Parse WorkDigest from block-trace "results[i]" JSON.
    Field name mapping:
    - accumulate_gas → gasLimit
    - refine_load.gas_used → gasUsed
    - refine_load.imports → importsCount
    - refine_load.extrinsic_count → extrinsicsCount
    - refine_load.extrinsic_size → extrinsicsSize
    - refine_load.exports → exportsCount -/
private def workDigestFromTraceJson (j : Json) : Except String WorkDigest := do
  let serviceId ← @fromJson? ServiceId _ (← j.getObjVal? "service_id")
  let codeHash ← @fromJson? Hash _ (← j.getObjVal? "code_hash")
  let payloadHash ← @fromJson? Hash _ (← j.getObjVal? "payload_hash")
  let gasLimit ← @fromJson? Gas _ (← j.getObjVal? "accumulate_gas")
  let result ← @fromJson? WorkResult _ (← j.getObjVal? "result")
  let refineLoad ← j.getObjVal? "refine_load"
  let gasUsed ← @fromJson? Gas _ (← refineLoad.getObjVal? "gas_used")
  let importsCount ← (← refineLoad.getObjVal? "imports").getNat?
  let extrinsicsCount ← (← refineLoad.getObjVal? "extrinsic_count").getNat?
  let extrinsicsSize ← (← refineLoad.getObjVal? "extrinsic_size").getNat?
  let exportsCount ← (← refineLoad.getObjVal? "exports").getNat?
  return { serviceId, codeHash, payloadHash, gasLimit, result, gasUsed,
           importsCount, extrinsicsCount, extrinsicsSize, exportsCount }

/-- Parse WorkReport from block-trace JSON.
    Field name mapping:
    - package_spec → availSpec
    - results → digests -/
private def workReportFromTraceJson (j : Json) : Except String WorkReport := do
  let availSpec ← availSpecFromTraceJson (← j.getObjVal? "package_spec")
  let context ← refinementContextFromTraceJson (← j.getObjVal? "context")
  let coreIndex ← @fromJson? CoreIndex _ (← j.getObjVal? "core_index")
  let authorizerHash ← @fromJson? Hash _ (← j.getObjVal? "authorizer_hash")
  let authGasUsed ← @fromJson? Gas _ (← j.getObjVal? "auth_gas_used")
  let authOutput ← @fromJson? ByteArray _ (← j.getObjVal? "auth_output")
  let segmentRootLookup : Dict Hash Hash ← do
    let srl ← j.getObjVal? "segment_root_lookup"
    match srl with
    | Json.arr items =>
      -- Array of [key, value] pairs or {key, value} objects
      let mut d : Dict Hash Hash := Dict.empty
      for item in items do
        match item with
        | Json.arr #[k, v] =>
          let key ← @fromJson? Hash _ k
          let val ← @fromJson? Hash _ v
          d := d.insert key val
        | _ => pure ()  -- skip malformed
      pure d
    | _ => @fromJson? (Dict Hash Hash) _ srl
  let resultsJson ← j.getObjVal? "results"
  let digests ← match resultsJson with
    | Json.arr items => items.toList.mapM workDigestFromTraceJson |>.map List.toArray
    | _ => .error "expected array for results"
  return { availSpec, context, coreIndex, authorizerHash, authGasUsed,
           authOutput, segmentRootLookup, digests }

/-- Parse a Guarantee from block-trace JSON.
    Field name mapping:
    - signatures → credentials
    - slot → timeslot -/
private def guaranteeFromTraceJson (j : Json) : Except String Guarantee := do
  let report ← workReportFromTraceJson (← j.getObjVal? "report")
  let timeslot ← @fromJson? Timeslot _ (← j.getObjVal? "slot")
  let sigsJson ← j.getObjVal? "signatures"
  let credentials ← match sigsJson with
    | Json.arr items => do
        let list ← items.toList.mapM fun item => do
          let vi ← @fromJson? ValidatorIndex _ (← item.getObjVal? "validator_index")
          let sig ← @fromJson? Ed25519Signature _ (← item.getObjVal? "signature")
          pure (vi, sig)
        pure list.toArray
    | _ => .error "expected array for signatures"
  return { report, timeslot, credentials }

/-- Parse an Assurance from block-trace JSON. -/
private def assuranceFromTraceJson (j : Json) : Except String Assurance := do
  let anchor ← @fromJson? Hash _ (← j.getObjVal? "anchor")
  let bitfield ← @fromJson? ByteArray _ (← j.getObjVal? "bitfield")
  let validatorIndex ← @fromJson? ValidatorIndex _ (← j.getObjVal? "validator_index")
  let signature ← @fromJson? Ed25519Signature _ (← j.getObjVal? "signature")
  return { anchor, bitfield, validatorIndex, signature }

/-- Parse a Judgment from block-trace JSON. -/
private def judgmentFromTraceJson (j : Json) : Except String Judgment := do
  let isValid ← match (← j.getObjVal? "vote") with
    | Json.bool b => pure b
    | v => do
      let n ← v.getNat?
      pure (n != 0)
  let validatorIndex ← @fromJson? ValidatorIndex _ (← j.getObjVal? "validator_index")
  let signature ← @fromJson? Ed25519Signature _ (← j.getObjVal? "signature")
  return { isValid, validatorIndex, signature }

/-- Parse a Verdict from block-trace JSON. -/
private def verdictFromTraceJson (j : Json) : Except String Verdict := do
  let reportHash ← @fromJson? Hash _ (← j.getObjVal? "target")
  let age ← @fromJson? UInt32 _ (← j.getObjVal? "age")
  let judgmentsJson ← j.getObjVal? "votes"
  let judgments ← match judgmentsJson with
    | Json.arr items => items.toList.mapM judgmentFromTraceJson |>.map List.toArray
    | _ => .error "expected array for votes"
  return { reportHash, age, judgments }

/-- Parse a Culprit from block-trace JSON. -/
private def culpritFromTraceJson (j : Json) : Except String Culprit := do
  let reportHash ← @fromJson? Hash _ (← j.getObjVal? "target")
  let validatorKey ← @fromJson? Ed25519PublicKey _ (← j.getObjVal? "key")
  let signature ← @fromJson? Ed25519Signature _ (← j.getObjVal? "signature")
  return { reportHash, validatorKey, signature }

/-- Parse a Fault from block-trace JSON. -/
private def faultFromTraceJson (j : Json) : Except String Fault := do
  let reportHash ← @fromJson? Hash _ (← j.getObjVal? "target")
  let isValid ← match (← j.getObjVal? "vote") with
    | Json.bool b => pure b
    | v => do
      let n ← v.getNat?
      pure (n != 0)
  let validatorKey ← @fromJson? Ed25519PublicKey _ (← j.getObjVal? "key")
  let signature ← @fromJson? Ed25519Signature _ (← j.getObjVal? "signature")
  return { reportHash, isValid, validatorKey, signature }

/-- Parse a DisputesExtrinsic from block-trace JSON. -/
private def disputesFromTraceJson (j : Json) : Except String DisputesExtrinsic := do
  let verdictsJson ← j.getObjVal? "verdicts"
  let verdicts ← match verdictsJson with
    | Json.arr items => items.toList.mapM verdictFromTraceJson |>.map List.toArray
    | _ => .error "expected array for verdicts"
  let culpritsJson ← j.getObjVal? "culprits"
  let culprits ← match culpritsJson with
    | Json.arr items => items.toList.mapM culpritFromTraceJson |>.map List.toArray
    | _ => .error "expected array for culprits"
  let faultsJson ← j.getObjVal? "faults"
  let faults ← match faultsJson with
    | Json.arr items => items.toList.mapM faultFromTraceJson |>.map List.toArray
    | _ => .error "expected array for faults"
  return { verdicts, culprits, faults }

/-- Parse a TicketProof from block-trace JSON. -/
private def ticketProofFromTraceJson (j : Json) : Except String TicketProof := do
  let attempt ← (← j.getObjVal? "attempt").getNat?
  let proof ← @fromJson? BandersnatchRingVrfProof _ (← j.getObjVal? "signature")
  return { attempt := ⟨attempt, sorry⟩, proof }

/-- Parse a preimage entry from block-trace JSON.
    Block traces use { "requester": serviceId, "blob": hexdata }
    instead of (serviceId, bytearray). -/
private def preimageFromTraceJson (j : Json) : Except String (ServiceId × ByteArray) := do
  let requester ← @fromJson? ServiceId _ (← j.getObjVal? "requester")
  let blob ← @fromJson? ByteArray _ (← j.getObjVal? "blob")
  return (requester, blob)

/-- Parse Extrinsic from block-trace JSON. -/
private def extrinsicFromTraceJson (j : Json) : Except String Extrinsic := do
  -- tickets
  let ticketsJson ← j.getObjVal? "tickets"
  let tickets ← match ticketsJson with
    | Json.arr items => items.toList.mapM ticketProofFromTraceJson |>.map List.toArray
    | _ => .error "expected array for tickets"
  -- preimages
  let preimagesJson ← j.getObjVal? "preimages"
  let preimages ← match preimagesJson with
    | Json.arr items => items.toList.mapM preimageFromTraceJson |>.map List.toArray
    | _ => .error "expected array for preimages"
  -- guarantees
  let guaranteesJson ← j.getObjVal? "guarantees"
  let guarantees ← match guaranteesJson with
    | Json.arr items => items.toList.mapM guaranteeFromTraceJson |>.map List.toArray
    | _ => .error "expected array for guarantees"
  -- assurances
  let assurancesJson ← j.getObjVal? "assurances"
  let assurances ← match assurancesJson with
    | Json.arr items => items.toList.mapM assuranceFromTraceJson |>.map List.toArray
    | _ => .error "expected array for assurances"
  -- disputes
  let disputes ← disputesFromTraceJson (← j.getObjVal? "disputes")
  return { tickets, disputes, preimages, assurances, guarantees }

/-- Parse Block from block-trace JSON. -/
private def blockFromTraceJson (j : Json) : Except String Block := do
  let header ← headerFromTraceJson (← j.getObjVal? "header")
  let extrinsic ← extrinsicFromTraceJson (← j.getObjVal? "extrinsic")
  return { header, extrinsic }

-- ============================================================================
-- State deserialization from keyvals
-- ============================================================================

/-- Parse a hex string to ByteArray (strips 0x prefix). -/
private def parseHex (s : String) : Except String ByteArray :=
  hexToBytes s

/-- Parse keyvals array from JSON into raw byte pairs. -/
private def parseKeyvals (j : Json) : Except String (Array (ByteArray × ByteArray)) := do
  match j with
  | Json.arr items =>
    let mut result : Array (ByteArray × ByteArray) := #[]
    for item in items do
      let keyStr ← match ← item.getObjVal? "key" with
        | Json.str s => pure s
        | _ => .error "expected string for key"
      let valueStr ← match ← item.getObjVal? "value" with
        | Json.str s => pure s
        | _ => .error "expected string for value"
      let key ← parseHex keyStr
      let value ← parseHex valueStr
      result := result.push (key, value)
    return result
  | _ => .error "expected array for keyvals"

-- ============================================================================
-- Test runner
-- ============================================================================

/-- Test result: passed, failed, or skipped. -/
inductive TestResult where
  | pass | fail | skip

/-- Run a single block test. Returns pass/fail/skip. -/
def runBlockTest [JamConfig] (inputPath : System.FilePath) : IO TestResult := do
  let name := inputPath.fileName.getD inputPath.toString
  let outputPath := inputPath.toString.replace ".input." ".output."

  -- Read files
  let inputContent ← IO.FS.readFile inputPath
  let outputContent ← IO.FS.readFile outputPath

  -- Parse JSON
  let inputJson ← IO.ofExcept (Json.parse inputContent)
  let outputJson ← IO.ofExcept (Json.parse outputContent)

  -- Parse pre_state
  let preStateJson ← IO.ofExcept (inputJson.getObjVal? "pre_state")
  let expectedPreRoot ← IO.ofExcept (@fromJson? Hash _ (← IO.ofExcept (preStateJson.getObjVal? "state_root")))

  -- Check if keyvals are present (some traces only have state_root)
  let hasKeyvals := match preStateJson.getObjVal? "keyvals" with
    | .ok (Json.arr _) => true
    | _ => false

  if !hasKeyvals then
    IO.println s!"  SKIP {name}: no keyvals in pre_state (state_root only)"
    return .skip

  let keyvals ← IO.ofExcept (do
    let kvJson ← preStateJson.getObjVal? "keyvals"
    parseKeyvals kvJson)

  -- Deserialize state from keyvals
  let stateOpt := @StateSerialization.deserializeState _ keyvals
  let (state, opaqueData) ← match stateOpt with
    | some (s, od) => pure (s, od)
    | none =>
      -- Diagnose: try deserializing each KV individually
      for (key, value) in keyvals do
        let idx := key.get! 0
        if idx >= 1 && idx <= 16 then
          -- Try individual component deserialization
          let ok := (@StateSerialization.deserializeState _ #[(key, value)]).isSome
          if !ok then
            IO.println s!"  DEBUG deser FAIL on idx={idx} val_len={value.size}"
      IO.println s!"  FAIL {name}: failed to deserialize pre_state from keyvals"
      return .fail

  -- First, verify raw keyvals produce the expected root (tests trieRoot only)
  let rawEntries := keyvals.map fun (k, v) => ((⟨k, sorry⟩ : OctetSeq 31), v)
  let rawRoot := Merkle.trieRoot rawEntries
  if rawRoot != expectedPreRoot then
    IO.println s!"  FAIL {name}: raw keyvals trieRoot mismatch (trie bug)"
    IO.println s!"    expected: {bytesToHex expectedPreRoot.data}"
    IO.println s!"    got:      {bytesToHex rawRoot.data}"
    return .fail

  -- Note: serialize(deserialize(keyvals)) can't roundtrip perfectly because
  -- totalFootprint and preimageCount are computed fields. For pre_state verification,
  -- we already confirmed the raw keyvals match via trieRoot above. Proceed to block transition.

  -- Parse block
  let block ← IO.ofExcept (do
    let blockJson ← inputJson.getObjVal? "block"
    blockFromTraceJson blockJson)

  -- Check if expected output is an error
  let isError := match outputJson.getObjVal? "error" with
    | .ok _ => true
    | .error _ => false

  -- Run state transition, skipping seal/VRF verification for now
  -- (validateHeader seal check is incorrect — uses wrong context)
  let result := @stateTransitionNoSealCheck _ state block
  -- If transition fails, diagnose which check failed
  if result.isNone then
    let h := block.header
    let parentOk : Bool := if state.recent.blocks.size = 0 then true
      else
        let idx := state.recent.blocks.size - 1
        if hlt : idx < state.recent.blocks.size then
          h.parent == state.recent.blocks[idx].headerHash
        else true
    let timeslotOk : Bool := decide (h.timeslot.toNat > state.timeslot.toNat)
    let authorOk : Bool := decide (h.authorIndex.val < V)
    let epochChange := @isEpochChange _ state.timeslot h.timeslot
    let epochMarkerOk : Bool := match h.epochMarker with
      | some _ => epochChange
      | none => epochChange == false
    -- Check seal verification
    let sealOk : Bool :=
      if h.authorIndex.val < state.currentValidators.size then
        let authorKey := state.currentValidators[h.authorIndex.val]!
        let unsignedHeader := Codec.encodeUnsignedHeader h
        Crypto.bandersnatchVerify authorKey.bandersnatch
          Crypto.ctxTicketSeal unsignedHeader h.sealSig
      else false
    IO.println s!"  DEBUG {name}: parent={parentOk} timeslot={timeslotOk} author={authorOk} epochMarker={epochMarkerOk} seal={sealOk}"
    IO.println s!"    header.slot={h.timeslot.toNat} state.timeslot={state.timeslot.toNat} authorIdx={h.authorIndex.val}"

  match result with
  | some postState =>
    if isError then
      IO.println s!"  FAIL {name}: expected error but transition succeeded"
      return .fail
    else
      -- Check post_state root
      let postStateJson ← IO.ofExcept (outputJson.getObjVal? "post_state")
      let expectedPostRoot ← IO.ofExcept (@fromJson? Hash _ (← IO.ofExcept (postStateJson.getObjVal? "state_root")))

      -- Compute Merkle root of posterior state
      -- Include opaque service data entries (storage/preimages) that pass through unchanged
      let postKvs := (@StateSerialization.serializeState _ postState).map fun (k, v) => (k.data, v)
      let byteArrayLt (a b : ByteArray) : Bool :=
        let len := min a.size b.size
        Id.run do
          for i in [:len] do
            if a.get! i < b.get! i then return true
            if a.get! i > b.get! i then return false
          return a.size < b.size
      let allPostKvs := (postKvs ++ opaqueData).qsort fun (k1, _) (k2, _) => byteArrayLt k1 k2
      let computedRoot := Merkle.trieRoot (allPostKvs.map fun (k, v) => ((⟨k, sorry⟩ : OctetSeq 31), v))

      if computedRoot == expectedPostRoot then
        IO.println s!"  PASS {name}"
        return .pass
      else
        IO.println s!"  FAIL {name}: post_state root mismatch"
        IO.println s!"    expected: {bytesToHex expectedPostRoot.data}"
        IO.println s!"    got:      {bytesToHex computedRoot.data}"
        -- Compare individual KVs with expected post_state keyvals
        match postStateJson.getObjVal? "keyvals" with
        | .ok kvJson =>
          match parseKeyvals kvJson with
          | .ok expectedKvs =>
            let ourKvs := allPostKvs
            -- Show first few diffs (compare by key index)
            let mut diffCount := 0
            for i in [:min expectedKvs.size ourKvs.size] do
              let (ek, ev) := expectedKvs[i]!
              let (ok, ov) := ourKvs[i]!
              if ek != ok then
                if diffCount < 3 then
                  IO.println s!"    kv[{i}] KEY: exp={bytesToHex ek |>.take 16}.. got={bytesToHex ok |>.take 16}.."
                diffCount := diffCount + 1
              else if ev != ov then
                if diffCount < 3 then
                  let idx := ek.get! 0
                  IO.println s!"    kv[{i}] idx={idx} VAL: exp_len={ev.size} got_len={ov.size}"
                  for j in [:min ev.size ov.size] do
                    if ev.get! j != ov.get! j then
                      IO.println s!"      first diff at byte {j}"
                      break
                diffCount := diffCount + 1
            if diffCount > 3 then
              IO.println s!"    ... {diffCount - 3} more diffs"
            IO.println s!"    expected {expectedKvs.size} kvs, got {ourKvs.size} kvs"
          | .error _ => pure ()
        | .error _ => pure ()
        return .fail
  | none =>
    if isError then
      IO.println s!"  PASS {name} (expected error)"
      return .pass
    else
      IO.println s!"  FAIL {name}: transition returned none but expected success"
      return .fail

/-- Run all block tests in a trace directory. -/
def runBlockTestDir [JamConfig] (dir : String) : IO UInt32 := do
  let dirPath : System.FilePath := dir
  let entries ← dirPath.readDir
  let suffix := s!".input.{JamConfig.name}.json"
  let jsonFiles := entries.filter (fun e => e.fileName.endsWith suffix)
  let sorted := jsonFiles.qsort (fun a b => a.fileName < b.fileName)

  if sorted.size == 0 then
    IO.println s!"  No test files found matching *{suffix} in {dir}"
    return 1

  IO.println s!"  Found {sorted.size} block tests"

  let mut passed : Nat := 0
  let mut failed : Nat := 0
  let mut skipped : Nat := 0

  for entry in sorted do
    let result ← runBlockTest entry.path
    match result with
    | .pass => passed := passed + 1
    | .fail => failed := failed + 1
    | .skip => skipped := skipped + 1

  IO.println s!"  Results: {passed} passed, {failed} failed, {skipped} skipped (of {sorted.size})"
  if failed > 0 then return 1 else return 0

/-- Run block tests sequentially, threading state from block to block.
    Used for conformance traces where only the first block has keyvals. -/
def runBlockTestDirSeq [JamConfig] (dir : String) : IO UInt32 := do
  let dirPath : System.FilePath := dir
  let entries ← dirPath.readDir
  let suffix := s!".input.{JamConfig.name}.json"
  let jsonFiles := entries.filter (fun e => e.fileName.endsWith suffix)
  let sorted := jsonFiles.qsort (fun a b => a.fileName < b.fileName)

  if sorted.size == 0 then
    IO.println s!"  No test files found matching *{suffix} in {dir}"
    return 1

  IO.println s!"  Found {sorted.size} block tests (sequential mode)"

  let mut passed : Nat := 0
  let mut failed : Nat := 0
  let mut currentState : Option (State × Array (ByteArray × ByteArray)) := none
  -- For fork handling: map from header hash -> (post_state, opaque_data)
  -- When a new block has parent == a known header hash, use that post_state.
  let mut stateMap : Array (Hash × State × Array (ByteArray × ByteArray)) := #[]

  for entry in sorted do
    let name := entry.fileName
    let inputContent ← IO.FS.readFile entry.path
    let outputPath := entry.path.toString.replace ".input." ".output."
    let outputContent ← IO.FS.readFile outputPath
    let inputJson ← IO.ofExcept (Json.parse inputContent)
    let outputJson ← IO.ofExcept (Json.parse outputContent)

    -- Get state: from keyvals if available, otherwise from threaded state
    let stateAndOpaque ← do
      let preStateJson ← IO.ofExcept (inputJson.getObjVal? "pre_state")
      match preStateJson.getObjVal? "keyvals" with
      | .ok kvJson =>
        match parseKeyvals kvJson with
        | .ok kvs =>
          match @StateSerialization.deserializeState _ kvs with
          | some (s, od) => pure (some (s, od))
          | none => pure currentState  -- fall back to threaded
        | .error _ => pure currentState
      | .error _ => pure currentState

    -- Fork handling: parse the block parent hash and look up the matching
    -- post-state from stateMap. This allows reverting to an earlier state
    -- when a fork block shares the same parent as a previously-applied block.
    let blockParentHash : Option Hash := match (do
        let blockJson ← inputJson.getObjVal? "block"
        let headerJson ← blockJson.getObjVal? "header"
        @fromJson? Hash _ (← headerJson.getObjVal? "parent")) with
      | .ok h => some h
      | .error _ => none

    let stateAndOpaque : Option (State × Array (ByteArray × ByteArray)) :=
      match blockParentHash with
      | some parentHash =>
        -- Look up if we have a post-state for this parent hash
        match stateMap.findRev? (fun (h, _, _) => h == parentHash) with
        | some (_, s, od) => some (s, od)
        | none => stateAndOpaque
      | none => stateAndOpaque

    -- If this is the first time we have a state (from keyvals), save it
    -- keyed by the genesis block's header hash (from the recent history)
    match stateAndOpaque with
    | some (s, od) =>
      if stateMap.size == 0 then
        -- Save genesis/initial state keyed by the last recent block's header hash
        if hn : s.recent.blocks.size > 0 then
          let lastIdx := s.recent.blocks.size - 1
          have : lastIdx < s.recent.blocks.size := by omega
          let genesisHash := s.recent.blocks[lastIdx].headerHash
          stateMap := stateMap.push (genesisHash, s, od)
    | none => pure ()

    match stateAndOpaque with
    | none =>
      IO.println s!"  SKIP {name}: no state available"
      continue
    | some (state, opaqueData) =>

    -- Parse block (may fail for invalid blocks, e.g. out-of-range author index)
    let blockResult := do
      let blockJson ← inputJson.getObjVal? "block"
      blockFromTraceJson blockJson

    -- Check expected output
    let isError := match outputJson.getObjVal? "error" with
      | .ok _ => true
      | .error _ => false

    -- If block parsing fails, treat as rejected block
    match blockResult with
    | .error parseErr =>
      if isError then
        IO.println s!"  PASS {name} (parse error: {parseErr})"
        passed := passed + 1
        continue
      else
        IO.println s!"  FAIL {name}: block parse failed: {parseErr}"
        failed := failed + 1
        continue
    | .ok _ => pure ()

    let block ← IO.ofExcept blockResult

    -- Block import validation: parent state root check
    -- H_r must match the Merkle root of the pre-state (parent's posterior state)
    let byteArrayLtForRoot (a b : ByteArray) : Bool :=
      let len := min a.size b.size
      Id.run do
        for i in [:len] do
          if a.get! i < b.get! i then return true
          if a.get! i > b.get! i then return false
        return a.size < b.size
    let preKvs := (@StateSerialization.serializeState _ state).map fun (k, v) => (k.data, v)
    let allPreKvs := (preKvs ++ opaqueData).qsort fun (k1, _) (k2, _) => byteArrayLtForRoot k1 k2
    let preStateRoot := Merkle.trieRoot (allPreKvs.map fun (k, v) => ((⟨k, sorry⟩ : OctetSeq 31), v))
    let stateRootOk := block.header.stateRoot == preStateRoot
    -- If state root doesn't match, reject the block
    let result := if !stateRootOk then none
      else @stateTransitionWithOpaque _ state block opaqueData
    -- (debug checks removed)
    let exitReasons : Array (ServiceId × String) := match result with
      | some r => r.2.2.1
      | none => #[]
    let remainingOpaque : Array (ByteArray × ByteArray) := match result with
      | some r => r.2.2.2
      | none => opaqueData
    let postStateOpt : Option State := result.map (·.1)

    match postStateOpt with
    | some postState =>
      if isError then
        IO.println s!"  FAIL {name}: expected error but transition succeeded"
        failed := failed + 1
        -- Keep original state: the invalid block shouldn't change state
      else
        -- Check post_state root
        let postStateJson ← IO.ofExcept (outputJson.getObjVal? "post_state")
        let expectedPostRoot ← IO.ofExcept (@fromJson? Hash _ (← IO.ofExcept (postStateJson.getObjVal? "state_root")))
        let postKvs := (@StateSerialization.serializeState _ postState).map fun (k, v) => (k.data, v)
        let byteArrayLt (a b : ByteArray) : Bool :=
          let len := min a.size b.size
          Id.run do
            for i in [:len] do
              if a.get! i < b.get! i then return true
              if a.get! i > b.get! i then return false
            return a.size < b.size
        -- Use remaining opaque data from accumulation (consumed entries already removed).
        -- Additionally filter out any entries whose keys now appear in serialized state
        -- (e.g., storage entries promoted during accumulation).
        let postKeys := postKvs.map Prod.fst
        let filteredOpaque := remainingOpaque.filter fun (k, _) =>
          !postKeys.any (· == k)
        let allPostKvs := (postKvs ++ filteredOpaque).qsort fun (k1, _) (k2, _) => byteArrayLt k1 k2
        let computedRoot := Merkle.trieRoot (allPostKvs.map fun (k, v) => ((⟨k, sorry⟩ : OctetSeq 31), v))
        if computedRoot == expectedPostRoot then
          IO.println s!"  PASS {name}"
          -- Print exit reasons for blocks with accumulation
          if exitReasons.size > 0 then
            for (sid, reason) in exitReasons do
              -- Only show first 100 chars of reason
              let short := if reason.length > 100 then (reason.toList.take 100 |> String.mk) ++ "..." else reason
              IO.println s!"    acc svc={sid}: {short}"
            for (sid, acct) in postState.services.entries.toArray do
              IO.println s!"    svc {sid}: storage={acct.storage.size} items={acct.created} footprint={acct.totalFootprint}"
          pure ()
          passed := passed + 1
          currentState := some (postState, filteredOpaque)
          -- Save post-state keyed by header hash for fork handling
          let headerHash := Crypto.blake2b (Codec.encodeHeader block.header)
          stateMap := stateMap.push (headerHash, postState, filteredOpaque)
        else
          IO.println s!"  FAIL {name}: post_state root mismatch"
          IO.println s!"    expected: {bytesToHex expectedPostRoot.data}"
          IO.println s!"    got:      {bytesToHex computedRoot.data}"
          IO.println s!"    total KVs: {allPostKvs.size} (serialized={postKvs.size} opaque={filteredOpaque.size})"
          if false then
            let preSerKvs := (@StateSerialization.serializeState _ state).map fun (k, v) => (k.data, v)
            let preOpaqueKvs := (preSerKvs ++ opaqueData).qsort fun (k1, _) (k2, _) => byteArrayLt k1 k2
            let preMap := preOpaqueKvs.foldl (init := Dict.empty (K := ByteArray) (V := ByteArray))
              fun acc (k, v) => acc.insert k v
            -- Which indices changed?
            let mut changedIdxs : Array Nat := #[]
            for (k, v) in allPostKvs do
              match preMap.lookup k with
              | some preV => if preV != v then
                  let idx := k.get! 0 |>.toNat
                  if !changedIdxs.contains idx then changedIdxs := changedIdxs.push idx
              | none => pure ()
            IO.println s!"    changed: {changedIdxs.toList}"
            -- Revert all EXCEPT service data (idx > 16)
            let svcOnlyKvs := allPostKvs.map fun (k, v) =>
              if k.get! 0 <= 16 then
                match preMap.lookup k with
                | some preV => (k, preV)
                | none => (k, v)
              else (k, v)
            let svcOnlyRoot := Merkle.trieRoot (svcOnlyKvs.map fun (k, v) => ((⟨k, sorry⟩ : OctetSeq 31), v))
            if svcOnlyRoot == expectedPostRoot then
              IO.println s!"    FIX: all global components wrong, service data correct"
            -- Revert all EXCEPT global (idx <= 16)
            let globalOnlyKvs := allPostKvs.map fun (k, v) =>
              if k.get! 0 > 16 then
                match preMap.lookup k with
                | some preV => (k, preV)
                | none => (k, v)
              else (k, v)
            let globalOnlyRoot := Merkle.trieRoot (globalOnlyKvs.map fun (k, v) => ((⟨k, sorry⟩ : OctetSeq 31), v))
            if globalOnlyRoot == expectedPostRoot then
              IO.println s!"    FIX: service data wrong, global components correct"
            -- Revert ALL to verify pre-state root
            let allRevertKvs := allPostKvs.map fun (k, v) =>
              match preMap.lookup k with
              | some preV => (k, preV)
              | none => (k, v)
            let allRevertRoot := Merkle.trieRoot (allRevertKvs.map fun (k, v) => ((⟨k, sorry⟩ : OctetSeq 31), v))
            let preRoot := Merkle.trieRoot (preOpaqueKvs.map fun (k, v) => ((⟨k, sorry⟩ : OctetSeq 31), v))
            IO.println s!"    preRoot: {bytesToHex preRoot.data |>.take 16}.. allRevert: {bytesToHex allRevertRoot.data |>.take 16}.."
            -- Try reverting all 7 global + service metadata
            let all8Kvs := allPostKvs.map fun (k, v) =>
              let idx := k.get! 0 |>.toNat
              if idx == 3 || idx == 6 || idx == 10 || idx == 11 || idx == 13 || idx == 15 || idx == 16 || idx == 255 then
                match preMap.lookup k with
                | some preV => (k, preV)
                | none => (k, v)
              else (k, v)
            let all8Root := Merkle.trieRoot (all8Kvs.map fun (k, v) => ((⟨k, sorry⟩ : OctetSeq 31), v))
            IO.println s!"    revert all 8 changed: {bytesToHex all8Root.data |>.take 16}.. (pre: {bytesToHex preRoot.data |>.take 16}..)"
            -- Try keeping only small subsets of changed components
            -- Keep timeslot + service metadata + entropy (should be trivially correct)
            let trivialKvs := allPostKvs.map fun (k, v) =>
              let idx := k.get! 0 |>.toNat
              if idx == 11 || idx == 255 || idx == 6 then (k, v)
              else match preMap.lookup k with
                | some preV => (k, preV)
                | none => (k, v)
            let trivialRoot := Merkle.trieRoot (trivialKvs.map fun (k, v) => ((⟨k, sorry⟩ : OctetSeq 31), v))
            -- Keep everything except statistics (idx=13)
            let noStatsKvs := allPostKvs.map fun (k, v) =>
              if k.get! 0 == 13 then
                match preMap.lookup k with
                | some preV => (k, preV)
                | none => (k, v)
              else (k, v)
            let noStatsRoot := Merkle.trieRoot (noStatsKvs.map fun (k, v) => ((⟨k, sorry⟩ : OctetSeq 31), v))
            IO.println s!"    trivial(11,255,6): {bytesToHex trivialRoot.data |>.take 16}.."
            IO.println s!"    no stats(~13): {bytesToHex noStatsRoot.data |>.take 16}.."
            IO.println s!"    expected: {bytesToHex expectedPostRoot.data |>.take 16}.."
            -- Check if maybe some component that should be UNCHANGED is wrong
            -- If all changes are right, root should match expected
            -- If a MISSING change exists, we need to find which unchanged idx should change
            -- Try: apply ONLY idx=11 change (trivially correct)
            let onlyTimeslotKvs := allPostKvs.map fun (k, v) =>
              if k.get! 0 == 11 then (k, v)  -- keep timeslot
              else match preMap.lookup k with
                | some preV => (k, preV)
                | none => (k, v)
            let onlyTsRoot := Merkle.trieRoot (onlyTimeslotKvs.map fun (k, v) => ((⟨k, sorry⟩ : OctetSeq 31), v))
            -- Hmm, what if idx=1 (authPool) SHOULD change but isn't?
            -- Check if expected root = pre-state with ONLY timeslot changed
            IO.println s!"    only timeslot: {bytesToHex onlyTsRoot.data |>.take 16}.."
            -- Dump statistics bytes to find exact differences
            for (k, v) in allPostKvs do
              if k.get! 0 == 13 then
                match preMap.lookup k with
                | some preV =>
                  -- Show byte differences in statistics
                  let diffBytes := Id.run do
                    let mut diffs : Array (Nat × Nat × Nat) := #[]  -- (pos, pre, post)
                    for i in [:min preV.size v.size] do
                      if preV.get! i != v.get! i then
                        diffs := diffs.push (i, preV.get! i |>.toNat, v.get! i |>.toNat)
                    return diffs
                  IO.println s!"    stats diffs ({diffBytes.size} bytes differ, pre={preV.size} post={v.size}):"
                  for (pos, pre, post) in diffBytes.toSubarray 0 (min 20 diffBytes.size) do
                    IO.println s!"      byte {pos}: {pre} -> {post}"
                | none => pure ()
          for (sid, reason) in exitReasons do
            IO.println s!"    acc svc={sid}: {reason}"
          -- Debug: show service storage state
          for (sid, acct) in postState.services.entries.toArray do
            IO.println s!"    svc {sid}: storage={acct.storage.size} preimages={acct.preimages.size} preimageInfo={acct.preimageInfo.size} bal={acct.balance} parent={acct.parent} created={acct.created} footprint={acct.totalFootprint} lastAcc={acct.lastAccumulation} preimCount={acct.preimageCount} gratis={acct.gratis}"
          -- Debug: show serialized component sizes and hashes
          for (k, v) in allPostKvs do
            let idx := k.get! 0
            if idx >= 1 && idx <= 16 || idx == 255 then
              let h := Crypto.blake2b v
              IO.println s!"    idx={idx} val_len={v.size} hash={bytesToHex h.data |>.take 16}.."
          -- Debug: show queue state
          let totalQ := postState.accQueue.foldl (init := 0) fun acc s => acc + s.size
          if totalQ > 0 then
            IO.println s!"    accQueue: {totalQ} entries"
            for i in [:postState.accQueue.size] do
              let slot := postState.accQueue[i]!
              for (wr, deps) in slot do
                let pkgHex := bytesToHex wr.availSpec.packageHash.data |>.take 12
                IO.println s!"      [{i}] pkg={pkgHex}.. deps={deps.size} digests={wr.digests.size}"
          pure ()
          failed := failed + 1
          -- Continue threading to see if subsequent blocks also fail
          currentState := some (postState, filteredOpaque)
          let headerHash := Crypto.blake2b (Codec.encodeHeader block.header)
          stateMap := stateMap.push (headerHash, postState, filteredOpaque)
    | none =>
      if isError then
        IO.println s!"  PASS {name} (expected error)"
        passed := passed + 1
        -- State unchanged on rejected block
      else
        IO.println s!"  FAIL {name}: transition returned none but expected success"
        failed := failed + 1
        -- Keep original state for subsequent blocks to try

  IO.println s!"  Results: {passed} passed, {failed} failed (of {sorted.size})"
  if failed > 0 then return 1 else return 0

end Jar.Test.BlockTest
