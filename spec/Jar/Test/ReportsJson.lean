import Jar.Json
import Jar.Codec
import Jar.Crypto
import Jar.Variant
import Jar.Test.Reports

/-!
# Reports JSON Test Runner

FromJson instances for reports test-specific types and a JSON-based test runner.
-/

namespace Jar.Test.ReportsJson

open Lean (Json ToJson FromJson toJson fromJson?)
open Jar Jar.Json Jar.Crypto Jar.Codec Jar.Test.Reports

variable [JamVariant]

-- ============================================================================
-- Work report encoding for reportHash computation
-- Dispatches between gp072 (compact) and jar1 (fixed-width) based on variant.
-- ============================================================================

/-- Encode TRWorkResult matching Codec.encodeWorkResult. -/
private def encodeTRWorkResult (r : TRWorkResult) : ByteArray :=
  match r with
  | .ok data => ByteArray.mk #[0] ++ encodeLengthPrefixed data
  | .outOfGas => ByteArray.mk #[1]
  | .panic => ByteArray.mk #[2]
  | .badExports => ByteArray.mk #[3]
  | .badCode => ByteArray.mk #[4]
  | .codeOversize => ByteArray.mk #[5]

/-- Encode a count-prefixed sequence (count + concatenated items). -/
private def encodeCountPrefixed (f : α → ByteArray) (xs : Array α) : ByteArray :=
  encodeNat xs.size ++ concatBytes (xs.map f)

/-- Encode TRWorkDigest. -/
private def encodeTRWorkDigest (d : TRWorkDigest) : ByteArray :=
  encodeFixedNat 4 d.serviceId
    ++ d.codeHash.data
    ++ d.payloadHash.data
    ++ encodeFixedNat 8 d.accumulateGas
    ++ encodeTRWorkResult d.result
    ++ encodeNat d.gasUsed
    ++ encodeNat d.imports
    ++ encodeNat d.extrinsicCount
    ++ encodeNat d.extrinsicSize
    ++ encodeNat d.exports

/-- Encode TRAvailSpec. -/
private def encodeTRAvailSpec (a : TRAvailSpec) : ByteArray :=
  a.packageHash.data
    ++ encodeFixedNat 4 a.bundleLength
    ++ a.erasureRoot.data
    ++ a.exportsRoot.data
    ++ encodeFixedNat 2 a.exportsCount

/-- Encode TRContext. -/
private def encodeTRContext (c : TRContext) : ByteArray :=
  c.anchor.data
    ++ c.stateRoot.data
    ++ c.beefyRoot.data
    ++ c.lookupAnchor.data
    ++ encodeFixedNat 4 c.lookupAnchorSlot
    ++ encodeCountPrefixed (fun h => h.data) c.prerequisites

/-- Encode TRWorkReport matching the Grey JAM codec. -/
private def encodeTRWorkReport (wr : TRWorkReport) : ByteArray :=
  encodeTRAvailSpec wr.packageSpec
    ++ encodeTRContext wr.context
    ++ encodeNat wr.coreIndex       -- compact, not fixed 2-byte
    ++ wr.authorizerHash.data
    ++ encodeNat wr.authGasUsed     -- compact
    ++ encodeLengthPrefixed wr.authOutput
    ++ encodeCountPrefixed (fun (k, v) => k.data ++ v.data) wr.segmentRootLookup
    ++ encodeCountPrefixed encodeTRWorkDigest wr.results

-- ============================================================================
-- jar1 encoding (no compact — all fixed-width)
-- ============================================================================

private def jar1EncodeTRWorkResult (r : TRWorkResult) : ByteArray :=
  match r with
  | .ok data => ByteArray.mk #[0] ++ encodeFixedNat 4 data.size ++ data
  | .outOfGas => ByteArray.mk #[1]
  | .panic => ByteArray.mk #[2]
  | .badExports => ByteArray.mk #[3]
  | .badCode => ByteArray.mk #[4]
  | .codeOversize => ByteArray.mk #[5]

private def jar1EncodeCountPrefixed (f : α → ByteArray) (xs : Array α) : ByteArray :=
  encodeFixedNat 4 xs.size ++ concatBytes (xs.map f)

private def jar1EncodeTRWorkDigest (d : TRWorkDigest) : ByteArray :=
  encodeFixedNat 4 d.serviceId
    ++ d.codeHash.data
    ++ d.payloadHash.data
    ++ encodeFixedNat 8 d.accumulateGas
    ++ jar1EncodeTRWorkResult d.result
    ++ encodeFixedNat 8 d.gasUsed
    ++ encodeFixedNat 2 d.imports
    ++ encodeFixedNat 2 d.extrinsicCount
    ++ encodeFixedNat 4 d.extrinsicSize
    ++ encodeFixedNat 2 d.exports

private def jar1EncodeTRContext (c : TRContext) : ByteArray :=
  c.anchor.data
    ++ c.stateRoot.data
    ++ c.beefyRoot.data
    ++ c.lookupAnchor.data
    ++ encodeFixedNat 4 c.lookupAnchorSlot
    ++ jar1EncodeCountPrefixed (fun h => h.data) c.prerequisites

private def jar1EncodeTRWorkReport (wr : TRWorkReport) : ByteArray :=
  encodeTRAvailSpec wr.packageSpec
    ++ jar1EncodeTRContext wr.context
    ++ encodeFixedNat 2 wr.coreIndex
    ++ wr.authorizerHash.data
    ++ encodeFixedNat 8 wr.authGasUsed
    ++ encodeFixedNat 4 wr.authOutput.size ++ wr.authOutput
    ++ jar1EncodeCountPrefixed (fun (k, v) => k.data ++ v.data) wr.segmentRootLookup
    ++ jar1EncodeCountPrefixed jar1EncodeTRWorkDigest wr.results

-- ============================================================================
-- Dispatch: use jar1 encoding when variant is jar1, gp072 otherwise
-- ============================================================================

/-- Compute reportHash = blake2b(encode(report)), using variant-appropriate codec. -/
private def computeReportHash (wr : TRWorkReport) : Hash :=
  if JamConfig.variableValidators then
    blake2b (jar1EncodeTRWorkReport wr)
  else
    blake2b (encodeTRWorkReport wr)

-- ============================================================================
-- FromJson instances for TRWorkResult
-- ============================================================================

private def workResultFromJson (j : Json) : Except String TRWorkResult := do
  if let .ok v := j.getObjVal? "ok" then
    return .ok (← @fromJson? ByteArray _ v)
  else if let .ok (Json.str s) := j.getObjVal? "err" then
    match s with
    | "out_of_gas" => return .outOfGas
    | "panic" => return .panic
    | "bad_exports" => return .badExports
    | "bad_code" => return .badCode
    | "code_oversize" => return .codeOversize
    | other => .error s!"unknown work result error: {other}"
  else
    .error "TRWorkResult: expected 'ok' or 'err'"

-- ============================================================================
-- FromJson instances for test types
-- ============================================================================

instance : FromJson TRWorkDigest where
  fromJson? j := do
    let serviceId ← (← j.getObjVal? "service_id").getNat?
    let codeHash ← @fromJson? Hash _ (← j.getObjVal? "code_hash")
    let payloadHash ← @fromJson? Hash _ (← j.getObjVal? "payload_hash")
    let accumulateGas ← (← j.getObjVal? "accumulate_gas").getNat?
    let result ← workResultFromJson (← j.getObjVal? "result")
    let refineLoad ← j.getObjVal? "refine_load"
    let gasUsed ← (← refineLoad.getObjVal? "gas_used").getNat?
    let imports ← (← refineLoad.getObjVal? "imports").getNat?
    let extrinsicCount ← (← refineLoad.getObjVal? "extrinsic_count").getNat?
    let extrinsicSize ← (← refineLoad.getObjVal? "extrinsic_size").getNat?
    let exports ← (← refineLoad.getObjVal? "exports").getNat?
    return { serviceId, codeHash, payloadHash, accumulateGas, result,
             gasUsed, imports, extrinsicCount, extrinsicSize, exports }

instance : FromJson TRAvailSpec where
  fromJson? j := do
    let packageHash ← @fromJson? Hash _ (← j.getObjVal? "hash")
    let bundleLength ← (← j.getObjVal? "length").getNat?
    let erasureRoot ← @fromJson? Hash _ (← j.getObjVal? "erasure_root")
    let exportsRoot ← @fromJson? Hash _ (← j.getObjVal? "exports_root")
    let exportsCount ← (← j.getObjVal? "exports_count").getNat?
    return { packageHash, bundleLength, erasureRoot, exportsRoot, exportsCount }

instance : FromJson TRContext where
  fromJson? j := do
    let anchor ← @fromJson? Hash _ (← j.getObjVal? "anchor")
    let stateRoot ← @fromJson? Hash _ (← j.getObjVal? "state_root")
    let beefyRoot ← @fromJson? Hash _ (← j.getObjVal? "beefy_root")
    let lookupAnchor ← @fromJson? Hash _ (← j.getObjVal? "lookup_anchor")
    let lookupAnchorSlot ← (← j.getObjVal? "lookup_anchor_slot").getNat?
    let prerequisites ← @fromJson? (Array Hash) _ (← j.getObjVal? "prerequisites")
    return { anchor, stateRoot, beefyRoot, lookupAnchor, lookupAnchorSlot, prerequisites }

private def segmentRootLookupEntryFromJson (j : Json) : Except String (Hash × Hash) := do
  let wph ← @fromJson? Hash _ (← j.getObjVal? "work_package_hash")
  let str ← @fromJson? Hash _ (← j.getObjVal? "segment_tree_root")
  return (wph, str)

instance : FromJson TRWorkReport where
  fromJson? j := do
    let packageSpec ← @fromJson? TRAvailSpec _ (← j.getObjVal? "package_spec")
    let context ← @fromJson? TRContext _ (← j.getObjVal? "context")
    let coreIndex ← (← j.getObjVal? "core_index").getNat?
    let authorizerHash ← @fromJson? Hash _ (← j.getObjVal? "authorizer_hash")
    let authGasUsed ← (← j.getObjVal? "auth_gas_used").getNat?
    let authOutput ← @fromJson? ByteArray _ (← j.getObjVal? "auth_output")
    let srlJson ← j.getObjVal? "segment_root_lookup"
    let segmentRootLookup ← match srlJson with
      | Json.arr items => items.toList.mapM segmentRootLookupEntryFromJson |>.map Array.mk
      | _ => .error "expected array for segment_root_lookup"
    let results ← @fromJson? (Array TRWorkDigest) _ (← j.getObjVal? "results")
    return { packageSpec, context, coreIndex, authorizerHash, authGasUsed,
             authOutput, segmentRootLookup, results }

instance : FromJson TRSignature where
  fromJson? j := do
    let validatorIndex ← (← j.getObjVal? "validator_index").getNat?
    let signature ← @fromJson? Ed25519Signature _ (← j.getObjVal? "signature")
    return { validatorIndex, signature }

private def guaranteeFromJson (j : Json) : Except String TRGuarantee := do
  let report ← @fromJson? TRWorkReport _ (← j.getObjVal? "report")
  let slot ← (← j.getObjVal? "slot").getNat?
  let signatures ← @fromJson? (Array TRSignature) _ (← j.getObjVal? "signatures")
  let reportHash := computeReportHash report
  return { report, slot, signatures, reportHash }

private def recentBlockFromJson (j : Json) : Except String TRRecentBlock := do
  let headerHash ← @fromJson? Hash _ (← j.getObjVal? "header_hash")
  let stateRoot ← @fromJson? Hash _ (← j.getObjVal? "state_root")
  let beefyRoot ← @fromJson? Hash _ (← j.getObjVal? "beefy_root")
  let reportedJson ← j.getObjVal? "reported"
  let reported ← match reportedJson with
    | Json.arr items => items.toList.mapM (fun (rj : Json) => do
        let h ← @fromJson? Hash _ (← rj.getObjVal? "hash")
        let er ← @fromJson? Hash _ (← rj.getObjVal? "exports_root")
        return (h, er)) |>.map Array.mk
    | _ => .error "expected array for reported"
  return { headerHash, stateRoot, beefyRoot, reported }

private def serviceInfoFromJson (j : Json) : Except String TRServiceInfo := do
  let serviceId ← (← j.getObjVal? "id").getNat?
  let dataJson ← j.getObjVal? "data"
  let serviceJson ← dataJson.getObjVal? "service"
  let codeHash ← @fromJson? Hash _ (← serviceJson.getObjVal? "code_hash")
  let minItemGas ← (← serviceJson.getObjVal? "min_item_gas").getNat?
  return { serviceId, codeHash, minItemGas }

private def availAssignmentFromJson (j : Json) : Except String (Option TRAvailAssignment) := do
  match j with
  | Json.null => return none
  | _ =>
    let reportJson ← j.getObjVal? "report"
    let packageSpecJson ← reportJson.getObjVal? "package_spec"
    let packageHash ← @fromJson? Hash _ (← packageSpecJson.getObjVal? "hash")
    let timeout ← (← j.getObjVal? "timeout").getNat?
    return some { packageHash, timeout }

instance : FromJson TRState where
  fromJson? j := do
    let availJson ← j.getObjVal? "avail_assignments"
    let availAssignments ← match availJson with
      | Json.arr items => items.toList.mapM availAssignmentFromJson |>.map Array.mk
      | _ => .error "expected array for avail_assignments"
    let currValidators ← @fromJson? (Array ValidatorKey) _ (← j.getObjVal? "curr_validators")
    let prevValidators ← @fromJson? (Array ValidatorKey) _ (← j.getObjVal? "prev_validators")
    let entropy ← @fromJson? (Array Hash) _ (← j.getObjVal? "entropy")
    let offenders ← @fromJson? (Array Ed25519PublicKey) _ (← j.getObjVal? "offenders")
    let recentBlocksJson ← j.getObjVal? "recent_blocks"
    let historyJson ← recentBlocksJson.getObjVal? "history"
    let recentBlocks ← match historyJson with
      | Json.arr items => items.toList.mapM recentBlockFromJson |>.map Array.mk
      | _ => .error "expected array for recent_blocks.history"
    let authPools ← @fromJson? (Array (Array Hash)) _ (← j.getObjVal? "auth_pools")
    let accountsJson ← j.getObjVal? "accounts"
    let accounts ← match accountsJson with
      | Json.arr items => items.toList.mapM serviceInfoFromJson |>.map Array.mk
      | _ => .error "expected array for accounts"
    return { availAssignments, currValidators, prevValidators, entropy,
             offenders, recentBlocks, authPools, accounts }

instance : FromJson TRInput where
  fromJson? j := do
    let guaranteesJson ← j.getObjVal? "guarantees"
    let guarantees ← match guaranteesJson with
      | Json.arr items => items.toList.mapM guaranteeFromJson |>.map Array.mk
      | _ => .error "expected array for guarantees"
    let knownPackages ← @fromJson? (Array Hash) _ (← j.getObjVal? "known_packages")
    let slot ← (← j.getObjVal? "slot").getNat?
    return { guarantees, knownPackages, slot }

instance : FromJson TRResult where
  fromJson? j := do
    if let .ok _ := j.getObjVal? "ok" then
      return .ok
    else if let .ok (Json.str e) := j.getObjVal? "err" then
      return .err e
    else
      .error "TRResult: expected 'ok' or 'err'"

-- ============================================================================
-- ToJson instances for STF server output
-- ============================================================================

instance : ToJson TRAvailAssignment where
  toJson a := Json.mkObj [
    ("report", Json.mkObj [
      ("package_spec", Json.mkObj [("hash", toJson a.packageHash)])]),
    ("timeout", toJson a.timeout)]

private instance : ToJson (Option TRAvailAssignment) where
  toJson
    | none => Json.null
    | some a => toJson a

instance : ToJson TRResult where
  toJson
    | .ok => Json.mkObj [("ok", Json.mkObj [])]
    | .err e => Json.mkObj [("err", Json.str e)]

-- ============================================================================
-- JSON Test Runner
-- ============================================================================

/-- Run a single reports test from separate input/output JSON files. -/
def runJsonTest (inputPath : System.FilePath) : IO Bool := do
  let inputContent ← IO.FS.readFile inputPath
  let inputJson ← IO.ofExcept (Json.parse inputContent)
  let outputPath := System.FilePath.mk (inputPath.toString.replace s!".input.{JamConfig.name}.json" s!".output.{JamConfig.name}.json")
  let outputContent ← IO.FS.readFile outputPath
  let outputJson ← IO.ofExcept (Json.parse outputContent)
  let pre ← IO.ofExcept (@fromJson? TRState _ (← IO.ofExcept (inputJson.getObjVal? "pre_state")))
  let input ← IO.ofExcept (@fromJson? TRInput _ (← IO.ofExcept (inputJson.getObjVal? "input")))
  let expectedResult ← IO.ofExcept (@fromJson? TRResult _ (← IO.ofExcept (outputJson.getObjVal? "output")))
  -- Extract post avail from post_state
  let postStateJson ← IO.ofExcept (outputJson.getObjVal? "post_state")
  let postAvailJson ← IO.ofExcept (postStateJson.getObjVal? "avail_assignments")
  let postAvail ← IO.ofExcept (match postAvailJson with
    | Json.arr items => items.toList.mapM availAssignmentFromJson |>.map Array.mk
    | _ => .error "expected array for post avail_assignments")
  let name := inputPath.fileName.getD (toString inputPath)
  Reports.runTest name pre input expectedResult postAvail

/-- Run all JSON tests in a directory. -/
def runJsonTestDir (dir : System.FilePath) : IO UInt32 := do
  let entries ← dir.readDir
  let jsonFiles := entries.filter (fun e => e.fileName.endsWith s!".input.{JamConfig.name}.json")
  let sorted := jsonFiles.qsort (fun a b => a.fileName < b.fileName)
  let mut passed := 0
  let mut failed := 0
  for entry in sorted do
    let ok ← runJsonTest entry.path
    if ok then passed := passed + 1 else failed := failed + 1
  IO.println s!"\nReports JSON tests: {passed} passed, {failed} failed, {passed + failed} total"
  return if failed > 0 then 1 else 0

end Jar.Test.ReportsJson
