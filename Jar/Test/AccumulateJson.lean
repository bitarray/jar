import Jar.Json
import Jar.Test.Accumulate

/-!
# Accumulate JSON Test Runner

FromJson instances for accumulate test-specific types and a JSON-based test runner.
Grey test vectors use different field names from core Jar types, so we define
custom parsing functions scoped to this module.
-/

namespace Jar.Test.AccumulateJson

open Lean (Json ToJson FromJson toJson fromJson?)
open Jar Jar.Json Jar.Test.Accumulate

variable [JamConfig]

-- ============================================================================
-- Grey-format parsers for Work types (different field names from Jar.Json)
-- ============================================================================

/-- Parse AvailabilitySpec from Grey's `package_spec` format. -/
private def parseGreyAvailSpec (j : Json) : Except String AvailabilitySpec := do
  return {
    packageHash := ← fromJson? (← j.getObjVal? "hash")
    bundleLength := ← fromJson? (← j.getObjVal? "length")
    erasureRoot := ← fromJson? (← j.getObjVal? "erasure_root")
    segmentRoot := ← fromJson? (← j.getObjVal? "exports_root")
    segmentCount := ← (← j.getObjVal? "exports_count").getNat?
  }

/-- Parse RefinementContext from Grey's `context` format. -/
private def parseGreyContext (j : Json) : Except String RefinementContext := do
  return {
    anchorHash := ← fromJson? (← j.getObjVal? "anchor")
    anchorStateRoot := ← fromJson? (← j.getObjVal? "state_root")
    anchorBeefyRoot := ← fromJson? (← j.getObjVal? "beefy_root")
    lookupAnchorHash := ← fromJson? (← j.getObjVal? "lookup_anchor")
    lookupAnchorTimeslot := ← fromJson? (← j.getObjVal? "lookup_anchor_slot")
    prerequisites := ← fromJson? (← j.getObjVal? "prerequisites")
  }

/-- Parse WorkDigest from Grey's `results` entry format. -/
private def parseGreyDigest (j : Json) : Except String WorkDigest := do
  let refineLoad ← j.getObjVal? "refine_load"
  return {
    serviceId := ← fromJson? (← j.getObjVal? "service_id")
    codeHash := ← fromJson? (← j.getObjVal? "code_hash")
    payloadHash := ← fromJson? (← j.getObjVal? "payload_hash")
    gasLimit := ← fromJson? (← j.getObjVal? "accumulate_gas")
    result := ← fromJson? (← j.getObjVal? "result")
    gasUsed := ← fromJson? (← refineLoad.getObjVal? "gas_used")
    importsCount := ← (← refineLoad.getObjVal? "imports").getNat?
    extrinsicsCount := ← (← refineLoad.getObjVal? "extrinsic_count").getNat?
    extrinsicsSize := ← (← refineLoad.getObjVal? "extrinsic_size").getNat?
    exportsCount := ← (← refineLoad.getObjVal? "exports").getNat?
  }

/-- Parse segment_root_lookup from Grey format: array of {work_package_hash, segment_tree_root}. -/
private def parseGreySegmentRootLookup (j : Json) : Except String (Dict Hash Hash) := do
  match j with
  | Json.arr items => do
    let mut entries : List (Hash × Hash) := []
    for item in items do
      let k ← @fromJson? Hash _ (← item.getObjVal? "work_package_hash")
      let v ← @fromJson? Hash _ (← item.getObjVal? "segment_tree_root")
      entries := (k, v) :: entries
    return ⟨entries.reverse⟩
  | _ => .error "expected array for segment_root_lookup"

/-- Parse WorkReport from Grey format. -/
private def parseGreyWorkReport (j : Json) : Except String WorkReport := do
  let resultsJson ← j.getObjVal? "results"
  let digests ← match resultsJson with
    | Json.arr items => items.toList.mapM parseGreyDigest |>.map Array.mk
    | _ => .error "expected array for results"
  let coreIndexNat ← (← j.getObjVal? "core_index").getNat?
  return {
    availSpec := ← parseGreyAvailSpec (← j.getObjVal? "package_spec")
    context := ← parseGreyContext (← j.getObjVal? "context")
    coreIndex := ⟨coreIndexNat, sorry⟩
    authorizerHash := ← fromJson? (← j.getObjVal? "authorizer_hash")
    authOutput := ← fromJson? (← j.getObjVal? "auth_output")
    segmentRootLookup := ← parseGreySegmentRootLookup (← j.getObjVal? "segment_root_lookup")
    digests := digests
    authGasUsed := ← fromJson? (← j.getObjVal? "auth_gas_used")
  }

-- ============================================================================
-- Grey-format parsers for ServiceAccount
-- ============================================================================

/-- Parse ServiceAccount from Grey's account data format. -/
private def parseGreyServiceAccount (dataJson : Json) : Except String ServiceAccount := do
  let svc ← dataJson.getObjVal? "service"

  -- Parse storage: [{key, value}] -> Dict ByteArray ByteArray
  let storageJson ← dataJson.getObjVal? "storage"
  let storage ← match storageJson with
    | Json.arr items => do
      let mut entries : List (ByteArray × ByteArray) := []
      for item in items do
        let k ← @fromJson? ByteArray _ (← item.getObjVal? "key")
        let v ← @fromJson? ByteArray _ (← item.getObjVal? "value")
        entries := (k, v) :: entries
      pure (⟨entries.reverse⟩ : Dict ByteArray ByteArray)
    | _ => .error "expected array for storage"

  -- Parse preimage_blobs: [{hash, blob}] -> Dict Hash ByteArray
  let blobsJson ← dataJson.getObjVal? "preimage_blobs"
  let preimages ← match blobsJson with
    | Json.arr items => do
      let mut entries : List (Hash × ByteArray) := []
      for item in items do
        let h ← @fromJson? Hash _ (← item.getObjVal? "hash")
        let b ← @fromJson? ByteArray _ (← item.getObjVal? "blob")
        entries := (h, b) :: entries
      pure (⟨entries.reverse⟩ : Dict Hash ByteArray)
    | _ => .error "expected array for preimage_blobs"

  -- Parse preimage_requests: [{key: {hash, length}, value: [timeslots]}]
  -- -> Dict (Hash × BlobLength) (Array Timeslot)
  let reqsJson ← dataJson.getObjVal? "preimage_requests"
  let preimageInfo ← match reqsJson with
    | Json.arr items => do
      let mut entries : List ((Hash × BlobLength) × Array Timeslot) := []
      for item in items do
        let key ← item.getObjVal? "key"
        let h ← @fromJson? Hash _ (← key.getObjVal? "hash")
        let len ← (← key.getObjVal? "length").getNat?
        let valJson ← item.getObjVal? "value"
        let timeslots ← match valJson with
          | Json.arr ts => ts.toList.mapM (fun (t : Json) => do
              let n ← t.getNat?; pure (Nat.toUInt32 n)) |>.map Array.mk
          | _ => .error "expected array for timeslots"
        entries := ((h, Nat.toUInt32 len), timeslots) :: entries
      pure (⟨entries.reverse⟩ : Dict (Hash × BlobLength) (Array Timeslot))
    | _ => .error "expected array for preimage_requests"

  return {
    storage := storage
    preimages := preimages
    preimageInfo := preimageInfo
    gratis := match svc.getObjVal? "deposit_offset" with
      | .ok v => match @fromJson? UInt64 _ v with | .ok n => n | .error _ => 0
      | .error _ => 0
    codeHash := ← fromJson? (← svc.getObjVal? "code_hash")
    balance := ← fromJson? (← svc.getObjVal? "balance")
    minAccGas := ← fromJson? (← svc.getObjVal? "min_item_gas")
    minOnTransferGas := ← fromJson? (← svc.getObjVal? "min_memo_gas")
    -- NOTE: JAR ServiceAccount field names are mismatched with GP semantics.
    -- For the STF accumulate test harness, the JSON fields map as:
    -- JSON "creation_slot" → JAR.created (internally used as a_i items for eject)
    -- JSON "last_accumulation_slot" → JAR.lastAccumulation
    -- JSON "parent_service" → JAR.parent
    -- The real items/bytes/etc come from separate fields:
    created := ← fromJson? (← svc.getObjVal? "creation_slot")
    lastAccumulation := ← fromJson? (← svc.getObjVal? "last_accumulation_slot")
    parent := ← fromJson? (← svc.getObjVal? "parent_service")
    totalFootprint := match svc.getObjVal? "bytes" with
      | .ok v => match v.getNat? with | .ok n => n | .error _ => 0
      | .error _ => 0
    preimageCount := match svc.getObjVal? "items" with
      | .ok v => match v.getNat? with | .ok n => n | .error _ => 0
      | .error _ => 0
  }

-- ============================================================================
-- Grey-format parsers for accumulate test types
-- ============================================================================

/-- Parse TAReadyRecord from Grey format: {report, dependencies}. -/
private def parseGreyReadyRecord (j : Json) : Except String TAReadyRecord := do
  let report ← parseGreyWorkReport (← j.getObjVal? "report")
  let deps ← @fromJson? (Array Hash) _ (← j.getObjVal? "dependencies")
  return { report, dependencies := deps }

/-- Parse TAServiceStats from Grey format: {id, record: {...}}. -/
private def parseGreyServiceStats (j : Json) : Except String TAServiceStats := do
  let sid ← (← j.getObjVal? "id").getNat?
  let r ← j.getObjVal? "record"
  return {
    serviceId := sid
    providedCount := ← (← r.getObjVal? "provided_count").getNat?
    providedSize := ← (← r.getObjVal? "provided_size").getNat?
    refinementCount := ← (← r.getObjVal? "refinement_count").getNat?
    refinementGasUsed := ← (← r.getObjVal? "refinement_gas_used").getNat?
    imports := ← (← r.getObjVal? "imports").getNat?
    extrinsicCount := ← (← r.getObjVal? "extrinsic_count").getNat?
    extrinsicSize := ← (← r.getObjVal? "extrinsic_size").getNat?
    exports := ← (← r.getObjVal? "exports").getNat?
    accumulateCount := ← (← r.getObjVal? "accumulate_count").getNat?
    accumulateGasUsed := ← (← r.getObjVal? "accumulate_gas_used").getNat?
  }

/-- Parse TAPrivileges from Grey format. -/
private def parseGreyPrivileges (j : Json) : Except String TAPrivileges := do
  let bless ← (← j.getObjVal? "bless").getNat?
  let assignJson ← j.getObjVal? "assign"
  let assign ← match assignJson with
    | Json.arr items => items.toList.mapM (fun (x : Json) => x.getNat?) |>.map Array.mk
    | _ => .error "expected array for assign"
  let designate ← (← j.getObjVal? "designate").getNat?
  let register ← (← j.getObjVal? "register").getNat?
  let aaJson ← j.getObjVal? "always_acc"
  let alwaysAcc ← match aaJson with
    | Json.arr items => items.toList.mapM (fun (item : Json) => do
        match item with
        | Json.arr pair =>
          if pair.size < 2 then Except.error "expected [sid, gas] pair"
          let sid ← pair[0]!.getNat?
          let gas ← pair[1]!.getNat?
          pure (sid, gas)
        | _ => Except.error "expected [sid, gas] pair") |>.map Array.mk
    | _ => .error "expected array for always_acc"
  return { bless, assign, designate, register, alwaysAcc }

/-- Parse accounts array: [{id, data: {...}}] -> Dict ServiceId ServiceAccount. -/
private def parseGreyAccounts (j : Json) : Except String (Dict ServiceId ServiceAccount) := do
  match j with
  | Json.arr items => do
    let mut entries : List (ServiceId × ServiceAccount) := []
    for item in items do
      let sid ← (← item.getObjVal? "id").getNat?
      let dataJson ← item.getObjVal? "data"
      let acct ← parseGreyServiceAccount dataJson
      entries := (sid.toUInt32, acct) :: entries
    return ⟨entries.reverse⟩
  | _ => .error "expected array for accounts"

/-- Parse TAState from Grey format. -/
def parseGreyState (j : Json) : Except String TAState := do
  let slot ← (← j.getObjVal? "slot").getNat?
  let entropy ← @fromJson? Hash _ (← j.getObjVal? "entropy")

  -- ready_queue: Array (Array TAReadyRecord)
  let rqJson ← j.getObjVal? "ready_queue"
  let readyQueue ← match rqJson with
    | Json.arr slots => slots.toList.mapM (fun slotJson => do
        match slotJson with
        | Json.arr items => items.toList.mapM parseGreyReadyRecord |>.map Array.mk
        | _ => .error "expected array for ready_queue slot") |>.map Array.mk
    | _ => .error "expected array for ready_queue"

  -- accumulated: Array (Array Hash)
  let accJson ← j.getObjVal? "accumulated"
  let accumulated ← match accJson with
    | Json.arr slots => slots.toList.mapM (fun slotJson => do
        match slotJson with
        | Json.arr items => items.toList.mapM (fun h =>
            @fromJson? Hash _ h) |>.map Array.mk
        | _ => .error "expected array for accumulated slot") |>.map Array.mk
    | _ => .error "expected array for accumulated"

  let privileges ← parseGreyPrivileges (← j.getObjVal? "privileges")

  -- statistics: Array TAServiceStats
  let statsJson ← j.getObjVal? "statistics"
  let statistics ← match statsJson with
    | Json.arr items => items.toList.mapM parseGreyServiceStats |>.map Array.mk
    | _ => .error "expected array for statistics"

  let accounts ← parseGreyAccounts (← j.getObjVal? "accounts")

  return { slot, entropy, readyQueue, accumulated, privileges, statistics, accounts }

/-- Parse TAInput from Grey format. -/
def parseGreyInput (j : Json) : Except String TAInput := do
  let slot ← (← j.getObjVal? "slot").getNat?
  let reportsJson ← j.getObjVal? "reports"
  let reports ← match reportsJson with
    | Json.arr items => items.toList.mapM parseGreyWorkReport |>.map Array.mk
    | _ => .error "expected array for reports"
  return { slot, reports }

-- ============================================================================
-- ToJson instances for STF server output
-- ============================================================================

private def toJsonGreyServiceAccount (sid : ServiceId) (acct : ServiceAccount) : Json :=
  let storageEntries := acct.storage.entries.map fun (k, v) =>
    Json.mkObj [("key", toJson k), ("value", toJson v)]
  let blobEntries := acct.preimages.entries.map fun (h, b) =>
    Json.mkObj [("hash", toJson h), ("blob", toJson b)]
  let reqEntries := acct.preimageInfo.entries.map fun ((h, len), ts) =>
    Json.mkObj [
      ("key", Json.mkObj [("hash", toJson h), ("length", toJson len)]),
      ("value", Json.arr (ts.map fun t => toJson t))]
  Json.mkObj [
    ("id", toJson sid),
    ("data", Json.mkObj [
      ("service", Json.mkObj [
        ("code_hash", toJson acct.codeHash),
        ("balance", toJson acct.balance),
        ("min_item_gas", toJson acct.minAccGas),
        ("min_memo_gas", toJson acct.minOnTransferGas),
        ("creation_slot", toJson acct.created),
        ("last_accumulation_slot", toJson acct.lastAccumulation),
        ("parent_service", toJson acct.parent),
        ("bytes", Json.num (Lean.JsonNumber.fromNat acct.totalFootprint)),
        ("items", Json.num (Lean.JsonNumber.fromNat acct.preimageCount))]),
      ("storage", Json.arr storageEntries.toArray),
      ("preimage_blobs", Json.arr blobEntries.toArray),
      ("preimage_requests", Json.arr reqEntries.toArray)])]

private def toJsonGreyServiceStats (s : TAServiceStats) : Json :=
  Json.mkObj [
    ("id", toJson s.serviceId),
    ("record", Json.mkObj [
      ("provided_count", toJson s.providedCount),
      ("provided_size", toJson s.providedSize),
      ("refinement_count", toJson s.refinementCount),
      ("refinement_gas_used", toJson s.refinementGasUsed),
      ("imports", toJson s.imports),
      ("extrinsic_count", toJson s.extrinsicCount),
      ("extrinsic_size", toJson s.extrinsicSize),
      ("exports", toJson s.exports),
      ("accumulate_count", toJson s.accumulateCount),
      ("accumulate_gas_used", toJson s.accumulateGasUsed)])]

private def toJsonGreyPrivileges (p : TAPrivileges) : Json :=
  Json.mkObj [
    ("bless", toJson p.bless),
    ("assign", Json.arr (p.assign.map fun a => toJson a)),
    ("designate", toJson p.designate),
    ("register", toJson p.register),
    ("always_acc", Json.arr (p.alwaysAcc.map fun (s, g) =>
      Json.arr #[toJson s, toJson g]))]

def toJsonGreyState (s : TAState) : Json :=
  let readyQueueJson := Json.arr (s.readyQueue.map fun slot =>
    Json.arr (slot.map fun r => Json.mkObj [
      ("report", toJson r.report),
      ("dependencies", toJson r.dependencies)]))
  let accumulatedJson := Json.arr (s.accumulated.map fun slot =>
    Json.arr (slot.map fun h => toJson h))
  let accountsJson := Json.arr (s.accounts.entries.map fun (sid, acct) =>
    toJsonGreyServiceAccount sid acct).toArray
  Json.mkObj [
    ("slot", toJson s.slot),
    ("entropy", toJson s.entropy),
    ("ready_queue", readyQueueJson),
    ("accumulated", accumulatedJson),
    ("privileges", toJsonGreyPrivileges s.privileges),
    ("statistics", Json.arr (s.statistics.map toJsonGreyServiceStats)),
    ("accounts", accountsJson)]

-- ============================================================================
-- JSON Test Runner
-- ============================================================================

/-- Run a single accumulate test from separate input/output JSON files. -/
def runJsonTest (inputPath : System.FilePath) (verbose := false) : IO Bool := do
  let t0 ← IO.monoMsNow
  let inputContent ← IO.FS.readFile inputPath
  let inputJson ← IO.ofExcept (Json.parse inputContent)
  let outputPath := System.FilePath.mk (inputPath.toString.replace s!".input.{JamConfig.name}.json" s!".output.{JamConfig.name}.json")
  let outputContent ← IO.FS.readFile outputPath
  let outputJson ← IO.ofExcept (Json.parse outputContent)
  let t1 ← IO.monoMsNow
  let pre ← IO.ofExcept (parseGreyState (← IO.ofExcept (inputJson.getObjVal? "pre_state")))
  let input ← IO.ofExcept (parseGreyInput (← IO.ofExcept (inputJson.getObjVal? "input")))
  let t2 ← IO.monoMsNow

  -- Parse output: {ok: hash}
  let expOutputJson ← IO.ofExcept (outputJson.getObjVal? "output")
  let expectedHash ← IO.ofExcept (do
    let okVal ← expOutputJson.getObjVal? "ok"
    @fromJson? Hash _ okVal)

  let post ← IO.ofExcept (parseGreyState (← IO.ofExcept (outputJson.getObjVal? "post_state")))
  let t3 ← IO.monoMsNow
  let name := inputPath.fileName.getD (toString inputPath)
  let ok ← Accumulate.runTest name pre input expectedHash post
  let t4 ← IO.monoMsNow
  if verbose then
    IO.println s!"    [parse_json={t1-t0}ms parse_state={t2-t1}ms parse_output={t3-t2}ms transition+compare={t4-t3}ms]"
  return ok

/-- Run all JSON tests in a directory (in parallel). -/
def runJsonTestDir (dir : System.FilePath) (verbose := false) : IO UInt32 := do
  let entries ← dir.readDir
  let jsonFiles := entries.filter (fun e => e.fileName.endsWith s!".input.{JamConfig.name}.json")
  let sorted := jsonFiles.qsort (fun a b => a.fileName < b.fileName)
  -- Launch all tests in parallel
  let tasks ← sorted.mapM fun entry => IO.asTask (runJsonTest entry.path verbose)
  let mut passed := 0
  let mut failed := 0
  for task in tasks do
    let result ← IO.ofExcept (← IO.wait task)
    if result then passed := passed + 1 else failed := failed + 1
  IO.println s!"\nAccumulate JSON tests: {passed} passed, {failed} failed, {passed + failed} total"
  return if failed > 0 then 1 else 0

end Jar.Test.AccumulateJson
