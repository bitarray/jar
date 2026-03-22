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
  -- Accept both Grey ("hash"/"length"/"exports_root"/"exports_count")
  -- and JAR ("package_hash"/"bundle_length"/"segment_root"/"segment_count") field names
  let getField (a b : String) : Except String Json :=
    match j.getObjVal? a with | .ok v => .ok v | .error _ => j.getObjVal? b
  return {
    packageHash := ← fromJson? (← getField "hash" "package_hash")
    bundleLength := ← fromJson? (← getField "length" "bundle_length")
    erasureRoot := ← fromJson? (← j.getObjVal? "erasure_root")
    segmentRoot := ← fromJson? (← getField "exports_root" "segment_root")
    segmentCount := ← (← getField "exports_count" "segment_count").getNat?
  }

/-- Parse RefinementContext from Grey or JAR format. -/
private def parseGreyContext (j : Json) : Except String RefinementContext := do
  let getField (a b : String) : Except String Json :=
    match j.getObjVal? a with | .ok v => .ok v | .error _ => j.getObjVal? b
  return {
    anchorHash := ← fromJson? (← getField "anchor" "anchor_hash")
    anchorStateRoot := ← fromJson? (← getField "state_root" "anchor_state_root")
    anchorBeefyRoot := ← fromJson? (← getField "beefy_root" "anchor_beefy_root")
    lookupAnchorHash := ← fromJson? (← getField "lookup_anchor" "lookup_anchor_hash")
    lookupAnchorTimeslot := ← fromJson? (← getField "lookup_anchor_slot" "lookup_anchor_timeslot")
    prerequisites := ← fromJson? (← j.getObjVal? "prerequisites")
  }

/-- Parse WorkDigest from Grey or JAR format.
    Grey nests gas_used/imports/extrinsics/exports under `refine_load`.
    JAR puts them flat with slightly different names. -/
private def parseGreyDigest (j : Json) : Except String WorkDigest := do
  let getField (a b : String) : Except String Json :=
    match j.getObjVal? a with | .ok v => .ok v | .error _ => j.getObjVal? b
  -- Grey nests under "refine_load"; JAR puts them flat
  let (gasUsed, importsCount, extrinsicsCount, extrinsicsSize, exportsCount) ←
    match j.getObjVal? "refine_load" with
    | .ok rl => do
      pure (← fromJson? (← rl.getObjVal? "gas_used"),
            ← (← rl.getObjVal? "imports").getNat?,
            ← (← rl.getObjVal? "extrinsic_count").getNat?,
            ← (← rl.getObjVal? "extrinsic_size").getNat?,
            ← (← rl.getObjVal? "exports").getNat?)
    | .error _ => do
      pure (← fromJson? (← j.getObjVal? "gas_used"),
            ← (← j.getObjVal? "imports_count").getNat?,
            ← (← j.getObjVal? "extrinsics_count").getNat?,
            ← (← j.getObjVal? "extrinsics_size").getNat?,
            ← (← j.getObjVal? "exports_count").getNat?)
  return {
    serviceId := ← fromJson? (← j.getObjVal? "service_id")
    codeHash := ← fromJson? (← j.getObjVal? "code_hash")
    payloadHash := ← fromJson? (← j.getObjVal? "payload_hash")
    gasLimit := ← fromJson? (← getField "accumulate_gas" "gas_limit")
    result := ← fromJson? (← j.getObjVal? "result")
    gasUsed, importsCount, extrinsicsCount, extrinsicsSize, exportsCount
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

/-- Parse WorkReport from Grey or JAR format. Accepts both field name conventions. -/
private def parseGreyWorkReport (j : Json) : Except String WorkReport := do
  -- Accept both "results" (Grey) and "digests" (JAR) field names
  let resultsJson ← match j.getObjVal? "results" with
    | .ok v => pure v
    | .error _ => j.getObjVal? "digests"
  let digests ← match resultsJson with
    | Json.arr items => items.toList.mapM parseGreyDigest |>.map Array.mk
    | _ => .error "expected array for results/digests"
  let coreIndexNat ← (← j.getObjVal? "core_index").getNat?
  -- Accept both "package_spec" (Grey) and "avail_spec" (JAR) field names
  let availSpecJson ← match j.getObjVal? "package_spec" with
    | .ok v => pure v
    | .error _ => j.getObjVal? "avail_spec"
  return {
    availSpec := ← parseGreyAvailSpec availSpecJson
    context := ← parseGreyContext (← j.getObjVal? "context")
    coreIndex := ⟨coreIndexNat % C, Nat.mod_lt _ JamConfig.valid.hC⟩
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

  -- Accept both Grey and JAR field name conventions for service account fields
  let svcField (a b : String) : Except String Json :=
    match svc.getObjVal? a with | .ok v => .ok v | .error _ => svc.getObjVal? b
  let svcFieldNat (a b : String) (default : Nat := 0) : Except String Nat :=
    match svc.getObjVal? a with
    | .ok v => match v.getNat? with | .ok n => .ok n | .error _ => .ok default
    | .error _ => match svc.getObjVal? b with
      | .ok v => match v.getNat? with | .ok n => .ok n | .error _ => .ok default
      | .error _ => .ok default
  return {
    storage := storage
    preimages := preimages
    preimageInfo := preimageInfo
    gratis := match svc.getObjVal? "deposit_offset" with
      | .ok v => match @fromJson? UInt64 _ v with | .ok n => n | .error _ => 0
      | .error _ => match svc.getObjVal? "gratis" with
        | .ok v => match @fromJson? UInt64 _ v with | .ok n => n | .error _ => 0
        | .error _ => 0
    codeHash := ← fromJson? (← svc.getObjVal? "code_hash")
    balance := ← fromJson? (← svc.getObjVal? "balance")
    minAccGas := ← fromJson? (← svcField "min_item_gas" "min_acc_gas")
    minOnTransferGas := ← fromJson? (← svcField "min_memo_gas" "min_on_transfer_gas")
    itemCount := UInt32.ofNat (← svcFieldNat "items" "item_count")
    creationSlot := ← fromJson? (← svcField "creation_slot" "creation_slot")
    lastAccumulation := ← fromJson? (← svcField "last_accumulation_slot" "last_accumulation")
    parentServiceId := ← svcFieldNat "parent_service" "parent_service_id"
    totalFootprint := ← svcFieldNat "bytes" "total_footprint"
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
        ("creation_slot", toJson acct.creationSlot),
        ("last_accumulation_slot", toJson acct.lastAccumulation),
        ("parent_service", toJson acct.parentServiceId),
        ("bytes", Json.num (Lean.JsonNumber.fromNat acct.totalFootprint)),
        ("items", Json.num (Lean.JsonNumber.fromNat acct.itemCount.toNat))]),
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

private def toJsonGreyDigest (d : WorkDigest) : Json :=
  Json.mkObj [
    ("service_id", toJson d.serviceId),
    ("code_hash", toJson d.codeHash),
    ("payload_hash", toJson d.payloadHash),
    ("accumulate_gas", toJson d.gasLimit),
    ("result", toJson d.result),
    ("refine_load", Json.mkObj [
      ("gas_used", toJson d.gasUsed),
      ("imports", Json.num d.importsCount),
      ("extrinsic_count", Json.num d.extrinsicsCount),
      ("extrinsic_size", Json.num d.extrinsicsSize),
      ("exports", Json.num d.exportsCount)])]

private def toJsonGreyWorkReport (wr : WorkReport) : Json :=
  Json.mkObj [
    ("package_spec", Json.mkObj [
      ("hash", toJson wr.availSpec.packageHash),
      ("length", toJson wr.availSpec.bundleLength),
      ("erasure_root", toJson wr.availSpec.erasureRoot),
      ("exports_root", toJson wr.availSpec.segmentRoot),
      ("exports_count", Json.num wr.availSpec.segmentCount)]),
    ("context", Json.mkObj [
      ("anchor", toJson wr.context.anchorHash),
      ("state_root", toJson wr.context.anchorStateRoot),
      ("beefy_root", toJson wr.context.anchorBeefyRoot),
      ("lookup_anchor", toJson wr.context.lookupAnchorHash),
      ("lookup_anchor_slot", toJson wr.context.lookupAnchorTimeslot),
      ("prerequisites", toJson wr.context.prerequisites)]),
    ("core_index", toJson wr.coreIndex),
    ("authorizer_hash", toJson wr.authorizerHash),
    ("auth_output", toJson wr.authOutput),
    ("segment_root_lookup", Json.arr (wr.segmentRootLookup.entries.map fun (k, v) =>
      Json.mkObj [("work_package_hash", toJson k), ("segment_tree_root", toJson v)]).toArray),
    ("results", Json.arr (wr.digests.map toJsonGreyDigest)),
    ("auth_gas_used", toJson wr.authGasUsed)]

def toJsonGreyState (s : TAState) : Json :=
  let readyQueueJson := Json.arr (s.readyQueue.map fun slot =>
    Json.arr (slot.map fun r => Json.mkObj [
      ("report", toJsonGreyWorkReport r.report),
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
