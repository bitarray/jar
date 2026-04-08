import Jar.Json
import Jar.Test.Statistics

/-!
# Statistics JSON Test Runner

FromJson instances for statistics test-specific types and a JSON-based test runner.
-/

namespace Jar.Test.StatisticsJson

open Lean (Json ToJson FromJson toJson fromJson?)
open Jar Jar.Json Jar.Test.Statistics

variable [JarConfig]

-- ============================================================================
-- JSON instances for statistics test types
-- ============================================================================

instance : FromJson FlatValidatorRecord where
  fromJson? j := do
    let blocks ← (← j.getObjVal? "blocks").getNat?
    let tickets ← (← j.getObjVal? "tickets").getNat?
    let preImages ← (← j.getObjVal? "pre_images").getNat?
    let preImagesSize ← (← j.getObjVal? "pre_images_size").getNat?
    let guarantees ← (← j.getObjVal? "guarantees").getNat?
    let assurances ← (← j.getObjVal? "assurances").getNat?
    return { blocks, tickets, preImages, preImagesSize, guarantees, assurances }

instance : FromJson FlatStatisticsState where
  fromJson? j := do
    let valsCurrStats ← @fromJson? (Array FlatValidatorRecord) _ (← j.getObjVal? "vals_curr_stats")
    let valsLastStats ← @fromJson? (Array FlatValidatorRecord) _ (← j.getObjVal? "vals_last_stats")
    let slot ← @fromJson? Timeslot _ (← j.getObjVal? "slot")
    -- curr_validators field exists in JSON but is not part of our Lean state; ignore it
    return { valsCurrStats, valsLastStats, slot }

/-- Parse a hex blob string and return its byte length. -/
private def hexBlobByteLength (j : Json) : Except String Nat := do
  let s ← j.getStr?
  let s := if s.startsWith "0x" || s.startsWith "0X" then s.drop 2 else s
  return s.toString.length / 2

instance : FromJson StatsExtrinsic where
  fromJson? j := do
    -- tickets: array of ticket proof objects — we need the count
    let ticketsArr ← j.getObjVal? "tickets"
    let ticketCount ← match ticketsArr with
      | Json.arr items => pure items.size
      | _ => .error "expected array for tickets"
    -- preimages: array of {requester, blob} — we need blob byte lengths
    let preimagesArr ← j.getObjVal? "preimages"
    let preimageSizes ← match preimagesArr with
      | Json.arr items => items.toList.mapM fun item => do
          hexBlobByteLength (← item.getObjVal? "blob")
      | _ => .error "expected array for preimages"
    -- guarantees: array of {report, slot, signatures:[{validator_index, signature}]}
    let guaranteesArr ← j.getObjVal? "guarantees"
    let guaranteeSigners ← match guaranteesArr with
      | Json.arr items => items.toList.mapM fun item => do
          let sigs ← item.getObjVal? "signatures"
          match sigs with
          | Json.arr sigItems => do
            let indices ← sigItems.toList.mapM fun sig => do
              (← sig.getObjVal? "validator_index").getNat?
            pure indices.toArray
          | _ => .error "expected array for signatures"
      | _ => .error "expected array for guarantees"
    -- assurances: array of {anchor, bitfield, validator_index, signature}
    let assurancesArr ← j.getObjVal? "assurances"
    let assuranceValidators ← match assurancesArr with
      | Json.arr items => items.toList.mapM fun item => do
          (← item.getObjVal? "validator_index").getNat?
      | _ => .error "expected array for assurances"
    return {
      ticketCount
      preimageSizes := preimageSizes.toArray
      guaranteeSigners := guaranteeSigners.toArray
      assuranceValidators := assuranceValidators.toArray
    }

instance : FromJson StatsInput where
  fromJson? j := do
    let slot ← @fromJson? Timeslot _ (← j.getObjVal? "slot")
    let authorIndex ← (← j.getObjVal? "author_index").getNat?
    let extrinsic ← @fromJson? StatsExtrinsic _ (← j.getObjVal? "extrinsic")
    return { slot, authorIndex, extrinsic }

-- ============================================================================
-- ToJson instances for STF server output
-- ============================================================================

instance : ToJson FlatValidatorRecord where
  toJson r := Json.mkObj [
    ("blocks", toJson r.blocks),
    ("tickets", toJson r.tickets),
    ("pre_images", toJson r.preImages),
    ("pre_images_size", toJson r.preImagesSize),
    ("guarantees", toJson r.guarantees),
    ("assurances", toJson r.assurances)]

instance : ToJson FlatStatisticsState where
  toJson s := Json.mkObj [
    ("vals_curr_stats", toJson s.valsCurrStats),
    ("vals_last_stats", toJson s.valsLastStats),
    ("slot", toJson s.slot)]

-- ============================================================================
-- JSON Test Runner
-- ============================================================================

/-- Run a single statistics test from separate input/output JSON files. -/
def runJsonTest (inputPath : System.FilePath) : IO Bool := do
  let inputContent ← IO.FS.readFile inputPath
  let inputJson ← IO.ofExcept (Json.parse inputContent)
  let outputPath := System.FilePath.mk (inputPath.toString.replace s!".input.{JarConfig.name}.json" s!".output.{JarConfig.name}.json")
  let outputContent ← IO.FS.readFile outputPath
  let outputJson ← IO.ofExcept (Json.parse outputContent)
  let pre ← IO.ofExcept (@fromJson? FlatStatisticsState _ (← IO.ofExcept (inputJson.getObjVal? "pre_state")))
  let input ← IO.ofExcept (@fromJson? StatsInput _ (← IO.ofExcept (inputJson.getObjVal? "input")))
  let expectedPost ← IO.ofExcept (@fromJson? FlatStatisticsState _ (← IO.ofExcept (outputJson.getObjVal? "post_state")))
  let name := inputPath.fileName.getD (toString inputPath)
  Statistics.runTest name pre input expectedPost

/-- Run all JSON tests in a directory. -/
def runJsonTestDir (dir : System.FilePath) : IO UInt32 := do
  let entries ← dir.readDir
  let jsonFiles := entries.filter (fun e => e.fileName.endsWith s!".input.{JarConfig.name}.json")
  let sorted := jsonFiles.qsort (fun a b => a.fileName < b.fileName)
  let mut passed := 0
  let mut failed := 0
  for entry in sorted do
    let ok ← runJsonTest entry.path
    if ok then passed := passed + 1 else failed := failed + 1
  IO.println s!"\nStatistics JSON tests: {passed} passed, {failed} failed, {passed + failed} total"
  return if failed > 0 then 1 else 0

end Jar.Test.StatisticsJson
