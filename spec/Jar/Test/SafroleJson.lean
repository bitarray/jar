import Jar.Json
import Jar.Test.Safrole

/-!
# Safrole JSON Test Runner

FromJson/ToJson instances for safrole test-specific types and a JSON-based test runner.
-/

namespace Jar.Test.SafroleJson

open Lean (Json ToJson FromJson toJson fromJson?)
open Jar Jar.Json Jar.Test.Safrole

variable [JarConfig]

-- ============================================================================
-- JSON instances for safrole test types
-- ============================================================================

private def ticketProofFromJson (j : Json) : Except String TicketProof := do
  let attempt ← (← j.getObjVal? "attempt").getNat?
  let sig ← @fromJson? BandersnatchRingVrfProof _ (← j.getObjVal? "signature")
  return { attempt, proof := sig }

private def ticketFromJson (j : Json) : Except String Ticket := do
  let id ← @fromJson? Hash _ (← j.getObjVal? "id")
  let attempt ← (← j.getObjVal? "attempt").getNat?
  return { id := id, attempt }

instance : FromJson FlatSafroleState where
  fromJson? j := do
    let tau ← @fromJson? Timeslot _ (← j.getObjVal? "tau")
    let eta ← @fromJson? (Array Hash) _ (← j.getObjVal? "eta")
    let lambda ← @fromJson? (Array ValidatorKey) _ (← j.getObjVal? "lambda")
    let kappa ← @fromJson? (Array ValidatorKey) _ (← j.getObjVal? "kappa")
    let gamma_k ← @fromJson? (Array ValidatorKey) _ (← j.getObjVal? "gamma_k")
    let iota ← @fromJson? (Array ValidatorKey) _ (← j.getObjVal? "iota")
    -- gamma_a: Array Ticket — need custom deserialization for attempt field
    let gamma_a_json ← j.getObjVal? "gamma_a"
    let gamma_a ← match gamma_a_json with
      | Json.arr items => items.toList.mapM ticketFromJson |>.map Array.mk
      | _ => .error "expected array for gamma_a"
    let gamma_s ← @fromJson? SealKeySeries _ (← j.getObjVal? "gamma_s")
    let gamma_z ← @fromJson? BandersnatchRingRoot _ (← j.getObjVal? "gamma_z")
    let post_offenders ← @fromJson? (Array Ed25519PublicKey) _ (← j.getObjVal? "post_offenders")
    return { tau, eta, lambda, kappa, gamma_k, iota, gamma_a, gamma_s, gamma_z, post_offenders }

instance : ToJson FlatSafroleState where
  toJson s := Json.mkObj [
    ("tau", toJson s.tau),
    ("eta", toJson s.eta),
    ("lambda", toJson s.lambda),
    ("kappa", toJson s.kappa),
    ("gamma_k", toJson s.gamma_k),
    ("iota", toJson s.iota),
    ("gamma_a", toJson s.gamma_a),
    ("gamma_s", toJson s.gamma_s),
    ("gamma_z", toJson s.gamma_z),
    ("post_offenders", toJson s.post_offenders)]

instance : FromJson SafroleInput where
  fromJson? j := do
    let slot ← @fromJson? Timeslot _ (← j.getObjVal? "slot")
    let entropy ← @fromJson? Hash _ (← j.getObjVal? "entropy")
    let extrinsic_json ← j.getObjVal? "extrinsic"
    let extrinsic ← match extrinsic_json with
      | Json.arr items => items.toList.mapM ticketProofFromJson |>.map Array.mk
      | _ => .error "expected array for extrinsic"
    return { slot, entropy, extrinsic }

instance : ToJson SafroleInput where
  toJson i := Json.mkObj [
    ("slot", toJson i.slot),
    ("entropy", toJson i.entropy),
    ("extrinsic", toJson i.extrinsic)]

instance : FromJson SafroleOutput where
  fromJson? j := do
    let epoch_mark_json := j.getObjVal? "epoch_mark"
    let epoch_mark ← match epoch_mark_json with
      | .ok Json.null => pure none
      | .ok v => do pure (some (← @fromJson? EpochMarker _ v))
      | .error _ => pure none
    let tickets_mark_json := j.getObjVal? "tickets_mark"
    let tickets_mark ← match tickets_mark_json with
      | .ok Json.null => pure none
      | .ok v => do
        -- Array Ticket with custom attempt handling
        match v with
        | Json.arr items => do
          let arr ← items.toList.mapM ticketFromJson |>.map Array.mk
          pure (some arr)
        | _ => .error "expected array for tickets_mark"
      | .error _ => pure none
    return { epoch_mark, tickets_mark }

instance : ToJson SafroleOutput where
  toJson o := Json.mkObj [
    ("epoch_mark", match o.epoch_mark with | none => Json.null | some em => toJson em),
    ("tickets_mark", match o.tickets_mark with | none => Json.null | some ts => toJson ts)]

instance : FromJson SafroleResult where
  fromJson? j := do
    if let .ok v := j.getObjVal? "ok" then
      return .ok (← @fromJson? SafroleOutput _ v)
    else if let .ok (Json.str e) := j.getObjVal? "err" then
      return .err e
    else
      .error "SafroleResult: expected 'ok' or 'err'"

instance : ToJson SafroleResult where
  toJson
    | .ok out => Json.mkObj [("ok", toJson out)]
    | .err e => Json.mkObj [("err", Json.str e)]

-- ============================================================================
-- JSON Test Runner
-- ============================================================================

/-- Run a single safrole test from separate input/output JSON files. -/
def runJsonTest (inputPath : System.FilePath) : IO Bool := do
  let inputContent ← IO.FS.readFile inputPath
  let inputJson ← IO.ofExcept (Json.parse inputContent)
  let outputPath := System.FilePath.mk (inputPath.toString.replace s!".input.{JarConfig.name}.json" s!".output.{JarConfig.name}.json")
  let outputContent ← IO.FS.readFile outputPath
  let outputJson ← IO.ofExcept (Json.parse outputContent)
  let pre ← IO.ofExcept (@fromJson? FlatSafroleState _ (← IO.ofExcept (inputJson.getObjVal? "pre_state")))
  let input ← IO.ofExcept (@fromJson? SafroleInput _ (← IO.ofExcept (inputJson.getObjVal? "input")))
  let expectedResult ← IO.ofExcept (@fromJson? SafroleResult _ (← IO.ofExcept (outputJson.getObjVal? "output")))
  let expectedPost ← IO.ofExcept (@fromJson? FlatSafroleState _ (← IO.ofExcept (outputJson.getObjVal? "post_state")))
  let name := inputPath.fileName.getD (toString inputPath)
  Safrole.runTest name pre input expectedResult expectedPost

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
  IO.println s!"\nSafrole JSON tests: {passed} passed, {failed} failed, {passed + failed} total"
  return if failed > 0 then 1 else 0

end Jar.Test.SafroleJson
