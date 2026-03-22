import Jar.Json
import Jar.Test.Disputes

namespace Jar.Test.DisputesJson

open Lean (Json ToJson FromJson toJson fromJson?)
open Jar Jar.Json Jar.Test.Disputes

variable [JamConfig]

-- ============================================================================
-- JSON instances for disputes test types
-- ============================================================================

instance : FromJson TDVote where
  fromJson? j := do
    let vote ← (← j.getObjVal? "vote").getBool?
    let index ← (← j.getObjVal? "index").getNat?
    let signature ← @fromJson? Ed25519Signature _ (← j.getObjVal? "signature")
    return { vote, index, signature }

instance : FromJson TDVerdict where
  fromJson? j := do
    let target ← @fromJson? Hash _ (← j.getObjVal? "target")
    let age ← (← j.getObjVal? "age").getNat?
    let votes ← @fromJson? (Array TDVote) _ (← j.getObjVal? "votes")
    return { target, age, votes }

instance : FromJson TDCulprit where
  fromJson? j := do
    let target ← @fromJson? Hash _ (← j.getObjVal? "target")
    let key ← @fromJson? Ed25519PublicKey _ (← j.getObjVal? "key")
    let signature ← @fromJson? Ed25519Signature _ (← j.getObjVal? "signature")
    return { target, key, signature }

instance : FromJson TDFault where
  fromJson? j := do
    let target ← @fromJson? Hash _ (← j.getObjVal? "target")
    let vote ← (← j.getObjVal? "vote").getBool?
    let key ← @fromJson? Ed25519PublicKey _ (← j.getObjVal? "key")
    let signature ← @fromJson? Ed25519Signature _ (← j.getObjVal? "signature")
    return { target, vote, key, signature }

instance : FromJson TDInput where
  fromJson? j := do
    let verdicts ← @fromJson? (Array TDVerdict) _ (← j.getObjVal? "verdicts")
    let culprits ← @fromJson? (Array TDCulprit) _ (← j.getObjVal? "culprits")
    let faults ← @fromJson? (Array TDFault) _ (← j.getObjVal? "faults")
    return { verdicts, culprits, faults }

instance : FromJson TDJudgments where
  fromJson? j := do
    let good ← @fromJson? (Array Hash) _ (← j.getObjVal? "good")
    let bad ← @fromJson? (Array Hash) _ (← j.getObjVal? "bad")
    let wonky ← @fromJson? (Array Hash) _ (← j.getObjVal? "wonky")
    let offenders ← @fromJson? (Array Ed25519PublicKey) _ (← j.getObjVal? "offenders")
    return { good, bad, wonky, offenders }

-- rho in Grey JSON: array of null | {report, timeout}
-- In Lean: Array Bool (presence = true)
private def parseRho (j : Json) : Except String (Array Bool) := do
  match j with
  | Json.arr items => return items.map fun
    | Json.null => false
    | _ => true
  | _ => .error "expected array for rho"

instance : FromJson TDState where
  fromJson? j := do
    let psi ← @fromJson? TDJudgments _ (← j.getObjVal? "psi")
    let rho ← parseRho (← j.getObjVal? "rho")
    let tau ← @fromJson? Timeslot _ (← j.getObjVal? "tau")
    let kappa ← @fromJson? (Array ValidatorKey) _ (← j.getObjVal? "kappa")
    let lambda ← @fromJson? (Array ValidatorKey) _ (← j.getObjVal? "lambda")
    return { psi, rho, tau, kappa, lambda }

instance : FromJson TDResult where
  fromJson? j := do
    if let .ok v := j.getObjVal? "ok" then
      let offenders ← @fromJson? (Array Ed25519PublicKey) _ (← v.getObjVal? "offenders_mark")
      return .ok offenders
    else if let .ok (Json.str e) := j.getObjVal? "err" then
      return .err e
    else
      .error "TDResult: expected 'ok' or 'err'"

-- ============================================================================
-- ToJson instances for STF server output
-- ============================================================================

instance : ToJson TDJudgments where
  toJson j := Json.mkObj [
    ("good", toJson j.good),
    ("bad", toJson j.bad),
    ("wonky", toJson j.wonky),
    ("offenders", toJson j.offenders)]

instance : ToJson TDResult where
  toJson
    | .ok offenders => Json.mkObj [("ok", Json.mkObj [("offenders_mark", toJson offenders)])]
    | .err e => Json.mkObj [("err", Json.str e)]

-- ============================================================================
-- JSON Test Runner
-- ============================================================================

def runJsonTest (inputPath : System.FilePath) : IO Bool := do
  let inputContent ← IO.FS.readFile inputPath
  let inputJson ← IO.ofExcept (Json.parse inputContent)
  let outputPath := System.FilePath.mk (inputPath.toString.replace s!".input.{JamConfig.name}.json" s!".output.{JamConfig.name}.json")
  let outputContent ← IO.FS.readFile outputPath
  let outputJson ← IO.ofExcept (Json.parse outputContent)
  let pre ← IO.ofExcept (@fromJson? TDState _ (← IO.ofExcept (inputJson.getObjVal? "pre_state")))
  -- input wraps in "disputes" object
  let inputObj ← IO.ofExcept (inputJson.getObjVal? "input")
  let inp ← IO.ofExcept (@fromJson? TDInput _ (← IO.ofExcept (inputObj.getObjVal? "disputes")))
  let expectedResult ← IO.ofExcept (@fromJson? TDResult _ (← IO.ofExcept (outputJson.getObjVal? "output")))
  let postPsi ← IO.ofExcept (@fromJson? TDJudgments _ (← IO.ofExcept ((← IO.ofExcept (outputJson.getObjVal? "post_state")).getObjVal? "psi")))
  let name := inputPath.fileName.getD (toString inputPath)
  Disputes.runTest name pre inp expectedResult postPsi

def runJsonTestDir (dir : System.FilePath) : IO UInt32 := do
  let entries ← dir.readDir
  let jsonFiles := entries.filter (fun e => e.fileName.endsWith s!".input.{JamConfig.name}.json")
  let sorted := jsonFiles.qsort (fun a b => a.fileName < b.fileName)
  let mut passed := 0
  let mut failed := 0
  for entry in sorted do
    let ok ← runJsonTest entry.path
    if ok then passed := passed + 1 else failed := failed + 1
  IO.println s!"\nDisputes JSON tests: {passed} passed, {failed} failed, {passed + failed} total"
  return if failed > 0 then 1 else 0

end Jar.Test.DisputesJson
