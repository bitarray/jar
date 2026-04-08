import Jar.Json
import Jar.Test.SafroleJson
import Jar.Test.StatisticsJson
import Jar.Test.AuthorizationsJson
import Jar.Test.HistoryJson
import Jar.Test.DisputesJson
import Jar.Test.AssurancesJson
import Jar.Test.PreimagesJson
import Jar.Test.ReportsJson
import Jar.Test.AccumulateJson

/-!
# STF Server — JSON-based Sub-Transition Function Executor

Reads a JSON test vector (pre_state + input), runs the specified sub-transition,
and writes the output (result + post_state) as JSON to stdout.

Usage: `jar-stf <sub-transition> <input.json>`
-/

namespace Jar.Test.StfServer

open Lean (Json ToJson FromJson toJson fromJson?)
open Jar Jar.Json

variable [JarConfig]

-- ============================================================================
-- Safrole
-- ============================================================================

open Jar.Test.Safrole Jar.Test.SafroleJson in
def runSafrole (json : Json) : IO Json := do
  let pre ← IO.ofExcept (@fromJson? FlatSafroleState _ (← IO.ofExcept (json.getObjVal? "pre_state")))
  let input ← IO.ofExcept (@fromJson? SafroleInput _ (← IO.ofExcept (json.getObjVal? "input")))
  let (result, post) := safroleTransition pre input
  return Json.mkObj [
    ("output", toJson result),
    ("post_state", toJson post)]

-- ============================================================================
-- Statistics
-- ============================================================================

open Jar.Test.Statistics Jar.Test.StatisticsJson in
def runStatistics (json : Json) : IO Json := do
  let pre ← IO.ofExcept (@fromJson? FlatStatisticsState _ (← IO.ofExcept (json.getObjVal? "pre_state")))
  let input ← IO.ofExcept (@fromJson? StatsInput _ (← IO.ofExcept (json.getObjVal? "input")))
  let post := statisticsTransition pre input
  return Json.mkObj [
    ("output", Json.mkObj [("ok", Json.mkObj [])]),
    ("post_state", toJson post)]

-- ============================================================================
-- Authorizations
-- ============================================================================

open Jar.Test.Authorizations Jar.Test.AuthorizationsJson in
def runAuthorizations (json : Json) : IO Json := do
  let pre ← IO.ofExcept (@fromJson? FlatAuthState _ (← IO.ofExcept (json.getObjVal? "pre_state")))
  let input ← IO.ofExcept (@fromJson? AuthInput _ (← IO.ofExcept (json.getObjVal? "input")))
  let post := authorizationTransition pre input
  return Json.mkObj [
    ("output", Json.mkObj [("ok", Json.mkObj [])]),
    ("post_state", toJson post)]

-- ============================================================================
-- History
-- ============================================================================

open Jar.Test.History Jar.Test.HistoryJson in
def runHistory (json : Json) : IO Json := do
  let preStateJson ← IO.ofExcept (json.getObjVal? "pre_state")
  let betaPre ← IO.ofExcept (preStateJson.getObjVal? "beta")
  let pre ← IO.ofExcept (@fromJson? FlatHistoryState _ betaPre)
  let input ← IO.ofExcept (@fromJson? HistoryInput _ (← IO.ofExcept (json.getObjVal? "input")))
  let post := historyTransition pre input
  return Json.mkObj [
    ("output", Json.mkObj [("ok", Json.mkObj [])]),
    ("post_state", Json.mkObj [("beta", toJson post)])]

-- ============================================================================
-- Disputes
-- ============================================================================

open Jar.Test.Disputes Jar.Test.DisputesJson in
def runDisputes (json : Json) : IO Json := do
  let pre ← IO.ofExcept (@fromJson? TDState _ (← IO.ofExcept (json.getObjVal? "pre_state")))
  let inputJson ← IO.ofExcept (json.getObjVal? "input")
  let inp ← IO.ofExcept (@fromJson? TDInput _ (← IO.ofExcept (inputJson.getObjVal? "disputes")))
  let (result, postPsi) := disputesTransition pre inp
  return Json.mkObj [
    ("output", toJson result),
    ("post_state", Json.mkObj [("psi", toJson postPsi)])]

-- ============================================================================
-- Assurances
-- ============================================================================

open Jar.Test.Assurances Jar.Test.AssurancesJson in
def runAssurances (json : Json) : IO Json := do
  let pre ← IO.ofExcept (@fromJson? TAState _ (← IO.ofExcept (json.getObjVal? "pre_state")))
  let input ← IO.ofExcept (@fromJson? TAInput _ (← IO.ofExcept (json.getObjVal? "input")))
  let (result, postAvail) := assurancesTransition pre input
  return Json.mkObj [
    ("output", toJson result),
    ("post_state", Json.mkObj [("avail_assignments", Json.arr (postAvail.map fun a =>
      match a with | none => Json.null | some v => toJson v))])]

-- ============================================================================
-- Preimages
-- ============================================================================

open Jar.Test.Preimages Jar.Test.PreimagesJson in
def runPreimages (json : Json) : IO Json := do
  let pre ← IO.ofExcept (parseTPState (← IO.ofExcept (json.getObjVal? "pre_state")))
  let input ← IO.ofExcept (@fromJson? TPInput _ (← IO.ofExcept (json.getObjVal? "input")))
  let (result, post) := preimagesTransition pre input
  return Json.mkObj [
    ("output", toJson result),
    ("post_state", toJsonTPState post)]

-- ============================================================================
-- Reports
-- ============================================================================

open Jar.Test.Reports Jar.Test.ReportsJson in
def runReports (json : Json) : IO Json := do
  let pre ← IO.ofExcept (@fromJson? TRState _ (← IO.ofExcept (json.getObjVal? "pre_state")))
  let input ← IO.ofExcept (@fromJson? TRInput _ (← IO.ofExcept (json.getObjVal? "input")))
  let (result, postAvail) := reportsTransition pre input
  return Json.mkObj [
    ("output", toJson result),
    ("post_state", Json.mkObj [("avail_assignments", Json.arr (postAvail.map fun a =>
      match a with | none => Json.null | some v => toJson v))])]

-- ============================================================================
-- Accumulate
-- ============================================================================

open Jar.Test.Accumulate Jar.Test.AccumulateJson in
def runAccumulate (json : Json) (baseDir : System.FilePath := ".") : IO Json := do
  let json ← resolveBlobFiles json baseDir
  let pre ← IO.ofExcept (parseGreyState (← IO.ofExcept (json.getObjVal? "pre_state")))
  let input ← IO.ofExcept (parseGreyInput (← IO.ofExcept (json.getObjVal? "input")))
  let (hash, post) := accumulateTransition pre input
  return Json.mkObj [
    ("output", Json.mkObj [("ok", toJson hash)]),
    ("post_state", toJsonGreyState post)]

-- ============================================================================
-- Dispatcher
-- ============================================================================

private def allTransitions : String :=
  "safrole, statistics, authorizations, history, disputes, assurances, preimages, reports, accumulate"

def runSubTransition (name : String) (json : Json) (baseDir : System.FilePath := ".") : IO Json :=
  match name with
  | "safrole" => runSafrole json
  | "statistics" => runStatistics json
  | "authorizations" => runAuthorizations json
  | "history" => runHistory json
  | "disputes" => runDisputes json
  | "assurances" => runAssurances json
  | "preimages" => runPreimages json
  | "reports" => runReports json
  | "accumulate" => runAccumulate json baseDir
  | other => throw (IO.userError s!"unknown sub-transition: {other}\nSupported: {allTransitions}")

private def blessFile (subTransition : String) (inputPath : System.FilePath) : IO Unit := do
  let content ← IO.FS.readFile inputPath
  let json ← IO.ofExcept (Json.parse content)
  -- Run transition on pre_state + input
  let baseDir := inputPath.parent.getD "."
  let result ← runSubTransition subTransition json baseDir
  -- Write computed output/post_state to the output file only
  let outputPath := System.FilePath.mk (inputPath.toString.replace s!".input.{JarConfig.name}.json" s!".output.{JarConfig.name}.json")
  IO.FS.writeFile outputPath (result.pretty ++ "\n")
  IO.println s!"  blessed: {inputPath.fileName.getD (toString inputPath)}"

private def blessDir (subTransition : String) (dir : System.FilePath) : IO UInt32 := do
  let entries ← dir.readDir
  let jsonFiles := entries.filter (fun e => e.fileName.endsWith s!".input.{JarConfig.name}.json")
  let sorted := jsonFiles.qsort (fun a b => a.fileName < b.fileName)
  IO.println s!"Blessing {sorted.size} test vectors in: {dir}"
  for entry in sorted do
    blessFile subTransition entry.path
  IO.println s!"Done: {sorted.size} files blessed."
  return 0

def main (args : List String) : IO UInt32 := do
  match args with
  | ["--bless", subTransition, dir] =>
    blessDir subTransition dir
  | [subTransition, inputPath] =>
    let content ← IO.FS.readFile inputPath
    let json ← IO.ofExcept (Json.parse content)
    let result ← runSubTransition subTransition json
    IO.println result.pretty
    return 0
  | _ =>
    IO.eprintln "Usage: jar-stf <sub-transition> <input.json>"
    IO.eprintln "       jar-stf --bless <sub-transition> <dir>"
    IO.eprintln s!"Supported sub-transitions: {allTransitions}"
    return 1

end Jar.Test.StfServer
