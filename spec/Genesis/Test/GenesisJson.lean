/-
  Genesis Protocol — JSON Test Runner

  FromJson/ToJson for test-specific types and a JSON-based test runner
  that dispatches by filename prefix.
-/

import Genesis.Test.Genesis

namespace Genesis.Test.GenesisJson

open Lean (Json ToJson FromJson toJson fromJson?)
open Genesis.Json Genesis.Test

/-! ### JSON instances for test types -/

instance : FromJson SelectTargetsInput where
  fromJson? j := do
    let prId ← j.getObjValAs? Nat "prId"
    let prCreatedAt ← j.getObjValAs? Nat "prCreatedAt"
    let indices ← j.getObjValAs? (List CommitIndex) "indices"
    let ranking ← match j.getObjVal? "ranking" with
      | .ok v => some <$> @fromJson? (List CommitId) _ v
      | .error _ => pure none
    return { prId, prCreatedAt, indices, ranking }

instance : ToJson SelectTargetsOutput where
  toJson o := Json.mkObj [("targets", toJson o.targets)]

instance : FromJson SelectTargetsOutput where
  fromJson? j := do
    let targets ← j.getObjValAs? (List CommitId) "targets"
    return { targets }

instance : FromJson EvaluateInput where
  fromJson? j := do
    let commit ← j.getObjValAs? SignedCommit "commit"
    let pastIndices ← j.getObjValAs? (List CommitIndex) "pastIndices"
    let ranking ← match j.getObjVal? "ranking" with
      | .ok v => some <$> @fromJson? (List CommitId) _ v
      | .error _ => pure none
    return { commit, pastIndices, ranking }

instance : FromJson CheckMergeInput where
  fromJson? j := do
    let reviews ← j.getObjValAs? (List EmbeddedReview) "reviews"
    let metaReviews ← j.getObjValAs? (List MetaReview) "metaReviews"
    let indices ← j.getObjValAs? (List CommitIndex) "indices"
    return { reviews, metaReviews, indices }

instance : ToJson CheckMergeOutput where
  toJson o := Json.mkObj [
    ("ready", toJson o.ready),
    ("mergeWeight", toJson o.mergeWeight),
    ("rejectWeight", toJson o.rejectWeight),
    ("totalWeight", toJson o.totalWeight)]

instance : FromJson CheckMergeOutput where
  fromJson? j := do
    let ready ← j.getObjValAs? Bool "ready"
    let mergeWeight ← j.getObjValAs? Nat "mergeWeight"
    let rejectWeight ← j.getObjValAs? Nat "rejectWeight"
    let totalWeight ← j.getObjValAs? Nat "totalWeight"
    return { ready, mergeWeight, rejectWeight, totalWeight }

instance : FromJson RankingInput where
  fromJson? j := do
    let signedCommits ← j.getObjValAs? (List SignedCommit) "signedCommits"
    let indices ← j.getObjValAs? (List CommitIndex) "indices"
    return { signedCommits, indices }

instance : ToJson BTScore where
  toJson s := Json.mkObj [("commit", toJson s.commit), ("mu", toJson s.mu), ("sigma2", toJson s.sigma2)]

instance : FromJson BTScore where
  fromJson? j := do
    let commit ← j.getObjValAs? CommitId "commit"
    let mu ← j.getObjValAs? Int "mu"
    let sigma2 ← j.getObjValAs? Nat "sigma2"
    return { commit, mu, sigma2 }

instance : ToJson RankingOutput where
  toJson o :=
    let fields := [("ranking", toJson o.ranking)]
    let fields := match o.scores with
      | some s => fields ++ [("scores", toJson s)]
      | none => fields
    Json.mkObj fields

instance : FromJson RankingOutput where
  fromJson? j := do
    let ranking ← j.getObjValAs? (List CommitId) "ranking"
    let scores ← match j.getObjVal? "scores" with
      | .ok v => some <$> @fromJson? (List BTScore) _ v
      | .error _ => pure none
    return { ranking, scores }

instance : FromJson FinalizeInput where
  fromJson? j := do
    let indices ← j.getObjValAs? (List CommitIndex) "indices"
    return { indices }

instance : ToJson FinalizeOutput where
  toJson o := Json.mkObj [
    ("weights", Json.arr (o.weights.toArray.map fun (id, w) =>
      Json.mkObj [("id", toJson id), ("weight", toJson w)]))]

instance : FromJson FinalizeOutput where
  fromJson? j := do
    let arr ← j.getObjValAs? (List Json) "weights"
    let weights ← arr.mapM fun item => do
      let id ← item.getObjValAs? String "id"
      let weight ← item.getObjValAs? Nat "weight"
      return (id, weight)
    return { weights }

instance : FromJson ScoringFunction where
  fromJson?
    | Json.str "percentileFromRanking" => .ok .percentileFromRanking
    | Json.str "weightedQuantile" => .ok .weightedQuantile
    | j => .error s!"unknown scoring function: {j}"

instance : FromJson ScoringInput where
  fromJson? j := do
    let function ← j.getObjValAs? ScoringFunction "function"
    let ranking ← match j.getObjVal? "ranking" with
      | .ok v => some <$> @fromJson? (List CommitId) _ v
      | .error _ => pure none
    let currentPR ← match j.getObjVal? "currentPR" with
      | .ok v => some <$> @fromJson? CommitId _ v
      | .error _ => pure none
    let entries ← match j.getObjVal? "entries" with
      | .ok v => some <$> @fromJson? (List (Nat × Nat)) _ v
      | .error _ => pure none
    return { function, ranking, currentPR, entries }

instance : ToJson ScoringOutput where
  toJson o := Json.mkObj [("result", toJson o.result)]

instance : FromJson ScoringOutput where
  fromJson? j := do
    let result ← j.getObjValAs? Nat "result"
    return { result }

/-! ### JSON Test Runner -/

/-- Run a single test: dispatch by filename prefix, compare output. -/
def runJsonTest (inputPath : System.FilePath) (bless : Bool) : IO Bool := do
  let inputContent ← IO.FS.readFile inputPath
  let inputJson ← IO.ofExcept (Json.parse inputContent)
  let outputPath := System.FilePath.mk (inputPath.toString.replace ".input.json" ".output.json")
  let name := inputPath.fileName.getD (toString inputPath)
  let shortName := name.replace ".input.json" ""

  -- Dispatch and compute actual output
  let actualJson ←
    if shortName.startsWith "select_targets-" then
      let input ← IO.ofExcept (@fromJson? SelectTargetsInput _ inputJson)
      let output := runSelectTargetsTest input
      pure (toJson output)
    else if shortName.startsWith "evaluate-" then
      let input ← IO.ofExcept (@fromJson? EvaluateInput _ inputJson)
      let output := runEvaluateTest input
      pure (toJson output)
    else if shortName.startsWith "check_merge-" then
      let input ← IO.ofExcept (@fromJson? CheckMergeInput _ inputJson)
      let output := runCheckMergeTest input
      pure (toJson output)
    else if shortName.startsWith "ranking-" then
      let input ← IO.ofExcept (@fromJson? RankingInput _ inputJson)
      let output := runRankingTest input
      pure (toJson output)
    else if shortName.startsWith "finalize-" then
      let input ← IO.ofExcept (@fromJson? FinalizeInput _ inputJson)
      let output := runFinalizeTest input
      pure (toJson output)
    else if shortName.startsWith "scoring-" then
      let input ← IO.ofExcept (@fromJson? ScoringInput _ inputJson)
      let output := runScoringTest input
      pure (toJson output)
    else
      IO.eprintln s!"  ? {shortName}: unknown test category (skipped)"
      return true

  if bless then
    IO.FS.writeFile outputPath (actualJson.pretty 2 ++ "\n")
    IO.println s!"  ✓ {shortName} (blessed)"
    return true
  else
    let outputContent ← IO.FS.readFile outputPath
    let expectedJson ← IO.ofExcept (Json.parse outputContent)
    compareJson shortName expectedJson actualJson

/-- Run all JSON tests in a directory. -/
def runJsonTestDir (dir : System.FilePath) (bless : Bool := false) : IO UInt32 := do
  let entries ← dir.readDir
  let jsonFiles := entries.filter (fun e => e.fileName.endsWith ".input.json")
  let sorted := jsonFiles.qsort (fun a b => a.fileName < b.fileName)
  if sorted.isEmpty then
    IO.println s!"No test vectors found in {dir}"
    return 1
  let mut passed := 0
  let mut failed := 0
  for entry in sorted do
    let ok ← runJsonTest entry.path bless
    if ok then passed := passed + 1 else failed := failed + 1
  IO.println s!"\nGenesis tests: {passed} passed, {failed} failed, {passed + failed} total"
  return if failed > 0 then 1 else 0

end Genesis.Test.GenesisJson
