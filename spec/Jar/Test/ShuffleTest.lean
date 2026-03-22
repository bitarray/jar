import Lean.Data.Json
import Lean.Data.Json.Parser
import Jar.Crypto

/-!
# Shuffle Test Runner

Runs Fisher-Yates shuffle test vectors from `tests/vectors/shuffle/shuffle_tests.json`.
Each test case provides a sequence length, entropy hash, and expected permuted array.
-/

namespace Jar.Test.ShuffleTest

open Lean (Json)

/-- Decode a hex string (no 0x prefix) to ByteArray. -/
private def hexDecode (s : String) : Except String ByteArray := do
  let utf8 := s.toUTF8
  if utf8.size % 2 != 0 then
    throw s!"hex string has odd length: {utf8.size}"
  let nBytes := utf8.size / 2
  let mut result := ByteArray.empty
  for i in [:nBytes] do
    let pos := i * 2
    let hi ← hexDigitByte (utf8.get! pos)
    let lo ← hexDigitByte (utf8.get! (pos + 1))
    result := result.push ((hi <<< 4) ||| lo)
  return result
where
  hexDigitByte (b : UInt8) : Except String UInt8 :=
    if 0x30 ≤ b && b ≤ 0x39 then .ok (b - 0x30)
    else if 0x61 ≤ b && b ≤ 0x66 then .ok (b - 0x61 + 10)
    else if 0x41 ≤ b && b ≤ 0x46 then .ok (b - 0x41 + 10)
    else .error s!"invalid hex digit: {b}"

/-- Parse a single shuffle test case from JSON. Returns (length, entropy, expectedOutput). -/
private def parseTestCase (j : Json) : Except String (Nat × Hash × Array Nat) := do
  let n ← (← j.getObjVal? "input").getNat?
  let entropyStr ← j.getObjValAs? String "entropy"
  let entropyBytes ← hexDecode entropyStr
  if h : entropyBytes.size = 32 then
    let entropy : Hash := ⟨entropyBytes, h⟩
    let outputJson ← j.getObjVal? "output"
    let outputArr ← match outputJson with
      | Json.arr items => items.toList.mapM fun item => item.getNat?
      | _ => .error s!"expected array for output, got {outputJson}"
    return (n, entropy, outputArr.toArray)
  else
    .error s!"entropy must be 32 bytes, got {entropyBytes.size}"

/-- Format an array of Nats as a short string for display. -/
private def showArray (arr : Array Nat) : String :=
  if arr.size ≤ 10 then
    toString arr.toList
  else
    let first := (arr.extract 0 5).toList
    let last := (arr.extract (arr.size - 3) arr.size).toList
    s!"{first} ... {last} ({arr.size} elems)"

/-- Run all shuffle test vectors. Returns 0 on success, 1 on failure. -/
def runAll : IO UInt32 := do
  let path := "tests/vectors/shuffle/shuffle_tests.json"
  IO.println s!"Running shuffle tests from: {path}"
  let contents ← IO.FS.readFile path
  let json ← match Lean.Json.parse contents with
    | .ok j => pure j
    | .error e => IO.println s!"Failed to parse JSON: {e}"; return 1
  let cases ← match json with
    | Json.arr items => pure items
    | _ => IO.println "Expected JSON array"; return 1
  let mut passed := 0
  let mut failed := 0
  for i in [:cases.size] do
    let case_ := cases[i]!
    match parseTestCase case_ with
    | .error e =>
      IO.println s!"  Case {i}: PARSE ERROR: {e}"
      failed := failed + 1
    | .ok (n, entropy, expected) =>
      -- Create array [0, 1, ..., n-1]
      let input := Array.ofFn (n := n) fun ⟨i, _⟩ => i
      let result := Crypto.shuffle input entropy
      if result == expected then
        IO.println s!"  Case {i}: PASS (n={n})"
        passed := passed + 1
      else
        IO.println s!"  Case {i}: FAIL (n={n})"
        IO.println s!"    expected: {showArray expected}"
        IO.println s!"    got:      {showArray result}"
        failed := failed + 1
  IO.println s!"Shuffle tests: {passed} passed, {failed} failed out of {cases.size}"
  return if failed == 0 then 0 else 1

end Jar.Test.ShuffleTest
