import Lean.Data.Json
import Lean.Data.Json.Parser
import Jar.Merkle
import Jar.Json

/-!
# Trie Test Runner

Runs Merkle trie root test vectors from `tests/vectors/trie/trie.json`.
Each test case provides a dict of hex_key -> hex_value pairs and an expected
Merkle root hash. Keys are 32 bytes; leaf encoding truncates to 31 bytes.
-/

namespace Jar.Test.TrieTest

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

/-- Encode ByteArray to hex string (no 0x prefix). -/
private def hexEncode (bs : ByteArray) : String :=
  let chars := bs.foldl (init := #[]) fun acc b =>
    acc.push (hexNibble (b >>> 4)) |>.push (hexNibble (b &&& 0x0f))
  String.ofList chars.toList
where
  hexNibble (n : UInt8) : Char :=
    if n < 10 then Char.ofNat (n.toNat + '0'.toNat)
    else Char.ofNat (n.toNat - 10 + 'a'.toNat)

/-- Parse a single trie test case from JSON. Returns (entries, expectedHash). -/
private def parseTestCase (j : Json) : Except String (Array (ByteArray × ByteArray) × ByteArray) := do
  let inputObj ← j.getObjVal? "input"
  let outputStr ← j.getObjValAs? String "output"
  let expectedHash ← hexDecode outputStr
  let mut entries : Array (ByteArray × ByteArray) := #[]
  match inputObj with
  | Json.obj kvs =>
    for ⟨k, v⟩ in kvs.toArray do
      let keyBytes ← hexDecode k
      let valStr ← match v with
        | Json.str s => pure s
        | _ => .error s!"expected string value, got {v}"
      let valBytes ← hexDecode valStr
      entries := entries.push (keyBytes, valBytes)
  | _ => throw s!"expected object for input, got {inputObj}"
  return (entries, expectedHash)

/-- Run all trie test vectors. Returns 0 on success, 1 on failure. -/
def runAll : IO UInt32 := do
  let path := "tests/vectors/trie/trie.json"
  IO.println s!"Running trie tests from: {path}"
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
    | .ok (entries, expectedHash) =>
      let result := Merkle.trieRoot32 entries
      let resultBytes := result.data
      if resultBytes == expectedHash then
        IO.println s!"  Case {i}: PASS ({entries.size} keys)"
        passed := passed + 1
      else
        IO.println s!"  Case {i}: FAIL ({entries.size} keys)"
        IO.println s!"    expected: {hexEncode expectedHash}"
        IO.println s!"    got:      {hexEncode resultBytes}"
        failed := failed + 1
  IO.println s!"Trie tests: {passed} passed, {failed} failed out of {cases.size}"
  return if failed == 0 then 0 else 1

end Jar.Test.TrieTest
