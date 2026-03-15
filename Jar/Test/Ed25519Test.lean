import Lean.Data.Json
import Lean.Data.Json.Parser
import Jar.Crypto

/-!
# Ed25519 Signature Verification Test Runner

Runs Ed25519 test vectors from `tests/vectors/ed25519/vectors.json`.
Each test case provides pk, r, s, msg, pk_canonical, and r_canonical.
A signature should verify successfully only when both pk_canonical and r_canonical are true.
-/

namespace Jar.Test.Ed25519Test

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

/-- Decode a hex string to an OctetSeq of exactly n bytes. -/
private def hexDecodeSeq (s : String) (n : Nat) : Except String (OctetSeq n) := do
  let bs ← hexDecode s
  if h : bs.size = n then
    return ⟨bs, h⟩
  else
    throw s!"expected {n} bytes, got {bs.size}"

/-- Encode ByteArray to hex string (no 0x prefix). -/
private def hexEncode (bs : ByteArray) : String :=
  let chars := bs.foldl (init := #[]) fun acc b =>
    acc.push (hexNibble (b >>> 4)) |>.push (hexNibble (b &&& 0x0f))
  String.ofList chars.toList
where
  hexNibble (n : UInt8) : Char :=
    if n < 10 then Char.ofNat (n.toNat + '0'.toNat)
    else Char.ofNat (n.toNat - 10 + 'a'.toNat)

/-- A parsed Ed25519 test vector. -/
structure TestVector where
  number : Nat
  desc : String
  pk : Ed25519PublicKey
  sig : Ed25519Signature
  msg : ByteArray
  pkCanonical : Bool
  rCanonical : Bool

/-- Parse a single test vector from JSON. -/
private def parseTestVector (j : Json) : Except String TestVector := do
  let number ← (← j.getObjVal? "number").getNat?
  let desc ← j.getObjValAs? String "desc"
  let pkHex ← j.getObjValAs? String "pk"
  let rHex ← j.getObjValAs? String "r"
  let sHex ← j.getObjValAs? String "s"
  let msgHex ← j.getObjValAs? String "msg"
  let pkCanonical ← (← j.getObjVal? "pk_canonical").getBool?
  let rCanonical ← (← j.getObjVal? "r_canonical").getBool?
  let pk ← hexDecodeSeq pkHex 32
  let rBytes ← hexDecode rHex
  let sBytes ← hexDecode sHex
  if rBytes.size != 32 then throw s!"r must be 32 bytes, got {rBytes.size}"
  if sBytes.size != 32 then throw s!"s must be 32 bytes, got {sBytes.size}"
  let sigBytes := rBytes ++ sBytes
  -- sigBytes.size = rBytes.size + sBytes.size = 32 + 32 = 64,
  -- but this is runtime knowledge so we use a decidable check.
  if h : sigBytes.size = 64 then
    let sig : Ed25519Signature := ⟨sigBytes, h⟩
    let msg ← hexDecode msgHex
    return { number, desc, pk, sig, msg, pkCanonical, rCanonical }
  else
    throw s!"signature must be 64 bytes, got {sigBytes.size}"

/-- Run all Ed25519 test vectors. Returns 0 on success, 1 on failure. -/
def runAll : IO UInt32 := do
  let path := "tests/vectors/ed25519/vectors.json"
  IO.println s!"Running Ed25519 tests from: {path}"
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
    match parseTestVector case_ with
    | .error e =>
      IO.println s!"  Case {i}: PARSE ERROR: {e}"
      failed := failed + 1
    | .ok tv =>
      -- Expected result: verify succeeds only when both canonical
      let expected := tv.pkCanonical && tv.rCanonical
      let result := Crypto.ed25519Verify tv.pk tv.msg tv.sig
      if result == expected then
        passed := passed + 1
      else
        IO.println s!"  Case {tv.number} ({tv.desc}): FAIL"
        IO.println s!"    expected verify={expected} (pk_canonical={tv.pkCanonical}, r_canonical={tv.rCanonical})"
        IO.println s!"    got verify={result}"
        IO.println s!"    pk={hexEncode tv.pk.data} sig={hexEncode tv.sig.data}"
        failed := failed + 1
  IO.println s!"Ed25519 tests: {passed} passed, {failed} failed out of {cases.size}"
  return if failed == 0 then 0 else 1

end Jar.Test.Ed25519Test
