import Jar.Json
import Jar.Crypto
import Jar.Codec.Jar1
import Jar.Codec.Common
import Jar.Variant

/-!
# Reports Test Vector Generator for jar1

Re-signs existing reports test vector inputs with jar1 codec encoding.
Reads each *.input.jar1.json, re-encodes work reports with jar1 codec,
re-signs guarantor signatures with deterministic test keys, and replaces
both the validator keys in pre_state and the signatures in guarantees.

Usage: lake build genreports && .lake/build/bin/genreports tests/vectors/reports
-/

namespace Jar.Test.GenReports

open Lean (Json toJson fromJson?)
open Jar Jar.Crypto Jar.Json

-- Use jar1 variant for encoding
instance : JamVariant := JamVariant.jar1

-- ============================================================================
-- Hex helpers
-- ============================================================================

private def hexDigit (n : UInt8) : Char :=
  if n < 10 then Char.ofNat (48 + n.toNat) else Char.ofNat (87 + n.toNat)

def toHex (bs : ByteArray) : String := Id.run do
  let mut s := "0x"
  for b in bs.data do
    s := s.push (hexDigit (b / 16))
    s := s.push (hexDigit (b % 16))
  return s

private def fromHex (s : String) : ByteArray :=
  let s := (if s.startsWith "0x" then s.drop 2 else s).toString
  if s.isEmpty then ByteArray.empty
  else
    let hexToNibble (c : Char) : UInt8 :=
      if '0' ≤ c && c ≤ '9' then c.toNat.toUInt8 - 48
      else if 'a' ≤ c && c ≤ 'f' then c.toNat.toUInt8 - 87
      else if 'A' ≤ c && c ≤ 'F' then c.toNat.toUInt8 - 55
      else 0
    let bytes := Id.run do
      let mut result : Array UInt8 := #[]
      let chars := s.data
      let mut i := 0
      while h : i + 1 < chars.length do
        let hi := hexToNibble chars[i]!
        let lo := hexToNibble chars[i + 1]!
        result := result.push (hi * 16 + lo)
        i := i + 2
      return result
    ByteArray.mk bytes

-- ============================================================================
-- Key derivation (matches grey-consensus/src/genesis.rs)
-- ============================================================================

/-- Generate deterministic Ed25519 seed for validator index. -/
def ed25519Seed (index : Nat) : ByteArray :=
  let seed := ByteArray.mk (Array.replicate 32 0)
  let seed := seed.set! 0 (UInt8.ofNat (index % 256))
  let seed := seed.set! 1 (UInt8.ofNat (index / 256))
  seed.set! 31 0xED

/-- Make a test validator with deterministic keys. -/
structure TestValidator where
  index : Nat
  seed : ByteArray
  publicKey : Ed25519PublicKey

instance : Inhabited TestValidator where
  default := { index := 0, seed := ByteArray.mk (Array.replicate 32 0), publicKey := default }

def makeValidator (index : Nat) : TestValidator :=
  let seed := ed25519Seed index
  { index, seed, publicKey := ed25519PublicFromSeed seed }

-- ============================================================================
-- jar1 Work Report Encoding (from JSON)
-- ============================================================================

/-- Helper: get a Nat from JSON, defaulting to 0. -/
private def jnat (j : Json) : Nat :=
  match j.getNat? with
  | .ok n => n
  | .error _ => 0

/-- Helper: get a String from JSON. -/
private def jstr (j : Json) : String :=
  match j with
  | Json.str s => s
  | _ => ""

/-- Helper: get object field, return null if missing. -/
private def jget (j : Json) (key : String) : Json :=
  match j.getObjVal? key with
  | .ok v => v
  | .error _ => Json.null

/-- Helper: get array, return empty if missing. -/
private def jarr (j : Json) : Array Json :=
  match j with
  | Json.arr a => a
  | _ => #[]

/-- Encode a work report from its JSON representation using jar1 codec.
    Returns the raw bytes for hashing/signing. -/
def encodeWorkReportFromJson (report : Json) : ByteArray := Id.run do
  let ps := jget report "package_spec"
  let ctx := jget report "context"
  let enc := Codec.Common.encodeFixedNat

  let mut buf := ByteArray.empty

  -- AvailabilitySpec
  buf := buf ++ fromHex (jstr (jget ps "hash"))
  buf := buf ++ enc 4 (jnat (jget ps "length"))
  buf := buf ++ fromHex (jstr (jget ps "erasure_root"))
  buf := buf ++ fromHex (jstr (jget ps "exports_root"))
  buf := buf ++ enc 2 (jnat (jget ps "exports_count"))

  -- RefinementContext
  buf := buf ++ fromHex (jstr (jget ctx "anchor"))
  buf := buf ++ fromHex (jstr (jget ctx "state_root"))
  buf := buf ++ fromHex (jstr (jget ctx "beefy_root"))
  buf := buf ++ fromHex (jstr (jget ctx "lookup_anchor"))
  buf := buf ++ enc 4 (jnat (jget ctx "lookup_anchor_timeslot"))
  let prereqs := jarr (jget ctx "prerequisites")
  buf := buf ++ enc 4 prereqs.size
  for h in prereqs do
    buf := buf ++ fromHex (jstr h)

  -- core_index: u16 LE
  buf := buf ++ enc 2 (jnat (jget report "core_index"))
  -- authorizer_hash
  buf := buf ++ fromHex (jstr (jget report "authorizer_hash"))
  -- auth_gas_used: u64 LE
  buf := buf ++ enc 8 (jnat (jget report "auth_gas_used"))
  -- auth_output: u32 length + bytes
  let authOutput := fromHex (jstr (jget report "auth_output"))
  buf := buf ++ enc 4 authOutput.size
  buf := buf ++ authOutput
  -- segment_root_lookup: u32 count + entries
  let srl := jarr (jget report "segment_root_lookup")
  buf := buf ++ enc 4 srl.size
  for entry in srl do
    buf := buf ++ fromHex (jstr (jget entry "key"))
    buf := buf ++ fromHex (jstr (jget entry "value"))
  -- results: u32 count + WorkDigests
  let results := jarr (jget report "results")
  buf := buf ++ enc 4 results.size
  for d in results do
    buf := buf ++ enc 4 (jnat (jget d "service_id"))
    buf := buf ++ fromHex (jstr (jget d "code_hash"))
    buf := buf ++ fromHex (jstr (jget d "payload_hash"))
    buf := buf ++ enc 8 (jnat (jget d "accumulate_gas"))
    -- WorkResult
    match jget d "result" |>.getObjVal? "ok" with
    | .ok okVal =>
      let data := fromHex (jstr okVal)
      buf := buf ++ ByteArray.mk #[0]
      buf := buf ++ enc 4 data.size
      buf := buf ++ data
    | .error _ =>
      let errStr := jstr (jget (jget d "result") "err")
      buf := buf ++ ByteArray.mk #[match errStr with
        | "out_of_gas" => 1 | "panic" => 2 | "bad_exports" => 3
        | "bad_code" => 4 | "code_oversize" => 5 | _ => 1]
    -- RefineLoad: all fixed-width
    buf := buf ++ enc 8 (jnat (jget d "gas_used"))
    buf := buf ++ enc 2 (jnat (jget d "imports"))
    buf := buf ++ enc 2 (jnat (jget d "extrinsic_count"))
    buf := buf ++ enc 4 (jnat (jget d "extrinsic_size"))
    buf := buf ++ enc 2 (jnat (jget d "exports"))

  return buf

-- ============================================================================
-- Re-sign a test vector file
-- ============================================================================

/-- Replace validators in pre_state and re-sign all guarantees. -/
def resignTestVector (content : String) : IO String := do
  let json ← IO.ofExcept (Json.parse content)

  -- Make deterministic validators (V=1023 for Config.full)
  let numValidators := 1023
  let validators := Array.ofFn (n := numValidators) fun ⟨i, _⟩ => makeValidator i

  -- Build validator JSON array for pre_state
  let validatorJsonArr : Array Json := validators.map fun v =>
    Json.mkObj [
      ("bandersnatch", Json.str (toHex (ByteArray.mk (Array.replicate 32 0)))),
      ("ed25519", Json.str (toHex v.publicKey.data)),
      ("bls", Json.str (toHex (ByteArray.mk (Array.replicate 144 0)))),
      ("metadata", Json.str (toHex (ByteArray.mk (Array.replicate 128 0))))
    ]

  -- Helper: set a key in a JSON object
  let jset (obj : Json) (key : String) (val : Json) : Json :=
    match obj with
    | Json.obj kvs => Json.mkObj (kvs.toList.map fun (k, v) => if k == key then (k, val) else (k, v))
    | other => other

  -- Update pre_state validators
  let preState := jget json "pre_state"
  let preState := jset (jset preState "curr_validators" (Json.arr validatorJsonArr))
                       "prev_validators" (Json.arr validatorJsonArr)

  -- Re-sign each guarantee
  let input := jget json "input"
  let guarantees := jarr (jget input "guarantees")

  let mut newGuarantees : Array Json := #[]
  for g in guarantees do
    let report := jget g "report"
    let oldSigs := jarr (jget g "signatures")

    -- Encode work report with jar1 codec
    let encoding := encodeWorkReportFromJson report
    let reportHash := blake2b encoding
    let message := "jam_guarantee".toUTF8 ++ reportHash.data

    -- Re-sign with the same validator indices but our keys
    let mut newSigs : Array Json := #[]
    for oldSig in oldSigs do
      let vi := jnat (jget oldSig "validator_index")
      if vi < numValidators then
        let v := validators[vi]!
        let sig := ed25519Sign v.seed message
        newSigs := newSigs.push (Json.mkObj [
          ("validator_index", toJson vi),
          ("signature", Json.str (toHex sig.data))
        ])
      else
        -- Keep original (for bad_validator_index test cases)
        newSigs := newSigs.push oldSig

    newGuarantees := newGuarantees.push (Json.mkObj [
      ("report", report),
      ("slot", toJson (jnat (jget g "slot"))),
      ("signatures", Json.arr newSigs)
    ])

  -- Reconstruct input and top-level JSON
  let newInput := jset input "guarantees" (Json.arr newGuarantees)
  let newJson := jset (jset json "pre_state" preState) "input" newInput

  return newJson.pretty ++ "\n"

-- ============================================================================
-- Main: process all *.input.jar1.json files in a directory
-- ============================================================================

def main (args : List String) : IO UInt32 := do
  let dir := match args with
    | [d] => d
    | _ => "tests/vectors/reports"

  IO.println s!"Re-signing jar1 reports test vectors in: {dir}"

  let entries ← System.FilePath.readDir dir
  let jsonFiles := entries.filter (fun e => e.fileName.endsWith ".input.jar1.json")
  let sorted := jsonFiles.qsort (fun a b => a.fileName < b.fileName)

  IO.println s!"Found {sorted.size} jar1 input files"

  let mut count := 0
  for entry in sorted do
    let content ← IO.FS.readFile entry.path
    let resigned ← resignTestVector content
    IO.FS.writeFile entry.path resigned
    IO.println s!"  re-signed: {entry.fileName}"
    count := count + 1

  IO.println s!"Done: {count} files re-signed."
  return 0

end Jar.Test.GenReports

def main (args : List String) : IO UInt32 :=
  Jar.Test.GenReports.main args
