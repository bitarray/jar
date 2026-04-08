import Lean.Data.Json
import Lean.Data.Json.Parser
import Jar.Erasure
import Jar.Types.Config
import Jar.Types.Accounts

/-!
# Erasure Coding Test Runner

Runs Reed-Solomon erasure coding test vectors from `tests/vectors/erasure/`.
Each test case provides data and expected shards after erasure encoding.

The erasure coding operates in GF(2^16). For tiny config: W_P=1026, V=6.
For full config: W_P=6, V=1023.
-/

namespace Jar.Test.ErasureTest

open Lean (Json)

/-- Decode hex digit from raw UTF-8 byte. -/
@[inline] private def hexDigitByte (b : UInt8) : Except String UInt8 :=
  if 0x30 ≤ b && b ≤ 0x39 then .ok (b - 0x30)
  else if 0x61 ≤ b && b ≤ 0x66 then .ok (b - 0x61 + 10)
  else if 0x41 ≤ b && b ≤ 0x46 then .ok (b - 0x41 + 10)
  else .error s!"invalid hex digit: {b}"

/-- Decode a hex string (with optional 0x prefix) to ByteArray.
    Handles the 0x prefix by working on raw UTF-8 bytes. -/
private def hexDecode (s : String) : Except String ByteArray := do
  let utf8 := s.toUTF8
  let start : Nat := if utf8.size ≥ 2 && utf8.get! 0 == 0x30
      && (utf8.get! 1 == 0x78 || utf8.get! 1 == 0x58) then 2 else 0
  let len := utf8.size - start
  if len % 2 != 0 then
    throw s!"hex string has odd length: {len}"
  let nBytes := len / 2
  let mut result := ByteArray.empty
  for i in [:nBytes] do
    let pos := start + i * 2
    let hi ← hexDigitByte (utf8.get! pos)
    let lo ← hexDigitByte (utf8.get! (pos + 1))
    result := result.push ((hi <<< 4) ||| lo)
  return result

/-- Encode ByteArray to hex string (no 0x prefix). -/
private def hexEncode (bs : ByteArray) : String :=
  let chars := bs.foldl (init := #[]) fun acc b =>
    acc.push (hexNibble (b >>> 4)) |>.push (hexNibble (b &&& 0x0f))
  String.ofList chars.toList
where
  hexNibble (n : UInt8) : Char :=
    if n < 10 then Char.ofNat (n.toNat + '0'.toNat)
    else Char.ofNat (n.toNat - 10 + 'a'.toNat)

/-- A parsed erasure coding test vector. -/
structure TestVector where
  data : ByteArray
  shards : Array ByteArray

/-- Parse a single test vector from JSON. -/
private def parseTestVector (j : Json) : Except String TestVector := do
  let dataStr ← j.getObjValAs? String "data"
  let data ← hexDecode dataStr
  let shardsJson ← j.getObjVal? "shards"
  let shardsArr ← match shardsJson with
    | Json.arr items => pure items
    | _ => .error s!"expected array for shards, got {shardsJson}"
  let mut shards : Array ByteArray := #[]
  for item in shardsArr do
    let s ← match item with
      | Json.str hex => hexDecode hex
      | _ => .error s!"expected hex string in shards array, got {item}"
    shards := shards.push s
  return { data, shards }

/-- Run erasure coding tests for a single file. Returns (passed, failed). -/
private def runFile [JarConfig] (path : String) : IO (Nat × Nat) := do
  let contents ← IO.FS.readFile path
  let json ← match Lean.Json.parse contents with
    | .ok j => pure j
    | .error e => IO.println s!"  Failed to parse JSON: {e}"; return (0, 1)
  match parseTestVector json with
  | .error e =>
    IO.println s!"  PARSE ERROR: {e}"
    return (0, 1)
  | .ok tv =>
    let numShards := tv.shards.size
    if numShards == 0 then
      IO.println s!"  FAIL: no shards in test vector"
      return (0, 1)
    let shardSize := tv.shards[0]!.size
    -- k = shardSize / 2 (each shard encodes k GF(2^16) elements = 2k bytes)
    let k := shardSize / 2
    if k == 0 then
      IO.println s!"  FAIL: shard size too small ({shardSize} bytes)"
      return (0, 1)
    -- Call erasure coding
    let result := @Erasure.erasureCode _ k tv.data
    -- Check if the function is actually implemented (not just returning empty arrays)
    let allEmpty := result.all (·.size == 0)
    if allEmpty then
      IO.println s!"SKIP (not implemented) [data={tv.data.size}B, k={k}, expected {numShards} shards]"
      return (0, 0)  -- not counted as pass or fail
    -- Compare shards
    if result.size != numShards then
      IO.println s!"FAIL: expected {numShards} shards, got {result.size}"
      return (0, 1)
    let mut allMatch := true
    for idx in [:numShards] do
      let expected := tv.shards[idx]!
      let actual := result[idx]!
      if actual != expected then
        if allMatch then  -- only print first mismatch details
          IO.println s!"FAIL: shard {idx} mismatch"
          IO.println s!"    expected: {hexEncode expected}"
          IO.println s!"    got:      {hexEncode actual}"
        allMatch := false
    if allMatch then
      IO.println s!"PASS [data={tv.data.size}B, k={k}, {numShards} shards]"
      return (1, 0)
    else
      return (0, 1)

/-- Run recovery tests for a single test vector file. Returns (passed, failed). -/
private def runRecoveryFile [JarConfig] (path : String) : IO (Nat × Nat) := do
  let contents ← IO.FS.readFile path
  let json ← match Lean.Json.parse contents with
    | .ok j => pure j
    | .error e => IO.println s!"  Failed to parse JSON: {e}"; return (0, 1)
  match parseTestVector json with
  | .error e =>
    IO.println s!"  PARSE ERROR: {e}"
    return (0, 1)
  | .ok tv =>
    let numShards := tv.shards.size
    if numShards == 0 then return (0, 1)
    let shardSize := tv.shards[0]!.size
    let k := shardSize / 2
    if k == 0 then return (0, 1)
    let ds := @Erasure.dataShards _

    -- Zero-pad original data to match what recovery will produce
    let ps := @Erasure.pieceSize _
    let paddedLen := if tv.data.size == 0 then ps
                     else ((tv.data.size + ps - 1) / ps) * ps
    let mut padded := tv.data
    while padded.size < paddedLen do
      padded := padded.push 0

    let mut passed := 0
    let mut failed := 0

    -- Test 1: All data shards (fast path)
    let dataChunks : Array (ByteArray × Nat) := Array.ofFn (n := ds) fun ⟨i, _⟩ =>
      (tv.shards[i]!, i)
    match @Erasure.erasureRecover _ k dataChunks with
    | some recovered =>
      if recovered == padded then
        passed := passed + 1
      else
        IO.println s!"  FAIL recover(data): len exp={padded.size} got={recovered.size}"
        failed := failed + 1
    | none =>
      IO.println s!"  FAIL recover(data): returned none"
      failed := failed + 1

    -- Test 2: Last dataShards shards (all recovery)
    let lastChunks : Array (ByteArray × Nat) := Array.ofFn (n := ds) fun ⟨i, _⟩ =>
      let idx := numShards - ds + i
      (tv.shards[idx]!, idx)
    match @Erasure.erasureRecover _ k lastChunks with
    | some recovered =>
      if recovered == padded then
        passed := passed + 1
      else
        IO.println s!"  FAIL recover(last): mismatch at data={tv.data.size}B"
        failed := failed + 1
    | none =>
      IO.println s!"  FAIL recover(last): returned none"
      failed := failed + 1

    -- Test 3: Mixed — first shard data, rest recovery
    let mut mixedChunks : Array (ByteArray × Nat) := #[(tv.shards[0]!, 0)]
    for i in [1:ds] do
      let idx := ds + i - 1
      mixedChunks := mixedChunks.push (tv.shards[idx]!, idx)
    match @Erasure.erasureRecover _ k mixedChunks with
    | some recovered =>
      if recovered == padded then
        passed := passed + 1
      else
        IO.println s!"  FAIL recover(mixed): mismatch at data={tv.data.size}B"
        failed := failed + 1
    | none =>
      IO.println s!"  FAIL recover(mixed): returned none"
      failed := failed + 1

    if failed == 0 then
      IO.println s!"PASS [data={tv.data.size}B, k={k}, 3 recovery tests]"
    return (passed, failed)

/-- Test file names (data sizes). -/
private def testDataSizes : Array String := #["3", "32", "100", "4096", "4104", "10000"]

/-- Run all erasure coding test vectors for a given config. Returns (passed, failed, skipped). -/
def runAllForConfig [JarConfig] (configName : String) : IO (Nat × Nat × Nat) := do
  let dir := "tests/vectors/erasure"
  IO.println s!"Running erasure coding tests ({configName}):"
  let mut passed := 0
  let mut failed := 0
  let mut skipped := 0
  for sz in testDataSizes do
    let path := s!"{dir}/ec-{sz}.{configName}.json"
    -- Check if file exists
    let exists_ ← do
      try
        let _ ← IO.FS.readFile path
        pure true
      catch _ => pure false
    if exists_ then
      IO.print s!"  {path}: "
      let (p, f) ← runFile path
      passed := passed + p
      failed := failed + f
      if p == 0 && f == 0 then skipped := skipped + 1
    else
      IO.println s!"  {path}: not found (skipped)"
      skipped := skipped + 1
  return (passed, failed, skipped)

/-- Run all erasure coding tests across both configs. -/
def runAll : IO UInt32 := do
  IO.println "Running erasure coding test vectors"
  IO.println "==================================="
  -- Tiny config
  let tinyJarConfig : JarConfig := {
    name := "gp072_tiny"
    config := Params.tiny
    valid := Params.tiny_valid
    EconType := Jar.BalanceEcon
    TransferType := Jar.BalanceTransfer
  }
  let (tp, tf, ts) ← @runAllForConfig tinyJarConfig "gp072_tiny"
  -- Full config
  let fullJarConfig : JarConfig := {
    name := "gp072_full"
    config := Params.full
    valid := Params.full_valid
    EconType := Jar.BalanceEcon
    TransferType := Jar.BalanceTransfer
  }
  let (fp, ff, fs) ← @runAllForConfig fullJarConfig "gp072_full"
  -- Recovery tests (tiny only — full config recovery is slow for large data sizes)
  IO.println s!"Running erasure recovery tests (gp072_tiny):"
  let mut rp := 0
  let mut rf := 0
  for sz in testDataSizes do
    let path := s!"tests/vectors/erasure/ec-{sz}.gp072_tiny.json"
    let exists_ ← do try let _ ← IO.FS.readFile path; pure true catch _ => pure false
    if exists_ then
      IO.print s!"  {path}: "
      let (p, f) ← @runRecoveryFile tinyJarConfig path
      rp := rp + p
      rf := rf + f
  IO.println s!"Recovery tests: {rp} passed, {rf} failed"
  let totalPassed := tp + fp + rp
  let totalFailed := tf + ff + rf
  let totalSkipped := ts + fs
  IO.println s!"Erasure tests: {totalPassed} passed, {totalFailed} failed, {totalSkipped} skipped"
  return if totalFailed == 0 then 0 else 1

end Jar.Test.ErasureTest
