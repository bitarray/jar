import Jar.Notation
import Jar.Types.Numerics
import Jar.Types.Constants

/-!
# Erasure Coding — Appendix H

Reed-Solomon erasure coding in GF(2^16) for data availability.
Uses the Leopard-RS (Lin-Chung-Han 2014) algorithm with Cantor basis FFT,
matching the `reed-solomon-simd` Rust crate's encoding.

References: `graypaper/text/erasure_coding.tex`.

## Parameters
- Field: GF(2^16) with irreducible polynomial x^16 + x^5 + x^3 + x^2 + 1
- Rate: data_shards:total_shards (systematic code)
- For full config: 342:1023 (V=1023 validators)
- For tiny config: 2:6 (V=6 validators)
-/

namespace Jar.Erasure
variable [JarConfig]

-- ============================================================================
-- GF(2^16) Constants
-- ============================================================================

/-- Element of GF(2^16). Represented as a 16-bit integer.
    Field polynomial: x^16 + x^5 + x^3 + x^2 + 1. -/
abbrev GF16 := UInt16

/-- The irreducible polynomial for GF(2^16): x^16 + x^5 + x^3 + x^2 + 1.
    In binary: 0x1002D (bit 16 + bit 5 + bit 3 + bit 2 + bit 0). -/
def GF_POLYNOMIAL : UInt32 := 0x1002D

/-- GF(2^16) order = 2^16 = 65536. -/
def GF_ORDER : Nat := 65536

/-- GF(2^16) modulus = 65535. Used as the "infinity" log value (log of 0). -/
def GF_MODULUS : UInt16 := 65535

/-- Number of bits in GF elements. -/
def GF_BITS : Nat := 16

/-- Cantor basis vectors for GF(2^16).
    These define the basis change between standard and Cantor representations.
    Values from the reed-solomon-simd crate. -/
def CANTOR_BASIS : Array UInt16 := #[
  0x0001, 0xACCA, 0x3C0E, 0x163E, 0xC582, 0xED2E, 0x914C, 0x4012,
  0x6C98, 0x10D8, 0x6A72, 0xB900, 0xFDB8, 0xFB34, 0xFF38, 0x991E
]

-- ============================================================================
-- GF(2^16) Arithmetic via Log/Exp Tables — Cantor Basis
-- ============================================================================

/-- Modular addition for log values: (x + y) mod 65535, mapping 65535 to 0. -/
@[inline] def addMod (x y : UInt16) : UInt16 :=
  let sum := x.toUInt32 + y.toUInt32
  (sum + (sum >>> 16)).toUInt16

/-- Build the exp and log tables for GF(2^16) with Cantor basis.
    Returns (exp, log) where:
    - exp maps discrete logarithm → Cantor basis element
    - log maps Cantor basis element → discrete logarithm
    - Multiplication: a * b = exp[addMod(log[a], log[b])]  (for a,b ≠ 0) -/
def buildExpLog : Array UInt16 × Array UInt16 := Id.run do
  -- Step 1: Generate LFSR exponentiation table
  let mut exp := Array.replicate GF_ORDER (0 : UInt16)
  let mut state : UInt32 := 1
  for i in [:GF_MODULUS.toNat] do
    exp := exp.set! state.toNat i.toUInt16
    state := state <<< 1
    if state >= GF_ORDER.toUInt32 then
      state := state ^^^ GF_POLYNOMIAL
  exp := exp.set! 0 GF_MODULUS

  -- Step 2: Build Cantor basis conversion in log table
  let mut log := Array.replicate GF_ORDER (0 : UInt16)
  for i in [:GF_BITS] do
    let width := 1 <<< i
    for j in [:width] do
      log := log.set! (j + width) (log[j]! ^^^ CANTOR_BASIS[i]!)

  -- Step 3: Compose tables
  for i in [:GF_ORDER] do
    log := log.set! i (exp[log[i]!.toNat]!)

  for i in [:GF_ORDER] do
    exp := exp.set! (log[i]!.toNat) i.toUInt16

  exp := exp.set! GF_MODULUS.toNat exp[0]!

  (exp, log)

/-- Cached exp table. -/
@[noinline] def expTable : Array UInt16 := buildExpLog.1

/-- Cached log table. -/
@[noinline] def logTable : Array UInt16 := buildExpLog.2

/-- Multiply GF element `x` by element whose log is `logM`, using exp/log tables.
    Returns 0 if x = 0. -/
@[inline] def tableMul (x : UInt16) (logM : UInt16) : UInt16 :=
  if x == 0 then 0
  else expTable[addMod (logTable[x.toNat]!) logM |>.toNat]!

/-- Multiply two GF(2^16) elements. -/
@[inline] def gfMul (x y : UInt16) : UInt16 :=
  if x == 0 || y == 0 then 0
  else expTable[addMod (logTable[x.toNat]!) (logTable[y.toNat]!) |>.toNat]!

/-- Multiplicative inverse in GF(2^16). Returns 0 for input 0. -/
@[inline] def gfInv (x : UInt16) : UInt16 :=
  if x == 0 then 0
  else expTable[(65535 - (logTable[x.toNat]!).toNat) % 65535]!

/-- Build the skew factor table used in FFT/IFFT butterflies.
    The skew table has 65535 entries (indexed 0..65534). -/
def buildSkew : Array UInt16 := Id.run do
  let log := logTable
  let mut skew := Array.replicate GF_MODULUS.toNat (0 : UInt16)
  let mut temp := Array.replicate (GF_BITS - 1) (0 : UInt16)

  for i in [1:GF_BITS] do
    temp := temp.set! (i - 1) ((1 : UInt16) <<< i.toUInt16)

  for m in [:GF_BITS - 1] do
    let step := 1 <<< (m + 1)
    skew := skew.set! ((1 <<< m) - 1) 0

    for i in [m:GF_BITS - 1] do
      let s := 1 <<< (i + 1)
      let mut j := (1 <<< m) - 1
      while j < s do
        skew := skew.set! (j + s) (skew[j]! ^^^ temp[i]!)
        j := j + step

    let t := temp[m]!
    let tXor1 := t ^^^ 1
    let mulResult := tableMul t (log[tXor1.toNat]!)
    temp := temp.set! m (GF_MODULUS - log[mulResult.toNat]!)

    for i in [m + 1:GF_BITS - 1] do
      let tXor1 := temp[i]! ^^^ 1
      let sum := addMod (log[tXor1.toNat]!) (temp[m]!)
      temp := temp.set! i (tableMul (temp[i]!) sum)

  for i in [:GF_MODULUS.toNat] do
    skew := skew.set! i (log[skew[i]!.toNat]!)

  skew

/-- Cached skew table. -/
@[noinline] def skewTable : Array UInt16 := buildSkew

-- ============================================================================
-- FFT and IFFT — Leopard-RS Additive FFT
-- ============================================================================

/-- In-place decimation-in-time FFT (fast Fourier transform) on GF(2^16) elements.
    Operates on `data[pos .. pos + size]` where `size` is a power of 2. -/
def fftInPlace (data : Array UInt16) (pos size truncatedSize skewDelta : Nat) : Array UInt16 := Id.run do
  let skew := skewTable
  let mut d := data
  let mut dist := size / 2
  while dist > 0 do
    let mut r := 0
    while r < truncatedSize do
      let logM := skew[r + dist + skewDelta - 1]!
      for i in [r:r + dist] do
        let a := d[pos + i]!
        let b := d[pos + i + dist]!
        let newA := if logM != GF_MODULUS then a ^^^ tableMul b logM else a
        d := d.set! (pos + i) newA
        d := d.set! (pos + i + dist) (newA ^^^ b)
      r := r + dist * 2
    dist := dist / 2
  d

/-- In-place decimation-in-time IFFT (inverse fast Fourier transform).
    Operates on `data[pos .. pos + size]` where `size` is a power of 2. -/
def ifftInPlace (data : Array UInt16) (pos size truncatedSize skewDelta : Nat) : Array UInt16 := Id.run do
  let skew := skewTable
  let mut d := data
  let mut dist := 1
  while dist < size do
    let mut r := 0
    while r < truncatedSize do
      let logM := skew[r + dist + skewDelta - 1]!
      for i in [r:r + dist] do
        let a := d[pos + i]!
        let b := d[pos + i + dist]!
        let newB := a ^^^ b
        let newA := if logM != GF_MODULUS then a ^^^ tableMul newB logM else a
        d := d.set! (pos + i) newA
        d := d.set! (pos + i + dist) newB
      r := r + dist * 2
    dist := dist * 2
  d

-- ============================================================================
-- RS Encoding — IFFT + copy + FFT pipeline
-- ============================================================================

/-- Next power of 2 that is >= n. -/
def nextPowerOfTwo (n : Nat) : Nat := Id.run do
  if n <= 1 then return 1
  let mut p := 1
  while p < n do
    p := p * 2
  return p

/-- Round `n` up to the nearest multiple of `m`. -/
def nextMultipleOf (n m : Nat) : Nat :=
  ((n + m - 1) / m) * m

/-- Encode `originalCount` data GF(2^16) symbols into `recoveryCount` parity symbols
    using the Leopard-RS additive FFT approach.
    Returns an array of `recoveryCount` parity GF elements. -/
def encodeRS (originalCount recoveryCount : Nat) (dataSymbols : Array UInt16) : Array UInt16 := Id.run do
  let chunkSize := nextPowerOfTwo originalCount
  let workCount := nextMultipleOf recoveryCount chunkSize

  -- Initialize work array with data + zeros
  let mut work := Array.replicate workCount (0 : UInt16)
  for i in [:originalCount] do
    work := work.set! i dataSymbols[i]!

  -- IFFT on the original data chunk
  work := ifftInPlace work 0 chunkSize originalCount 0

  -- Copy IFFT result to other chunks
  let mut cs := chunkSize
  while cs < recoveryCount do
    for i in [:chunkSize] do
      work := work.set! (cs + i) work[i]!
    cs := cs + chunkSize

  -- FFT on each full chunk with appropriate skew_delta
  cs := 0
  while cs + chunkSize <= recoveryCount do
    work := fftInPlace work cs chunkSize chunkSize (cs + chunkSize)
    cs := cs + chunkSize

  -- FFT on final partial chunk (if any)
  let lastCount := recoveryCount % chunkSize
  if lastCount > 0 then
    work := fftInPlace work cs chunkSize lastCount (cs + chunkSize)

  work.extract 0 recoveryCount

-- ============================================================================
-- Erasure Coding Functions — Appendix H
-- ============================================================================

/-- Number of data shards: 3 * W_E / W_P.
    For full config (W_P=6): 3 * 684 / 6 = 342.
    For tiny config (W_P=1026): 3 * 684 / 1026 = 2. -/
def dataShards : Nat := 3 * W_E / W_P

/-- Number of recovery shards: V - dataShards. -/
def recoveryShards : Nat := V - dataShards

/-- Piece size in bytes: dataShards * 2. -/
def pieceSize : Nat := dataShards * 2

/-- C_k(data) : Erasure-code a blob into V chunks. GP Appendix H eq (H.4).
    Input: data blob.
    Output: V chunks of 2k octets each.
    The first dataShards chunks are the original data (systematic).
    The remaining recoveryShards chunks are RS parity. -/
def erasureCode (_k : Nat) (data : ByteArray) : Array ByteArray := Id.run do
  let ds := dataShards
  let rs := recoveryShards
  let ps := pieceSize

  -- Compute k: number of GF symbols per shard
  let k_ := if data.size == 0 then 1
             else (data.size + ps - 1) / ps
  let paddedLen := k_ * ps

  -- Zero-pad data
  let mut padded := data
  while padded.size < paddedLen do
    padded := padded.push 0

  -- Split padded data into ds data chunks of 2*k_ bytes each
  let shardBytes := k_ * 2

  -- For each of k_ symbol positions, extract one GF element from each data chunk,
  -- RS-encode the row, and distribute to output shards.
  let mut result : Array ByteArray := Array.replicate V ByteArray.empty

  for symPos in [:k_] do
    -- Extract one GF(2^16) symbol (2 bytes, little-endian) from each data chunk
    let mut row := Array.replicate ds (0 : UInt16)
    for j in [:ds] do
      let byteOffset := j * shardBytes + symPos * 2
      let lo := padded.get! byteOffset
      let hi := padded.get! (byteOffset + 1)
      row := row.set! j (lo.toUInt16 ||| (hi.toUInt16 <<< 8))

    -- RS-encode: ds data symbols → rs parity symbols
    let parity := encodeRS ds rs row

    -- Distribute data symbols to output shards 0..ds
    for j in [:ds] do
      let val := row[j]!
      result := result.modify j (· |>.push val.toUInt8 |>.push (val >>> 8).toUInt8)

    -- Distribute parity symbols to output shards ds..V
    for j in [:rs] do
      let val := parity[j]!
      result := result.modify (ds + j) (· |>.push val.toUInt8 |>.push (val >>> 8).toUInt8)

  result

/-- R_k(chunks) : Recover original data from any dataShards chunks.
    GP Appendix H eq (H.5).
    Input: at least dataShards (chunk, index) pairs.
    Output: reconstructed data of original length.
    (Not yet implemented — recovery requires IFFT-based decoding.) -/
def erasureRecover (_k : Nat) (chunks : Array (ByteArray × Nat)) : Option ByteArray := Id.run do
  let ds := dataShards
  let rs := recoveryShards

  -- Need at least dataShards chunks
  if chunks.size < ds then return none
  let chunks := chunks.extract 0 ds

  -- Derive k from chunk byte size
  let chunkBytes := chunks[0]!.1.size
  if chunkBytes < 2 || chunkBytes % 2 != 0 then return none
  let k := chunkBytes / 2

  -- Validate all chunks have same size
  for (c, _) in chunks do
    if c.size != chunkBytes then return none

  -- Fast path: if all data shard indices 0..ds-1 are present, just reorder
  let receivedIndices := chunks.map (·.2)
  let allDataPresent := (List.range ds).all fun i => receivedIndices.any (· == i)
  if allDataPresent then
    let mut result := ByteArray.empty
    for i in [:ds] do
      let (c, _) := (chunks.find? fun (_, idx) => idx == i).get!
      result := result ++ c
    return some result

  -- Build parity matrix P[rs × ds] by encoding unit vectors
  -- P_transposed[j] = encodeRS(e_j), so P_transposed[j][i] = P[i][j]
  let mut pT : Array (Array UInt16) := #[]
  for j in [:ds] do
    let mut ej := Array.replicate ds (0 : UInt16)
    ej := ej.set! j 1
    let col := encodeRS ds rs ej
    pT := pT.push col

  -- Build submatrix A[ds × ds] for received chunk indices
  let mut A : Array (Array UInt16) := #[]
  for (_, idx) in chunks do
    if idx < ds then
      -- Identity row: row[j] = δ(idx, j)
      let row := Array.ofFn (n := ds) fun ⟨j, _⟩ =>
        if idx == j then (1 : UInt16) else 0
      A := A.push row
    else
      -- Parity row: row[j] = P[idx - ds][j] = pT[j][idx - ds]
      let parityIdx := idx - ds
      let row := Array.ofFn (n := ds) fun ⟨j, _⟩ =>
        pT[j]![parityIdx]!
      A := A.push row

  -- Gauss-Jordan elimination on [A | I] to compute A⁻¹
  let n := ds
  -- Build augmented matrix: each row is A_row ++ I_row
  let mut aug : Array (Array UInt16) := Array.ofFn (n := n) fun ⟨i, _⟩ =>
    let left := A[i]!
    let right := Array.ofFn (n := n) fun ⟨j, _⟩ => if i == j then (1 : UInt16) else 0
    left ++ right

  for col in [:n] do
    -- Find pivot row
    let mut pivotRow : Option Nat := none
    for row in [col:n] do
      if aug[row]![col]! != 0 then
        pivotRow := some row
        break
    match pivotRow with
    | none => return none  -- Singular matrix (shouldn't happen with valid RS)
    | some pr =>
      -- Swap pivot row into position
      if pr != col then
        let tmp := aug[col]!
        aug := aug.set! col (aug[pr]!)
        aug := aug.set! pr tmp
      -- Scale pivot row so A[col][col] = 1
      let pivotVal := aug[col]![col]!
      let inv := gfInv pivotVal
      aug := aug.set! col (aug[col]!.map (gfMul · inv))
      -- Eliminate all other rows
      for row in [:n] do
        if row != col then
          let factor := aug[row]![col]!
          if factor != 0 then
            let pivotRowData := aug[col]!
            aug := aug.set! row (Array.zipWith (fun a b => a ^^^ gfMul b factor) aug[row]! pivotRowData)

  -- Extract A⁻¹ from right half of augmented matrix
  let Ainv : Array (Array UInt16) := Array.ofFn (n := n) fun ⟨i, _⟩ =>
    aug[i]!.extract n (2 * n)

  -- For each symbol position, recover data symbols
  let mut result : Array ByteArray := Array.replicate ds ByteArray.empty
  for j in [:ds] do
    result := result.set! j (ByteArray.mk (Array.replicate chunkBytes 0))

  for symPos in [:k] do
    -- Extract received GF16 values at this symbol position
    let y : Array UInt16 := chunks.map fun (chunkData, _) =>
      let lo := chunkData.get! (symPos * 2)
      let hi := chunkData.get! (symPos * 2 + 1)
      lo.toUInt16 ||| (hi.toUInt16 <<< 8)

    -- Compute data = Ainv · y
    for j in [:ds] do
      let mut val : UInt16 := 0
      for i in [:ds] do
        val := val ^^^ gfMul (Ainv[j]![i]!) (y[i]!)
      -- Write to result[j] at position symPos
      result := result.modify j fun chunk =>
        chunk.set! (symPos * 2) (val &&& 0xFF).toUInt8
          |>.set! (symPos * 2 + 1) ((val >>> 8) &&& 0xFF).toUInt8

  some (result.foldl (· ++ ·) ByteArray.empty)

-- ============================================================================
-- Segment-Level Functions — Appendix H
-- ============================================================================

/-- Split a blob into k sub-sequences of n octets each. -/
def split (data : ByteArray) (k n : Nat) : Array ByteArray :=
  Array.ofFn (n := k) fun ⟨i, _⟩ =>
    data.extract (i * n) ((i + 1) * n)

/-- Join k sub-sequences into a single blob. -/
def join (chunks : Array ByteArray) : ByteArray :=
  chunks.foldl (· ++ ·) ByteArray.empty

/-- Erasure-code a segment (4104 bytes = W_G) with k=6 parallelism.
    GP §14: segments are W_G = 4104 bytes, encoded with k=6. -/
def erasureCodeSegment (segment : ByteArray) : Array ByteArray :=
  erasureCode 6 segment

/-- Recover a segment from validator chunks. -/
def recoverSegment (chunks : Array (ByteArray × Nat)) : Option ByteArray :=
  erasureRecover 6 chunks

end Jar.Erasure
