import Jar.Notation
import Jar.Types.Numerics
import Jar.Types.Constants

/-!
# PVM Instruction Decoding — Appendix A

Instruction encoding, deblob function, register/immediate extraction,
and sign extension helpers.
References: `graypaper/text/pvm.tex`.
-/

namespace Jar.PVM

-- ============================================================================
-- Sign Extension — GP eq (191)
-- ============================================================================

/-- Sign-extend a value from n bytes to 64-bit. GP eq (191).
    sext(n, x) = x + ⌊x / 2^(8n-1)⌋ · (2^64 - 2^(8n)).
    For n ∈ {1,2,4,8}. -/
def sext (nBytes : Nat) (x : UInt64) : UInt64 :=
  if nBytes == 0 || nBytes >= 8 then x
  else
    let bits := 8 * nBytes
    let signBit := UInt64.ofNat (2 ^ (bits - 1))
    if x &&& signBit != 0 then
      -- Sign bit is set: extend with 1s
      let mask := UInt64.ofNat (2 ^ 64 - 2 ^ bits)
      x ||| mask
    else x

/-- Sign-extend from 4 bytes (32-bit) to 64-bit. -/
def sext32 (x : UInt64) : UInt64 := sext 4 x

-- ============================================================================
-- Signed Interpretation — GP eq (158)
-- ============================================================================

/-- Convert unsigned 64-bit to signed interpretation. GP eq (158).
    sign(x) = x if x < 2^63, else x - 2^64. -/
def toSigned (x : UInt64) : Int64 := Int64.ofUInt64 x

/-- Convert signed back to unsigned. -/
def toUnsigned (x : Int64) : UInt64 := x.toUInt64

-- ============================================================================
-- Program Deblob — GP Appendix A
-- ============================================================================

/-- Decoded program blob components. -/
structure ProgramBlob where
  /-- Instruction code bytes. -/
  code : ByteArray
  /-- Opcode bitmask: bit i is set if byte i is an opcode position. -/
  bitmask : ByteArray
  /-- Jump table: maps dynamic jump indices to code positions. -/
  jumpTable : Array UInt32

/-- Decode a fixed-width natural from `n` LE bytes starting at offset. -/
def decodeLEn (data : ByteArray) (offset n : Nat) : Nat :=
  let rec go (i : Nat) (acc : Nat) (fuel : Nat) : Nat :=
    match fuel with
    | 0 => acc
    | fuel' + 1 =>
      if i >= n then acc
      else
        let byteIdx := offset + i
        let b := if byteIdx < data.size then data.get! byteIdx |>.toNat else 0
        go (i + 1) (acc + b * 2 ^ (8 * i)) fuel'
  go 0 0 n

-- ============================================================================
-- JAR v1 Program Header
-- ============================================================================

/-- JAR v1 unified program header (all u32 LE fields + u8 entry_size). -/
structure JarProgramHeader where
  roSize : Nat
  rwSize : Nat
  heapPages : Nat
  maxHeapPages : Nat
  stackPages : Nat
  jumpLen : Nat
  entrySize : Nat
  codeLen : Nat

/-- JAR v1 magic value as u32 LE: 'J'=0x4A, 'A'=0x41, 'R'=0x52, 0x01. -/
def jarMagic : Nat := decodeLEn ⟨#[0x4A, 0x41, 0x52, 0x01]⟩ 0 4

/-- Parse a JAR v1 unified program header (33 bytes). -/
def parseJarHeader (blob : ByteArray) : Option (JarProgramHeader × Nat) := do
  if blob.size < 33 then none
  let magic := decodeLEn blob 0 4
  if magic != jarMagic then none
  some ({
    roSize := decodeLEn blob 4 4
    rwSize := decodeLEn blob 8 4
    heapPages := decodeLEn blob 12 4
    maxHeapPages := decodeLEn blob 16 4
    stackPages := decodeLEn blob 20 4
    jumpLen := decodeLEn blob 24 4
    entrySize := (blob.get! 28).toNat
    codeLen := decodeLEn blob 29 4
  }, 33)

/-- Gas cost per page for memory allocation (init + grow_heap). -/
def gasPerPage : Nat := 1500

/-- Compute memory tier load/store cycles based on total accessible pages. -/
def computeMemCycles (totalPages : Nat) : Nat :=
  if totalPages ≤ 2048 then 25
  else if totalPages ≤ 8192 then 50
  else if totalPages ≤ 65536 then 75
  else 100

-- ============================================================================
-- Legacy Compact Encoding (gp072)
-- ============================================================================

/-- Decode a JAM codec variable-length natural number. GP Appendix C.
    Returns (value, bytes_consumed) or none. -/
def decodeJamNatural (data : ByteArray) (offset : Nat) : Option (Nat × Nat) :=
  if offset >= data.size then none
  else
    let first := data.get! offset |>.toNat
    if first < 128 then
      some (first, 1)
    else if first < 192 then
      if offset + 2 > data.size then none
      else
        let val := (first &&& 0x3F) * 256 + (data.get! (offset + 1)).toNat
        some (val, 2)
    else if first < 224 then
      if offset + 3 > data.size then none
      else
        let val := (first &&& 0x1F) * 65536
          + (data.get! (offset + 2)).toNat * 256
          + (data.get! (offset + 1)).toNat
        some (val, 3)
    else
      if offset + 4 > data.size then none
      else
        let val := (first &&& 0x0F) * 16777216
          + (data.get! (offset + 3)).toNat * 65536
          + (data.get! (offset + 2)).toNat * 256
          + (data.get! (offset + 1)).toNat
        some (val, 4)

/-- Decode a natural from the deblob header. In compact mode (gp072) uses JAM
    variable-length encoding; in fixed mode (jar1) uses u32 LE. -/
def decodeDeBlobNat (blob : ByteArray) (offset : Nat) (compact : Bool)
    : Option (Nat × Nat) :=
  if compact then decodeJamNatural blob offset
  else if offset + 4 ≤ blob.size then some (decodeLEn blob offset 4, 4)
  else none

/-- Deblob: parse a program blob into (code, bitmask, jumpTable). GP Appendix A.
    Format: E(|j|) ‖ E₁(z) ‖ E(|c|) ‖ E_z(j) ‖ c ‖ k
    where z = jump table entry size (1-4), j = jump table, c = code, k = bitmask.
    When `compact` is true, E() uses JAM codec variable-length natural (gp072).
    When false, E() = E₄() is u32 LE (jar1). -/
def deblob (blob : ByteArray) (compact : Bool := true) : Option ProgramBlob := do
  -- Decode |j|
  let (jumpLen, n1) ← decodeDeBlobNat blob 0 compact
  let mut offset := n1
  -- Decode z: 1 byte (bytes per jump table entry)
  if offset >= blob.size then none
  let z := (blob.get! offset).toNat
  offset := offset + 1
  if z == 0 || z > 4 then none
  -- Decode |c|
  let (codeLen, n3) ← decodeDeBlobNat blob offset compact
  offset := offset + n3
  -- Read jump table: jumpLen entries of z bytes each
  let jumpDataStart := offset
  let jumpDataLen := jumpLen * z
  if jumpDataStart + jumpDataLen > blob.size then none
  let jumpTable := Array.ofFn (n := jumpLen) fun ⟨i, _⟩ =>
    UInt32.ofNat (decodeLEn blob (jumpDataStart + i * z) z)
  offset := jumpDataStart + jumpDataLen
  -- Read code: codeLen bytes
  if offset + codeLen > blob.size then none
  let code := blob.extract offset (offset + codeLen)
  offset := offset + codeLen
  -- Read bitmask: packed bits, ceil(codeLen/8) bytes
  let bitmaskLen := (codeLen + 7) / 8
  if offset + bitmaskLen > blob.size then none
  let packedBitmask := blob.extract offset (offset + bitmaskLen)
  -- Unpack: each bit becomes one byte (LSB first per byte)
  let bitmask := ByteArray.mk (Array.ofFn (n := codeLen) fun ⟨i, _⟩ =>
    let byteIdx := i / 8
    let bitIdx := i % 8
    if byteIdx < packedBitmask.size then
      UInt8.ofNat ((packedBitmask.get! byteIdx).toNat / (2 ^ bitIdx) % 2)
    else 0)
  some { code, bitmask, jumpTable }

/-- Check if opcode is a basic block terminator (v0.8.0). -/
def isTerminator (opcode : Nat) : Bool :=
  match opcode with
  | 0 | 1 | 2 => true   -- trap, fallthrough, unlikely
  | 10 => true           -- ecalli
  | 40 | 50 | 80 | 180 => true  -- jump, jump_ind, load_imm_jump, load_imm_jump_ind
  | n => (81 ≤ n && n ≤ 90) || (170 ≤ n && n ≤ 175)  -- branches

-- ============================================================================
-- Bitmask / Skip — GP Appendix A
-- ============================================================================

/-- Check if bit at position `i` is set in the (unpacked) bitmask.
    After deblob, the bitmask has one byte per code byte (0 or 1). -/
def bitmaskGet (bm : ByteArray) (i : Nat) : Bool :=
  if i < bm.size then bm.get! i != 0
  else true  -- beyond bitmask is treated as set (for termination)

/-- Skip distance: number of bytes until the next opcode position. GP eq (77).
    F_skip(i) = min(24, j ∈ ℕ : bitmask[i+1+j] = 1). -/
def skipDistance (bm : ByteArray) (i : Nat) : Nat :=
  let rec go (j : Nat) (fuel : Nat) : Nat :=
    match fuel with
    | 0 => j
    | fuel' + 1 =>
      if j >= 24 then 24
      else if bitmaskGet bm (i + 1 + j) then j
      else go (j + 1) fuel'
  go 0 25

/-- Validate a deblobbed program for v0.8.0 basic block requirements:
    1. Last instruction must be a basic block terminator
    2. All branch/jump targets must be valid instruction boundaries (bitmask set)
    Returns true if valid. -/
def validateBasicBlocks (prog : ProgramBlob) : Bool :=
  let code := prog.code
  if code.size == 0 then false
  else
    -- Check last instruction is a terminator
    let lastInstr := Id.run do
      let mut last := code.size - 1
      while last > 0 && !bitmaskGet prog.bitmask last do
        last := last - 1
      return last
    let lastOpcode := if lastInstr < code.size then code.get! lastInstr |>.toNat else 0
    if !bitmaskGet prog.bitmask lastInstr || !isTerminator lastOpcode then false
    else
      -- Check all jump table entries point to valid instruction boundaries
      prog.jumpTable.all fun target =>
        target.toNat == 0 || bitmaskGet prog.bitmask target.toNat

-- ============================================================================
-- Register Decoding — GP Appendix A
-- ============================================================================

/-- Decode register A from instruction byte 1 (lower 4 bits), capped at 12. -/
def regA (instrBytes : ByteArray) (pc : Nat) : Fin 13 :=
  let b := if pc + 1 < instrBytes.size then instrBytes.get! (pc + 1) |>.toNat else 0
  ⟨min 12 (b % 16), by omega⟩

/-- Decode register B from instruction byte 1 (upper 4 bits), capped at 12. -/
def regB (instrBytes : ByteArray) (pc : Nat) : Fin 13 :=
  let b := if pc + 1 < instrBytes.size then instrBytes.get! (pc + 1) |>.toNat else 0
  ⟨min 12 (b / 16), by omega⟩

/-- Decode register D from instruction byte 2 (lower 4 bits), capped at 12.
    Used in 3-register format. -/
def regD (instrBytes : ByteArray) (pc : Nat) : Fin 13 :=
  let b := if pc + 2 < instrBytes.size then instrBytes.get! (pc + 2) |>.toNat else 0
  ⟨min 12 (b % 16), by omega⟩

-- ============================================================================
-- Immediate Extraction — GP Appendix A
-- ============================================================================

/-- Read `n` bytes starting at `offset` from instruction stream, returning LE value. -/
def readImmBytes (code : ByteArray) (offset n : Nat) : UInt64 :=
  UInt64.ofNat (decodeLEn code offset n)

/-- Read `n` bytes and sign-extend (matching Rust read_signed_at). -/
def readSignedAt (code : ByteArray) (offset n : Nat) : UInt64 :=
  if n == 0 then 0
  else sext n (readImmBytes code offset n)

/-- Zero-extended code read (ζ, eq A.4). -/
def zeta (code : ByteArray) (i : Nat) : Nat :=
  if i < code.size then code.get! i |>.toNat else 0

-- ============================================================================
-- Argument Extraction — GP Appendix A.5 (matching javm/src/args.rs)
-- ============================================================================

/-- A.5.2: OneImm — one immediate (ecalli).
    lX = min(4, ℓ), νX = X_lX(E_lX⁻¹(ζ[ı+1..+lX])). -/
def extractOneImm (code : ByteArray) (pc : Nat) (skip : Nat) : UInt64 :=
  let lx := min 4 skip
  readSignedAt code (pc + 1) lx

/-- Generic immediate extraction: read sign-extended imm starting at byte `startByte`.
    Available bytes = max(0, ℓ + 1 - startByte), capped at 4. -/
def extractImm (code : ByteArray) (pc : Nat) (skip : Nat) (startByte : Nat) : UInt64 :=
  let avail := if skip + 1 > startByte then skip + 1 - startByte else 0
  let lx := min 4 avail
  readSignedAt code (pc + startByte) lx

/-- A.5.3: OneRegExtImm — register + 8-byte immediate (load_imm_64). -/
def extractImm64 (code : ByteArray) (pc : Nat) (_skip : Nat) : UInt64 :=
  readImmBytes code (pc + 2) 8  -- E₈⁻¹(ζ[ı+2..+8]), no sign extension

/-- A.5.4: TwoImm — two immediates (store_imm_*).
    lX = min(4, ζ[ı+1] mod 8). -/
def extractTwoImm (code : ByteArray) (pc : Nat) (skip : Nat) : UInt64 × UInt64 :=
  let lx := min 4 (zeta code (pc + 1) % 8)
  let ly := if skip > lx + 1 then min 4 (skip - lx - 1) else 0
  let immX := readSignedAt code (pc + 2) lx
  let immY := readSignedAt code (pc + 2 + lx) ly
  (immX, immY)

/-- A.5.5: OneOffset — jump target.
    lX = min(4, ℓ), target = ı + Z_lX(...). -/
def extractOffset (code : ByteArray) (pc : Nat) (skip : Nat) : UInt64 :=
  let lx := min 4 skip
  let signedOffset := readSignedAt code (pc + 1) lx
  -- target = pc + signed_offset (wrapping)
  (UInt64.ofNat pc) + signedOffset

/-- A.5.6: OneRegOneImm — register + one immediate.
    rA = min(12, ζ[ı+1] mod 16), lX = min(4, max(0, ℓ-1)). -/
def extractRegImm (code : ByteArray) (pc : Nat) (skip : Nat) : Fin 13 × UInt64 :=
  let ra : Fin 13 := ⟨min 12 (zeta code (pc + 1) % 16), by omega⟩
  let lx := if skip > 1 then min 4 (skip - 1) else 0
  let imm := readSignedAt code (pc + 2) lx
  (ra, imm)

/-- A.5.7: OneRegTwoImm — register + two immediates (branch_eq_imm etc).
    Byte 1: low 4 = reg, bits 4-6 = lX encoding. -/
def extractRegTwoImm (code : ByteArray) (pc : Nat) (skip : Nat) : Fin 13 × UInt64 × UInt64 :=
  let b1 := zeta code (pc + 1)
  let ra : Fin 13 := ⟨min 12 (b1 % 16), by omega⟩
  let lx := min 4 (b1 / 16 % 8)
  let ly := if skip > lx + 1 then min 4 (skip - lx - 1) else 0
  let immX := readSignedAt code (pc + 2) lx
  let immY := readSignedAt code (pc + 2 + lx) ly
  (ra, immX, immY)

/-- A.5.8: OneRegImmOffset — register + immediate + offset (load_imm_jump, branches).
    Same encoding as OneRegTwoImm but second value is pc-relative offset.
    Returns (reg, imm, target). -/
def extractRegImmOffset (code : ByteArray) (pc : Nat) (skip : Nat) : Fin 13 × UInt64 × UInt64 :=
  let b1 := zeta code (pc + 1)
  let reg : Fin 13 := ⟨min 12 (b1 % 16), by omega⟩
  let lx := min 4 (b1 / 16 % 8)
  let ly := if skip > lx + 1 then min 4 (skip - lx - 1) else 0
  let imm := readSignedAt code (pc + 2) lx
  let signedOffset := readSignedAt code (pc + 2 + lx) ly
  let target := (UInt64.ofNat pc) + signedOffset
  (reg, imm, target)

/-- A.5.10: TwoRegOneImm — two registers + one immediate.
    lX = min(4, max(0, ℓ-1)). Used for ALU ops, loads, stores. -/
def extractTwoRegImm (code : ByteArray) (pc : Nat) (skip : Nat)
    : Fin 13 × Fin 13 × UInt64 :=
  let rA := regA code pc
  let rB := regB code pc
  let lx := if skip > 1 then min 4 (skip - 1) else 0
  let imm := readSignedAt code (pc + 2) lx
  (rA, rB, imm)

/-- A.5.11: TwoRegOneOffset — two registers + offset.
    Same as TwoRegOneImm but value is pc-relative. Returns (rA, rB, target). -/
def extractTwoRegOffset (code : ByteArray) (pc : Nat) (skip : Nat)
    : Fin 13 × Fin 13 × UInt64 :=
  let rA := regA code pc
  let rB := regB code pc
  let lx := if skip > 1 then min 4 (skip - 1) else 0
  let signedOffset := readSignedAt code (pc + 2) lx
  let target := (UInt64.ofNat pc) + signedOffset
  (rA, rB, target)

/-- A.5.12: TwoRegTwoImm — two registers + two immediates.
    lX from ζ[ı+2], uses separate encoding byte. -/
def extractTwoRegTwoImm (code : ByteArray) (pc : Nat) (skip : Nat)
    : Fin 13 × Fin 13 × UInt64 × UInt64 :=
  let rA := regA code pc
  let rB := regB code pc
  let lx := min 4 (zeta code (pc + 2) % 8)
  let ly := if skip > lx + 2 then min 4 (skip - lx - 2) else 0
  let immX := readSignedAt code (pc + 3) lx
  let immY := readSignedAt code (pc + 3 + lx) ly
  (rA, rB, immX, immY)

-- ============================================================================
-- Dynamic Jump — GP eq (210)
-- ============================================================================

/-- Host-call result sentinel values. GP Appendix B. -/
def RESULT_NONE : UInt64 := UInt64.ofNat (2^64 - 1)
def RESULT_WHAT : UInt64 := UInt64.ofNat (2^64 - 2)
def RESULT_OOB  : UInt64 := UInt64.ofNat (2^64 - 3)
def RESULT_WHO  : UInt64 := UInt64.ofNat (2^64 - 4)
def RESULT_FULL : UInt64 := UInt64.ofNat (2^64 - 5)
def RESULT_CORE : UInt64 := UInt64.ofNat (2^64 - 6)
def RESULT_CASH : UInt64 := UInt64.ofNat (2^64 - 7)
def RESULT_LOW  : UInt64 := UInt64.ofNat (2^64 - 8)
def RESULT_HUH  : UInt64 := UInt64.ofNat (2^64 - 9)
def RESULT_OK   : UInt64 := 0

/-- Invoke (12) exit codes. GP §B.4. -/
def INVOKE_HALT  : UInt64 := 0
def INVOKE_PANIC : UInt64 := 1
def INVOKE_FAULT : UInt64 := 2
def INVOKE_HOST  : UInt64 := 3
def INVOKE_OOG   : UInt64 := 4

-- ============================================================================
-- JAR v2 Program Blob Parser
-- ============================================================================

/-- JAR v2 magic value: 'J'=0x4A, 'A'=0x41, 'R'=0x52, 0x02. -/
def jarV2Magic : Nat := decodeLEn ⟨#[0x4A, 0x41, 0x52, 0x02]⟩ 0 4

/-- JAR v2 header (11 bytes). -/
structure JarV2Header where
  memoryPages : Nat
  capCount : Nat
  invokeCap : Nat
  argsCap : Nat

/-- JAR v2 capability entry (19 bytes). -/
structure JarV2CapEntry where
  capIndex : Nat
  isCode : Bool      -- true = CODE, false = DATA
  basePage : Nat     -- DATA only
  pageCount : Nat    -- DATA only
  isRW : Bool        -- DATA only (true = RW, false = RO)
  dataOffset : Nat   -- offset into data section
  dataLen : Nat      -- bytes of initial data

/-- Parse a JAR v2 header (11 bytes). Returns header + offset after header. -/
def parseJarV2Header (blob : ByteArray) : Option (JarV2Header × Nat) := do
  if blob.size < 11 then none
  let magic := decodeLEn blob 0 4
  if magic != jarV2Magic then none
  some ({
    memoryPages := decodeLEn blob 4 4
    capCount := (blob.get! 8).toNat
    invokeCap := (blob.get! 9).toNat
    argsCap := (blob.get! 10).toNat
  }, 11)

/-- Parse a JAR v2 capability entry (19 bytes) at the given offset. -/
def parseJarV2CapEntry (blob : ByteArray) (offset : Nat) : Option (JarV2CapEntry × Nat) := do
  if offset + 19 > blob.size then none
  let capType := (blob.get! (offset + 1)).toNat
  if capType > 1 then none
  let initAccess := (blob.get! (offset + 10)).toNat
  if initAccess > 1 then none
  some ({
    capIndex := (blob.get! offset).toNat
    isCode := capType == 0
    basePage := decodeLEn blob (offset + 2) 4
    pageCount := decodeLEn blob (offset + 6) 4
    isRW := initAccess == 1
    dataOffset := decodeLEn blob (offset + 11) 4
    dataLen := decodeLEn blob (offset + 15) 4
  }, offset + 19)

/-- Parse a CODE cap's sub-blob into a ProgramBlob.
    Format: jump_len(4) + entry_size(1) + code_len(4) + jt + code + bitmask. -/
def parseCodeSubBlob (blob : ByteArray) (dataOffset dataLen : Nat)
    : Option ProgramBlob := do
  if dataLen < 9 then none
  let off := dataOffset
  if off + 9 > blob.size then none
  let jumpLen := decodeLEn blob off 4
  let entrySize := (blob.get! (off + 4)).toNat
  let codeLen := decodeLEn blob (off + 5) 4
  if entrySize == 0 || entrySize > 4 then none

  let off := off + 9
  -- Jump table
  let jtBytes := jumpLen * entrySize
  if off + jtBytes > blob.size then none
  let jumpTable := Array.ofFn (n := jumpLen) fun ⟨i, _⟩ =>
    UInt32.ofNat (decodeLEn blob (off + i * entrySize) entrySize)
  let off := off + jtBytes

  -- Code
  if off + codeLen > blob.size then none
  let code := blob.extract off (off + codeLen)
  let off := off + codeLen

  -- Packed bitmask
  let bitmaskLen := (codeLen + 7) / 8
  if off + bitmaskLen > blob.size then none
  let packedBitmask := blob.extract off (off + bitmaskLen)
  let bitmask := ByteArray.mk (Array.ofFn (n := codeLen) fun ⟨i, _⟩ =>
    let byteIdx := i / 8
    let bitIdx := i % 8
    if byteIdx < packedBitmask.size then
      UInt8.ofNat ((packedBitmask.get! byteIdx).toNat / (2 ^ bitIdx) % 2)
    else 0)

  let prog : ProgramBlob := { code, bitmask, jumpTable }
  if !validateBasicBlocks prog then none
  some prog

end Jar.PVM
