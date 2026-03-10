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
def toSigned (x : UInt64) : Int64 := Int64.mk x

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

/-- Decode a variable-length natural from `n` LE bytes starting at offset. -/
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

/-- Deblob: parse a program blob into (code, bitmask, jumpTable). GP Appendix A.
    Format: encode[3](|j|) ‖ encode[1](z) ‖ encode[3](|c|) ‖ encode[z](j) ‖ c ‖ k
    where z = jump table entry size (1-4), j = jump table, c = code, k = bitmask. -/
def deblob (blob : ByteArray) : Option ProgramBlob := do
  if blob.size < 7 then none
  let jumpLen := decodeLEn blob 0 3     -- |j|: number of jump table entries
  let z := decodeLEn blob 3 1           -- z: bytes per jump table entry
  let codeLen := decodeLEn blob 4 3     -- |c|: code length
  if z == 0 || z > 4 then none
  let jumpDataStart := 7
  let jumpDataLen := jumpLen * z
  let codeStart := jumpDataStart + jumpDataLen
  let bitmaskStart := codeStart + codeLen
  -- Bitmask covers code bytes, packed 8 bits per byte, ceil division
  let bitmaskLen := (codeLen + 7) / 8
  if bitmaskStart + bitmaskLen > blob.size then none
  -- Parse jump table
  let jumpTable := Array.ofFn (n := jumpLen) fun ⟨i, _⟩ =>
    UInt32.ofNat (decodeLEn blob (jumpDataStart + i * z) z)
  -- Extract code
  let code := blob.extract codeStart (codeStart + codeLen)
  -- Extract bitmask
  let bitmask := blob.extract bitmaskStart (bitmaskStart + bitmaskLen)
  some { code, bitmask, jumpTable }

-- ============================================================================
-- Bitmask / Skip — GP Appendix A
-- ============================================================================

/-- Check if bit at position `i` is set in the bitmask. -/
def bitmaskGet (bm : ByteArray) (i : Nat) : Bool :=
  let byteIdx := i / 8
  let bitIdx := i % 8
  if byteIdx < bm.size then
    (bm.get! byteIdx).toNat / (2 ^ bitIdx) % 2 == 1
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

/-- Extract a sign-extended immediate from instruction bytes.
    Starts at `pc + startByte`, reads up to `skip + 1 - startByte` bytes.
    The immediate is sign-extended based on the number of available bytes. -/
def extractImm (code : ByteArray) (pc : Nat) (skip : Nat) (startByte : Nat) : UInt64 :=
  let availBytes := if skip + 1 > startByte then skip + 1 - startByte else 0
  let nBytes := min availBytes 4
  if nBytes == 0 then 0
  else
    let raw := readImmBytes code (pc + startByte) nBytes
    sext nBytes raw

/-- Extract a sign-extended 8-byte immediate (for load_imm_64). -/
def extractImm64 (code : ByteArray) (pc : Nat) (skip : Nat) : UInt64 :=
  let availBytes := if skip + 1 > 2 then skip + 1 - 2 else 0
  let nBytes := min availBytes 8
  if nBytes == 0 then 0
  else
    let raw := readImmBytes code (pc + 2) nBytes
    sext nBytes raw

/-- Extract two immediates for two-immediate format (opcodes 30-33, 70-73, 80-90, 180).
    Byte 1 encodes lengths: lX in bits 0-1, lY in bits 2-3 (each 0-3 means 1-4 bytes).
    Returns (immX, immY). -/
def extractTwoImm (code : ByteArray) (pc : Nat) (_skip : Nat) : UInt64 × UInt64 :=
  let b1 := if pc + 1 < code.size then code.get! (pc + 1) |>.toNat else 0
  let lX := (b1 % 4) + 1  -- 1-4 bytes for first immediate
  let lY := (b1 / 4 % 4) + 1  -- 1-4 bytes for second immediate
  let immX := sext lX (readImmBytes code (pc + 2) lX)
  let immY := sext lY (readImmBytes code (pc + 2 + lX) lY)
  (immX, immY)

/-- Extract register + immediate + offset for branch-imm format (opcodes 80-90).
    Byte 1 low 4 bits: register, rest: lX length encoding.
    Returns (reg, imm, offset). -/
def extractRegImmOffset (code : ByteArray) (pc : Nat) (skip : Nat) : Fin 13 × UInt64 × UInt64 :=
  let b1 := if pc + 1 < code.size then code.get! (pc + 1) |>.toNat else 0
  let reg : Fin 13 := ⟨min 12 (b1 % 16), by omega⟩
  let lX := (b1 / 16 % 4) + 1
  let immX := sext lX (readImmBytes code (pc + 2) lX)
  -- Offset is the remaining bytes after immX
  let offsetStart := pc + 2 + lX
  let remainingBytes := if skip + 1 > (2 + lX) then skip + 1 - (2 + lX) else 0
  let nOff := min remainingBytes 4
  let offset := sext nOff (readImmBytes code offsetStart nOff)
  (reg, immX, offset)

/-- Extract two registers + two immediates for format 180. -/
def extractTwoRegTwoImm (code : ByteArray) (pc : Nat) (_skip : Nat)
    : Fin 13 × Fin 13 × UInt64 × UInt64 :=
  let rA := regA code pc
  let rB := regB code pc
  let b2 := if pc + 2 < code.size then code.get! (pc + 2) |>.toNat else 0
  let lX := (b2 % 4) + 1
  let lY := (b2 / 4 % 4) + 1
  let immX := sext lX (readImmBytes code (pc + 3) lX)
  let immY := sext lY (readImmBytes code (pc + 3 + lX) lY)
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

end Jar.PVM
