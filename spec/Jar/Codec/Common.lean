import Jar.Notation
import Jar.Types.Numerics
import Jar.Types.Constants
import Jar.Types.Work
import Jar.Types.Header

/-!
# JAM Codec — Common Definitions

Shared encoding/decoding utilities used by both gp072 and jar1 codecs.
-/

namespace Jar.Codec.Common
variable [JarConfig]

-- ============================================================================
-- Fixed-width Little-Endian Integer Encoding — 𝓔_l
-- ============================================================================

/-- 𝓔_l : Fixed-width LE encoding. GP eq (C.12).
    Encodes natural x into exactly l bytes, little-endian. -/
def encodeFixedNat : Nat → Nat → ByteArray
  | 0, _ => ByteArray.empty
  | l + 1, x => ByteArray.mk #[UInt8.ofNat (x % 256)] ++ encodeFixedNat l (x / 256)

/-- Decode fixed-width LE bytes back to a natural number. -/
def decodeFixedNat (bs : ByteArray) : Nat :=
  bs.data.foldl (init := (0, 1)) (fun (acc, mul) b => (acc + b.toNat * mul, mul * 256)) |>.1

-- ============================================================================
-- Discriminator Encodings
-- ============================================================================

/-- ¿x : Optional discriminator encoding. GP eq (C.6).
    None → [0], Some x → [1] ++ encode(x). -/
def encodeOption (f : α → ByteArray) : Option α → ByteArray
  | none => ByteArray.mk #[0]
  | some x => ByteArray.mk #[1] ++ f x

-- ============================================================================
-- Bit Sequence Encoding — §C.2
-- ============================================================================

/-- Pack 8 bits starting at offset into a single byte, LSB-first. -/
private def packByte (bs : Array Bool) (offset : Nat) : UInt8 :=
  let fold (acc : UInt8) (bitIdx : Nat) : UInt8 :=
    let i := offset + bitIdx
    if h : i < bs.size then
      if bs[i] then acc ||| (1 <<< bitIdx.toUInt8) else acc
    else acc
  List.foldl fold 0 [0, 1, 2, 3, 4, 5, 6, 7]

/-- Pack a boolean array into bytes, LSB-first within each byte. GP eq (C.9). -/
def encodeBits (bs : Array Bool) : ByteArray :=
  if bs.size == 0 then ByteArray.empty
  else
    let numBytes := (bs.size + 7) / 8
    let bytes := Array.ofFn (n := numBytes) fun ⟨byteIdx, _⟩ =>
      packByte bs (byteIdx * 8)
    ByteArray.mk bytes

-- ============================================================================
-- Concatenation helpers
-- ============================================================================

/-- Concatenate an array of ByteArrays. -/
def concatBytes (parts : Array ByteArray) : ByteArray :=
  parts.foldl (· ++ ·) ByteArray.empty

/-- Encode an array of items and concatenate (no prefix). -/
def encodeArray (f : α → ByteArray) (xs : Array α) : ByteArray :=
  concatBytes (xs.map f)

-- ============================================================================
-- Work Result Encoding O(result) — §C.3
-- ============================================================================

open Jar in
/-- O(result) : Work result encoding. GP eq (C.3).
    This is shared between gp072 and jar1 — discriminant + optional payload. -/
def encodeWorkResult (encodeLenPrefixed : ByteArray → ByteArray) (r : Jar.WorkResult) : ByteArray :=
  match r with
  | .ok data => ByteArray.mk #[0] ++ encodeLenPrefixed data
  | .err .outOfGas => ByteArray.mk #[1]
  | .err .panic => ByteArray.mk #[2]
  | .err .badExports => ByteArray.mk #[3]
  | .err .badCode => ByteArray.mk #[4]
  | .err .bigCode => ByteArray.mk #[5]
  | .err .oversize => ByteArray.mk #[5]

end Jar.Codec.Common
