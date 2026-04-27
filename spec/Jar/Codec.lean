import Jar.Notation
import Jar.Types.Numerics
import Jar.Types.Constants
import Jar.Types.Work
import Jar.Types.Header

/-!
# JAM Codec — Appendix C

Serialization and deserialization for the JAM protocol.
References: `graypaper/text/serialization.tex`.

## Structure
- §C.7: Fixed-width little-endian integer encoding `𝓔_l`
- §C.1: Variable-length natural encoding `𝓔` for ℕ_{2^64}
- §C.1: Optional discriminator `¿x`
- §C.1: Length-prefixed discriminator `↕x`
- §C.2: Bit sequence packing
- §C.3: Work result encoding `O(result)`
- §C.4: Block serialization
-/

namespace Jar.Codec
variable [JarConfig]

-- ============================================================================
-- §C.7 — Fixed-width Little-Endian Integer Encoding
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
-- §C.1 — Variable-length Natural Encoding
-- ============================================================================

/-- Compute l such that 2^{7l} ≤ x < 2^{7(l+1)}, or 8 if x ≥ 2^{56}.
    Exposed for use in proof code (Jar.Proofs.Codec). -/
def lengthClass (x : Nat) : Nat :=
  if x < 2^7  then 0
  else if x < 2^14 then 1
  else if x < 2^21 then 2
  else if x < 2^28 then 3
  else if x < 2^35 then 4
  else if x < 2^42 then 5
  else if x < 2^49 then 6
  else if x < 2^56 then 7
  else 8  -- needs 8-byte mode with 0xFF prefix

/-- 𝓔 : Variable-length natural encoding. GP eq (C.1).
    Encodes naturals up to 2^64 into 1–9 bytes. -/
def encodeNat (x : Nat) : ByteArray :=
  if x == 0 then ByteArray.mk #[0]
  else
    let l := lengthClass x
    if l < 8 then
      -- Header byte: 2^8 - 2^(8-l) + ⌊x / 2^(8l)⌋
      let header := 256 - (256 / (2^l)) + (x / (2^(8*l)))
      ByteArray.mk #[UInt8.ofNat header] ++ encodeFixedNat l (x % (2^(8*l)))
    else
      -- 0xFF prefix + 8 bytes LE
      ByteArray.mk #[0xFF] ++ encodeFixedNat 8 x

-- ============================================================================
-- §C.1 — Discriminator Encodings
-- ============================================================================

/-- ¿x : Optional discriminator encoding. GP eq (C.6).
    None → [0], Some x → [1] ++ 𝓔(x). -/
def encodeOption (f : α → ByteArray) : Option α → ByteArray
  | none => ByteArray.mk #[0]
  | some x => ByteArray.mk #[1] ++ f x

/-- ↕x : Length-prefixed encoding. GP eq (C.4).
    Prepends the byte-length of the encoded data as a variable-length natural. -/
def encodeLengthPrefixed (data : ByteArray) : ByteArray :=
  encodeNat data.size ++ data

-- ============================================================================
-- §C.2 — Bit Sequence Encoding
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
-- §C.3 — Work Result Encoding O(result)
-- ============================================================================

/-- O(result) : Work result encoding. GP eq (C.3).
    ok(blob) → 0 ++ ↕blob
    outOfGas → 1, panic → 2, badExports → 3, oversize → 4, bad → 5, big → 6. -/
def encodeWorkResult (r : Jar.WorkResult) : ByteArray :=
  match r with
  | .ok data => ByteArray.mk #[0] ++ encodeLengthPrefixed data
  | .err .outOfGas => ByteArray.mk #[1]
  | .err .panic => ByteArray.mk #[2]
  | .err .badExports => ByteArray.mk #[3]
  | .err .badCode => ByteArray.mk #[4]      -- GP: ⊤
  | .err .bigCode => ByteArray.mk #[5]      -- GP: BIG
  | .err .oversize => ByteArray.mk #[5]     -- maps to BIG (not in GP as separate variant)

-- ============================================================================
-- §C.4 — Compound Serialization Helpers
-- ============================================================================

/-- Concatenate an array of ByteArrays. -/
def concatBytes (parts : Array ByteArray) : ByteArray :=
  parts.foldl (· ++ ·) ByteArray.empty

/-- Encode an array of items and concatenate (for fixed-size element encoding). -/
def encodeArray (f : α → ByteArray) (xs : Array α) : ByteArray :=
  concatBytes (xs.map f)

/-- Encode an array with byte-length prefix (for backward compat). -/
def encodeLengthPrefixedArray (f : α → ByteArray) (xs : Array α) : ByteArray :=
  encodeLengthPrefixed (encodeArray f xs)

/-- Encode a sequence with count prefix. GP eq (C.4):
    𝓔([x₁, ..., xₙ]) ≡ 𝓔(n) ⌢ 𝓔(x₁) ⌢ ... ⌢ 𝓔(xₙ). -/
def encodeCountPrefixedArray (f : α → ByteArray) (xs : Array α) : ByteArray :=
  encodeNat xs.size ++ encodeArray f xs

-- ============================================================================
-- Block Serialization — §C.4 (eq C.16–C.35)
-- ============================================================================

open Jar in
/-- Encode a Ticket. GP eq (C.34). -/
def encodeTicket (t : Ticket) : ByteArray :=
  t.id.data ++ ByteArray.mk #[UInt8.ofNat t.attempt]

open Jar in
/-- Encode a TicketProof for the tickets extrinsic. -/
def encodeTicketProof (tp : TicketProof) : ByteArray :=
  ByteArray.mk #[UInt8.ofNat tp.attempt] ++ tp.proof.data

open Jar in
/-- Encode an Assurance. GP §C.4. -/
def encodeAssurance (a : Assurance) : ByteArray :=
  a.anchor.data ++ a.bitfield ++ encodeFixedNat 2 a.validatorIndex.val ++ a.signature.data

open Jar in
/-- Encode a single Judgment. -/
def encodeJudgment (j : Judgment) : ByteArray :=
  ByteArray.mk #[if j.isValid then 1 else 0]
    ++ encodeFixedNat 2 j.validatorIndex.val
    ++ j.signature.data

open Jar in
/-- Encode a Verdict. -/
def encodeVerdict (v : Verdict) : ByteArray :=
  v.reportHash.data
    ++ encodeFixedNat 4 v.age.toNat
    ++ encodeArray encodeJudgment v.judgments

open Jar in
/-- Encode a Culprit. -/
def encodeCulprit (c : Culprit) : ByteArray :=
  c.reportHash.data ++ c.validatorKey.data ++ c.signature.data

open Jar in
/-- Encode a Fault. -/
def encodeFault (f : Fault) : ByteArray :=
  f.reportHash.data
    ++ ByteArray.mk #[if f.isValid then 1 else 0]
    ++ f.validatorKey.data
    ++ f.signature.data

open Jar in
/-- Encode the disputes extrinsic. GP §C.4. -/
def encodeDisputes (d : DisputesExtrinsic) : ByteArray :=
  encodeCountPrefixedArray encodeVerdict d.verdicts
    ++ encodeCountPrefixedArray encodeCulprit d.culprits
    ++ encodeCountPrefixedArray encodeFault d.faults

open Jar in
/-- Encode the preimages extrinsic. GP §C.4. -/
def encodePreimages (ps : PreimagesExtrinsic) : ByteArray :=
  encodeCountPrefixedArray (fun (sid, blob) =>
    encodeFixedNat 4 sid.toNat ++ encodeLengthPrefixed blob) ps

open Jar in
/-- Encode an AvailabilitySpec. GP §C.4. -/
def encodeAvailSpec (a : AvailabilitySpec) : ByteArray :=
  a.packageHash.data
    ++ encodeFixedNat 4 a.bundleLength.toNat
    ++ a.erasureRoot.data
    ++ a.segmentRoot.data
    ++ encodeFixedNat 2 a.segmentCount

open Jar in
/-- Encode a RefinementContext. GP §C.4. -/
def encodeRefinementContext (c : RefinementContext) : ByteArray :=
  c.anchorHash.data
    ++ c.anchorStateRoot.data
    ++ c.anchorBeefyRoot.data
    ++ c.lookupAnchorHash.data
    ++ encodeFixedNat 4 c.lookupAnchorTimeslot.toNat
    ++ encodeCountPrefixedArray (fun h => h.data) c.prerequisites

open Jar in
/-- Encode a WorkDigest. GP §C.4. -/
def encodeWorkDigest (d : WorkDigest) : ByteArray :=
  encodeFixedNat 4 d.serviceId.toNat
    ++ d.codeHash.data
    ++ d.payloadHash.data
    ++ encodeFixedNat 8 d.gasLimit.toNat
    ++ encodeWorkResult d.result
    ++ encodeNat d.gasUsed.toNat
    ++ encodeNat d.importsCount
    ++ encodeNat d.extrinsicsCount
    ++ encodeNat d.extrinsicsSize
    ++ encodeNat d.exportsCount

open Jar in
/-- Encode a WorkReport. GP §C.4. -/
def encodeWorkReport (wr : WorkReport) : ByteArray :=
  encodeAvailSpec wr.availSpec
    ++ encodeRefinementContext wr.context
    ++ encodeNat wr.coreIndex.val              -- GP: compact encoding
    ++ wr.authorizerHash.data
    ++ encodeNat wr.authGasUsed.toNat          -- GP: compact encoding
    ++ encodeLengthPrefixed wr.authOutput      -- GP C.3: byte string
    ++ encodeCountPrefixedArray (fun (k, v) => k.data ++ v.data)
        wr.segmentRootLookup.entries.toArray   -- GP C.4: count prefix
    ++ encodeCountPrefixedArray encodeWorkDigest wr.digests  -- GP C.4: count prefix

open Jar in
/-- Encode a Guarantee. GP §C.4. -/
def encodeGuarantee (g : Guarantee) : ByteArray :=
  encodeWorkReport g.report
    ++ encodeFixedNat 4 g.timeslot.toNat
    ++ encodeCountPrefixedArray (fun (vi, sig) =>
        encodeFixedNat 2 vi.val ++ sig.data) g.credentials

open Jar in
/-- Encode an EpochMarker. GP#514: variable-length validators when variableValidators. -/
def encodeEpochMarker (em : EpochMarker) : ByteArray :=
  em.entropy.data
    ++ em.entropyPrev.data
    ++ (if JarConfig.variableValidators
        then encodeNat em.validators.size  -- variable-length count prefix
        else ByteArray.empty)
    ++ encodeArray (fun (bk, ek) => bk.data ++ ek.data) em.validators

open Jar in
/-- 𝓔_U(H) : Unsigned header encoding. GP eq (C.26). -/
def encodeUnsignedHeader (h : Header) : ByteArray :=
  h.parent.data
    ++ h.stateRoot.data
    ++ h.extrinsicHash.data
    ++ encodeFixedNat 4 h.timeslot.toNat
    ++ encodeOption encodeEpochMarker h.epochMarker
    ++ encodeOption (encodeArray encodeTicket) h.ticketsMarker
    ++ encodeFixedNat 2 h.authorIndex.val
    ++ h.vrfSignature.data
    ++ encodeCountPrefixedArray (fun k => k.data) h.offenders

open Jar in
/-- 𝓔(H) : Full header encoding (unsigned + seal). GP eq (C.25). -/
def encodeHeader (h : Header) : ByteArray :=
  encodeUnsignedHeader h ++ h.sealSig.data

open Jar in
/-- 𝓔(E) : Extrinsic encoding. GP §C.4. -/
def encodeExtrinsic (e : Extrinsic) : ByteArray :=
  encodeCountPrefixedArray encodeTicketProof e.tickets
    ++ encodePreimages e.preimages
    ++ encodeCountPrefixedArray encodeGuarantee e.guarantees
    ++ encodeCountPrefixedArray encodeAssurance e.assurances
    ++ encodeDisputes e.disputes

open Jar in
/-- 𝓔(B) : Block encoding. GP eq (C.16). -/
def encodeBlock (b : Block) : ByteArray :=
  encodeHeader b.header ++ encodeExtrinsic b.extrinsic

-- ============================================================================
-- Decoder Monad
-- ============================================================================

/-- State for the decoder: a ByteArray and a current position. -/
structure DecodeState where
  data : ByteArray
  pos : Nat

/-- Decoder monad: a function from state to an optional (result, new state). -/
abbrev Decoder (α : Type) := DecodeState → Option (α × DecodeState)

namespace Decoder

/-- Run a decoder on a ByteArray starting at position 0. -/
def run (d : Decoder α) (data : ByteArray) : Option α :=
  (d { data, pos := 0 }).map (·.1)

/-- Pure: return a value without consuming any input. -/
def pure (a : α) : Decoder α := fun s => some (a, s)

/-- Bind: sequence two decoders. -/
def bind (d : Decoder α) (f : α → Decoder β) : Decoder β := fun s =>
  match d s with
  | none => none
  | some (a, s') => f a s'

instance : Monad Decoder where
  pure := Decoder.pure
  bind := Decoder.bind

instance : Alternative Decoder where
  failure := fun _ => none
  orElse d1 d2 := fun s =>
    match d1 s with
    | some r => some r
    | none => d2 () s

/-- Guard: fail if condition is false. -/
def guard (b : Bool) : Decoder Unit := fun s =>
  if b then some ((), s) else none

/-- Read exactly n bytes from the input. -/
def readBytes (n : Nat) : Decoder ByteArray := fun s =>
  if s.pos + n ≤ s.data.size then
    some (s.data.extract s.pos (s.pos + n), { s with pos := s.pos + n })
  else none

/-- Read a single byte. -/
def readByte : Decoder UInt8 := fun s =>
  if h : s.pos < s.data.size then
    some (s.data[s.pos], { s with pos := s.pos + 1 })
  else none

/-- Check remaining bytes available. -/
def remaining : Decoder Nat := fun s =>
  some (s.data.size - s.pos, s)

/-- Decode an array by repeating a decoder exactly n times. -/
def replicateD (n : Nat) (d : Decoder α) : Decoder (Array α) :=
  go n #[]
where
  go : Nat → Array α → Decoder (Array α)
    | 0, acc => Decoder.pure acc
    | k + 1, acc => fun s =>
      match d s with
      | none => none
      | some (v, s') => go k (acc.push v) s'

end Decoder

-- ============================================================================
-- §C.7 — Fixed-width LE Decoding (Decoder monad version)
-- ============================================================================

/-- Decode a fixed-width LE natural of exactly n bytes. -/
def decodeFixedNatD (n : Nat) : Decoder Nat := do
  let bs ← Decoder.readBytes n
  return decodeFixedNat bs

-- ============================================================================
-- §C.1 — Variable-length Natural Decoding
-- ============================================================================

/-- 𝓔⁻¹ : Decode a variable-length natural. Inverse of encodeNat. -/
def decodeNatD : Decoder Nat := do
  let header ← Decoder.readByte
  let h := header.toNat
  if h < 128 then        -- l=0
    return h
  else if h < 192 then   -- l=1
    let b ← Decoder.readByte
    return (h - 128) * 256 + b.toNat
  else if h < 224 then   -- l=2
    let bs ← Decoder.readBytes 2
    let lo := decodeFixedNat bs
    return (h - 192) * 65536 + lo
  else if h < 240 then   -- l=3
    let bs ← Decoder.readBytes 3
    let lo := decodeFixedNat bs
    return (h - 224) * 16777216 + lo
  else if h < 248 then   -- l=4
    let bs ← Decoder.readBytes 4
    let lo := decodeFixedNat bs
    return (h - 240) * 4294967296 + lo
  else if h < 252 then   -- l=5
    let bs ← Decoder.readBytes 5
    let lo := decodeFixedNat bs
    return (h - 248) * 1099511627776 + lo
  else if h < 254 then   -- l=6
    let bs ← Decoder.readBytes 6
    let lo := decodeFixedNat bs
    return (h - 252) * 281474976710656 + lo
  else if h < 255 then   -- l=7
    let bs ← Decoder.readBytes 7
    let lo := decodeFixedNat bs
    return (h - 254) * 72057594037927936 + lo
  else                    -- h=0xFF, l=8
    let bs ← Decoder.readBytes 8
    return decodeFixedNat bs

-- ============================================================================
-- §C.1 — Discriminator Decodings
-- ============================================================================

/-- Decode an optional value. Inverse of encodeOption. -/
def decodeOptionD (f : Decoder α) : Decoder (Option α) := do
  let tag ← Decoder.readByte
  if tag.toNat == 0 then
    return none
  else if tag.toNat == 1 then
    let v ← f
    return some v
  else
    failure

/-- Decode a length-prefixed blob. Inverse of encodeLengthPrefixed. -/
def decodeLengthPrefixedD : Decoder ByteArray := do
  let len ← decodeNatD
  Decoder.readBytes len

-- ============================================================================
-- §C.2 — Bit Sequence Decoding
-- ============================================================================

/-- Unpack bits from a byte, LSB-first, returning up to `count` bools. -/
private def unpackByteBools (b : UInt8) (count : Nat) : List Bool :=
  go 0 count
where
  go (i : Nat) : Nat → List Bool
    | 0 => []
    | remaining + 1 => ((b >>> i.toUInt8) &&& 1 == 1) :: go (i + 1) remaining

/-- Unpack all bits from a ByteArray, returning exactly `totalBits` bools. -/
private def unpackAllBits (bs : ByteArray) (totalBits : Nat) : Array Bool :=
  go 0 #[]
where
  go (byteIdx : Nat) (acc : Array Bool) : Array Bool :=
    if byteIdx ≥ bs.size then acc
    else
      let bitsLeft := totalBits - byteIdx * 8
      let count := if bitsLeft < 8 then bitsLeft else 8
      if h : byteIdx < bs.size then
        let byte := bs[byteIdx]
        let bits := unpackByteBools byte count
        go (byteIdx + 1) (acc ++ bits.toArray)
      else acc

/-- Decode n bits packed LSB-first. Inverse of encodeBits. -/
def decodeBitsD (n : Nat) : Decoder (Array Bool) := do
  if n == 0 then return #[]
  let numBytes := (n + 7) / 8
  let bs ← Decoder.readBytes numBytes
  return unpackAllBits bs n

-- ============================================================================
-- §C.4 — Compound Deserialization Helpers
-- ============================================================================

/-- Decode a count-prefixed array. Inverse of encodeCountPrefixedArray. -/
def decodeCountPrefixedArrayD (f : Decoder α) : Decoder (Array α) := do
  let count ← decodeNatD
  Decoder.replicateD count f

/-- Decode a fixed-size array (no count prefix). Inverse of encodeArray. -/
def decodeArrayD (n : Nat) (f : Decoder α) : Decoder (Array α) :=
  Decoder.replicateD n f

-- ============================================================================
-- §C.3 — Work Result Decoding
-- ============================================================================

open Jar in
/-- Decode a WorkResult. Inverse of encodeWorkResult. -/
def decodeWorkResultD : Decoder WorkResult := do
  let tag ← Decoder.readByte
  match tag.toNat with
  | 0 =>
    let blob ← decodeLengthPrefixedD
    return WorkResult.ok blob
  | 1 => return WorkResult.err .outOfGas
  | 2 => return WorkResult.err .panic
  | 3 => return WorkResult.err .badExports
  | 4 => return WorkResult.err .badCode
  | 5 => return WorkResult.err .bigCode
  | _ => failure

-- ============================================================================
-- §C.4 — Block Deserialization
-- ============================================================================

/-- Decode a fixed-size OctetSeq. -/
def decodeOctetSeqD (n : Nat) : Decoder (OctetSeq n) := do
  let bs ← Decoder.readBytes n
  if h : bs.size = n then
    return ⟨bs, h⟩
  else
    failure

/-- Decode a Hash (32 bytes). -/
def decodeHashD : Decoder Hash := decodeOctetSeqD 32

open Jar in
/-- Decode a Ticket. Inverse of encodeTicket. -/
def decodeTicketD : Decoder Ticket := do
  let id ← decodeHashD
  let attempt ← Decoder.readByte
  return { id, attempt := attempt.toNat }

open Jar in
/-- Decode a TicketProof. Inverse of encodeTicketProof. -/
def decodeTicketProofD : Decoder TicketProof := do
  let attempt ← Decoder.readByte
  let proof ← decodeOctetSeqD 784
  return { attempt := attempt.toNat, proof }

open Jar in
/-- Decode an Assurance. Inverse of encodeAssurance. -/
def decodeAssuranceD : Decoder Assurance := do
  let anchor ← decodeHashD
  let bitfieldLen := (C + 7) / 8
  let bitfield ← Decoder.readBytes bitfieldLen
  let vi ← decodeFixedNatD 2
  let sig ← decodeOctetSeqD 64
  if h : vi < V then
    return { anchor, bitfield, validatorIndex := ⟨vi, h⟩, signature := sig }
  else
    failure

open Jar in
/-- Decode a Judgment. Inverse of encodeJudgment. -/
def decodeJudgmentD : Decoder Judgment := do
  let isValidByte ← Decoder.readByte
  let isValid := isValidByte.toNat != 0
  let vi ← decodeFixedNatD 2
  let sig ← decodeOctetSeqD 64
  if h : vi < V then
    return { isValid, validatorIndex := ⟨vi, h⟩, signature := sig }
  else
    failure

open Jar in
/-- Decode a Verdict. Inverse of encodeVerdict. -/
def decodeVerdictD : Decoder Verdict := do
  let reportHash ← decodeHashD
  let ageNat ← decodeFixedNatD 4
  let age := UInt32.ofNat ageNat
  let judgments ← decodeCountPrefixedArrayD decodeJudgmentD
  return { reportHash, age, judgments }

open Jar in
/-- Decode a Culprit. Inverse of encodeCulprit. -/
def decodeCulpritD : Decoder Culprit := do
  let reportHash ← decodeHashD
  let validatorKey ← decodeOctetSeqD 32
  let signature ← decodeOctetSeqD 64
  return { reportHash, validatorKey, signature }

open Jar in
/-- Decode a Fault. Inverse of encodeFault. -/
def decodeFaultD : Decoder Fault := do
  let reportHash ← decodeHashD
  let isValidByte ← Decoder.readByte
  let isValid := isValidByte.toNat != 0
  let validatorKey ← decodeOctetSeqD 32
  let signature ← decodeOctetSeqD 64
  return { reportHash, isValid, validatorKey, signature }

open Jar in
/-- Decode the disputes extrinsic. Inverse of encodeDisputes. -/
def decodeDisputesD : Decoder DisputesExtrinsic := do
  let verdicts ← decodeCountPrefixedArrayD decodeVerdictD
  let culprits ← decodeCountPrefixedArrayD decodeCulpritD
  let faults ← decodeCountPrefixedArrayD decodeFaultD
  return { verdicts, culprits, faults }

open Jar in
/-- Decode the preimages extrinsic. Inverse of encodePreimages. -/
def decodePreimagesD : Decoder PreimagesExtrinsic := do
  decodeCountPrefixedArrayD do
    let sid ← decodeFixedNatD 4
    let blob ← decodeLengthPrefixedD
    return (UInt32.ofNat sid, blob)

open Jar in
/-- Decode an AvailabilitySpec. Inverse of encodeAvailSpec. -/
def decodeAvailSpecD : Decoder AvailabilitySpec := do
  let packageHash ← decodeHashD
  let bundleLength ← decodeFixedNatD 4
  let erasureRoot ← decodeHashD
  let segmentRoot ← decodeHashD
  let segmentCount ← decodeFixedNatD 2
  return {
    packageHash
    bundleLength := UInt32.ofNat bundleLength
    erasureRoot
    segmentRoot
    segmentCount
  }

open Jar in
/-- Decode a RefinementContext. Inverse of encodeRefinementContext. -/
def decodeRefinementContextD : Decoder RefinementContext := do
  let anchorHash ← decodeHashD
  let anchorStateRoot ← decodeHashD
  let anchorBeefyRoot ← decodeHashD
  let lookupAnchorHash ← decodeHashD
  let lookupAnchorTimeslot ← decodeFixedNatD 4
  let prerequisites ← decodeCountPrefixedArrayD decodeHashD
  return {
    anchorHash
    anchorStateRoot
    anchorBeefyRoot
    lookupAnchorHash
    lookupAnchorTimeslot := UInt32.ofNat lookupAnchorTimeslot
    prerequisites
  }

open Jar in
/-- Decode a WorkDigest. Inverse of encodeWorkDigest. -/
def decodeWorkDigestD : Decoder WorkDigest := do
  let serviceId ← decodeFixedNatD 4
  let codeHash ← decodeHashD
  let payloadHash ← decodeHashD
  let gasLimit ← decodeFixedNatD 8
  let result ← decodeWorkResultD
  let gasUsed ← decodeNatD
  let importsCount ← decodeNatD
  let extrinsicsCount ← decodeNatD
  let extrinsicsSize ← decodeNatD
  let exportsCount ← decodeNatD
  return {
    serviceId := UInt32.ofNat serviceId
    codeHash
    payloadHash
    gasLimit := UInt64.ofNat gasLimit
    result
    gasUsed := UInt64.ofNat gasUsed
    importsCount
    extrinsicsCount
    extrinsicsSize
    exportsCount
  }

open Jar in
/-- Decode a WorkReport. Inverse of encodeWorkReport. -/
def decodeWorkReportD : Decoder WorkReport := do
  let availSpec ← decodeAvailSpecD
  let context ← decodeRefinementContextD
  let coreIndexNat ← decodeNatD
  let authorizerHash ← decodeHashD
  let authGasUsed ← decodeNatD
  let authOutput ← decodeLengthPrefixedD
  let segmentRootLookupArr ← decodeCountPrefixedArrayD do
    let k ← decodeHashD
    let v ← decodeHashD
    return (k, v)
  let digests ← decodeCountPrefixedArrayD decodeWorkDigestD
  if h : coreIndexNat < C then
    return {
      availSpec
      context
      coreIndex := ⟨coreIndexNat, h⟩
      authorizerHash
      authGasUsed := UInt64.ofNat authGasUsed
      authOutput
      segmentRootLookup := ⟨segmentRootLookupArr.toList⟩
      digests
    }
  else
    failure

open Jar in
/-- Decode a Guarantee. Inverse of encodeGuarantee. -/
def decodeGuaranteeD : Decoder Guarantee := do
  let report ← decodeWorkReportD
  let timeslot ← decodeFixedNatD 4
  let credentials ← decodeCountPrefixedArrayD do
    let vi ← decodeFixedNatD 2
    let sig ← decodeOctetSeqD 64
    if h : vi < V then
      return (⟨vi, h⟩, sig)
    else
      failure
  return {
    report
    timeslot := UInt32.ofNat timeslot
    credentials
  }

open Jar in
/-- Decode an EpochMarker. Inverse of encodeEpochMarker.
    GP#514: variable-length validators when variableValidators. -/
def decodeEpochMarkerD : Decoder EpochMarker := do
  let entropy ← decodeHashD
  let entropyPrev ← decodeHashD
  let count ← if JarConfig.variableValidators then decodeNatD else pure V
  let validators ← decodeArrayD count do
    let bk ← decodeOctetSeqD 32
    let ek ← decodeOctetSeqD 32
    return (bk, ek)
  return { entropy, entropyPrev, validators }

open Jar in
/-- Decode an unsigned header. Inverse of encodeUnsignedHeader. -/
def decodeUnsignedHeaderD : Decoder Header := do
  let parent ← decodeHashD
  let stateRoot ← decodeHashD
  let extrinsicHash ← decodeHashD
  let timeslot ← decodeFixedNatD 4
  let epochMarker ← decodeOptionD decodeEpochMarkerD
  let ticketsMarker ← decodeOptionD (decodeCountPrefixedArrayD decodeTicketD)
  let authorIndex ← decodeFixedNatD 2
  let vrfSignature ← decodeOctetSeqD 96
  let offenders ← decodeCountPrefixedArrayD (decodeOctetSeqD 32)
  if h : authorIndex < V then
    return {
      parent
      stateRoot
      extrinsicHash
      timeslot := UInt32.ofNat timeslot
      epochMarker
      ticketsMarker
      offenders
      authorIndex := ⟨authorIndex, h⟩
      vrfSignature
      sealSig := default  -- E_U(H) excludes seal; filled by decodeHeaderD (GP eq C.22-C.23)
    }
  else
    failure

open Jar in
/-- Decode a full header. Inverse of encodeHeader. -/
def decodeHeaderD : Decoder Header := do
  let h ← decodeUnsignedHeaderD
  let sealSig ← decodeOctetSeqD 96
  return { h with sealSig }

open Jar in
/-- Decode the extrinsic. Inverse of encodeExtrinsic. -/
def decodeExtrinsicD : Decoder Extrinsic := do
  let tickets ← decodeCountPrefixedArrayD decodeTicketProofD
  let preimages ← decodePreimagesD
  let guarantees ← decodeCountPrefixedArrayD decodeGuaranteeD
  let assurances ← decodeCountPrefixedArrayD decodeAssuranceD
  let disputes ← decodeDisputesD
  return { tickets, disputes, preimages, assurances, guarantees }

open Jar in
/-- Decode a Block. Inverse of encodeBlock. -/
def decodeBlockD : Decoder Block := do
  let header ← decodeHeaderD
  let extrinsic ← decodeExtrinsicD
  return { header, extrinsic }

-- ============================================================================
-- Work Package / Work Item Decoding (for codec test vectors)
-- ============================================================================

open Jar in
/-- Decode a WorkItem. Inverse of encodeWorkItem (if it existed).
    Format: serviceId(4) ++ codeHash(32) ++ payload(↕) ++ gasLimit(8) ++
    accGasLimit(8) ++ exportsCount(𝓔) ++
    imports(count-prefixed array of (hash(32), nat(𝓔))) ++
    extrinsics(count-prefixed array of (hash(32), nat(𝓔))) -/
def decodeWorkItemD : Decoder WorkItem := do
  let serviceId ← decodeFixedNatD 4
  let codeHash ← decodeHashD
  let payload ← decodeLengthPrefixedD
  let gasLimit ← decodeFixedNatD 8
  let accGasLimit ← decodeFixedNatD 8
  let exportsCount ← decodeNatD
  let imports ← decodeCountPrefixedArrayD do
    let h ← decodeHashD
    let n ← decodeNatD
    return (h, n)
  let extrinsics ← decodeCountPrefixedArrayD do
    let h ← decodeHashD
    let n ← decodeNatD
    return (h, n)
  return {
    serviceId := UInt32.ofNat serviceId
    codeHash
    payload
    gasLimit := UInt64.ofNat gasLimit
    accGasLimit := UInt64.ofNat accGasLimit
    exportsCount
    imports
    extrinsics
  }

open Jar in
/-- Decode a WorkPackage. Inverse of encodeWorkPackage (if it existed).
    Format: authToken(↕) ++ authCodeHost(4) ++ authCodeHash(32) ++
    authConfig(↕) ++ context(RefinementContext) ++
    items(count-prefixed array of WorkItem) -/
def decodeWorkPackageD : Decoder WorkPackage := do
  let authToken ← decodeLengthPrefixedD
  let authCodeHost ← decodeFixedNatD 4
  let authCodeHash ← decodeHashD
  let authConfig ← decodeLengthPrefixedD
  let context ← decodeRefinementContextD
  let items ← decodeCountPrefixedArrayD decodeWorkItemD
  return {
    authToken
    authCodeHost := UInt32.ofNat authCodeHost
    authCodeHash
    authConfig
    context
    items
  }

-- ============================================================================
-- Top-level Runner Functions
-- ============================================================================

open Jar in
/-- Decode a Block from raw bytes. -/
def decodeBlock (data : ByteArray) : Option Block :=
  Decoder.run decodeBlockD data

open Jar in
/-- Decode a Header from raw bytes. -/
def decodeHeader (data : ByteArray) : Option Header :=
  Decoder.run decodeHeaderD data

open Jar in
/-- Decode an Extrinsic from raw bytes. -/
def decodeExtrinsic (data : ByteArray) : Option Extrinsic :=
  Decoder.run decodeExtrinsicD data

open Jar in
/-- Decode a WorkReport from raw bytes. -/
def decodeWorkReport (data : ByteArray) : Option WorkReport :=
  Decoder.run decodeWorkReportD data

open Jar in
/-- Decode a WorkPackage from raw bytes. -/
def decodeWorkPackage (data : ByteArray) : Option WorkPackage :=
  Decoder.run decodeWorkPackageD data

end Jar.Codec
