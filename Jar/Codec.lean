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
variable [JamConfig]

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

/-- Compute l such that 2^{7l} ≤ x < 2^{7(l+1)}, or 8 if x ≥ 2^{56}. -/
private def lengthClass (x : Nat) : Nat :=
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
  t.id.data ++ ByteArray.mk #[UInt8.ofNat t.attempt.val]

open Jar in
/-- Encode a TicketProof for the tickets extrinsic. -/
def encodeTicketProof (tp : TicketProof) : ByteArray :=
  ByteArray.mk #[UInt8.ofNat tp.attempt.val] ++ tp.proof.data

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
/-- Encode an EpochMarker. -/
def encodeEpochMarker (em : EpochMarker) : ByteArray :=
  em.entropy.data
    ++ em.entropyPrev.data
    ++ encodeArray (fun (bk, ek) => bk.data ++ ek.data) em.validators

open Jar in
/-- 𝓔_U(H) : Unsigned header encoding. GP eq (C.26). -/
def encodeUnsignedHeader (h : Header) : ByteArray :=
  h.parent.data
    ++ h.stateRoot.data
    ++ h.extrinsicHash.data
    ++ encodeFixedNat 4 h.timeslot.toNat
    ++ encodeOption encodeEpochMarker h.epochMarker
    ++ encodeOption (encodeCountPrefixedArray encodeTicket) h.ticketsMarker
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

end Jar.Codec
