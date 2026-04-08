import Jar.Codec.Common

/-!
# JAR v1 Codec — No Compact Encoding

All integers are fixed-width LE. Variable-length arrays use u32 LE count prefix.
Fixed-size arrays have no prefix.

Convention:
- `[T; N]` (compile-time known N): no prefix, just N elements concatenated
- `Vec T` (dynamic length): u32 LE count prefix + elements
- `Option T`: discriminator byte (0=None, 1=Some) + payload
- Enums: u8 discriminator + variant payload
-/

namespace Jar.Codec.Jar1
variable [JarConfig]

open Jar.Codec.Common

-- ============================================================================
-- Jar1 array encoding — u32 LE count prefix
-- ============================================================================

/-- Encode a variable-length array with u32 LE count prefix. -/
def encodeCountPrefixed (f : α → ByteArray) (xs : Array α) : ByteArray :=
  encodeFixedNat 4 xs.size ++ encodeArray f xs

/-- Length-prefixed byte blob: u32 LE byte-length + raw bytes. -/
def encodeLengthPrefixed (data : ByteArray) : ByteArray :=
  encodeFixedNat 4 data.size ++ data

-- ============================================================================
-- Block component encoding
-- ============================================================================

open Jar in
/-- Encode a Ticket. -/
def encodeTicket (t : Ticket) : ByteArray :=
  t.id.data ++ ByteArray.mk #[UInt8.ofNat t.attempt]

open Jar in
/-- Encode a TicketProof. -/
def encodeTicketProof (tp : TicketProof) : ByteArray :=
  ByteArray.mk #[UInt8.ofNat tp.attempt] ++ tp.proof.data

open Jar in
/-- Encode an Assurance. Bitfield uses u32 byte-length prefix. -/
def encodeAssurance (a : Assurance) : ByteArray :=
  a.anchor.data
    ++ encodeLengthPrefixed a.bitfield
    ++ encodeFixedNat 2 a.validatorIndex.val
    ++ a.signature.data

open Jar in
/-- Encode a single Judgment. -/
def encodeJudgment (j : Judgment) : ByteArray :=
  ByteArray.mk #[if j.isValid then 1 else 0]
    ++ encodeFixedNat 2 j.validatorIndex.val
    ++ j.signature.data

open Jar in
/-- Encode a Verdict. Judgments use u32 count prefix. -/
def encodeVerdict (v : Verdict) : ByteArray :=
  v.reportHash.data
    ++ encodeFixedNat 4 v.age.toNat
    ++ encodeCountPrefixed encodeJudgment v.judgments

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
/-- Encode the disputes extrinsic. -/
def encodeDisputes (d : DisputesExtrinsic) : ByteArray :=
  encodeCountPrefixed encodeVerdict d.verdicts
    ++ encodeCountPrefixed encodeCulprit d.culprits
    ++ encodeCountPrefixed encodeFault d.faults

open Jar in
/-- Encode the preimages extrinsic. -/
def encodePreimages (ps : PreimagesExtrinsic) : ByteArray :=
  encodeCountPrefixed (fun (sid, blob) =>
    encodeFixedNat 4 sid.toNat ++ encodeLengthPrefixed blob) ps

open Jar in
/-- Encode an AvailabilitySpec. erasure_shards NOT encoded (wire format). -/
def encodeAvailSpec (a : AvailabilitySpec) : ByteArray :=
  a.packageHash.data
    ++ encodeFixedNat 4 a.bundleLength.toNat
    ++ a.erasureRoot.data
    ++ a.segmentRoot.data
    ++ encodeFixedNat 2 a.segmentCount

open Jar in
/-- Encode a RefinementContext. -/
def encodeRefinementContext (c : RefinementContext) : ByteArray :=
  c.anchorHash.data
    ++ c.anchorStateRoot.data
    ++ c.anchorBeefyRoot.data
    ++ c.lookupAnchorHash.data
    ++ encodeFixedNat 4 c.lookupAnchorTimeslot.toNat
    ++ encodeCountPrefixed (fun h => h.data) c.prerequisites

open Jar in
/-- Encode a WorkDigest. All numeric fields are fixed-width (no compact). -/
def encodeWorkDigest (d : WorkDigest) : ByteArray :=
  encodeFixedNat 4 d.serviceId.toNat
    ++ d.codeHash.data
    ++ d.payloadHash.data
    ++ encodeFixedNat 8 d.gasLimit.toNat
    ++ encodeWorkResult encodeLengthPrefixed d.result
    ++ encodeFixedNat 8 d.gasUsed.toNat          -- was compact, now u64
    ++ encodeFixedNat 2 d.importsCount            -- was compact, now u16
    ++ encodeFixedNat 2 d.extrinsicsCount         -- was compact, now u16
    ++ encodeFixedNat 4 d.extrinsicsSize          -- was compact, now u32
    ++ encodeFixedNat 2 d.exportsCount            -- was compact, now u16

open Jar in
/-- Encode a WorkReport. All numeric fields are fixed-width (no compact). -/
def encodeWorkReport (wr : WorkReport) : ByteArray :=
  encodeAvailSpec wr.availSpec
    ++ encodeRefinementContext wr.context
    ++ encodeFixedNat 2 wr.coreIndex.val          -- was compact, now u16
    ++ wr.authorizerHash.data
    ++ encodeFixedNat 8 wr.authGasUsed.toNat      -- was compact, now u64
    ++ encodeLengthPrefixed wr.authOutput
    ++ encodeCountPrefixed (fun (k, v) => k.data ++ v.data)
        wr.segmentRootLookup.entries.toArray
    ++ encodeCountPrefixed encodeWorkDigest wr.digests

open Jar in
/-- Encode a Guarantee. -/
def encodeGuarantee (g : Guarantee) : ByteArray :=
  encodeWorkReport g.report
    ++ encodeFixedNat 4 g.timeslot.toNat
    ++ encodeCountPrefixed (fun (vi, sig) =>
        encodeFixedNat 2 vi.val ++ sig.data) g.credentials

open Jar in
/-- Encode an EpochMarker. Validators always u32 count-prefixed. -/
def encodeEpochMarker (em : EpochMarker) : ByteArray :=
  em.entropy.data
    ++ em.entropyPrev.data
    ++ encodeCountPrefixed (fun (bk, ek) => bk.data ++ ek.data) em.validators

open Jar in
/-- Encode an unsigned header. -/
def encodeUnsignedHeader (h : Header) : ByteArray :=
  h.parent.data
    ++ h.stateRoot.data
    ++ h.extrinsicHash.data
    ++ encodeFixedNat 4 h.timeslot.toNat
    ++ encodeOption encodeEpochMarker h.epochMarker
    ++ encodeOption (encodeCountPrefixed encodeTicket) h.ticketsMarker
    ++ encodeFixedNat 2 h.authorIndex.val
    ++ h.vrfSignature.data
    ++ encodeCountPrefixed (fun k => k.data) h.offenders

open Jar in
/-- Encode a full header (unsigned + seal). -/
def encodeHeader (h : Header) : ByteArray :=
  encodeUnsignedHeader h ++ h.sealSig.data

open Jar in
/-- Encode an extrinsic. -/
def encodeExtrinsic (e : Extrinsic) : ByteArray :=
  encodeCountPrefixed encodeTicketProof e.tickets
    ++ encodePreimages e.preimages
    ++ encodeCountPrefixed encodeGuarantee e.guarantees
    ++ encodeCountPrefixed encodeAssurance e.assurances
    ++ encodeDisputes e.disputes

open Jar in
/-- Encode a block. -/
def encodeBlock (b : Block) : ByteArray :=
  encodeHeader b.header ++ encodeExtrinsic b.extrinsic

end Jar.Codec.Jar1
