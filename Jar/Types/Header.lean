import Jar.Notation
import Jar.Types.Numerics
import Jar.Types.Validators
import Jar.Types.Work

/-!
# Block Header & Extrinsic Types — Gray Paper §4–5

Block, Header, and Extrinsic structures.
References: `graypaper/text/overview.tex` eq:block, eq:extrinsic.
            `graypaper/text/header.tex` eq:header.
-/

namespace Jar
variable [JamConfig]

-- ============================================================================
-- §6.6 — Epoch Marker (from header.tex line 66–70)
-- ============================================================================

/-- Epoch marker: entropy and validator keys for the following epoch.
    GP §5.1: H_E ∈ ⟨ℍ, ℍ, ⟦⟨H̃, H̄⟩⟧_V⟩? -/
structure EpochMarker where
  /-- Randomness for next epoch. ℍ. -/
  entropy : Hash
  /-- Previous epoch randomness. ℍ. -/
  entropyPrev : Hash
  /-- Next epoch validator keys (Bandersnatch, Ed25519). ⟦⟨H̃, H̄⟩⟧_V. -/
  validators : Array (BandersnatchPublicKey × Ed25519PublicKey)

-- ============================================================================
-- §5 — Header (eq:header)
-- ============================================================================

/-- H : Block header. GP eq (5.1).
    H ≡ (H_p, H_r, H_x, H_t, H_e, H_w, H_o, H_i, H_v, H_s) -/
structure Header where
  /-- H_p : Parent block header hash. ℍ. -/
  parent : Hash
  /-- H_r : Prior state root (Merkle commitment of parent's posterior state). ℍ. -/
  stateRoot : Hash
  /-- H_x : Extrinsic hash (Merkle commitment of extrinsic data). ℍ. -/
  extrinsicHash : Hash
  /-- H_t : Timeslot index. ℕ_T. -/
  timeslot : Timeslot
  /-- H_e : Epoch marker. Optional — present only at epoch boundaries. -/
  epochMarker : Option EpochMarker
  /-- H_w : Winning-tickets marker. Optional — ⟦𝕋⟧_E when present. -/
  ticketsMarker : Option (Array Ticket)
  /-- H_o : Offenders marker — newly misbehaving validators. ⟦H̄⟧. -/
  offenders : Array Ed25519PublicKey
  /-- H_i : Block author index into validator set. ℕ_V. -/
  authorIndex : ValidatorIndex
  /-- H_v : Entropy-yielding VRF signature. 𝔹_96. -/
  vrfSignature : BandersnatchSignature
  /-- H_s : Block seal signature. 𝔹_96. -/
  sealSig : BandersnatchSignature

-- ============================================================================
-- §10 — Disputes Extrinsic (eq:disputesspec context)
-- ============================================================================

/-- A single judgment by a validator on a work-report. -/
structure Judgment where
  isValid : Bool
  validatorIndex : ValidatorIndex
  signature : Ed25519Signature

/-- A verdict on a work-report, composed of multiple judgments. -/
structure Verdict where
  reportHash : Hash
  age : UInt32
  judgments : Array Judgment

/-- Culprit: a validator who guaranteed an invalid work-report. -/
structure Culprit where
  reportHash : Hash
  validatorKey : Ed25519PublicKey
  signature : Ed25519Signature

/-- Fault: a validator who made an incorrect judgment. -/
structure Fault where
  reportHash : Hash
  isValid : Bool
  validatorKey : Ed25519PublicKey
  signature : Ed25519Signature

/-- E_D : Disputes extrinsic. GP §10.2. -/
structure DisputesExtrinsic where
  verdicts : Array Verdict
  culprits : Array Culprit
  faults : Array Fault

-- ============================================================================
-- §6.7 — Tickets Extrinsic (eq:ticketsextrinsic)
-- ============================================================================

/-- A ticket proof submitted in the tickets extrinsic. GP eq (6.29). -/
structure TicketProof where
  /-- Attempt index. -/
  attempt : TicketEntryIndex
  /-- Ring VRF proof. 𝔹_784. -/
  proof : BandersnatchRingVrfProof

/-- E_T : Tickets extrinsic. ⟦TicketProof⟧_{:K}. -/
abbrev TicketsExtrinsic := Array TicketProof

-- ============================================================================
-- §12.7 — Preimages Extrinsic
-- ============================================================================

/-- E_P : Preimages extrinsic. ⟦(ℕ_S, 𝔹)⟧. -/
abbrev PreimagesExtrinsic := Array (ServiceId × ByteArray)

-- ============================================================================
-- §11 — Guarantees and Assurances Extrinsics
-- ============================================================================

/-- A guarantee: a work report with validator credentials. GP §11.5. -/
structure Guarantee where
  /-- The work report being guaranteed. -/
  report : WorkReport
  /-- Timeslot of the guarantee. -/
  timeslot : Timeslot
  /-- Validator signatures (index, signature). -/
  credentials : Array (ValidatorIndex × Ed25519Signature)

/-- E_G : Guarantees extrinsic. ⟦Guarantee⟧. -/
abbrev GuaranteesExtrinsic := Array Guarantee

/-- An availability assurance by a validator. GP §11.3. -/
structure Assurance where
  /-- Parent block hash (anchor). ℍ. -/
  anchor : Hash
  /-- Availability bitfield — one bit per core. 𝕓_C. -/
  bitfield : ByteArray
  /-- Validator index. ℕ_V. -/
  validatorIndex : ValidatorIndex
  /-- Ed25519 signature. -/
  signature : Ed25519Signature

/-- E_A : Assurances extrinsic. ⟦Assurance⟧. -/
abbrev AssurancesExtrinsic := Array Assurance

-- ============================================================================
-- §4.1 — Extrinsic (eq:extrinsic)
-- ============================================================================

/-- E : Extrinsic data. GP eq (4).
    E ≡ (E_T, E_D, E_P, E_A, E_G) -/
structure Extrinsic where
  /-- E_T : Ticket submissions. -/
  tickets : TicketsExtrinsic
  /-- E_D : Dispute information. -/
  disputes : DisputesExtrinsic
  /-- E_P : Preimage data. -/
  preimages : PreimagesExtrinsic
  /-- E_A : Availability assurances. -/
  assurances : AssurancesExtrinsic
  /-- E_G : Work-report guarantees. -/
  guarantees : GuaranteesExtrinsic

-- ============================================================================
-- §4.1 — Block (eq:block)
-- ============================================================================

/-- B : Block. GP eq (3).
    B ≡ (H, E) -/
structure Block where
  /-- H : Block header. -/
  header : Header
  /-- E : Extrinsic data. -/
  extrinsic : Extrinsic

end Jar
