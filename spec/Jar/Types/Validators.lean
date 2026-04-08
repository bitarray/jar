import Jar.Notation
import Jar.Types.Numerics

/-!
# Validator Types — Gray Paper §6.2–6.3

Validator key sets and Safrole ticket types.
References: `graypaper/text/safrole.tex` eq:validatorkeys, eq:ticket,
            eq:consensusstatecomposition, eq:ticketaccumulatorsealticketsspec.
-/

namespace Jar
variable [JarConfig]

-- ============================================================================
-- §6.2 — Validator Keys (eq:validatorkeys)
-- ============================================================================

/-- 𝕂 : Validator key set. GP eq (56).
    K = 𝔹_336 decomposed as: k_b (Bandersnatch) ∥ k_e (Ed25519) ∥
    k_l (BLS) ∥ k_m (metadata).
    Total: 32 + 32 + 144 + 128 = 336 bytes. -/
structure ValidatorKey where
  /-- k_b : Bandersnatch key for block sealing and VRF. 𝔹_32. -/
  bandersnatch : BandersnatchPublicKey
  /-- k_e : Ed25519 key for signing guarantees, assurances, judgments. 𝔹_32. -/
  ed25519 : Ed25519PublicKey
  /-- k_l : BLS key for Beefy commitments. 𝔹_144. -/
  bls : BlsPublicKey
  /-- k_m : Metadata (hardware address etc). 𝔹_128. -/
  metadata : OctetSeq 128
  deriving Inhabited

-- ============================================================================
-- §6.2 — Tickets (eq:ticket)
-- ============================================================================

/-- 𝕋 : Safrole seal-key ticket. GP eq (42).
    T = ⟨id ∈ ℍ, entry_index ∈ ℕ_N⟩ -/
structure Ticket where
  /-- y : VRF output (ticket identifier). -/
  id : Hash
  /-- a : Attempt/entry index ∈ {0, 1}. -/
  attempt : TicketEntryIndex

instance : Inhabited Ticket where
  default := { id := default, attempt := 0 }

-- ============================================================================
-- §6.2 — Seal Key Series (eq:ticketaccumulatorsealticketsspec)
-- ============================================================================

/-- The seal-key series γ_s is either a sequence of E tickets (normal mode)
    or a sequence of E Bandersnatch keys (fallback mode). GP eq (39–41). -/
inductive SealKeySeries where
  /-- Regular mode: E tickets determine seal keys. -/
  | tickets : Array Ticket → SealKeySeries
  /-- Fallback mode: E Bandersnatch public keys directly. -/
  | fallback : Array BandersnatchPublicKey → SealKeySeries

-- ============================================================================
-- §6.2 — Safrole State (eq:consensusstatecomposition)
-- ============================================================================

/-- γ : Safrole consensus state. GP eq (34–37).
    γ ≡ ⟨γ_k, γ_z, γ_s, γ_a⟩ -/
structure SafroleState where
  /-- γ_k : Pending validator keys for next epoch. ⟦𝕂⟧_V. -/
  pendingKeys : Array ValidatorKey
  /-- γ_z : Epoch ring root for ticket submissions. -/
  ringRoot : BandersnatchRingRoot
  /-- γ_s : Seal-key series (tickets or fallback keys). -/
  sealKeys : SealKeySeries
  /-- γ_a : Ticket accumulator for next epoch. ⟦𝕋⟧_{:E}. -/
  ticketAccumulator : Array Ticket

-- ============================================================================
-- §6.4 — Entropy (eq:entropycomposition)
-- ============================================================================

/-- η : Entropy accumulator. GP eq (68).
    η ≡ ⟦ℍ⟧_4 — a 4-element tuple of hashes. -/
structure Entropy where
  /-- η_0 : Current accumulator. -/
  current : Hash
  /-- η_1 : Previous epoch's randomness. -/
  previous : Hash
  /-- η_2 : Two epochs ago. -/
  twoBack : Hash
  /-- η_3 : Three epochs ago. -/
  threeBack : Hash

end Jar
