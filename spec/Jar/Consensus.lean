import Jar.Notation
import Jar.Types
import Jar.Crypto
import Jar.Codec

/-!
# Consensus — §6, §19

Safrole block production and GRANDPA finality.
References: `graypaper/text/safrole.tex`, `graypaper/text/best_chain.tex`.

## Safrole (§6)
- Epoch/slot management (E=600, P=6s)
- Seal verification (ticketed vs fallback modes)
- Ticket submission and accumulation
- Outside-in sequencer Z
- Epoch boundary: key rotation, entropy rotation
- Fallback key sequence generation

## GRANDPA / Best Chain (§19)
- Best chain selection rule
- Finalization with auditing condition
-/

namespace Jar.Consensus
variable [JamConfig]

-- ============================================================================
-- §6.3 — Outside-In Sequencer Z
-- ============================================================================

/-- Z(tickets) : Outside-in sequencer. GP eq (6.25).
    Interleaves tickets from outside inward:
    Z([a,b,c,d,...]) = [a, last, b, second-to-last, ...].
    Used to arrange ticket accumulator into seal-key sequence. -/
def outsideInSequencer (tickets : Array Ticket) : Array Ticket :=
  let n := tickets.size
  Array.ofFn (n := n) fun ⟨i, hi⟩ =>
    if i % 2 == 0 then
      have : i / 2 < n := by omega
      tickets[i / 2]
    else
      have : n - 1 - i / 2 < n := by omega
      tickets[n - 1 - i / 2]

-- ============================================================================
-- §6.4 — Fallback Key Sequence
-- ============================================================================

/-- F(η, κ) : Fallback seal-key sequence. GP eq (6.26).
    When tickets are insufficient, generates E keys by hashing
    entropy ∥ slot_index for each slot independently. -/
def fallbackKeySequence
    (entropy : Hash) (validators : Array ValidatorKey)
    : Array BandersnatchPublicKey :=
  let v := validators.size
  if v == 0 then Array.replicate E default
  else
    Array.ofFn (n := E) fun ⟨i, _⟩ =>
      let preimage := entropy.data ++ Codec.encodeFixedNat 4 i
      let hash := Crypto.blake2b preimage
      let idx := (Codec.decodeFixedNat (hash.data.extract 0 4)) % v
      validators[idx]!.bandersnatch

-- ============================================================================
-- §6.5 — Seal Verification
-- ============================================================================

/-- Verify a block seal in ticketed mode. GP eq (6.24).
    H_s ∈ Ṽ_k^{X_T ∥ η'_3 ∥ i_a}⟨𝓔_U(H)⟩ -/
def verifySealTicketed
    (authorKey : BandersnatchPublicKey)
    (entropy3 : Hash)
    (ticket : Ticket)
    (unsignedHeader : ByteArray)
    (sealSig : BandersnatchSignature) : Bool :=
  let context := Crypto.ctxTicketSeal ++ entropy3.data
    ++ ByteArray.mk #[UInt8.ofNat ticket.attempt]
  Crypto.bandersnatchVerify authorKey context unsignedHeader sealSig

/-- Verify a block seal in fallback mode. GP eq (6.25).
    H_s ∈ Ṽ_k^{X_F ∥ η'_3}⟨𝓔_U(H)⟩ -/
def verifySealFallback
    (authorKey : BandersnatchPublicKey)
    (entropy3 : Hash)
    (unsignedHeader : ByteArray)
    (sealSig : BandersnatchSignature) : Bool :=
  let context := Crypto.ctxFallbackSeal ++ entropy3.data
  Crypto.bandersnatchVerify authorKey context unsignedHeader sealSig

/-- Verify the entropy VRF signature. GP eq (6.27).
    H_v ∈ Ṽ_k^{X_E ∥ Y(H_s)}⟨⟩ -/
def verifyEntropyVrf
    (authorKey : BandersnatchPublicKey)
    (sealSig : BandersnatchSignature)
    (vrfSig : BandersnatchSignature) : Bool :=
  let sealOutput := Crypto.bandersnatchOutput sealSig
  let context := Crypto.ctxEntropy ++ sealOutput.data
  Crypto.bandersnatchVerify authorKey context ByteArray.empty vrfSig

-- ============================================================================
-- §6.7 — Ticket Submission Verification
-- ============================================================================

/-- Verify a ticket proof from the tickets extrinsic. GP eq (6.29).
    proof ∈ V°_r^{X_T ∥ η'_2 ∥ attempt}⟨⟩ -/
def verifyTicketProof
    (ringRoot : BandersnatchRingRoot)
    (entropy2 : Hash)
    (tp : TicketProof)
    (ringSize : UInt32) : Bool :=
  let context := Crypto.ctxTicketSeal ++ entropy2.data
    ++ ByteArray.mk #[UInt8.ofNat tp.attempt]
  Crypto.bandersnatchRingVerify ringRoot context ByteArray.empty tp.proof ringSize

-- ============================================================================
-- §6.7 — Ticket Accumulation
-- ============================================================================

/-- Accumulate new tickets into the ticket accumulator. GP eq (6.32–6.35).
    Sorts by ticket ID and keeps only the top E entries. -/
def accumulateTickets
    (accumulator : Array Ticket) (newTickets : Array Ticket)
    (epochChanged : Bool) : Array Ticket :=
  let base := if epochChanged then #[] else accumulator
  -- Add new tickets (filtering duplicates by ID)
  let combined := newTickets.foldl (init := base) fun acc t =>
    if acc.any (fun existing => existing.id == t.id) then acc
    else acc.push t
  -- Sort by ticket ID (ascending = lowest IDs win)
  let sorted := combined.qsort (fun a b => a.id.data.data < b.id.data.data)
  -- Keep at most E tickets
  if sorted.size > E then sorted.extract 0 E else sorted

-- ============================================================================
-- §6 — Full Safrole State Update
-- ============================================================================

/-- Update the Safrole state for a new block. GP §6.
    This combines epoch transitions, seal key updates, and ticket accumulation.
    `oldSlotInEpoch` is the PRIOR timeslot's position in its epoch (τ % E). -/
def updateSafrole
    (gamma : SafroleState)
    (tickets : TicketsExtrinsic)
    (eta' : Entropy)
    (kappa' : Array ValidatorKey)
    (epochChanged : Bool)
    (oldSlotInEpoch : Nat)
    (oldEpoch newEpoch : Nat)
    (iota : Array ValidatorKey)
    (offenders : Array Ed25519PublicKey) : SafroleState :=
  -- Ticket accumulation: clear on epoch change, then add new
  let newTickets := tickets.map fun tp =>
    let ticketId := Crypto.bandersnatchRingOutput tp.proof
    { id := ticketId, attempt := tp.attempt : Ticket }
  let acc' := accumulateTickets gamma.ticketAccumulator newTickets epochChanged
  -- Key rotation on epoch boundary (GP eq 6.13)
  let (newGammaP, newKappa, newRingRoot) :=
    if epochChanged then
      let filtered := iota.map fun k =>
        if offenders.any (· == k.ed25519) then
          { bandersnatch := default, ed25519 := default, bls := default, metadata := default : ValidatorKey }
        else k
      let ringRoot := Crypto.bandersnatchRingRoot (filtered.map (·.bandersnatch))
      (filtered, gamma.pendingKeys, ringRoot)  -- γ_P' = Φ(ι), κ' = γ_P
    else
      (gamma.pendingKeys, kappa', gamma.ringRoot)
  -- Seal key update on epoch boundary (GP eq 6.24)
  let sealKeys' :=
    if epochChanged then
      let singleAdvance := newEpoch == oldEpoch + 1
      let wasPastY := oldSlotInEpoch >= Y_TAIL
      let accumulatorFull := gamma.ticketAccumulator.size >= E
      if singleAdvance && wasPastY && accumulatorFull then
        SealKeySeries.tickets (outsideInSequencer gamma.ticketAccumulator)
      else
        SealKeySeries.fallback (fallbackKeySequence eta'.twoBack newKappa)
    else gamma.sealKeys
  { pendingKeys := newGammaP
    ringRoot := newRingRoot
    sealKeys := sealKeys'
    ticketAccumulator := acc' }

-- ============================================================================
-- §19 — Best Chain Selection
-- ============================================================================

/-- Chain ancestry data: maps header hash → (parent hash, timeslot).
    Represents the set of known headers for ancestry traversal. -/
abbrev ChainAncestry := List (Hash × Hash × Timeslot)

/-- A(H) : Ancestor set of a block. GP §19.
    Traces parent links back through known headers. -/
partial def ancestors (chain : ChainAncestry) (headerHash : Hash) : List Hash :=
  match chain.find? (fun (h, _, _) => h == headerHash) with
  | none => []
  | some (_, parent, _) => headerHash :: ancestors chain parent

/-- Check if a block is acceptable for best chain consideration. GP §19.
    A block must:
    1. Be a descendant of the finalized block: A(H♭) ∋ H♮
    2. Have all reports audited: U♭ ≡ ⊤
    3. Not contain equivocating headers in unfinalized range:
       ¬∃ H^A ≠ H^B : H^A_T = H^B_T ∧ H^A ∈ A(H♭) ∧ H^A ∉ A(H♮) -/
def isAcceptable
    (chain : ChainAncestry)
    (headerHash : Hash) (finalizedHash : Hash)
    (isAudited : Bool) : Bool :=
  -- 1. Ancestry: finalized block must be in ancestor set
  let candidateAncestors := ancestors chain headerHash
  let hasFinalized := candidateAncestors.any (· == finalizedHash)
  -- 2. Auditing
  let audited := isAudited
  -- 3. No equivocation: no two distinct unfinalized headers share a timeslot
  let finalizedAncestors := ancestors chain finalizedHash
  let unfinalizedHeaders := candidateAncestors.filter fun h =>
    !finalizedAncestors.any (· == h)
  let unfinalizedWithSlot := unfinalizedHeaders.filterMap fun h =>
    chain.find? (fun (h', _, _) => h' == h) |>.map fun (_, _, ts) => (h, ts)
  let noEquivocation := !unfinalizedWithSlot.any fun (h1, ts1) =>
    unfinalizedWithSlot.any fun (h2, ts2) => h1 != h2 && ts1 == ts2
  hasFinalized && audited && noEquivocation

/-- Best chain metric: count of ticketed (non-fallback) seals among ancestors. GP §19.
    m = Σ_{H^A ∈ A♭} T^A.  Select B♭ to maximize this value. -/
def chainMetric
    (chain : ChainAncestry) (headerHash : Hash)
    (isTicketed : Hash → Bool) : Nat :=
  let ancestorSet := ancestors chain headerHash
  ancestorSet.foldl (fun count h => if isTicketed h then count + 1 else count) 0

end Jar.Consensus
