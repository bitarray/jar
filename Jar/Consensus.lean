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
    When tickets are insufficient, generates E keys by shuffling
    validator Bandersnatch keys using entropy. -/
def fallbackKeySequence
    (entropy : Hash) (validators : Array ValidatorKey)
    : Array BandersnatchPublicKey :=
  let bsKeys := validators.map (·.bandersnatch)
  let shuffled := Crypto.shuffle bsKeys entropy
  -- Cycle through shuffled keys to fill E slots
  Array.ofFn (n := E) fun ⟨i, _⟩ =>
    if shuffled.size > 0 then shuffled[i % shuffled.size]!
    else default

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
    ++ ByteArray.mk #[UInt8.ofNat ticket.attempt.val]
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
    ++ ByteArray.mk #[UInt8.ofNat tp.attempt.val]
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
    This combines epoch transitions, seal key updates, and ticket accumulation. -/
def updateSafrole
    (gamma : SafroleState)
    (tickets : TicketsExtrinsic)
    (eta' : Entropy)
    (kappa' : Array ValidatorKey)
    (epochChanged : Bool)
    (slotInEpoch : Nat) : SafroleState :=
  -- Ticket accumulation
  let newTickets := tickets.map fun tp =>
    let ticketId := Crypto.bandersnatchRingOutput tp.proof
    { id := ticketId, attempt := tp.attempt : Ticket }
  let acc' := accumulateTickets gamma.ticketAccumulator newTickets epochChanged
  -- Seal key update on epoch boundary
  let epochTailStart := E / 2  -- Y epoch tail start
  let sealKeys' :=
    if epochChanged then
      -- Check if accumulator was full at epoch tail
      if slotInEpoch >= epochTailStart && acc'.size >= E then
        SealKeySeries.tickets (outsideInSequencer acc')
      else
        SealKeySeries.fallback (fallbackKeySequence eta'.twoBack kappa')
    else gamma.sealKeys
  -- Ring root update on epoch boundary
  let ringRoot' := if epochChanged then
    Crypto.bandersnatchRingRoot (kappa'.map (·.bandersnatch))
  else gamma.ringRoot
  { pendingKeys := gamma.pendingKeys  -- updated via accumulation
    ringRoot := ringRoot'
    sealKeys := sealKeys'
    ticketAccumulator := acc' }

-- ============================================================================
-- §19 — Best Chain Selection
-- ============================================================================

/-- Metric for best chain selection. GP §19 eq (19.1–19.4).
    The best chain maximizes the count of ticketed seals among ancestors
    which are not yet finalized. -/
def chainMetric (ticketedCount : Nat) : Nat := ticketedCount

/-- Check if a block is acceptable for best chain consideration. GP §19.
    A block must:
    1. Be a descendant of the finalized block
    2. Have all reports audited
    3. Not contain equivocating headers (same timeslot, different hash) -/
def isAcceptable
    (_headerHash : Hash) (_finalizedHash : Hash)
    (_isAudited : Bool) : Bool :=
  -- Simplified: full implementation would check ancestry and equivocation
  _isAudited

end Jar.Consensus
