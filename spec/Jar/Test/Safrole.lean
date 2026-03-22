import Jar.Notation
import Jar.Types
import Jar.Crypto
import Jar.Consensus

/-!
# Safrole Sub-Transition Test Harness

Defines the flattened state shape matching the STF test vectors,
a `safroleTransition` function implementing the full sub-transition,
and a test runner.
-/

namespace Jar.Test.Safrole

open Jar Jar.Crypto Jar.Consensus

variable [JamConfig]

-- ============================================================================
-- Flattened Safrole State (matches test vector JSON shape)
-- ============================================================================

/-- Flattened safrole state matching test vector pre_state / post_state. -/
structure FlatSafroleState where
  tau : Timeslot
  eta : Array Hash  -- 4 entries
  lambda : Array ValidatorKey
  kappa : Array ValidatorKey
  gamma_k : Array ValidatorKey
  iota : Array ValidatorKey
  gamma_a : Array Ticket
  gamma_s : SealKeySeries
  gamma_z : BandersnatchRingRoot
  post_offenders : Array Ed25519PublicKey

/-- Input to the safrole sub-transition. -/
structure SafroleInput where
  slot : Timeslot
  entropy : Hash
  extrinsic : Array TicketProof

/-- Output of a successful safrole sub-transition. -/
structure SafroleOutput where
  epoch_mark : Option EpochMarker
  tickets_mark : Option (Array Ticket)

/-- Result: ok with output, or err with error string. -/
inductive SafroleResult where
  | ok : SafroleOutput → SafroleResult
  | err : String → SafroleResult

-- ============================================================================
-- Helpers
-- ============================================================================

/-- Check if the slot crosses an epoch boundary. -/
def isEpochChange (oldSlot newSlot : Timeslot) : Bool :=
  oldSlot.toNat / E != newSlot.toNat / E

/-- Slot index within the current epoch. -/
def epochSlot (slot : Timeslot) : Nat :=
  slot.toNat % E

/-- Filter offenders: replace matching keys with null (zero) keys. GP eq 6.14: Φ. -/
def filterOffenders (keys : Array ValidatorKey) (offenders : Array Ed25519PublicKey)
    : Array ValidatorKey :=
  keys.map fun k =>
    if offenders.any (·.data == k.ed25519.data) then
      { bandersnatch := default, ed25519 := default, bls := default, metadata := default }
    else k

/-- Fallback key sequence F(r, κ). GP eq 6.26.
    For each slot i in 0..E: idx = LE32(H(r ++ LE32(i))[0..4]) mod |κ|. -/
def fallbackKeys (entropy : Hash) (validators : Array ValidatorKey)
    : Array BandersnatchPublicKey :=
  let v := validators.size
  if v == 0 then #[]
  else
    Array.ofFn (n := E) fun ⟨i, _⟩ =>
      let preimage := entropy.data ++ Codec.encodeFixedNat 4 i
      let h := blake2b preimage
      let idx := (h.data.get! 0).toNat + (h.data.get! 1).toNat * 256
        + (h.data.get! 2).toNat * 65536 + (h.data.get! 3).toNat * 16777216
      let idx := idx % v
      validators[idx]!.bandersnatch

/-- Verify and extract tickets from proofs. Returns (tickets, error?).
    ringSize must match the number of keys used to compute ringRoot. -/
def extractTickets (proofs : Array TicketProof) (ringRoot : BandersnatchRingRoot)
    (eta2 : Hash) (ringSize : Nat) : Except String (Array Ticket) := do
  let mut tickets : Array Ticket := #[]
  for tp in proofs do
    -- Validate attempt
    if tp.attempt >= N_TICKETS then
      throw "bad_ticket_attempt"
    -- Verify ring VRF proof
    let context := Crypto.ctxTicketSeal ++ eta2.data
      ++ ByteArray.mk #[UInt8.ofNat tp.attempt]
    let verifyResult := bandersnatchRingVerify ringRoot context ByteArray.empty tp.proof ringSize.toUInt32
    if !verifyResult then
      throw "bad_ticket_proof"
    let ticketId := bandersnatchRingOutput tp.proof
    tickets := tickets.push { id := ticketId, attempt := tp.attempt }
  -- Check sorted ascending by ticket ID
  for i in [:tickets.size] do
    if i + 1 < tickets.size then
      if !(tickets[i]!.id.data.data < tickets[i+1]!.id.data.data) then
        throw "bad_ticket_order"
  return tickets

/-- Merge new tickets into accumulator, keep lowest E entries. GP eq 6.34. -/
def mergeTickets (existing : Array Ticket) (newTickets : Array Ticket)
    : Array Ticket :=
  let all := existing ++ newTickets
  let sorted := all.qsort (fun a b => a.id.data.data < b.id.data.data)
  if sorted.size > E then sorted.extract 0 E else sorted

-- ============================================================================
-- Safrole Sub-Transition (GP §6)
-- ============================================================================

/-- The full Safrole sub-transition matching test vector interface. -/
def safroleTransition (pre : FlatSafroleState) (input : SafroleInput)
    : SafroleResult × FlatSafroleState :=
  -- Validate slot
  if input.slot ≤ pre.tau then
    (.err "bad_slot", pre)
  else
    let oldEpoch := pre.tau.toNat / E
    let newEpoch := input.slot.toNat / E
    let oldSlotInEpoch := pre.tau.toNat % E
    let newSlotInEpoch := input.slot.toNat % E
    let epochChanged := newEpoch > oldEpoch

    -- Validate ticket extrinsic (eq 6.30)
    if input.extrinsic.size > 0 && newSlotInEpoch >= Y_TAIL then
      (.err "unexpected_ticket", pre)
    else if input.extrinsic.size > 0 then
      -- Check attempt values
      let badAttempt := input.extrinsic.any fun tp => tp.attempt >= N_TICKETS
      if badAttempt then
        (.err "bad_ticket_attempt", pre)
      else
        safroleTransitionInner pre input epochChanged oldSlotInEpoch newSlotInEpoch
    else
      safroleTransitionInner pre input epochChanged oldSlotInEpoch newSlotInEpoch

where
  safroleTransitionInner (pre : FlatSafroleState) (input : SafroleInput)
      (epochChanged : Bool) (oldSlotInEpoch newSlotInEpoch : Nat)
      : SafroleResult × FlatSafroleState :=
    let eta0 := if pre.eta.size > 0 then pre.eta[0]! else default
    let eta1 := if pre.eta.size > 1 then pre.eta[1]! else default
    let eta2 := if pre.eta.size > 2 then pre.eta[2]! else default
    let eta3 := if pre.eta.size > 3 then pre.eta[3]! else default

    -- eq 6.23: Entropy rotation
    let (new_eta1, new_eta2, new_eta3) :=
      if epochChanged then (eta0, eta1, eta2)
      else (eta1, eta2, eta3)

    -- eq 6.13: Key rotation
    let (new_gamma_k, new_kappa, new_lambda, new_gamma_z) :=
      if epochChanged then
        let filtered := filterOffenders pre.iota pre.post_offenders
        let ringRoot := bandersnatchRingRoot (filtered.map (·.bandersnatch))
        (filtered, pre.gamma_k, pre.kappa, ringRoot)
      else
        (pre.gamma_k, pre.kappa, pre.lambda, pre.gamma_z)

    -- eq 6.22: Entropy accumulation
    let new_eta0 := blake2b (eta0.data ++ input.entropy.data)

    -- eq 6.29-6.31: Process ticket extrinsic
    -- NOTE: ringSize = gamma_k.size (6 for tiny, 1023 for full JAM)
    let ringSize := new_gamma_k.size
    let ticketResult :=
      if input.extrinsic.size > 0 then
        extractTickets input.extrinsic new_gamma_z new_eta2 ringSize
      else .ok #[]

    match ticketResult with
    | .error err => (.err err, pre)
    | .ok newTickets =>
      -- eq 6.33: No duplicate ticket IDs with existing accumulator
      let base := if epochChanged then #[] else pre.gamma_a
      if newTickets.size > 0 then
        let hasDup := newTickets.any fun t =>
          base.any fun existing => existing.id.data == t.id.data
        if hasDup then
          (.err "duplicate_ticket", pre)
        else
          continueAfterTickets pre input epochChanged oldSlotInEpoch newSlotInEpoch
            new_eta0 new_eta1 new_eta2 new_eta3
            new_gamma_k new_kappa new_lambda new_gamma_z
            base newTickets
      else
        continueAfterTickets pre input epochChanged oldSlotInEpoch newSlotInEpoch
          new_eta0 new_eta1 new_eta2 new_eta3
          new_gamma_k new_kappa new_lambda new_gamma_z
          base newTickets

  continueAfterTickets (pre : FlatSafroleState) (input : SafroleInput)
      (epochChanged : Bool) (oldSlotInEpoch newSlotInEpoch : Nat)
      (new_eta0 new_eta1 new_eta2 new_eta3 : Hash)
      (new_gamma_k new_kappa new_lambda : Array ValidatorKey)
      (new_gamma_z : BandersnatchRingRoot)
      (base newTickets : Array Ticket)
      : SafroleResult × FlatSafroleState :=
    -- eq 6.34: Merge tickets
    let new_gamma_a := mergeTickets base newTickets

    -- eq 6.35: All submitted tickets must be retained
    if newTickets.size > 0 then
      let allRetained := newTickets.all fun t =>
        new_gamma_a.any fun kept => kept.id.data == t.id.data
      if !allRetained then
        (.err "ticket_not_retained", pre)
      else
        finalize pre input epochChanged oldSlotInEpoch newSlotInEpoch
          new_eta0 new_eta1 new_eta2 new_eta3
          new_gamma_k new_kappa new_lambda new_gamma_z new_gamma_a
    else
      finalize pre input epochChanged oldSlotInEpoch newSlotInEpoch
        new_eta0 new_eta1 new_eta2 new_eta3
        new_gamma_k new_kappa new_lambda new_gamma_z new_gamma_a

  finalize (pre : FlatSafroleState) (input : SafroleInput)
      (epochChanged : Bool) (oldSlotInEpoch newSlotInEpoch : Nat)
      (new_eta0 new_eta1 new_eta2 new_eta3 : Hash)
      (new_gamma_k new_kappa new_lambda : Array ValidatorKey)
      (new_gamma_z : BandersnatchRingRoot) (new_gamma_a : Array Ticket)
      : SafroleResult × FlatSafroleState :=
    let eta0 := if pre.eta.size > 0 then pre.eta[0]! else default
    let eta1 := if pre.eta.size > 1 then pre.eta[1]! else default

    -- eq 6.24: Seal-key series
    let oldEpoch := pre.tau.toNat / E
    let newEpoch := input.slot.toNat / E
    let singleAdvance := newEpoch == oldEpoch + 1
    let new_gamma_s :=
      if epochChanged then
        let wasPastY := oldSlotInEpoch >= Y_TAIL
        let accFull := pre.gamma_a.size == E
        if singleAdvance && wasPastY && accFull then
          SealKeySeries.tickets (outsideInSequencer pre.gamma_a)
        else
          SealKeySeries.fallback (fallbackKeys new_eta2 new_kappa)
      else pre.gamma_s

    -- eq 6.27: Epoch marker (uses pre-state eta values)
    let epoch_mark :=
      if epochChanged then
        some {
          entropy := eta0
          entropyPrev := eta1
          validators := new_gamma_k.map fun k => (k.bandersnatch, k.ed25519)
        }
      else none

    -- eq 6.28: Winning-tickets marker
    let tickets_mark :=
      if !epochChanged && oldSlotInEpoch < Y_TAIL && newSlotInEpoch >= Y_TAIL
         && new_gamma_a.size == E then
        some (outsideInSequencer new_gamma_a)
      else none

    let post : FlatSafroleState := {
      tau := input.slot
      eta := #[new_eta0, new_eta1, new_eta2, new_eta3]
      lambda := new_lambda
      kappa := new_kappa
      gamma_k := new_gamma_k
      iota := pre.iota
      gamma_a := new_gamma_a
      gamma_s := new_gamma_s
      gamma_z := new_gamma_z
      post_offenders := pre.post_offenders
    }

    (.ok { epoch_mark, tickets_mark }, post)

-- ============================================================================
-- Comparison Helpers
-- ============================================================================

def bytesToHex (ba : ByteArray) : String :=
  let nibble (n : UInt8) : Char :=
    if n < 10 then Char.ofNat (48 + n.toNat) else Char.ofNat (87 + n.toNat)
  ba.foldl (init := "") fun acc b =>
    acc.push (nibble (b >>> 4)) |>.push (nibble (b &&& 0x0F))

def hashEq (a b : Hash) : Bool := a.data == b.data

def compareHashes (label : String) (a b : Array Hash) : IO Bool := do
  let mut ok := true
  if a.size != b.size then
    IO.println s!"  FAIL {label}: size {a.size} vs {b.size}"
    return false
  for i in [:a.size] do
    if !hashEq a[i]! b[i]! then
      IO.println s!"  FAIL {label}[{i}]: {bytesToHex a[i]!.data} vs {bytesToHex b[i]!.data}"
      ok := false
  return ok

def compareValidatorKeys (label : String) (a b : Array ValidatorKey) : IO Bool := do
  if a.size != b.size then
    IO.println s!"  FAIL {label}: size {a.size} vs {b.size}"
    return false
  let mut ok := true
  for i in [:a.size] do
    if a[i]!.bandersnatch.data != b[i]!.bandersnatch.data then
      IO.println s!"  FAIL {label}[{i}].bandersnatch"
      ok := false
      break
    if a[i]!.ed25519.data != b[i]!.ed25519.data then
      IO.println s!"  FAIL {label}[{i}].ed25519"
      ok := false
      break
  return ok

def compareTickets (label : String) (a b : Array Ticket) : IO Bool := do
  if a.size != b.size then
    IO.println s!"  FAIL {label}: size {a.size} vs {b.size}"
    return false
  let mut ok := true
  for i in [:a.size] do
    if !hashEq a[i]!.id b[i]!.id || a[i]!.attempt != b[i]!.attempt then
      IO.println s!"  FAIL {label}[{i}]"
      ok := false
      break
  return ok

def compareSealKeys (label : String) (a b : SealKeySeries) : IO Bool := do
  match a, b with
  | .fallback ka, .fallback kb =>
    if ka.size != kb.size then
      IO.println s!"  FAIL {label}: fallback size {ka.size} vs {kb.size}"
      return false
    let mut ok := true
    for i in [:ka.size] do
      if ka[i]!.data != kb[i]!.data then
        IO.println s!"  FAIL {label}.fallback[{i}]"
        ok := false
        break
    return ok
  | .tickets ta, .tickets tb => compareTickets label ta tb
  | _, _ =>
    IO.println s!"  FAIL {label}: variant mismatch"
    return false

def compareStates (got expected : FlatSafroleState) : IO Bool := do
  let mut ok := true
  if got.tau != expected.tau then
    IO.println s!"  FAIL tau: {got.tau} vs {expected.tau}"
    ok := false
  if !(← compareHashes "eta" got.eta expected.eta) then ok := false
  if !(← compareValidatorKeys "kappa" got.kappa expected.kappa) then ok := false
  if !(← compareValidatorKeys "lambda" got.lambda expected.lambda) then ok := false
  if !(← compareValidatorKeys "gamma_k" got.gamma_k expected.gamma_k) then ok := false
  if !(← compareValidatorKeys "iota" got.iota expected.iota) then ok := false
  if !(← compareTickets "gamma_a" got.gamma_a expected.gamma_a) then ok := false
  if !(← compareSealKeys "gamma_s" got.gamma_s expected.gamma_s) then ok := false
  if got.gamma_z.data != expected.gamma_z.data then
    IO.println s!"  FAIL gamma_z"
    ok := false
  return ok

/-- Run a single safrole test case. Returns true if passed. -/
def runTest (name : String) (pre : FlatSafroleState) (input : SafroleInput)
    (expectedResult : SafroleResult) (expectedPost : FlatSafroleState) : IO Bool := do
  let (result, post) := safroleTransition pre input
  match result, expectedResult with
  | .ok _, .ok _ =>
    let stateOk ← compareStates post expectedPost
    if stateOk then
      IO.println s!"  PASS {name}"
      return true
    else
      IO.println s!"  FAIL {name}: state mismatch"
      return false
  | .err got, .err expected =>
    if got == expected then
      IO.println s!"  PASS {name} (expected error: {got})"
      return true
    else
      IO.println s!"  FAIL {name}: error {got} vs {expected}"
      return false
  | .ok _, .err expected =>
    IO.println s!"  FAIL {name}: got ok, expected error {expected}"
    return false
  | .err got, .ok _ =>
    IO.println s!"  FAIL {name}: got error {got}, expected ok"
    return false

end Jar.Test.Safrole
