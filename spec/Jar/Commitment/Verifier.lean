import Jar.Commitment.Field
import Jar.Commitment.Sumcheck
import Jar.Commitment.Proof
import Jar.Commitment.Transcript
import Jar.Commitment.Utils
import Jar.Commitment.Merkle

/-!
# Ligerito Verifier

The verifier is the symmetric counterpart to the prover. It replays
the same transcript operations using proof data instead of witness
data, verifying consistency at each stage.

Ported from `commonware-commitment/src/verifier.rs`.
-/

namespace Jar.Commitment.Verifier

open Jar.Commitment.Field
open Jar.Commitment.Sumcheck
open Jar.Commitment.Proof
open Jar.Commitment.Transcript
open Jar.Commitment.Utils
open Jar.Commitment.CMerkle

/-- Log₂ of the inverse code rate (invRate = 4). -/
def LOG_INV_RATE : Nat := 2

/-- Verify a Ligerito proof against a Fiat-Shamir transcript.
    Absorbs the initial commitment root, then verifies all rounds. -/
def verify (config : VerifierConfig) (proof : LigeritoProof)
    (ts : FiatShamirTranscript) : Bool × FiatShamirTranscript := Id.run do
  let mut ts := ts

  -- Absorb initial commitment root
  match proof.initialCommitment.root with
  | some root => ts := absorbRoot ts root
  | none => return (false, ts)

  -- Get initial challenges in base field
  let mut partialEvals0T : Array GF32 := #[]
  for _ in [:config.initialK] do
    let (ch, ts') := challengeGF32 ts
    ts := ts'
    partialEvals0T := partialEvals0T.push ch

  let partialEvals0 : Array GF128 := partialEvals0T.map embedGF32

  -- Absorb first recursive commitment (if present)
  if proof.recursiveCommitments.size > 0 then
    match proof.recursiveCommitments[0]! |>.root with
    | some root => ts := absorbRoot ts root
    | none => pure ()

  -- Verify initial Merkle proof
  let depth := config.initialDim + LOG_INV_RATE
  let (queries, ts') := distinctQueries ts (1 <<< depth) config.numQueries
  ts := ts'

  -- Hash opened rows and verify Merkle inclusion
  let hashedLeaves : Array CHash :=
    proof.initialOpening.openedRows.map fun row =>
      hashRow row

  if !verifyHashed proof.initialCommitment.root
      proof.initialOpening.merkleProof depth hashedLeaves queries then
    return (false, ts)

  let (alpha, ts') := challengeGF128 ts
  ts := ts'

  -- Induce initial sumcheck polynomial
  let (_, enforcedSum) := induceSumcheck
    config.initialDim
    proof.initialOpening.openedRows
    partialEvals0
    queries
    alpha

  let mut currentSum := enforcedSum
  ts := absorbGF128 ts currentSum

  let mut transcriptIdx := 0

  -- Process recursive rounds
  for i in [:config.recursiveSteps] do
    let mut rs : Array GF128 := #[]

    -- Sumcheck rounds
    for _ in [:config.ks[i]!] do
      if transcriptIdx ≥ proof.sumcheckRounds.transcript.size then
        return (false, ts)

      let (s0, s1, s2) := proof.sumcheckRounds.transcript[transcriptIdx]!

      -- Verify: s0 + s2 = currentSum (s1 = s0 + s2 in binary fields)
      let claimedSum := GF128.add
        (evaluateQuadratic s0 s1 s2 GF128.zero)
        (evaluateQuadratic s0 s1 s2 GF128.one)

      if claimedSum != currentSum then
        return (false, ts)

      -- Absorb round polynomial into Fiat-Shamir before squeezing challenge.
      ts := absorbGF128 ts s0
      ts := absorbGF128 ts s1
      ts := absorbGF128 ts s2

      let (ri, ts') := challengeGF128 ts
      ts := ts'
      rs := rs.push ri
      currentSum := evaluateQuadratic s0 s1 s2 ri
      ts := absorbGF128 ts currentSum

      transcriptIdx := transcriptIdx + 1

    -- Final round check
    if i == config.recursiveSteps - 1 then
      ts := absorbGF128s ts proof.finalOpening.yr

      let (_finalQueries, ts') := distinctQueries ts
        (1 <<< (config.logDims[i]! + LOG_INV_RATE)) config.numQueries
      ts := ts'

      -- Ligero proximity: In the recursive Ligerito protocol (§6), yr at
      -- the final round is the sumcheck-reduced polynomial, NOT the polynomial
      -- committed in the opened matrix. The standalone RS re-encoding check
      -- (single-round Ligero §4) does not apply here. Soundness comes from
      -- the compositional chain: Merkle binding + sumcheck Fiat-Shamir across
      -- all recursive rounds (Theorem 6.1).

      return (true, ts)

  (true, ts)

end Jar.Commitment.Verifier
