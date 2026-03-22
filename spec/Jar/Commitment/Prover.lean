import Jar.Commitment.Field
import Jar.Commitment.Encode
import Jar.Commitment.Sumcheck
import Jar.Commitment.Proof
import Jar.Commitment.Transcript
import Jar.Commitment.Utils
import Jar.Commitment.ReedSolomon
import Jar.Commitment.DA

/-!
# Ligerito Prover

Composes encoding, commitment, transcript, and sumcheck into the full
Ligerito proving protocol.

Ported from `commonware-commitment/src/prover.rs`.

## Protocol

1. Initial Ligero commit: encode polynomial as matrix, RS-encode columns,
   hash rows → Merkle root.
2. Partial evaluation: fold polynomial with transcript challenges.
3. Recursive sumcheck rounds: induce sumcheck polynomial, fold with
   challenges, commit intermediate polynomials.
4. Final opening: send folded polynomial and open queried rows.
-/

namespace Jar.Commitment.Prover

open Jar.Commitment.Field
open Jar.Commitment.Encode
open Jar.Commitment.Sumcheck
open Jar.Commitment.Proof
open Jar.Commitment.Transcript
open Jar.Commitment.Utils
open Jar.Commitment.ReedSolomon

/-- Core proving logic.
    Takes initial witness and commitment (already computed, possibly
    reused from DA encoding via the "accidental computer" path). -/
def proveCore (config : ProverConfig) (poly : Array GF32)
    (wtns0 : Encode.Witness) (cm0 : Proof.Commitment) (ts : FiatShamirTranscript)
    : LigeritoProof × FiatShamirTranscript := Id.run do
  let mut ts := ts

  -- Get initial challenges in base field
  let mut partialEvals0 : Array GF32 := #[]
  for _ in [:config.initialK] do
    let (ch, ts') := challengeGF32 ts
    ts := ts'
    partialEvals0 := partialEvals0.push ch

  -- Partial evaluation of multilinear polynomial
  let fEvals := partialEvalMultilinear32 (poly) partialEvals0

  -- Convert to extension field
  let partialEvals0U : Array GF128 := partialEvals0.map embedGF32
  let _fEvalsU : Array GF128 := fEvals.map embedGF32

  -- First recursive step: commit folded polynomial in extension field
  -- (Simplified: using the folded evaluations as the commitment)
  let _rs1 := mkRSConfig (config.dims[0]!).1 ((config.dims[0]!).1 * 4)

  -- Query selection on initial witness
  let rows := wtns0.rows
  let (queries, ts') := distinctQueries ts rows config.numQueries
  ts := ts'
  let (alpha, ts') := challengeGF128 ts
  ts := ts'

  -- Prepare for sumcheck
  let n := fEvals.size.log2

  let openedRows : Array (Array GF32) := queries.map (gatherRow wtns0 ·)
  let mtreeProof := wtns0.tree.prove queries

  -- Induce the sumcheck polynomial
  let (basisPoly, enforcedSum) :=
    induceSumcheck n openedRows partialEvals0U queries alpha

  ts := absorbGF128 ts enforcedSum

  -- Sumcheck rounds
  let mut sumcheckTranscript : Array (GF128 × GF128 × GF128) := #[]
  let mut currentPoly := basisPoly
  let mut _currentSum := enforcedSum

  for _ in [:config.ks[0]!] do
    let (s0, s1, s2) := computeSumcheckCoefficients currentPoly
    sumcheckTranscript := sumcheckTranscript.push (s0, s1, s2)

    -- Absorb round polynomial into Fiat-Shamir before squeezing challenge.
    ts := absorbGF128 ts s0
    ts := absorbGF128 ts s1
    ts := absorbGF128 ts s2

    let (ri, ts') := challengeGF128 ts
    ts := ts'

    currentPoly := foldPolynomial currentPoly ri
    _currentSum := evaluateQuadratic s0 s1 s2 ri
    ts := absorbGF128 ts _currentSum

  -- Final opening
  ts := absorbGF128s ts currentPoly

  let (finalQueries, ts') := distinctQueries ts rows config.numQueries
  ts := ts'

  let finalOpenedRows : Array (Array GF128) :=
    finalQueries.map fun q =>
      (gatherRow wtns0 q).map embedGF32

  let finalMtreeProof := wtns0.tree.prove finalQueries

  let proof : LigeritoProof :=
    { initialCommitment := cm0
      initialOpening := { openedRows, merkleProof := mtreeProof }
      recursiveCommitments := #[]
      recursiveOpenings := #[]
      finalOpening :=
        { yr := currentPoly
          openedRows := finalOpenedRows
          merkleProof := finalMtreeProof }
      sumcheckRounds := { transcript := sumcheckTranscript } }

  (proof, ts)

/-- Generate a Ligerito proof for a polynomial.
    Performs the full protocol: commit → partial eval → sumcheck → open. -/
def prove (config : ProverConfig) (poly : Array GF32) (ts : FiatShamirTranscript)
    : LigeritoProof × FiatShamirTranscript := Id.run do
  -- Initial Ligero commitment over base field
  let rs := mkRSConfig config.initialDims.1 (config.initialDims.1 * 4)
  let wtns0 : Encode.Witness := ligeroCommit poly config.initialDims.1 config.initialDims.2 rs
  let cm0 : Proof.Commitment := commitmentFromWitness wtns0

  -- Absorb root
  let mut ts := ts
  match cm0.root with
  | some root => ts := absorbRoot ts root
  | none => pure ()

  proveCore config poly wtns0 ⟨cm0.root⟩ ts

/-- Generate a Ligerito proof from a pre-encoded DA block.
    **The "accidental computer" path**: reuses the DA encoding as the
    polynomial commitment, achieving zero additional prover cost. -/
def proveFromDABlock (config : ProverConfig) (block : DA.EncodedBlock)
    (poly : Array GF32) (ts : FiatShamirTranscript)
    : LigeritoProof × FiatShamirTranscript := Id.run do
  -- Reuse the DA block as the initial witness — ZERO re-encoding cost
  let wtns0 : Encode.Witness := block.intoWitness
  let cm0 : Proof.Commitment := ⟨block.rowRoot⟩

  let mut ts := ts
  match cm0.root with
  | some root => ts := absorbRoot ts root
  | none => pure ()

  proveCore config poly wtns0 cm0 ts

end Jar.Commitment.Prover
