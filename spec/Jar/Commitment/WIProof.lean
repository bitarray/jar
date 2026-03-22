import Jar.Commitment.Field
import Jar.Commitment.Circuit
import Jar.Commitment.WitnessEncoding
import Jar.Commitment.Proof
import Jar.Commitment.Prover
import Jar.Commitment.Verifier
import Jar.Commitment.Transcript
import Jar.Commitment.DA

/-!
# Witness-Indistinguishable Proof System

Bridges the constraint system and polynomial commitment. The verifier
is convinced the prover knows a witness satisfying the circuit, but
the opened rows in the Ligerito proof leak partial witness information
(WI, not full ZK — see <https://www.youtube.com/watch?v=GNaOgmqGxkI&t=11m>).

Ported from `commonware-commitment/src/circuit/wiproof.rs`.

## Accidental computer path

`proveFromBlock` takes an already DA-encoded block and produces a
WI proof without re-encoding. The DA encoding IS the polynomial
commitment — zero additional prover cost.

## Light client flow

1. Full node DA-encodes a block (tensor ZODA)
2. Full node builds threshold circuit: "≥ T of N validators signed"
3. Full node proves circuit satisfaction via `proveFromBlock`
   (reusing DA encoding — zero cost!)
4. Light client receives proof + public inputs (count, threshold)
5. Light client verifies WI proof (Ligerito verify)
6. Light client checks count ≥ threshold from public inputs
7. Light client accepts the block without checking each signature
-/

namespace Jar.Commitment.WIProof

open Jar.Commitment.Field
open Jar.Commitment.Circuit
open Jar.Commitment.WitnessEncoding
open Jar.Commitment.Proof
open Jar.Commitment.Prover
open Jar.Commitment.Verifier
open Jar.Commitment.Transcript
open Jar.Commitment.DA

/-- WI proof for circuit satisfaction. -/
structure WIProof where
  /-- Polynomial commitment proof. -/
  commitmentProof : LigeritoProof
  /-- Public inputs (revealed to verifier). -/
  publicInputs : Array UInt32
  /-- log₂ of witness polynomial size. -/
  logSize : Nat

/-- Prove circuit satisfaction.
    Creates polynomial commitment over the witness and proves via Ligerito. -/
def proveCircuit (circuit : Circuit) (witness : Witness) (seed : Int := 1234)
    : Option WIProof := Id.run do
  let inst := LigeritoInstance.create circuit witness

  -- Verify constraints locally
  if !inst.isSatisfied then return none

  let logSize := inst.witnessPoly.logSize
  -- Minimum size for Ligerito (needs enough structure for sumcheck)
  let targetLogSize := logSize.max 20

  -- Pad polynomial
  let mut poly := inst.getPolynomial
  let targetSize := 1 <<< targetLogSize
  while poly.size < targetSize do
    poly := poly.push 0

  -- Create config and prove. Bind public inputs to Fiat-Shamir transcript.
  let config := mkProverConfig targetLogSize
  let mut ts := mkTranscript seed
  -- Absorb public inputs so the proof is tied to these specific inputs.
  for pi in inst.publicInputs do
    ts := absorbGF32 ts pi
  let (proof, _) := prove config poly ts

  some {
    commitmentProof := proof
    publicInputs := inst.publicInputs
    logSize := targetLogSize
  }

/-- Verify a WI proof.
    Checks polynomial commitment validity and public input consistency. -/
def verifyProof (proof : WIProof) (expectedPublicInputs : Array UInt32)
    (seed : Int := 1234) : Bool := Id.run do
  -- Check public inputs match
  if proof.publicInputs != expectedPublicInputs then return false

  let config := mkVerifierConfig proof.logSize
  let mut ts := mkTranscript seed
  -- Must absorb the same public inputs the prover did.
  for pi in expectedPublicInputs do
    ts := absorbGF32 ts pi
  let (valid, _) := verify config proof.commitmentProof ts
  valid

/-- Prove circuit satisfaction reusing a DA-encoded block.
    **THE accidental computer construction**: DA encoding IS the
    polynomial commitment. Zero re-encoding cost.

    The block must have been created from the same polynomial data
    as the witness. -/
def proveFromBlock (block : EncodedBlock) (poly : Array GF32)
    (circuit : Circuit) (witness : Witness) (seed : Int := 1234)
    : Option WIProof := Id.run do
  let inst := LigeritoInstance.create circuit witness

  if !inst.isSatisfied then return none

  let logSize := inst.witnessPoly.logSize.max 20

  -- Pad polynomial
  let mut paddedPoly := poly
  let targetSize := 1 <<< logSize
  while paddedPoly.size < targetSize do
    paddedPoly := paddedPoly.push 0

  let config := mkProverConfig logSize

  -- Reuse DA block as initial witness — ZERO re-encoding cost
  let mut ts := mkTranscript seed
  for pi in inst.publicInputs do
    ts := absorbGF32 ts pi
  let (proof, _) := proveFromDABlock config block paddedPoly ts

  some {
    commitmentProof := proof
    publicInputs := inst.publicInputs
    logSize
  }

/-- High-level API: prove and verify in one call (for testing). -/
def proveAndVerify (circuit : Circuit) (witness : Witness) : Bool :=
  let pub := witness.publicInputs
  match proveCircuit circuit witness with
  | none => false
  | some proof => verifyProof proof pub

end Jar.Commitment.WIProof
