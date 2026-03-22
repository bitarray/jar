import Jar.Commitment.Field
import Jar.Commitment.Merkle

/-!
# Proof Data Structures

Proof structures for the Ligerito commitment scheme: commitments,
openings, sumcheck rounds, and the complete recursive proof.

Ported from `commonware-commitment/src/proof.rs`.
-/

namespace Jar.Commitment.Proof

open Jar.Commitment.Field
open Jar.Commitment.CMerkle

/-- Merkle root commitment. -/
structure Commitment where
  root : Option CHash
  deriving Inhabited

/-- Opened rows with Merkle inclusion proof. -/
structure Opening (T : Type) where
  openedRows : Array (Array T)
  merkleProof : Array CHash

/-- Final round proof data. -/
structure FinalOpening where
  /-- Folded polynomial (extension field). -/
  yr : Array GF128
  openedRows : Array (Array GF128)
  merkleProof : Array CHash

/-- Sumcheck round coefficients: (s0, s1, s2). -/
structure SumcheckRounds where
  transcript : Array (GF128 × GF128 × GF128)

/-- Complete Ligerito proof. -/
structure LigeritoProof where
  /-- Initial commitment (base field). -/
  initialCommitment : Commitment
  /-- Initial opening (base field rows). -/
  initialOpening : Opening GF32
  /-- Recursive round commitments (extension field). -/
  recursiveCommitments : Array Commitment
  /-- Recursive round openings (extension field). -/
  recursiveOpenings : Array (Opening GF128)
  /-- Final round opening. -/
  finalOpening : FinalOpening
  /-- Sumcheck round data. -/
  sumcheckRounds : SumcheckRounds

/-- Total byte size estimate of the proof. -/
def LigeritoProof.sizeOf (p : LigeritoProof) : Nat :=
  32  -- initial commitment
  + p.initialOpening.openedRows.foldl (fun acc row => acc + row.size * 4) 0
  + p.initialOpening.merkleProof.size * 32
  + p.recursiveCommitments.size * 32
  + p.recursiveOpenings.foldl (fun acc o =>
      acc + o.openedRows.foldl (fun a r => a + r.size * 16) 0 + o.merkleProof.size * 32) 0
  + p.finalOpening.yr.size * 16
  + p.finalOpening.openedRows.foldl (fun acc row => acc + row.size * 16) 0
  + p.finalOpening.merkleProof.size * 32
  + p.sumcheckRounds.transcript.size * 48  -- 3 × GF128

-- ============================================================================
-- Prover/Verifier Configuration
-- ============================================================================

/-- Verifier configuration (no prover-only dependencies). -/
structure VerifierConfig where
  /-- Number of recursive proof rounds. -/
  recursiveSteps : Nat
  /-- Log₂ of the initial matrix row count. -/
  initialDim : Nat
  /-- Log₂ of each recursive round's matrix row count. -/
  logDims : Array Nat
  /-- Number of initial partial evaluation challenges. -/
  initialK : Nat
  /-- Number of sumcheck rounds per recursive step. -/
  ks : Array Nat
  /-- Number of query rows to open (security parameter, ≥ 148 for 100-bit). -/
  numQueries : Nat

/-- Log₂ of the committed polynomial size. -/
def VerifierConfig.polyLogSize (c : VerifierConfig) : Nat :=
  c.initialDim + c.initialK

/-- Prover configuration. -/
structure ProverConfig where
  /-- Number of recursive proof rounds. -/
  recursiveSteps : Nat
  /-- Initial matrix dimensions (rows, cols). -/
  initialDims : Nat × Nat
  /-- Recursive round matrix dimensions. -/
  dims : Array (Nat × Nat)
  /-- Number of initial partial evaluation challenges. -/
  initialK : Nat
  /-- Number of sumcheck rounds per recursive step. -/
  ks : Array Nat
  /-- Number of query rows to open (≥ 148 for 100-bit security). -/
  numQueries : Nat

/-- Create a prover config for a given log₂ polynomial size.
    Uses fixed block-size parametrization (no autotuning). -/
def mkProverConfig (logSize : Nat) : ProverConfig :=
  -- Fixed parametrization: 1 recursive step, split at logSize-6
  let initialDimLog := logSize - 6
  let initialK := 6
  let recursiveDimLog := initialDimLog - 4
  let recursiveK := 4
  let _invRate := 4
  { recursiveSteps := 1
    initialDims := (1 <<< initialDimLog, 1 <<< initialK)
    dims := #[(1 <<< recursiveDimLog, 1 <<< recursiveK)]
    initialK := initialK
    ks := #[recursiveK]
    numQueries := 148 }

/-- Create a verifier config for a given log₂ polynomial size. -/
def mkVerifierConfig (logSize : Nat) : VerifierConfig :=
  let initialDimLog := logSize - 6
  let recursiveK := 4
  let recursiveDimLog := initialDimLog - recursiveK
  { recursiveSteps := 1
    initialDim := initialDimLog
    logDims := #[recursiveDimLog]
    initialK := 6
    ks := #[recursiveK]
    numQueries := 148 }

end Jar.Commitment.Proof
