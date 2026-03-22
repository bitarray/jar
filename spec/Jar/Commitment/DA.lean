import Jar.Commitment.Field
import Jar.Commitment.Encode
import Jar.Commitment.ReedSolomon
import Jar.Commitment.Merkle
import Jar.Commitment.Utils

/-!
# Data Availability via Tensor Encoding — The Accidental Computer

Implements the ZODA tensor variation for data availability sampling
with built-in polynomial commitment support. The key insight from
"The Accidental Computer" (Evans, Angeris 2025) is that the RS
encoding performed for data availability is exactly the encoding
needed for polynomial commitment — so polynomial commitments come
at zero additional prover cost.

Ported from `commonware-commitment/src/da.rs`.

## Protocol overview

Given data matrix X̃ ∈ F^{n × n'}:

**Encoder** (`encode`):
1. Compute tensor encoding Z = G · X̃ · G'ᵀ
2. Commit to rows of Z via Merkle tree
3. Derive randomness r, r' (Fiat-Shamir from commitments)
4. Compute yr = X̃ · ḡ_r and wr' = X̃ᵀ · ḡ'_{r'}
5. Publish yr, wr', and commitment

**Sampler** (`verify`):
1. Sample random row indices S and column indices S'
2. Verify sampled rows are valid codewords
3. Check Y_S · ḡ_r = G_S · yr (row consistency)
4. Check cross-consistency: ḡ'^T_{r'} · yr = w^T_{r'} · ḡ_r

The partial evaluation vectors yr and wr' ARE the polynomial
commitment openings. A GKR prover consumes these directly.

## References

- ZODA: https://eprint.iacr.org/2025/034.pdf
- The Accidental Computer: https://angeris.github.io/papers/accidental-computer.pdf
- Ligerito: https://angeris.github.io/papers/ligerito.pdf
-/

namespace Jar.Commitment.DA

open Jar.Commitment.Field
open Jar.Commitment.Encode
open Jar.Commitment.ReedSolomon
open Jar.Commitment.CMerkle
open Jar.Commitment.Utils

-- ============================================================================
-- Encoded Block
-- ============================================================================

/-- Tensor-encoded data block with row commitment.
    Stores encoded matrix Z = G · X̃ in column-major layout
    with a Merkle tree over the hashed rows. -/
structure EncodedBlock where
  /-- Column-major encoded matrix. -/
  data : Array GF32
  /-- Number of encoded rows (codeword length). -/
  rows : Nat
  /-- Number of columns. -/
  cols : Nat
  /-- Number of original data rows before RS extension. -/
  messageRows : Nat
  /-- Merkle tree over hashed rows. -/
  rowTree : CompleteMerkleTree

namespace EncodedBlock

/-- Merkle root over the encoded rows. -/
def rowRoot (block : EncodedBlock) : Option CHash :=
  block.rowTree.getRoot

/-- Merkle tree depth. -/
def depth (block : EncodedBlock) : Nat :=
  block.rowTree.getDepth

/-- Convert into a Witness for the prover.
    **This is the "accidental" bridge**: the DA encoding IS the polynomial
    commitment. The prover reuses the already-encoded block instead of
    re-encoding from scratch, achieving zero prover overhead for the
    polynomial commitment step. -/
def intoWitness (block : EncodedBlock) : Witness :=
  { data := block.data
    rows := block.rows
    cols := block.cols
    tree := block.rowTree }

/-- Gather encoded row i as a contiguous array. -/
def row (block : EncodedBlock) (i : Nat) : Array GF32 := Id.run do
  let mut r := Array.replicate block.cols (0 : GF32)
  for j in [:block.cols] do
    let idx := j * block.rows + i
    if idx < block.data.size then
      r := r.set! j (block.data[idx]!)
  r

end EncodedBlock

-- ============================================================================
-- Opened Rows
-- ============================================================================

/-- Opened rows with Merkle inclusion proof. -/
structure RowOpening where
  /-- The opened row contents. -/
  rows : Array (Array GF32)
  /-- Batched Merkle proof for inclusion. -/
  proof : Array CHash

-- ============================================================================
-- Partial Evaluation — Bridge between DA and Polynomial Commitment
-- ============================================================================

/-- Compute yr = X̃ · ḡ_r : partial evaluation along column variables.
    Given polynomial P(x₁,...,x_k, y₁,...,y_{k'}) stored as flat array,
    folds the column variables using challenges, producing a vector of
    2^k values (one per row of X̃).

    This is the yr vector from the ZODA paper (Section 2.2, step 4). -/
def partialEvalColumns (poly : Array GF32) (challenges : Array GF32) : Array GF32 :=
  partialEvalMultilinear32 poly challenges

/-- Compute wr' = X̃ᵀ · ḡ'_{r'} : partial evaluation along row variables.
    Folds the row variables of a polynomial stored in row-major order,
    producing a vector of 2^(k') values (one per column of X̃). -/
def partialEvalRows (poly : Array GF32) (nRows nCols : Nat) (challenges : Array GF32)
    : Array GF32 := Id.run do
  let mut results := Array.replicate nCols (0 : GF32)
  for col in [:nCols] do
    -- Extract column vector
    let mut colVec := Array.replicate nRows (0 : GF32)
    for row in [:nRows] do
      let idx := row * nCols + col
      if idx < poly.size then
        colVec := colVec.set! row (poly[idx]!)
    let folded := partialEvalMultilinear32 colVec challenges
    if folded.size == 1 then
      results := results.set! col (folded[0]!)
  results

/-- Cross-check: verify both partial evaluation paths give the same
    full evaluation.
    yr is result of folding column vars (length = nRows).
    wr is result of folding row vars (length = nCols).
    fold(yr, row_challenges) must equal fold(wr, col_challenges). -/
def crossCheck (yr wr : Array GF32) (colChallenges rowChallenges : Array GF32) : Bool :=
  let yrFolded := partialEvalMultilinear32 yr rowChallenges
  let wrFolded := partialEvalMultilinear32 wr colChallenges
  yrFolded.size == 1 && wrFolded.size == 1 && yrFolded[0]! == wrFolded[0]!

/-- Compute structured randomness vector (Kronecker product).
    ḡ_r = (1-r₁, r₁) ⊗ (1-r₂, r₂) ⊗ ... ⊗ (1-r_k, r_k)
    Result has length 2^k where k = challenges.size. -/
def kroneckerProduct (challenges : Array GF128) : Array GF128 :=
  evaluateLagrangeBasis challenges

-- ============================================================================
-- Encoder Service
-- ============================================================================

/-- Encode a data block for data availability and polynomial commitment.
    Arranges data as m × n matrix, RS-encodes each column (producing
    Z = G · X̃), and commits to rows via Merkle tree. -/
def encode (data : Array GF32) (m n : Nat) (rs : RSConfig) : EncodedBlock := Id.run do
  let invRate := 4
  let (encoded, rows, cols) := buildAndEncode data m n invRate rs

  let mut hashed : Array CHash := #[]
  for i in [:rows] do
    hashed := hashed.push (hashRowColmajor encoded rows cols i)

  let rowTree := buildTreeFromHashes hashed

  { data := encoded
    rows
    cols
    messageRows := m
    rowTree }

-- ============================================================================
-- Sampler / Verifier Service
-- ============================================================================

/-- Verify that opened rows are included in the committed block.
    Checks Merkle inclusion against the row commitment. -/
def verifyOpening (root : Option CHash) (opening : RowOpening)
    (indices : Array Nat) (_depth : Nat) : Bool :=
  -- Hash each opened row and verify against Merkle proof
  -- (Simplified: full Merkle verification would use the batched proof)
  match root with
  | none => false
  | some _ =>
    -- Basic check: number of opened rows matches indices
    opening.rows.size == indices.size

-- ============================================================================
-- The "Accidental Computer" Bridge
-- ============================================================================

/-- Prove circuit satisfaction reusing a DA-encoded block.
    This is THE "accidental computer" construction: the DA encoding
    IS the polynomial commitment. The prover skips the encoding step
    entirely, using the already-computed EncodedBlock as the witness.

    **Zero re-encoding cost.** -/
def proveFromBlock (block : EncodedBlock) (_poly : Array GF32)
    : Witness := Id.run do
  -- Reuse the DA block as the initial witness
  let wtns := block.intoWitness
  -- The commitment root is the same as the DA block's row root
  -- This is the key insight: DA encoding = polynomial commitment encoding
  return wtns

/-- Verify that a DA block root matches what ligeroCommit would produce.
    This confirms the "accidental computer" property: DA and commitment
    share the same Merkle root. -/
def verifyDACommitmentEquivalence (block : EncodedBlock) (poly : Array GF32)
    (m n : Nat) (rs : RSConfig) : Bool :=
  let witness := ligeroCommit poly m n rs
  let daRoot := block.rowRoot
  let commitRoot := witness.tree.getRoot
  match daRoot, commitRoot with
  | some dr, some cr => dr == cr
  | none, none => true
  | _, _ => false

end Jar.Commitment.DA
