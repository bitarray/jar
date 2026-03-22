import Jar.Commitment.Field
import Jar.Commitment.Utils

/-!
# Sumcheck Protocol

Polynomial induction for the sumcheck protocol, following the Ligerito
paper section 6.2. Computes batched basis polynomials for verifier
consistency checks.

Ported from `commonware-commitment/src/sumcheck/`.

## Key algorithms

- Tensorized dot product: exploits Kronecker structure to reduce
  O(2^k) to O(k · 2^(k-1)) via dimension folding.
- Sumcheck induction: computes batched basis polynomial and enforced
  sum for the verifier consistency check.
-/

namespace Jar.Commitment.Sumcheck

open Jar.Commitment.Field
open Jar.Commitment.Utils

-- ============================================================================
-- Tensorized Dot Product
-- ============================================================================

/-- Tensorized dot product exploiting Kronecker structure.
    Reduces O(2^k) to O(k · 2^(k-1)) by folding dimensions.
    Iterates challenges in reverse since Lagrange basis maps r0 to LSB. -/
def tensorizedDotProduct (row : Array GF32) (challenges : Array GF128) : GF128 := Id.run do
  if challenges.isEmpty then
    return if row.size == 1 then embedGF32 (row[0]!) else GF128.zero

  -- Lift row to extension field
  let mut current : Array GF128 := row.map embedGF32

  -- Fold from last to first challenge
  for idx in List.range challenges.size |>.reverse do
    let r := challenges[idx]!
    let half := current.size / 2
    let oneMinusR := GF128.add GF128.one r  -- char 2: 1-r = 1+r

    let mut next := Array.replicate half GF128.zero
    for i in [:half] do
      -- Lagrange contraction: (1-r)·left + r·right
      let left := current[2 * i]!
      let right := current[2 * i + 1]!
      next := next.set! i (GF128.add (GF128.mul left oneMinusR)
                                       (GF128.mul right r))
    current := next

  current[0]!

-- ============================================================================
-- Alpha Power Precomputation
-- ============================================================================

/-- Precompute powers of alpha: [1, α, α², ..., α^(n-1)]. -/
def precomputeAlphaPowers (alpha : GF128) (n : Nat) : Array GF128 := Id.run do
  let mut powers := Array.replicate n GF128.zero
  if n > 0 then
    powers := powers.set! 0 GF128.one
    for i in [1:n] do
      powers := powers.set! i (GF128.mul powers[i - 1]! alpha)
  powers

-- ============================================================================
-- Sumcheck Polynomial Induction
-- ============================================================================

/-- Full Ligerito sumcheck polynomial induction per paper section 6.2.
    Computes batched basis polynomial w_l for verifier consistency check.

    Returns (basis_poly, enforced_sum) where:
    - basis_poly: polynomial of length 2^n encoding the weighted sum
    - enforced_sum: the claimed total sum ∑ contributions

    The key optimization: since each query produces a delta function
    (only basis_poly[query_mod] is non-zero), we set it directly
    instead of scanning O(2^n). -/
def induceSumcheck (n : Nat) (openedRows : Array (Array GF32))
    (vChallenges : Array GF128) (sortedQueries : Array Nat) (alpha : GF128)
    : Array GF128 × GF128 := Id.run do
  let mut basisPoly := Array.replicate (1 <<< n) GF128.zero
  let mut enforcedSum := GF128.zero
  let alphaPows := precomputeAlphaPowers alpha openedRows.size

  for i in [:openedRows.size] do
    let row := openedRows[i]!
    let query := sortedQueries[i]!

    let dot := tensorizedDotProduct row vChallenges
    let contribution := GF128.mul dot (alphaPows[i]!)
    enforcedSum := GF128.add enforcedSum contribution

    -- Delta function: only basis_poly[query_mod] gets contribution
    let queryMod := query % (1 <<< n)
    basisPoly := basisPoly.set! queryMod
      (GF128.add (basisPoly[queryMod]!) contribution)

  (basisPoly, enforcedSum)

-- ============================================================================
-- Sumcheck Round Operations
-- ============================================================================

/-- Compute sumcheck round coefficients (s0, s1, s2) from current polynomial.
    s0 = sum of even-indexed terms
    s2 = sum of odd-indexed terms
    s1 = s0 + s2 -/
def computeSumcheckCoefficients (poly : Array GF128)
    : GF128 × GF128 × GF128 := Id.run do
  let n := poly.size / 2
  let mut s0 := GF128.zero
  let mut s1 := GF128.zero
  let mut s2 := GF128.zero

  for i in [:n] do
    let p0 := poly[2 * i]!
    let p1 := poly[2 * i + 1]!
    s0 := GF128.add s0 p0
    s1 := GF128.add s1 (GF128.add p0 p1)
    s2 := GF128.add s2 p1

  (s0, s1, s2)

/-- Fold polynomial in-place: poly[i] = poly[2i] + r · (poly[2i+1] + poly[2i]).
    Returns the folded (half-length) polynomial. -/
def foldPolynomial (poly : Array GF128) (r : GF128) : Array GF128 := Id.run do
  let n := poly.size / 2
  let mut result := Array.replicate n GF128.zero
  for i in [:n] do
    let p0 := poly[2 * i]!
    let p1 := poly[2 * i + 1]!
    result := result.set! i (GF128.add p0 (GF128.mul r (GF128.add p1 p0)))
  result

/-- Evaluate univariate sumcheck polynomial at x.
    f(x) = s0 + s1 · x (in binary fields). -/
@[inline] def evaluateQuadratic (s0 s1 _s2 : GF128) (x : GF128) : GF128 :=
  GF128.add s0 (GF128.mul s1 x)

/-- Combine two polynomials: result[i] = f[i] + β · g[i]. -/
def gluePolynomials (f g : Array GF128) (beta : GF128) : Array GF128 := Id.run do
  let mut result := Array.replicate f.size GF128.zero
  for i in [:f.size] do
    result := result.set! i
      (GF128.add (f[i]!) (GF128.mul beta (g[i]!)))
  result

/-- Combine two sums: sum_f + β · sum_g. -/
@[inline] def glueSums (sumF sumG beta : GF128) : GF128 :=
  GF128.add sumF (GF128.mul beta sumG)

end Jar.Commitment.Sumcheck
