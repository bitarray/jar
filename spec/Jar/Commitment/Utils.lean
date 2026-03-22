import Jar.Commitment.Field

/-!
# Shared Utilities

Lagrange basis evaluation, multilinear polynomial folding, and
subspace polynomial evaluation utilities shared by prover and verifier.

Ported from `commonware-commitment/src/utils.rs`.
-/

namespace Jar.Commitment.Utils

open Jar.Commitment.Field

-- ============================================================================
-- Lagrange Basis (Kronecker / Tensor Product)
-- ============================================================================

/-- Evaluate Lagrange basis at given challenge points.
    Returns the tensor product expansion: ḡ_r = ⊗_i (1-r_i, r_i).
    Result has length 2^(rs.size).

    This is the structured randomness vector from the papers. -/
def evaluateLagrangeBasis (rs : Array GF128) : Array GF128 := Id.run do
  if rs.isEmpty then return #[GF128.one]

  let r0 := rs[0]!
  let oneMinusR0 := GF128.add GF128.one r0  -- char 2: 1-r = 1+r = 1⊕r
  let mut current : Array GF128 := #[oneMinusR0, r0]

  for idx in [1:rs.size] do
    let r := rs[idx]!
    let oneMinusR := GF128.add GF128.one r
    let mut next : Array GF128 := #[]
    for val in current do
      next := next.push (GF128.mul val oneMinusR)
      next := next.push (GF128.mul val r)
    current := next

  current

-- ============================================================================
-- Multilinear Polynomial Operations
-- ============================================================================

/-- Partial evaluation of a multilinear polynomial.
    Folds the polynomial by evaluating at each point in `evals`,
    halving the length for each evaluation point.

    poly[i] = poly[2i] + e · (poly[2i+1] + poly[2i]) -/
def partialEvalMultilinear (poly : Array GF128) (evals : Array GF128)
    : Array GF128 := Id.run do
  let mut p := poly
  for e in evals do
    let n := p.size / 2
    let mut next := Array.replicate n GF128.zero
    for i in [:n] do
      let p0 := p[2 * i]!
      let p1 := p[2 * i + 1]!
      -- p0 + e * (p1 + p0)  [in char 2, subtraction = addition]
      next := next.set! i (GF128.add p0 (GF128.mul e (GF128.add p1 p0)))
    p := next
  p

/-- Partial evaluation over GF(2^32) polynomials. -/
def partialEvalMultilinear32 (poly : Array GF32) (evals : Array GF32)
    : Array GF32 := Id.run do
  let mut p := poly
  for e in evals do
    let n := p.size / 2
    let mut next := Array.replicate n (0 : GF32)
    for i in [:n] do
      let p0 := p[2 * i]!
      let p1 := p[2 * i + 1]!
      next := next.set! i (gf32Add p0 (gf32Mul e (gf32Add p1 p0)))
    p := next
  p

-- ============================================================================
-- Subspace Polynomial Evaluation
-- ============================================================================

/-- Compute s_k polynomial evaluations at v_k points (for sumcheck).
    n must be a power of two. Returns array of log2(n)+1 values. -/
def evalSkAtVks (n : Nat) : Array GF32 := Id.run do
  let numSubspaces := n.log2
  let mut sksVks := Array.replicate (numSubspaces + 1) (0 : GF32)
  sksVks := sksVks.set! 0 1  -- s_0(v_0) = 1

  let mut layer : Array GF32 := Array.ofFn (n := numSubspaces) fun ⟨i, _⟩ =>
    gf32FromBits (1 <<< (i + 1))

  let mut curLen := numSubspaces
  for i in [:numSubspaces] do
    for j in [:curLen] do
      let skAtVk := gf32Add (gf32Sqr layer[j]!)
                             (gf32Mul sksVks[i]! layer[j]!)
      if j == 0 then
        sksVks := sksVks.set! (i + 1) skAtVk
      if j > 0 then
        layer := layer.set! (j - 1) skAtVk
    curLen := curLen - 1

  sksVks

/-- Evaluate s_k at v_k for GF(2^128). -/
def evalSkAtVks128 (n : Nat) : Array GF128 := Id.run do
  let numSubspaces := n.log2
  let mut sksVks := Array.replicate (numSubspaces + 1) GF128.zero
  sksVks := sksVks.set! 0 GF128.one

  let mut layer : Array GF128 := Array.ofFn (n := numSubspaces) fun ⟨i, _⟩ =>
    gf128FromBits (1 <<< (i + 1))

  let mut curLen := numSubspaces
  for i in [:numSubspaces] do
    for j in [:curLen] do
      let elem := layer[j]!
      let skAtVk := GF128.add (GF128.sqr elem)
                               (GF128.mul sksVks[i]! elem)
      if j == 0 then
        sksVks := sksVks.set! (i + 1) skAtVk
      if j > 0 then
        layer := layer.set! (j - 1) skAtVk
    curLen := curLen - 1

  sksVks

end Jar.Commitment.Utils
