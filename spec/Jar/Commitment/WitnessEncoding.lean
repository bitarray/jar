import Jar.Commitment.Field
import Jar.Commitment.Circuit

/-!
# Witness Polynomial Encoding

Converts circuit witness into multilinear polynomial form suitable for
the polynomial commitment scheme. Witness values become coefficients;
the commitment scheme commits without revealing them.

Ported from `commonware-commitment/src/circuit/witness.rs`.

## Encoding

For n witness values w[0..n], create multilinear polynomial:
  f(x₀, ..., x_{log n - 1}) = Σᵢ w[i] · Lᵢ(x)
where Lᵢ is the Lagrange basis polynomial.
-/

namespace Jar.Commitment.WitnessEncoding

open Jar.Commitment.Field
open Jar.Commitment.Circuit

/-- Witness encoded as multilinear polynomial coefficients. -/
structure WitnessPolynomial where
  /-- Polynomial coefficients (padded to power of 2). -/
  coeffs : Array GF32
  /-- log₂ of polynomial size. -/
  logSize : Nat
  /-- Number of actual witness values (rest is padding). -/
  numWitness : Nat

namespace WitnessPolynomial

/-- Encode witness as multilinear polynomial. -/
def fromWitness (w : Witness) : WitnessPolynomial :=
  let n := w.values.size
  let logSize := n.nextPowerOfTwo.log2
  let paddedSize := 1 <<< logSize
  let coeffs := if w.values.size < paddedSize then
    w.values ++ Array.replicate (paddedSize - w.values.size) 0
  else
    w.values.extract 0 paddedSize
  { coeffs, logSize, numWitness := n }

/-- Evaluate at boolean hypercube point (just index into coefficients). -/
def evalAtHypercubePoint (wp : WitnessPolynomial) (point : Nat) : GF32 :=
  if point < wp.coeffs.size then wp.coeffs[point]! else 0

/-- Evaluate multilinear extension at arbitrary field point
    using Lagrange interpolation. -/
def evalMLE (wp : WitnessPolynomial) (point : Array GF128) : GF128 := Id.run do
  let mut result := GF128.zero
  for (coeff, i) in wp.coeffs.toList.zipIdx do
    -- Compute Lagrange basis at point i
    let mut basis := GF128.one
    for (r, j) in point.toList.zipIdx do
      let bit := (i / (2^j)) % 2
      if bit == 1 then
        basis := GF128.mul basis r
      else
        -- (1 - r) in binary field = (1 + r) = 1 ⊕ r
        basis := GF128.mul basis (GF128.add GF128.one r)
    result := GF128.add result (GF128.mul basis (embedGF32 coeff))
  result

end WitnessPolynomial

/-- Constraint polynomial: evaluates to 0 on boolean hypercube iff
    all constraints are satisfied. -/
structure ConstraintPolynomial where
  circuit : Circuit

namespace ConstraintPolynomial

/-- Evaluate single constraint contribution at witness point.
    Returns 0 in GF(2^128) if constraint is satisfied, non-zero otherwise.
    This is what the verifier checks via sumcheck. -/
def evalConstraint (_cp : ConstraintPolynomial) (c : Constraint)
    (wp : WitnessPolynomial) : GF128 :=
  match c with
  | .and a b cc =>
    let va := a.evaluate wp.coeffs
    let vb := b.evaluate wp.coeffs
    let vc := cc.evaluate wp.coeffs
    -- AND → multiply in GF(2^32): a · b + c should be 0
    embedGF32 (gf32Add (gf32Mul va vb) vc)
  | .xor a b cc =>
    let va := a.evaluate wp.coeffs
    let vb := b.evaluate wp.coeffs
    let vc := cc.evaluate wp.coeffs
    embedGF32 (gf32Add (gf32Add va vb) vc)
  | .eq a b =>
    let va := a.evaluate wp.coeffs
    let vb := b.evaluate wp.coeffs
    embedGF32 (gf32Add va vb)
  | .fieldMul a b result =>
    let va := wp.evalAtHypercubePoint a.idx
    let vb := wp.evalAtHypercubePoint b.idx
    let vr := wp.evalAtHypercubePoint result.idx
    embedGF32 (gf32Add (gf32Mul va vb) vr)
  | .assertConst wire value =>
    let v := wp.evalAtHypercubePoint wire.idx
    embedGF32 (gf32Add v value)
  | .boolean wire =>
    -- v · (v + 1) = 0 in GF(2^32). Only roots: v=0, v=1.
    let v := wp.evalAtHypercubePoint wire.idx
    embedGF32 (gf32Mul v (gf32Add v 1))
  | .rangeDecomposed wire bits => Id.run do
    let mut result : GF128 := GF128.zero
    for bw in bits do
      let v := wp.evalAtHypercubePoint bw.idx
      result := GF128.add result (embedGF32 (gf32Mul v (gf32Add v 1)))
    let mut reconstructed : GF32 := 0
    for i in [:bits.size] do
      let bitVal := wp.evalAtHypercubePoint (bits[i]!).idx
      -- Use integer 2^i (bit shift), NOT field x^i (gf32Pow 2 i).
      -- In GF(2^32), gf32Pow 2 i = x^i which is NOT the integer 2^i.
      let power : GF32 := (1 : UInt32) <<< i.toUInt32
      reconstructed := gf32Add reconstructed (gf32Mul bitVal power)
    let wireVal := wp.evalAtHypercubePoint wire.idx
    result := GF128.add result (embedGF32 (gf32Add wireVal reconstructed))
    result
  | .integerEq wire value =>
    let v := wp.evalAtHypercubePoint wire.idx
    embedGF32 (gf32Add v value)

/-- Evaluate full constraint polynomial at witness point.
    Returns 0 if all satisfied. -/
def evaluateAtWitness (cp : ConstraintPolynomial) (wp : WitnessPolynomial)
    : GF128 :=
  cp.circuit.constraints.foldl (fun acc c =>
    GF128.add acc (cp.evalConstraint c wp)
  ) GF128.zero

/-- Batch evaluate with Schwartz-Zippel random challenge. -/
def batchEvaluate (cp : ConstraintPolynomial) (wp : WitnessPolynomial)
    (challenge : GF128) : GF128 := Id.run do
  let mut result := GF128.zero
  let mut power := GF128.one
  for c in cp.circuit.constraints do
    let val := cp.evalConstraint c wp
    result := GF128.add result (GF128.mul val power)
    power := GF128.mul power challenge
  result

end ConstraintPolynomial

/-- Prepared instance for proving. -/
structure LigeritoInstance where
  witnessPoly : WitnessPolynomial
  constraintPoly : ConstraintPolynomial
  publicInputs : Array GF32

namespace LigeritoInstance

/-- Create instance from circuit and witness. -/
def create (circuit : Circuit) (witness : Witness) : LigeritoInstance :=
  let wp := WitnessPolynomial.fromWitness witness
  let cp : ConstraintPolynomial := ⟨circuit⟩
  let pub := witness.publicInputs
  { witnessPoly := wp, constraintPoly := cp, publicInputs := pub }

/-- Check if circuit is satisfied (for debugging). -/
def isSatisfied (inst : LigeritoInstance) : Bool :=
  inst.constraintPoly.circuit.check inst.witnessPoly.coeffs |>.isNone

/-- Get polynomial coefficients for the prover. -/
def getPolynomial (inst : LigeritoInstance) : Array GF32 :=
  inst.witnessPoly.coeffs

end LigeritoInstance

end Jar.Commitment.WitnessEncoding
