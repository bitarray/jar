import Jar.Commitment.Field
import Jar.Commitment.Circuit
import Jar.Commitment.WIProof
import Jar.Commitment.DA

/-!
# Threshold Signature Verification Circuit

Proves ≥ threshold of n validators signed via a binary adder tree
circuit committed through Ligerito. The DA encoding provides the
polynomial commitment for free (accidental computer).

## Why not pure sumcheck?

In GF(2^k), 1+1=0. So `Σ W(x)` over the boolean hypercube gives
the parity of set bits, NOT the integer count. Integer popcount
requires carry propagation → circuit constraints (the adder tree).
The accidental computer still helps: DA encoding = commitment for free.

Over a large-characteristic field (e.g. Goldilocks, BN254 scalar field)
where char > n, field addition IS integer addition for small values and
`Σ W(x) = count` would work directly via sumcheck — no adder tree needed.
The binary field choice (GF(2^32)/GF(2^128)) is driven by the fast
additive FFT and efficient DA encoding in the Ligerito/ZODA stack.

## GKR optimization (future work)

The binary adder tree is a layered arithmetic circuit. The GKR protocol
(Goldwasser-Kalai-Rothblum 2008) can verify layered circuits via one
sumcheck per layer, reducing to a single polynomial evaluation at the
input layer. The Accidental Computer paper (Evans-Angeris 2025, §3-4)
shows this evaluation is exactly what the ZODA partial evaluation
provides for free:

> "The GKR protocol reduces verifying C(X̃) = z to verifying a
>  multilinear polynomial evaluation [...] This is exactly what
>  the ZODA sampler already computes."
>  — The Accidental Computer, §3

Concretely, a GKR-based threshold proof would:
1. Express the adder tree as a layered circuit (same structure as below)
2. Run GKR sumcheck layer-by-layer from output to input
3. Reduce to a single claim W(r) at the input layer
4. Verify W(r) via the DA encoding's partial evaluation — **free**

This would replace the current single-sumcheck-over-all-constraints
approach with a more structured protocol. The per-layer sumcheck is
more efficient for deep circuits (O(n) total work vs O(n·depth) for
the flat constraint approach). For the threshold circuit specifically
(depth = O(log n), width = O(n)), GKR would give:
- Prover: O(n) field operations (same as now)
- Verifier: O(log²n) field operations (vs O(log n) now — marginal)
- The real win: composability with other GKR-verified computations

Implementation requires: a GKR prover/verifier module, wiring functions
for the layered adder tree, and integration with the existing Ligerito
opening protocol. See also Thaler, "Proofs, Arguments, and Zero-Knowledge"
§4.6 for the GKR-sumcheck connection.

## Soundness

1. Each sig bit ∈ {0,1}: `bit·(bit+1) = 0` in GF(2^32). Sound
   because GF(2^32) is a field (no zero divisors).

2. Popcount via binary adder tree (half-adders + full-adders) with
   all intermediate wires constrained. Count is bound to popcount.

3. `count ≥ threshold` via bit decomposition of the difference.

## Witness layout

- Wire 0: count (public)
- Wire 1: threshold (public)
- Wire 2: difference = count - threshold (public, ≥ 0)
- Wires 3..n+3: signature bits (private)
- Remaining: adder intermediates + difference bit decomposition
-/

namespace Jar.Commitment.Threshold

open Jar.Commitment.Field
open Jar.Commitment.Circuit
open Jar.Commitment.WIProof
open Jar.Commitment.DA

-- ============================================================================
-- Adder Tree
-- ============================================================================

/-- Record of an adder operation for witness replay. -/
inductive AdderOp where
  | half (a b sum carry : WireId)
  | full (a b cin sum cout s1 c1 c2 : WireId)

/-- Half adder: sum = a XOR b, carry = a AND b. -/
def addBits (builder : CircuitBuilder) (a b : WireId)
    : (WireId × WireId) × AdderOp × CircuitBuilder :=
  let (sumW, b1) := builder.addWitness
  let (carryW, b2) := b1.addWitness
  let b3 := b2.assertXor (Operand.empty.withWire a) (Operand.empty.withWire b)
                          (Operand.empty.withWire sumW)
  let b4 := b3.assertAnd (Operand.empty.withWire a) (Operand.empty.withWire b)
                          (Operand.empty.withWire carryW)
  ((sumW, carryW), .half a b sumW carryW, b4)

/-- Full adder: a + b + cin via two half-adders. -/
def fullAdder (builder : CircuitBuilder) (a b cin : WireId)
    : (WireId × WireId) × AdderOp × CircuitBuilder :=
  let (s1, b1) := builder.addWitness
  let (c1, b2) := b1.addWitness
  let (sumW, b3) := b2.addWitness
  let (c2, b4) := b3.addWitness
  let (coutW, b5) := b4.addWitness
  let b6 := b5.assertXor (Operand.empty.withWire a) (Operand.empty.withWire b)
                          (Operand.empty.withWire s1)
  let b7 := b6.assertAnd (Operand.empty.withWire a) (Operand.empty.withWire b)
                          (Operand.empty.withWire c1)
  let b8 := b7.assertXor (Operand.empty.withWire s1) (Operand.empty.withWire cin)
                          (Operand.empty.withWire sumW)
  let b9 := b8.assertAnd (Operand.empty.withWire s1) (Operand.empty.withWire cin)
                          (Operand.empty.withWire c2)
  let b10 := b9.assertXor (Operand.empty.withWire c1) (Operand.empty.withWire c2)
                           (Operand.empty.withWire coutW)
  ((sumW, coutW), .full a b cin sumW coutW s1 c1 c2, b10)

/-- Add two multi-bit numbers (LSB first). Returns result bit wires. -/
def addMultiBit (builder : CircuitBuilder) (aBits bBits : Array WireId)
    : Array WireId × Array AdderOp × CircuitBuilder := Id.run do
  let n := aBits.size.max bBits.size
  let mut result : Array WireId := #[]
  let mut ops : Array AdderOp := #[]
  let mut carry : Option WireId := none
  let mut b := builder

  for i in [:n] do
    let mut aw : WireId := ⟨0⟩
    if i < aBits.size then
      aw := aBits[i]!
    else
      let (z, b') := b.addWitness; b := b'.assertConst z 0; aw := z
    let mut bw : WireId := ⟨0⟩
    if i < bBits.size then
      bw := bBits[i]!
    else
      let (z, b') := b.addWitness; b := b'.assertConst z 0; bw := z

    match carry with
    | none =>
      let ((s, c), op, b') := addBits b aw bw
      b := b'; ops := ops.push op; result := result.push s; carry := some c
    | some cin =>
      let ((s, c), op, b') := fullAdder b aw bw cin
      b := b'; ops := ops.push op; result := result.push s; carry := some c

  match carry with
  | some c => result := result.push c
  | none => pure ()

  (result, ops, b)

/-- Binary reduction tree for popcount. Returns bit-decomposed sum (LSB first). -/
partial def popcountTree (builder : CircuitBuilder) (bits : Array WireId)
    : Array WireId × Array AdderOp × CircuitBuilder := Id.run do
  if bits.size ≤ 1 then return (bits, #[], builder)

  let mut numbers : Array (Array WireId) := bits.map (#[·])
  let mut allOps : Array AdderOp := #[]
  let mut b := builder

  while numbers.size > 1 do
    let mut next : Array (Array WireId) := #[]
    let mut i := 0
    while i + 1 < numbers.size do
      let (sumBits, ops, b') := addMultiBit b numbers[i]! numbers[i + 1]!
      b := b'; allOps := allOps ++ ops; next := next.push sumBits
      i := i + 2
    if i < numbers.size then
      next := next.push numbers[i]!
    numbers := next

  (numbers[0]!, allOps, b)

-- ============================================================================
-- Threshold Circuit
-- ============================================================================

/-- Wire layout for the threshold circuit. -/
structure ThresholdWires where
  count : WireId
  threshold : WireId
  difference : WireId
  sigBits : Array WireId
  adderOps : Array AdderOp
  popcountBits : Array WireId
  diffBits : Array WireId

/-- Build a threshold circuit for n validators. -/
def buildThresholdCircuit (n : Nat) : Circuit × ThresholdWires := Id.run do
  let mut builder : CircuitBuilder := {}
  let countBitsNeeded := (n + 1).log2 + 2

  let (count, b1) := builder.addPublic; builder := b1
  let (thresholdW, b2) := builder.addPublic; builder := b2
  let (difference, b3) := builder.addPublic; builder := b3

  let mut sigBits : Array WireId := #[]
  for _ in [:n] do
    let (bit, b') := builder.addWitness; builder := b'
    sigBits := sigBits.push bit

  -- Boolean: bit·(bit+1) = 0 via FieldMul(bit, bit, bit)
  for bit in sigBits do
    builder := builder.assertFieldMul bit bit bit

  -- Popcount via adder tree
  let (popcountBits, adderOps, b4) := popcountTree builder sigBits
  builder := b4
  builder := builder.addConstraint (.rangeDecomposed count popcountBits)

  -- Difference bit decomposition (proves count - threshold ≥ 0)
  let mut diffBits : Array WireId := #[]
  for _ in [:countBitsNeeded] do
    let (bit, b') := builder.addWitness; builder := b'
    diffBits := diffBits.push bit
    builder := builder.assertFieldMul bit bit bit
  builder := builder.addConstraint (.rangeDecomposed difference diffBits)

  (builder.build, { count, threshold := thresholdW, difference,
                     sigBits, adderOps, popcountBits, diffBits })

/-- Populate witness, replaying adder tree for intermediate values. -/
def buildThresholdWitness (wires : ThresholdWires) (signatures : Array Bool)
    (thresholdVal : Nat) : Witness := Id.run do
  let n := wires.sigBits.size
  let count := signatures.foldl (fun acc s => if s then acc + 1 else acc) 0
  let diff := if count >= thresholdVal then count - thresholdVal else 0

  let maxWire := #[wires.count.idx, wires.threshold.idx, wires.difference.idx].foldl Nat.max 0
    |> (wires.sigBits.foldl (fun acc w => acc.max w.idx) ·)
    |> (wires.popcountBits.foldl (fun acc w => acc.max w.idx) ·)
    |> (wires.diffBits.foldl (fun acc w => acc.max w.idx) ·)
    |> (wires.adderOps.foldl (fun acc op => match op with
        | .half _ _ s c => acc.max s.idx |>.max c.idx
        | .full _ _ _ s co s1 c1 c2 =>
          acc.max s.idx |>.max co.idx |>.max s1.idx |>.max c1.idx |>.max c2.idx) ·)
    |> (· + 1)

  let mut w := Witness.new maxWire 3
  w := w.set wires.count count.toUInt32
  w := w.set wires.threshold thresholdVal.toUInt32
  w := w.set wires.difference diff.toUInt32

  for i in [:n.min signatures.size] do
    w := w.set wires.sigBits[i]! (if signatures[i]! then 1 else 0)

  -- Replay adder tree
  for op in wires.adderOps do
    match op with
    | .half a b sum carry =>
      let va := w.get a; let vb := w.get b
      w := w.set sum (va ^^^ vb); w := w.set carry (va &&& vb)
    | .full a b cin sum cout s1 c1 c2 =>
      let va := w.get a; let vb := w.get b; let vc := w.get cin
      let vs1 := va ^^^ vb; let vc1 := va &&& vb
      let vsum := vs1 ^^^ vc; let vc2 := vs1 &&& vc
      w := w.set s1 vs1; w := w.set c1 vc1
      w := w.set sum vsum; w := w.set c2 vc2; w := w.set cout (vc1 ^^^ vc2)

  for i in [:wires.diffBits.size] do
    w := w.set wires.diffBits[i]! ((diff / (2 ^ i)) % 2).toUInt32

  w

-- ============================================================================
-- Light Client
-- ============================================================================

/-- Light client threshold check from public inputs [count, threshold, difference]. -/
def verifyThreshold (publicInputs : Array UInt32) (expectedThreshold : UInt32) : Bool :=
  if publicInputs.size < 3 then false
  else
    let count := publicInputs[0]!
    let threshold := publicInputs[1]!
    let difference := publicInputs[2]!
    count >= threshold && threshold >= expectedThreshold
    && count == threshold + difference

def checkThreshold (count threshold expected : UInt32) : Bool :=
  count >= threshold && threshold >= expected

/-- Prove a threshold claim. -/
def proveThreshold (n : Nat) (signatures : Array Bool) (thresholdVal : Nat)
    : Option WIProof :=
  let (circuit, wires) := buildThresholdCircuit n
  let witness := buildThresholdWitness wires signatures thresholdVal
  proveCircuit circuit witness

/-- Prove from DA block (zero additional encoding cost). -/
def proveThresholdFromBlock (block : EncodedBlock) (poly : Array GF32)
    (n : Nat) (signatures : Array Bool) (thresholdVal : Nat)
    : Option WIProof :=
  let (circuit, wires) := buildThresholdCircuit n
  let witness := buildThresholdWitness wires signatures thresholdVal
  WIProof.proveFromBlock block poly circuit witness

/-- Verify threshold proof (light client). -/
def verifyThresholdProof (proof : WIProof) (expectedThreshold : UInt32) : Bool :=
  let proofValid := verifyProof proof proof.publicInputs
  let thresholdMet := verifyThreshold proof.publicInputs expectedThreshold
  proofValid && thresholdMet

end Jar.Commitment.Threshold
