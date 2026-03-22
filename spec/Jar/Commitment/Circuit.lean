import Jar.Commitment.Field

/-!
# Constraint System for Circuit-Based Proofs

Binary field constraint system: AND, XOR, equality, field multiplication,
boolean/range constraints. The witness is encoded as a multilinear
polynomial committed via Ligerito.

Ported from `commonware-commitment/src/circuit/constraint.rs`.

## Constraint types

- **AND**: A & B ⊕ C = 0 (non-linear, costs 1x multiplicative constraint)
- **XOR**: A ⊕ B ⊕ C = 0 (linear, "free")
- **Eq**: A = B
- **FieldMul**: A · B = C in GF(2^32)
- **AssertConst**: wire = constant
- **Boolean**: wire ∈ {0, 1} (via AND self-check in integer domain)
- **RangeDecomposed**: wire = Σ bit_i · 2^i (ZK-sound range check)

## Important: GF(2^32) vs integer semantics

In GF(2^32), x² = x for many more elements than {0,1} (Frobenius
endomorphism). So boolean checks MUST use the AND constraint which
operates on the integer/bitwise representation: `bit AND bit = bit`
is only true for 0 and all-ones in bitwise AND, but for single-bit
wires stored as 0 or 1, we check `bit * (bit - 1) = 0` which in
the integer domain constrains to {0, 1}.

For the circuit polynomial (which operates in GF(2^32)), boolean
constraints are expressed as: bit · (1 + bit) = 0, since in GF(2)
subtraction = addition. This means bit = 0 or bit = 1.
-/

namespace Jar.Commitment.Circuit

open Jar.Commitment.Field

/-- Wire index into the witness vector. -/
structure WireId where
  idx : Nat
  deriving BEq, Inhabited, Repr, DecidableEq

/-- Shift operation on a wire value. -/
inductive ShiftOp where
  | none
  | sll (n : Nat)  -- logical left shift
  | srl (n : Nat)  -- logical right shift
  deriving BEq, Inhabited, Repr

namespace ShiftOp

/-- Apply shift to a 32-bit value. -/
def apply (op : ShiftOp) (value : UInt32) : UInt32 :=
  match op with
  | .none => value
  | .sll n => value <<< n.toUInt32
  | .srl n => value >>> n.toUInt32

end ShiftOp

/-- Operand: XOR combination of (possibly shifted) wires. -/
structure Operand where
  terms : Array (WireId × ShiftOp)
  deriving Inhabited

namespace Operand

def empty : Operand := ⟨#[]⟩

def withWire (op : Operand) (wire : WireId) : Operand :=
  { op with terms := op.terms.push (wire, .none) }

def withShifted (op : Operand) (wire : WireId) (shift : ShiftOp) : Operand :=
  { op with terms := op.terms.push (wire, shift) }

/-- Evaluate operand against witness: XOR all shifted wire values. -/
def evaluate (op : Operand) (witness : Array GF32) : GF32 :=
  op.terms.foldl (fun acc (wire, shift) =>
    let val := if wire.idx < witness.size then witness[wire.idx]! else 0
    gf32Add acc (shift.apply val)
  ) 0

end Operand

/-- Constraint types in the circuit. -/
inductive Constraint where
  /-- Bitwise AND: A & B ⊕ C = 0 (becomes A · B + C = 0 in the
      constraint polynomial over GF(2^32)). -/
  | and (a b c : Operand)
  /-- Bitwise XOR: A ⊕ B ⊕ C = 0 (linear). -/
  | xor (a b c : Operand)
  /-- Equality: A = B. -/
  | eq (a b : Operand)
  /-- GF(2^32) field multiplication: a · b = result. -/
  | fieldMul (a b result : WireId)
  /-- Assert wire equals constant. -/
  | assertConst (wire : WireId) (value : UInt32)
  /-- Boolean: wire · (1 + wire) = 0, i.e. wire ∈ {0, 1}.
      This is the correct boolean check in GF(2^32). -/
  | boolean (wire : WireId)
  /-- Range check with bit decomposition (ZK-sound).
      Asserts wire = Σᵢ bits[i] · 2^i AND each bit ∈ {0,1}. -/
  | rangeDecomposed (wire : WireId) (bits : Array WireId)
  /-- Integer addition over GF(2^32): a + b = sum.
      Uses XOR for GF(2) addition (no carry). For integer addition
      with carries, use the adder circuit builder below. -/
  | integerEq (wire : WireId) (value : UInt32)
  deriving Inhabited

namespace Constraint

/-- Get wire value from witness. -/
private def getWire (witness : Array GF32) (w : WireId) : GF32 :=
  if w.idx < witness.size then witness[w.idx]! else 0

/-- Check constraint against witness (integer/bitwise semantics for
    local verification by the prover before committing). -/
def check (c : Constraint) (witness : Array GF32) : Bool :=
  match c with
  | .and a b cc =>
    let va := a.evaluate witness
    let vb := b.evaluate witness
    let vc := cc.evaluate witness
    (va &&& vb) ^^^ vc == 0
  | .xor a b cc =>
    let va := a.evaluate witness
    let vb := b.evaluate witness
    let vc := cc.evaluate witness
    va ^^^ vb ^^^ vc == 0
  | .eq a b =>
    a.evaluate witness == b.evaluate witness
  | .fieldMul a b result =>
    gf32Mul (getWire witness a) (getWire witness b) == getWire witness result
  | .assertConst wire value =>
    getWire witness wire == value
  | .boolean wire =>
    let v := getWire witness wire
    v == 0 || v == 1
  | .rangeDecomposed wire bits =>
    -- Each bit must be 0 or 1
    let allBool := bits.all fun bw => let v := getWire witness bw; v == 0 || v == 1
    -- wire = Σ bits[i] · 2^i (integer arithmetic)
    let reconstructed : UInt32 := Id.run do
      let mut acc : UInt32 := 0
      for i in [:bits.size] do
        let bitVal := getWire witness (bits[i]!)
        acc := acc + (bitVal * (1 <<< i.toUInt32))
      acc
    allBool && getWire witness wire == reconstructed
  | .integerEq wire value =>
    getWire witness wire == value

/-- Check constraint in the GF(2^32) constraint polynomial domain.
    This is what the verifier actually checks via sumcheck. -/
def checkField (c : Constraint) (witness : Array GF32) : GF32 :=
  match c with
  | .and a b cc =>
    -- AND becomes MUL in GF(2^32): a · b + c
    let va := a.evaluate witness
    let vb := b.evaluate witness
    let vc := cc.evaluate witness
    gf32Add (gf32Mul va vb) vc
  | .xor a b cc =>
    -- XOR is addition in GF(2^32): a + b + c
    let va := a.evaluate witness
    let vb := b.evaluate witness
    let vc := cc.evaluate witness
    gf32Add (gf32Add va vb) vc
  | .eq a b =>
    gf32Add (a.evaluate witness) (b.evaluate witness)
  | .fieldMul a b result =>
    gf32Add (gf32Mul (getWire witness a) (getWire witness b))
            (getWire witness result)
  | .assertConst wire value =>
    gf32Add (getWire witness wire) value
  | .boolean wire =>
    -- wire · (1 + wire) = 0 in GF(2^32)
    -- This constrains wire to the roots of x² + x = x(x+1) = 0,
    -- i.e. x = 0 or x = 1 (since 1+1 = 0 in GF(2)).
    -- Wait: in GF(2^32), 1+1 = 0, so x(x+1) = x² + x.
    -- The roots are x=0 and x such that x+1=0, i.e. x=1 (since 1+1=0).
    -- But also any x with x = x² in GF(2^32)... that's x^2 = x, Frobenius.
    -- Actually x² + x = 0 means x(x+1) = 0 means x=0 or x=1 in GF(2^32)
    -- because GF(2^32) is a field (no zero divisors). Correct!
    let v := getWire witness wire
    gf32Add (gf32Mul v v) v  -- v² + v = v(v+1), zero iff v ∈ {0,1}
  | .rangeDecomposed wire bits => Id.run do
    let mut result : GF32 := 0
    for bw in bits do
      let v := getWire witness bw
      result := gf32Add result (gf32Add (gf32Mul v v) v)
    let mut reconstructed : GF32 := 0
    for i in [:bits.size] do
      let bitVal := getWire witness (bits[i]!)
      -- Integer 2^i via bit shift, NOT field x^i via gf32Pow.
      let power : GF32 := (1 : UInt32) <<< i.toUInt32
      reconstructed := gf32Add reconstructed (gf32Mul bitVal power)
    result := gf32Add result (gf32Add (getWire witness wire) reconstructed)
    result
  | .integerEq wire value =>
    gf32Add (getWire witness wire) value

end Constraint

/-- Compiled circuit ready for proving. -/
structure Circuit where
  numWires : Nat
  numPublic : Nat
  constraints : Array Constraint
  deriving Inhabited

namespace Circuit

/-- Check all constraints (integer semantics, prover-side). -/
def check (circ : Circuit) (witness : Array GF32) : Option Nat :=
  if witness.size < circ.numWires then some 0
  else circ.constraints.findIdx? (fun c => !c.check witness)

/-- Check all constraints (field semantics, verifier-side).
    Returns zero iff all satisfied. -/
def checkField (circ : Circuit) (witness : Array GF32) : GF32 :=
  circ.constraints.foldl (fun acc c => gf32Add acc (c.checkField witness)) 0

end Circuit

/-- Circuit builder. -/
structure CircuitBuilder where
  numWires : Nat := 0
  numPublic : Nat := 0
  constraints : Array Constraint := #[]

namespace CircuitBuilder

def addWitness (b : CircuitBuilder) : WireId × CircuitBuilder :=
  (⟨b.numWires⟩, { b with numWires := b.numWires + 1 })

def addPublic (b : CircuitBuilder) : WireId × CircuitBuilder :=
  let (w, b') := b.addWitness
  (w, { b' with numPublic := b'.numPublic + 1 })

def addConstraint (b : CircuitBuilder) (c : Constraint) : CircuitBuilder :=
  { b with constraints := b.constraints.push c }

def assertAnd (b : CircuitBuilder) (a bb c : Operand) : CircuitBuilder :=
  b.addConstraint (.and a bb c)

def assertXor (b : CircuitBuilder) (a bb c : Operand) : CircuitBuilder :=
  b.addConstraint (.xor a bb c)

def assertEqual (b : CircuitBuilder) (a bb : Operand) : CircuitBuilder :=
  b.addConstraint (.eq a bb)

def assertFieldMul (b : CircuitBuilder) (a bb result : WireId) : CircuitBuilder :=
  b.addConstraint (.fieldMul a bb result)

def assertConst (b : CircuitBuilder) (wire : WireId) (value : UInt32) : CircuitBuilder :=
  b.addConstraint (.assertConst wire value)

def assertBoolean (b : CircuitBuilder) (wire : WireId) : CircuitBuilder :=
  b.addConstraint (.boolean wire)

def assertRangeDecomposed (b : CircuitBuilder) (wire : WireId) (numBits : Nat)
    : Array WireId × CircuitBuilder := Id.run do
  let mut builder := b
  let mut bitWires : Array WireId := #[]
  for _ in [:numBits] do
    let (bw, b') := builder.addWitness
    builder := b'
    bitWires := bitWires.push bw
  (bitWires, builder.addConstraint (.rangeDecomposed wire bitWires))

def build (b : CircuitBuilder) : Circuit :=
  { numWires := b.numWires, numPublic := b.numPublic, constraints := b.constraints }

end CircuitBuilder

/-- Witness for a circuit execution. -/
structure Witness where
  values : Array GF32
  numPublic : Nat
  deriving Inhabited

namespace Witness

def new (numWires numPublic : Nat) : Witness :=
  { values := Array.replicate numWires 0, numPublic }

def set (w : Witness) (wire : WireId) (value : UInt32) : Witness :=
  { w with values := w.values.set! wire.idx value }

def get (w : Witness) (wire : WireId) : UInt32 :=
  if wire.idx < w.values.size then w.values[wire.idx]! else 0

def publicInputs (w : Witness) : Array UInt32 :=
  w.values.extract 0 w.numPublic

end Witness

end Jar.Commitment.Circuit
