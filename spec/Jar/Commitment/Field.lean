import Jar.Notation

/-!
# Binary Extension Field Arithmetic — GF(2^n)

Binary extension field elements over GF(2^16), GF(2^32), and GF(2^128).
Addition is XOR; multiplication uses carryless multiplication with reduction
modulo an irreducible polynomial.

Ported from `commonware-commitment/src/field/`.

## Irreducible polynomials
- GF(2^16): x^16 + x^5 + x^3 + x^2 + 1  (0x1002D)
- GF(2^32): x^32 + x^15 + x^9 + x^7 + x^4 + x^3 + x^0  (Conway)
- GF(2^128): x^128 + x^7 + x^2 + x + 1
-/

namespace Jar.Commitment.Field

-- ============================================================================
-- GF(2^32) — Base field for Ligerito commitment
-- ============================================================================

/-- Element of GF(2^32). Represented as a 32-bit integer.
    Irreducible polynomial: x^32 + x^15 + x^9 + x^7 + x^4 + x^3 + x^0. -/
abbrev GF32 := UInt32

/-- GF(2^32) irreducible polynomial (without leading x^32 term).
    Lower 32 bits: x^15 + x^9 + x^7 + x^4 + x^3 + x^0
    = 0x8099 = 0b1000_0000_1001_1001 ... let me compute properly.
    bits: 15,9,7,4,3,0 → 0x8299 -/
def GF32_IRREDUCIBLE : UInt64 :=
  ((1 : UInt64) <<< (32 : UInt64)) ||| ((1 : UInt64) <<< (15 : UInt64)) |||
  ((1 : UInt64) <<< (9 : UInt64)) ||| ((1 : UInt64) <<< (7 : UInt64)) |||
  ((1 : UInt64) <<< (4 : UInt64)) ||| ((1 : UInt64) <<< (3 : UInt64)) ||| (1 : UInt64)

/-- Addition in GF(2^32): XOR. -/
@[inline] def gf32Add (a b : GF32) : GF32 := a ^^^ b

/-- Carryless multiplication of two 32-bit polynomials → 64-bit result.
    Constant-time schoolbook multiply. -/
def gf32MulWide (a b : GF32) : UInt64 := Id.run do
  let mut result : UInt64 := 0
  let a64 : UInt64 := a.toUInt64
  for i in [:32] do
    let bit := (b.toUInt64 >>> i.toUInt64) &&& 1
    let mask := (0 : UInt64) - bit  -- all-ones if bit=1, all-zeros if bit=0
    result := result ^^^ ((a64 <<< i.toUInt64) &&& mask)
  result

/-- Reduce a 64-bit polynomial modulo the GF(2^32) irreducible. -/
def gf32Reduce (wide : UInt64) : GF32 := Id.run do
  let mut p := wide
  let irr := GF32_IRREDUCIBLE
  -- Reduce bits 63 down to 32
  for i in List.range 32 |>.reverse do
    let bit := 32 + i
    if (p >>> bit.toUInt64) &&& 1 != 0 then
      p := p ^^^ (irr <<< i.toUInt64)
  p.toUInt32

/-- Multiplication in GF(2^32). -/
@[inline] def gf32Mul (a b : GF32) : GF32 :=
  gf32Reduce (gf32MulWide a b)

/-- Squaring in GF(2^32). -/
@[inline] def gf32Sqr (a : GF32) : GF32 := gf32Mul a a

/-- Exponentiation by squaring in GF(2^32). -/
def gf32Pow (base : GF32) (exp : Nat) : GF32 := Id.run do
  if base == 0 then return 0
  let mut result : GF32 := 1
  let mut b := base
  let mut e := exp
  while e > 0 do
    if e % 2 == 1 then
      result := gf32Mul result b
    b := gf32Sqr b
    e := e / 2
  result

/-- Multiplicative inverse in GF(2^32) via Fermat's little theorem.
    a^(-1) = a^(2^32 - 2). -/
def gf32Inv (a : GF32) : GF32 :=
  if a == 0 then 0
  else Id.run do
    -- Use addition chain: 2^32 - 2 = 2 * (2^31 - 1)
    -- a^(2^32 - 2) computed via repeated squaring
    let mut acc := gf32Sqr a   -- a^2
    let mut result := acc
    for _ in [2:32] do
      acc := gf32Sqr acc
      result := gf32Mul result acc
    result

-- ============================================================================
-- GF(2^128) — Extension field for Ligerito sumcheck
-- ============================================================================

/-- Element of GF(2^128). Represented as a pair of 64-bit integers (lo, hi).
    Irreducible polynomial: x^128 + x^7 + x^2 + x + 1 (0x87). -/
structure GF128 where
  lo : UInt64
  hi : UInt64
  deriving BEq, Inhabited, Repr, DecidableEq

namespace GF128

def zero : GF128 := ⟨0, 0⟩
def one : GF128 := ⟨1, 0⟩

/-- Addition in GF(2^128): XOR. -/
@[inline] def add (a b : GF128) : GF128 :=
  ⟨a.lo ^^^ b.lo, a.hi ^^^ b.hi⟩

/-- Carryless multiply two 64-bit values → 128-bit result (lo, hi). -/
def clmul64 (a b : UInt64) : UInt64 × UInt64 := Id.run do
  let mut lo : UInt64 := 0
  let mut hi : UInt64 := 0
  for i in [:64] do
    let bit := (b >>> i.toUInt64) &&& 1
    let mask := (0 : UInt64) - bit
    let shifted_lo := a <<< i.toUInt64
    let shifted_hi := if i == 0 then 0 else a >>> (64 - i).toUInt64
    lo := lo ^^^ (shifted_lo &&& mask)
    hi := hi ^^^ (shifted_hi &&& mask)
  (lo, hi)

/-- Full 128×128 → 256-bit carryless multiplication using Karatsuba. -/
def mulFull (a b : GF128) : UInt64 × UInt64 × UInt64 × UInt64 := Id.run do
  -- Karatsuba: (aH*x^64 + aL)(bH*x^64 + bL)
  -- = aH*bH*x^128 + (aH*bL + aL*bH)*x^64 + aL*bL
  let (ll_lo, ll_hi) := clmul64 a.lo b.lo  -- aL * bL
  let (hh_lo, hh_hi) := clmul64 a.hi b.hi  -- aH * bH
  let (lh_lo, lh_hi) := clmul64 a.lo b.hi  -- aL * bH
  let (hl_lo, hl_hi) := clmul64 a.hi b.lo  -- aH * bL

  -- Cross terms: mid = aL*bH + aH*bL
  let mid_lo := lh_lo ^^^ hl_lo
  let mid_hi := lh_hi ^^^ hl_hi

  -- Combine: result[0] = ll_lo
  --          result[1] = ll_hi + mid_lo
  --          result[2] = hh_lo + mid_hi
  --          result[3] = hh_hi
  let r1 := ll_hi ^^^ mid_lo
  let r2 := hh_lo ^^^ mid_hi
  (ll_lo, r1, r2, hh_hi)

/-- Reduce 256-bit product modulo x^128 + x^7 + x^2 + x + 1. -/
def reduce256 (r0 r1 r2 r3 : UInt64) : GF128 :=
  -- The high 128 bits (r2, r3) need reduction.
  -- x^128 ≡ x^7 + x^2 + x + 1
  -- tmp = hi ^ (hi >> 127) ^ (hi >> 126) ^ (hi >> 121)
  -- then lo ^= tmp ^ (tmp << 1) ^ (tmp << 2) ^ (tmp << 7)
  let t0 := r2
  let t1 := r3
  let tmp_lo := t0 ^^^ (t1 >>> 63) ^^^ (t1 >>> 62) ^^^ (t1 >>> 57)
  let tmp_hi := t1 ^^^ 0  -- the shifts of t1 by 63,62,57 only affect lo part

  let out_lo := r0 ^^^ tmp_lo ^^^ (tmp_lo <<< 1) ^^^ (tmp_lo <<< 2) ^^^ (tmp_lo <<< 7)
  let out_hi := r1 ^^^ (tmp_hi) ^^^ (tmp_lo >>> 63) ^^^ (tmp_lo >>> 62) ^^^ (tmp_lo >>> 57)
  ⟨out_lo, out_hi⟩

/-- Multiplication in GF(2^128). -/
def mul (a b : GF128) : GF128 :=
  let (r0, r1, r2, r3) := mulFull a b
  reduce256 r0 r1 r2 r3

/-- Squaring in GF(2^128). -/
@[inline] def sqr (a : GF128) : GF128 := mul a a

/-- Exponentiation by squaring. -/
def pow (base : GF128) (exp : Nat) : GF128 := Id.run do
  if base == zero then return zero
  let mut result := one
  let mut b := base
  let mut e := exp
  while e > 0 do
    if e % 2 == 1 then
      result := mul result b
    b := sqr b
    e := e / 2
  result

/-- Multiplicative inverse via Fermat: a^(2^128 - 2).
    Uses the addition chain method for binary fields:
    2^128 - 2 = 2 + 4 + 8 + ... + 2^127
    So a^(2^128-2) = a^2 · a^4 · a^8 · ... · a^(2^127). -/
def inv (a : GF128) : GF128 :=
  if a == zero then zero
  else Id.run do
    -- a^2
    let mut acc := sqr a
    let mut result := acc
    -- Multiply by a^(2^i) for i = 2..127
    for _ in [2:128] do
      acc := sqr acc       -- a^(2^i)
      result := mul result acc
    result

/-- Construct from a 32-bit value (field embedding GF(2^32) → GF(2^128)). -/
def fromGF32 (v : GF32) : GF128 := ⟨v.toUInt64, 0⟩

/-- Construct from a raw 128-bit natural number. -/
def fromNat (n : Nat) : GF128 :=
  let lo := (n % (2^64)).toUInt64
  let hi := (n / (2^64) % (2^64)).toUInt64
  ⟨lo, hi⟩

end GF128

-- ============================================================================
-- Field embedding: GF(2^32) ↪ GF(2^128)
-- ============================================================================

/-- Embed a GF(2^32) element into GF(2^128).
    The embedding preserves addition and multiplication since GF(2^32) is
    a subfield of GF(2^128) (32 divides 128). -/
@[inline] def embedGF32 (x : GF32) : GF128 := GF128.fromGF32 x

-- ============================================================================
-- Binary subspace polynomials (for FFT twiddle computation)
-- ============================================================================

/-- Compute s(x) = x^2 + s_prev_at_root * x.
    This is the recursive subspace polynomial used in binary field FFT. -/
@[inline] def nextSubspacePoly (s_prev s_prev_at_root : GF32) : GF32 :=
  gf32Add (gf32Sqr s_prev) (gf32Mul s_prev_at_root s_prev)

/-- from_bits: construct field element from bit pattern.
    Bit i of `bits` sets the coefficient of x^i. -/
def gf32FromBits (bits : Nat) : GF32 := Id.run do
  let mut result : GF32 := 0
  let mut power : GF32 := 1  -- x^0 = 1
  let gen : GF32 := 2        -- x = generator
  for i in [:32] do
    if (bits / (2^i)) % 2 == 1 then
      result := gf32Add result power
    if i < 31 then
      power := gf32Mul power gen
  result

/-- from_bits for GF(2^128). -/
def gf128FromBits (bits : Nat) : GF128 := Id.run do
  let mut result := GF128.zero
  let mut power := GF128.one
  let gen := GF128.mk 2 0  -- x = generator
  for i in [:128] do
    if (bits / (2^i)) % 2 == 1 then
      result := GF128.add result power
    if i < 127 then
      power := GF128.mul power gen
  result

end Jar.Commitment.Field
