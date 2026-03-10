/-!
# Notation — Gray Paper §3

Foundational type definitions and notation to approximate
the Gray Paper's mathematical conventions.

## References
- Gray Paper v0.7.2, Section 3: Notational Conventions
- `graypaper/text/notation.tex`
-/

-- ============================================================================
-- §3.2 — Functions and Operators
-- ============================================================================

/-- Substitute-if-nothing (𝒰). GP eq (2).
    Returns the first non-none argument, or none if all are none. -/
def substituteIfNone : List (Option α) → Option α
  | [] => none
  | (some x) :: _ => some x
  | none :: rest => substituteIfNone rest

-- ============================================================================
-- §3.3 — Sets
-- ============================================================================

/-- GP uses ∅ for "no specific value" (we use `Option.none`)
    and ∇ for "unexpected failure / invalid". We model ∇ explicitly. -/
inductive Exceptional (α : Type) where
  | ok    : α → Exceptional α
  | none  : Exceptional α       -- GP: ∅
  | error : Exceptional α       -- GP: ∇

-- GP: `A?` ≡ A ∪ {∅}. We use Lean's built-in `Option α` throughout.

-- ============================================================================
-- §3.4 — Numbers
-- ============================================================================

-- ℕ_n : naturals less than n → `Fin n`
-- ℤ_{a..b} : integers in [a, b)

/-- ℤ_{a..b} : integers in [a, b). GP §3.4. -/
def IntRange (a b : Int) : Type := { x : Int // a ≤ x ∧ x < b }

-- ============================================================================
-- §3.5 — Dictionaries
-- ============================================================================

/-- A dictionary ⟨K→V⟩ : partial mapping with enumerable key-value pairs.
    GP §3.5. Represented as sorted association list with unique keys. -/
structure Dict (K : Type) (V : Type) [BEq K] where
  entries : List (K × V)

namespace Dict

variable {K V : Type} [BEq K]

def empty : Dict K V := ⟨[]⟩

/-- Lookup: d[k]. GP §3.5. -/
def lookup (d : Dict K V) (k : K) : Option V :=
  d.entries.lookup k

/-- Domain: 𝒦(d). GP §3.5. -/
def keys (d : Dict K V) : List K :=
  d.entries.map Prod.fst

/-- Range: 𝒱(d). GP §3.5. -/
def values (d : Dict K V) : List V :=
  d.entries.map Prod.snd

/-- Insert or update a key-value pair. -/
def insert (d : Dict K V) (k : K) (v : V) : Dict K V :=
  ⟨(k, v) :: d.entries.filter (fun p => !(p.1 == k))⟩

/-- Dictionary subtraction: d ∖ s. GP §3.5. -/
def subtract (d : Dict K V) (ks : List K) : Dict K V :=
  ⟨d.entries.filter (fun p => !ks.any (· == p.1))⟩

/-- Dictionary union with right-bias: d ∪ e. GP §3.5. -/
def union (d e : Dict K V) : Dict K V :=
  let eKeys := e.keys
  ⟨(d.entries.filter (fun p => !eKeys.any (· == p.1))) ++ e.entries⟩

end Dict

-- ============================================================================
-- §3.6 — Tuples
-- ============================================================================

-- GP tuples ⟨a ∈ ℕ, b ∈ ℕ⟩ are represented as Lean `structure`s.
-- Field access t_a is written t.a in Lean.

-- ============================================================================
-- §3.7 — Sequences
-- ============================================================================

-- ⟦T⟧    : sequences of any length   → `Array T` or `List T`
-- ⟦T⟧_n  : sequences of exactly n    → `Fin n → T` or `Vector T n`
-- ⟦T⟧_{:n}: at most n elements       → `{ s : Array T // s.size ≤ n }`
-- ⟦T⟧_{n:}: at least n elements      → `{ s : Array T // s.size ≥ n }`

-- Sequence concatenation ⌢ is `Array.append` (++)
-- Element append ⊞ i ≡ x ++ #[i]

/-- Modular subscript: s[i]↻ ≡ s[i % |s|]. GP §3.7. -/
def Array.cyclicGet (s : Array α) (i : Nat) (h : s.size > 0) : α :=
  s[i % s.size]'(Nat.mod_lt _ h)

/-- First n elements: →s^n. GP §3.7.2. -/
abbrev Array.firstN (s : Array α) (n : Nat) : Array α := s.extract 0 n

/-- Last n elements: ←s^n. GP §3.7.2. -/
def Array.lastN (s : Array α) (n : Nat) : Array α :=
  s.extract (s.size - n) s.size

-- ============================================================================
-- §3.7.3 — Boolean values and Bitstrings
-- ============================================================================

-- 𝕓_s = ⟦{⊥, ⊤}⟧_s : Boolean strings of length s
abbrev Bitstring (s : Nat) := { v : Array Bool // v.size = s }

-- ============================================================================
-- §3.7.4 — Octets and Blobs
-- ============================================================================

-- 𝔹 : octet strings of arbitrary length
abbrev Blob := ByteArray

/-- 𝔹_n : octet strings of exactly n bytes. GP §3.7.4. -/
structure OctetSeq (n : Nat) where
  data : ByteArray
  size_eq : data.size = n

instance : BEq ByteArray where
  beq a b := a.data == b.data

instance (n : Nat) : BEq (OctetSeq n) where
  beq a b := a.data == b.data

instance (n : Nat) : Inhabited (OctetSeq n) where
  default := ⟨⟨Array.mkArray n 0⟩, by simp [ByteArray.size, Array.size_mkArray]⟩

-- ============================================================================
-- §3.8 — Cryptographic types (algorithms in Jar.Crypto)
-- ============================================================================

/-- ℍ ≡ 𝔹_32 : 256-bit hash values. GP §3.8.1. -/
abbrev Hash := OctetSeq 32

/-- ℍ_0 : the zero hash, [0]_32. GP §3.8.1. -/
def Hash.zero : Hash := default

-- Signing key types. GP §3.8.2.
abbrev Ed25519PublicKey       := OctetSeq 32   -- H̄ ⊂ 𝔹_32
abbrev BandersnatchPublicKey  := OctetSeq 32   -- H̃ ⊂ 𝔹_32
abbrev BlsPublicKey           := OctetSeq 144  -- B^BLS ⊂ 𝔹_144
abbrev BandersnatchRingRoot   := OctetSeq 144  -- B° ⊂ 𝔹_144

-- Signature types. GP §3.8.2.
abbrev Ed25519Signature           := OctetSeq 64   -- V̄_k⟨m⟩ ⊂ 𝔹_64
abbrev BandersnatchSignature      := OctetSeq 96   -- Ṽ_k^m⟨x⟩ ⊂ 𝔹_96
abbrev BandersnatchRingVrfProof   := OctetSeq 784  -- V°_r^m⟨x⟩ ⊂ 𝔹_784
abbrev BlsSignature               := OctetSeq 48
