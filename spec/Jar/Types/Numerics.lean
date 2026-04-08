import Jar.Notation
import Jar.Types.Constants

/-!
# Numeric Type Aliases — Gray Paper §3.4, §4.6–4.7

Bounded numeric types used throughout the specification.
References: `graypaper/text/overview.tex` eq:balance, eq:gasregentry, eq:time.
-/

namespace Jar

-- ============================================================================
-- §4.6 — Balances (eq:balance)
-- ============================================================================

/-- ℕ_B ≡ ℕ_{2^64} : Balance values (64-bit unsigned). GP eq (19). -/
abbrev Balance := UInt64

-- ============================================================================
-- §4.7 — Gas and Registers (eq:gasregentry)
-- ============================================================================

/-- ℕ_G ≡ ℕ_{2^64} : Unsigned gas values (64-bit unsigned). GP eq (24). -/
abbrev Gas := UInt64

/-- ℤ_G ≡ ℤ_{-2^63..2^63} : Signed gas values (64-bit signed). GP eq (24). -/
abbrev SignedGas := Int64

/-- ℕ_R ≡ ℕ_{2^64} : PVM register values (64-bit unsigned). GP eq (24). -/
abbrev RegisterValue := UInt64

-- ============================================================================
-- §4.8 — Time (eq:time)
-- ============================================================================

/-- ℕ_T ≡ ℕ_{2^32} : Timeslot index (32-bit unsigned). GP eq (28). -/
abbrev Timeslot := UInt32

-- ============================================================================
-- §9 — Service identifiers (eq:serviceaccounts)
-- ============================================================================

/-- ℕ_S ≡ ℕ_{2^32} : Service identifier (32-bit unsigned). GP §9. -/
abbrev ServiceId := UInt32

-- ============================================================================
-- §3.4 — Blob lengths
-- ============================================================================

/-- ℕ_L ≡ ℕ_{2^32} : Blob length values. GP §3.4. -/
abbrev BlobLength := UInt32

-- ============================================================================
-- Index types (parameterized by JarConfig)
-- ============================================================================

/-- Core index: ℕ_{C}. Bounded by config.C. -/
abbrev CoreIndex [j : JarConfig] := Fin j.config.C

/-- Validator index: ℕ_{V}. Bounded by config.V. -/
abbrev ValidatorIndex [j : JarConfig] := Fin j.config.V

/-- Ticket entry index: ℕ_{N}. Raw Nat — validation enforces bounds. -/
abbrev TicketEntryIndex [JarConfig] := Nat

/-- Epoch slot index: ℕ_{E}. Bounded by config.E. -/
abbrev EpochIndex [j : JarConfig] := Fin j.config.E

-- Inhabited instances for parameterized Fin types
instance instInhabitedCoreIndex [j : JarConfig] : Inhabited (Fin j.config.C) := ⟨⟨0, j.valid.hC⟩⟩
instance instInhabitedValidatorIndex [j : JarConfig] : Inhabited (Fin j.config.V) := ⟨⟨0, j.valid.hV⟩⟩
instance instInhabitedEpochIndex [j : JarConfig] : Inhabited (Fin j.config.E) := ⟨⟨0, j.valid.hE⟩⟩

end Jar
