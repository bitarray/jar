import Jar.Notation
import Jar.Types.Numerics

/-!
# Service Account Types — Gray Paper §9

Service accounts, preimage lookups, and privileged services.
References: `graypaper/text/accounts.tex` eq:serviceaccounts, eq:serviceaccount.
-/

namespace Jar

-- ============================================================================
-- §9 — Service Account (eq:serviceaccount)
-- ============================================================================

/-- 𝔸 : Service account. GP eq (9.3).
    A = ⟨s, p, l, f, c, b, g, m, i, r, a⟩

    Contains code, storage, preimages, and gas configuration. -/
structure ServiceAccount where
  /-- s : Key-value storage. ⟨𝔹→𝔹⟩. -/
  storage : Dict ByteArray ByteArray
  /-- p : Preimage lookup. ⟨ℍ→𝔹⟩. -/
  preimages : Dict Hash ByteArray
  /-- l : Preimage request metadata. ⟨(ℍ, ℕ_L) → ⟦ℕ_T⟧_{:3}⟩. -/
  preimageInfo : Dict (Hash × BlobLength) (Array Timeslot)
  /-- f : Free (gratis) storage allowance. ℕ_B. -/
  gratis : Balance
  /-- c : Service code hash. ℍ. -/
  codeHash : Hash
  /-- b : Account balance. ℕ_B. -/
  balance : Balance
  /-- g : Minimum accumulation gas. ℕ_G. -/
  minAccGas : Gas
  /-- m : Minimum on-transfer (memo) gas. ℕ_G. -/
  minOnTransferGas : Gas
  /-- a_i : Number of storage items. ℕ_I. -/
  itemCount : UInt32 := 0
  /-- a_r : Creation timeslot. ℕ_T. -/
  creationSlot : Timeslot := 0
  /-- a_a : Most recent accumulation timeslot. ℕ_T. -/
  lastAccumulation : Timeslot := 0
  /-- a_p : Parent service ID. ℕ_S. -/
  parentServiceId : Nat := 0
  /-- a_o : Total storage footprint in octets (computed). Preserved from serialized state. -/
  totalFootprint : Nat := 0

-- ============================================================================
-- §9 — Service Accounts State (eq:serviceaccounts)
-- ============================================================================

-- δ ∈ ⟨ℕ_S → 𝔸⟩ : dictionary from service ID to account.
-- Represented as `Dict ServiceId ServiceAccount` in the State.

-- ============================================================================
-- §9.4 — Privileged Services (eq 9.9 equivalent)
-- ============================================================================

/-- χ : Privileged service identifiers. GP §9.4.
    χ = ⟨χ_M, χ_A, χ_V, χ_R, χ_Z⟩ -/
structure PrivilegedServices where
  /-- χ_M : Manager (blessed) service. ℕ_S. -/
  manager : ServiceId
  /-- χ_A : Core assigner services. ⟦ℕ_S⟧_C. -/
  assigners : Array ServiceId
  /-- χ_V : Validator-set designator service. ℕ_S. -/
  designator : ServiceId
  /-- χ_R : Registrar service. ℕ_S. -/
  registrar : ServiceId
  /-- χ_Z : Always-accumulate services with gas limits. ⟨ℕ_S → ℕ_G⟩. -/
  alwaysAccumulate : Dict ServiceId Gas

-- ============================================================================
-- §12 — Deferred Transfer (eq:defxfer)
-- ============================================================================

/-- 𝕏 : Deferred transfer. GP eq (12.3).
    X = ⟨s, d, a, m, g⟩ -/
structure DeferredTransfer where
  /-- s : Source service. ℕ_S. -/
  source : ServiceId
  /-- d : Destination service. ℕ_S. -/
  dest : ServiceId
  /-- a : Amount. ℕ_B. -/
  amount : Balance
  /-- m : Memo. 𝔹_{W_T} (128 bytes). -/
  memo : OctetSeq Jar.W_T
  /-- g : Gas limit for on-transfer. ℕ_G. -/
  gas : Gas

end Jar
