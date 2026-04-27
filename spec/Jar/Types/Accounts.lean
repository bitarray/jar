import Jar.Notation
import Jar.Types.Numerics
import Jar.Codec
import Lean.Data.Json
import Lean.Data.Json.FromToJson

/-!
# Service Account Types — Gray Paper §9

Service accounts, preimage lookups, and privileged services.
References: `graypaper/text/accounts.tex` eq:serviceaccounts, eq:serviceaccount.

## Economic Model

The protocol supports two economic models via the `EconModel` typeclass (defined in Config.lean):
- **BalanceEcon** (gp072 variants): token-based storage rent with balance/gratis fields.
- **QuotaEcon** (jar1 coinless): quota-based storage limits set by a privileged service.

Similarly, deferred transfers are parameterized:
- **BalanceTransfer** (gp072): carries a token amount.
- **QuotaTransfer** (jar1): pure message-passing, no amount field.

Encoding/serialization/JSON methods are NOT in the typeclass — they live in their
respective files (Accumulation.lean, StateSerialization.lean, Json.lean) where the
necessary imports (Codec, Lean.Data.Json) are available.

See `docs/ideas/coinless-storage-quota.md` for the full design rationale.
-/

namespace Jar

-- ============================================================================
-- Economic Model Types
-- ============================================================================

/-- Balance-based economic model (gp072 variants).
    Services must hold sufficient balance to cover storage costs.
    GP §9, eq (9.8): a_t = B_S + B_I × items + B_L × bytes - min(f, minBal). -/
structure BalanceEcon where
  /-- b : Account balance. ℕ_B. -/
  balance : Balance := 0
  /-- f : Free (gratis) storage allowance. ℕ_B. -/
  gratis : Balance := 0
  deriving BEq, Inhabited, Repr

/-- Quota-based economic model (jar1 coinless).
    Storage limits set by a privileged quota service (χ_Q). -/
structure QuotaEcon where
  /-- q_i : Maximum storage items allowed. -/
  quotaItems : UInt64 := 0
  /-- q_o : Maximum storage bytes allowed. -/
  quotaBytes : UInt64 := 0
  deriving BEq, Inhabited, Repr

/-- Balance-based transfer payload (gp072 variants).
    Carries a token amount to be debited from sender and credited to receiver. -/
structure BalanceTransfer where
  /-- a : Transfer amount. ℕ_B. -/
  amount : Balance := 0
  deriving BEq, Inhabited, Repr

/-- Quota-based transfer payload (jar1 coinless).
    Pure message-passing — no token amount. -/
structure QuotaTransfer where
  deriving BEq, Inhabited, Repr

-- ============================================================================
-- EconModel Instances
-- ============================================================================

/-- EconModel instance for BalanceEcon: balance-based service accounting. -/
instance : EconModel BalanceEcon BalanceTransfer where
  canAffordStorage e items bytes bI bL bS :=
    let minBal := bS + bI * items + bL * bytes
    let threshold := minBal - min e.gratis.toNat minBal
    threshold ≤ e.balance.toNat

  debitForNewService e newItems newBytes newGratis callerItems callerBytes bI bL bS :=
    -- Compute threshold for the NEW account (using newGratis, NOT caller's gratis)
    let newMinBal := bS + bI * newItems + bL * newBytes
    let newThreshold := newMinBal - min newGratis.toNat newMinBal
    -- Compute caller's own threshold (using caller's gratis from e)
    let callerMinBal := bS + bI * callerItems + bL * callerBytes
    let callerThreshold := callerMinBal - min e.gratis.toNat callerMinBal
    -- After paying newThreshold, caller must still afford own threshold
    let balanceAfter := if e.balance.toNat ≥ newThreshold then e.balance.toNat - newThreshold else 0
    if balanceAfter < callerThreshold then none
    else some { e with balance := e.balance - UInt64.ofNat newThreshold }

  newServiceEcon items bytes gratis bI bL bS :=
    let minBal := bS + bI * items + bL * bytes
    let threshold := minBal - min gratis.toNat minBal
    { balance := UInt64.ofNat threshold, gratis := gratis }

  creditTransfer e t := { e with balance := e.balance + t.amount }

  debitTransfer e amount :=
    if e.balance ≥ amount
    then some { e with balance := e.balance - amount }
    else none

  absorbEjected e ejected := { e with balance := e.balance + ejected.balance }

  setQuota _e _maxItems _maxBytes := none  -- Not supported for balance model

  makeTransferPayload amountReg := { amount := amountReg }

  encodeTransferAmount t := Codec.encodeFixedNat 8 t.amount.toNat

  encodeInfo e items bytes bI bL bS :=
    let minBal := bS + bI * items + bL * bytes
    let threshold := minBal - min e.gratis.toNat minBal
    Codec.encodeFixedNat 8 e.balance.toNat
      ++ Codec.encodeFixedNat 8 threshold
      ++ Codec.encodeFixedNat 8 e.gratis.toNat

  serializeEcon e :=
    Codec.encodeFixedNat 8 e.balance.toNat
      ++ Codec.encodeFixedNat 8 e.gratis.toNat

  deserializeEcon data offset :=
    if offset + 16 ≤ data.size then
      let balance := Codec.decodeFixedNat (data.extract offset (offset + 8))
      let gratis := Codec.decodeFixedNat (data.extract (offset + 8) (offset + 16))
      some ({ balance := UInt64.ofNat balance, gratis := UInt64.ofNat gratis }, offset + 16)
    else none

  econToJson e := [("balance", Lean.Json.num e.balance.toNat), ("gratis", Lean.Json.num e.gratis.toNat)]

  econFromJson? j := do
    let balJson ← j.getObjVal? "balance"
    let balNat ← balJson.getNat?
    let balance : Balance := balNat.toUInt64
    -- Handle legacy "deposit_offset" field name alongside "gratis"
    let gratis : Balance := match j.getObjVal? "gratis" with
      | .ok v => match v.getNat? with | .ok n => n.toUInt64 | .error _ => 0
      | .error _ => match j.getObjVal? "deposit_offset" with
        | .ok v => match v.getNat? with | .ok n => n.toUInt64 | .error _ => 0
        | .error _ => 0
    return { balance, gratis }

  xferToJson t := [("amount", Lean.Json.num t.amount.toNat)]

  xferFromJson? j := do
    let amtJson ← j.getObjVal? "amount"
    let amtNat ← amtJson.getNat?
    return { amount := amtNat.toUInt64 }

/-- EconModel instance for QuotaEcon: quota-based service accounting (coinless model). -/
instance : EconModel QuotaEcon QuotaTransfer where
  canAffordStorage e items bytes _bI _bL _bS :=
    items ≤ e.quotaItems.toNat && bytes ≤ e.quotaBytes.toNat

  debitForNewService e _newItems _newBytes _newGratis _callerItems _callerBytes _bI _bL _bS := some e  -- No debit in coinless

  newServiceEcon _items _bytes _gratis _bI _bL _bS :=
    { quotaItems := 0, quotaBytes := 0 }  -- Quota service must grant later

  creditTransfer e _t := e  -- No balance to credit

  debitTransfer e _amount := some e  -- No balance to debit

  absorbEjected e _ejected := e  -- Nothing to absorb

  setQuota _e maxItems maxBytes :=
    some { quotaItems := maxItems, quotaBytes := maxBytes }

  makeTransferPayload _amountReg := {}

  encodeTransferAmount _t := Codec.encodeFixedNat 8 0

  encodeInfo e _items _bytes _bI _bL _bS :=
    Codec.encodeFixedNat 8 e.quotaItems.toNat
      ++ Codec.encodeFixedNat 8 e.quotaBytes.toNat
      ++ Codec.encodeFixedNat 8 0  -- Padding (replaces gratis position)

  serializeEcon e :=
    Codec.encodeFixedNat 8 e.quotaItems.toNat
      ++ Codec.encodeFixedNat 8 e.quotaBytes.toNat

  deserializeEcon data offset :=
    if offset + 16 ≤ data.size then
      let quotaItems := Codec.decodeFixedNat (data.extract offset (offset + 8))
      let quotaBytes := Codec.decodeFixedNat (data.extract (offset + 8) (offset + 16))
      some ({ quotaItems := UInt64.ofNat quotaItems, quotaBytes := UInt64.ofNat quotaBytes }, offset + 16)
    else none

  econToJson e := [("quota_items", Lean.Json.num e.quotaItems.toNat), ("quota_bytes", Lean.Json.num e.quotaBytes.toNat)]

  econFromJson? j := do
    let qiJson ← j.getObjVal? "quota_items"
    let qiNat ← qiJson.getNat?
    let quotaItems : UInt64 := qiNat.toUInt64
    let qbJson ← j.getObjVal? "quota_bytes"
    let qbNat ← qbJson.getNat?
    let quotaBytes : UInt64 := qbNat.toUInt64
    return { quotaItems, quotaBytes }

  xferToJson _t := []

  xferFromJson? _j := return {}

-- ============================================================================
-- §9 — Service Account (eq:serviceaccount)
-- ============================================================================

/-- 𝔸 : Service account. GP eq (9.3).
    A = ⟨s, p, l, econ, c, g, m, i, r, a⟩

    Contains code, storage, preimages, and gas configuration.
    The economic model (balance vs quota) is determined by the variant. -/
structure ServiceAccount [JarConfig] where
  /-- s : Key-value storage. ⟨𝔹→𝔹⟩. -/
  storage : Dict ByteArray ByteArray
  /-- p : Preimage lookup. ⟨ℍ→𝔹⟩. -/
  preimages : Dict Hash ByteArray
  /-- l : Preimage request metadata. ⟨(ℍ, ℕ_L) → ⟦ℕ_T⟧_{:3}⟩. -/
  preimageInfo : Dict (Hash × BlobLength) (Array Timeslot)
  /-- Economic model fields (balance+gratis for gp072, quotaItems+quotaBytes for jar1). -/
  econ : JarConfig.EconType
  /-- c : Service code hash. ℍ. -/
  codeHash : Hash
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
    χ = ⟨χ_M, χ_A, χ_V, χ_R, χ_Z, χ_Q⟩ -/
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
  /-- χ_Q : Quota manager service (jar1 coinless). ℕ_S. -/
  quotaService : ServiceId := 0

-- ============================================================================
-- §12 — Deferred Transfer (eq:defxfer)
-- ============================================================================

/-- 𝕏 : Deferred transfer. GP eq (12.3).
    X = ⟨s, d, payload, m, g⟩
    The economic payload (token amount vs nothing) is determined by the variant. -/
structure DeferredTransfer [JarConfig] where
  /-- s : Source service. ℕ_S. -/
  source : ServiceId
  /-- d : Destination service. ℕ_S. -/
  dest : ServiceId
  /-- Economic payload (amount for gp072, unit for jar1). -/
  payload : JarConfig.TransferType
  /-- m : Memo. 𝔹_{W_T} (128 bytes). -/
  memo : OctetSeq Jar.W_T
  /-- g : Gas limit for on-transfer. ℕ_G. -/
  gas : Gas

end Jar
