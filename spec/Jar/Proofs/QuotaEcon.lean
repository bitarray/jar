import Jar.Types.Accounts
import Jar.Proofs.Codec

/-!
# QuotaEcon Proofs — jar1 coinless economic model

Properties of the `EconModel QuotaEcon QuotaTransfer` instance.
These prove the key semantic property: the coinless model is a no-op
for economic operations (debit, credit, absorb all preserve state).
-/

namespace Jar.Proofs

-- ============================================================================
-- Identity / no-op properties (the core semantic guarantee of coinless)
-- ============================================================================

/-- Service creation never fails in coinless mode — no balance to debit. -/
theorem quotaEcon_debitForNewService_always_some (e : QuotaEcon)
    (ni nb : Nat) (ng : UInt64) (ci cb bI bL bS : Nat) :
    @EconModel.debitForNewService QuotaEcon QuotaTransfer _ e ni nb ng ci cb bI bL bS = some e := by
  rfl

/-- Incoming transfers don't change quota state — no balance to credit. -/
theorem quotaEcon_creditTransfer_id (e : QuotaEcon) (t : QuotaTransfer) :
    @EconModel.creditTransfer QuotaEcon QuotaTransfer _ e t = e := by
  rfl

/-- Outgoing transfers always succeed in coinless mode — no balance to check. -/
theorem quotaEcon_debitTransfer_always_some (e : QuotaEcon) (amount : UInt64) :
    @EconModel.debitTransfer QuotaEcon QuotaTransfer _ e amount = some e := by
  rfl

/-- Absorbing ejected service state is identity — nothing to absorb. -/
theorem quotaEcon_absorbEjected_id (e ejected : QuotaEcon) :
    @EconModel.absorbEjected QuotaEcon QuotaTransfer _ e ejected = e := by
  rfl

/-- setQuota always succeeds, returning the new quota values.
    This means the set_quota hostcall never hits the RESULT_WHAT branch
    from "EconModel doesn't support set_quota" when in jar1 mode. -/
theorem quotaEcon_setQuota_always_some (e : QuotaEcon) (mi mb : UInt64) :
    @EconModel.setQuota QuotaEcon QuotaTransfer _ e mi mb
    = some { quotaItems := mi, quotaBytes := mb } := by
  rfl

/-- setQuota never returns none (corollary of always_some). -/
theorem quotaEcon_setQuota_never_none (e : QuotaEcon) (mi mb : UInt64) :
    @EconModel.setQuota QuotaEcon QuotaTransfer _ e mi mb ≠ none := by
  simp [quotaEcon_setQuota_always_some]

/-- setQuota is input-independent: the result depends only on (mi, mb), not on e.
    This is the "const" property — setQuota unconditionally overwrites quotas. -/
theorem quotaEcon_setQuota_const (e e' : QuotaEcon) (mi mb : UInt64) :
    @EconModel.setQuota QuotaEcon QuotaTransfer _ e mi mb
    = @EconModel.setQuota QuotaEcon QuotaTransfer _ e' mi mb := by
  rfl

/-- setQuota is idempotent: applying it to the result of setQuota with the same
    arguments produces the same output. -/
theorem quotaEcon_setQuota_idempotent (e : QuotaEcon) (mi mb : UInt64) :
    @EconModel.setQuota QuotaEcon QuotaTransfer _
      { quotaItems := mi, quotaBytes := mb } mi mb
    = @EconModel.setQuota QuotaEcon QuotaTransfer _ e mi mb := by
  rfl

-- ============================================================================
-- canAffordStorage monotonicity
-- ============================================================================

/-- canAffordStorage monotonicity: if storage is affordable under quota e1,
    and e2 has at least as large quotas, then it's affordable under e2.
    This is the key safety property — increasing quotas never revokes
    previously affordable storage. -/
theorem quotaEcon_canAffordStorage_mono
    (e1 e2 : QuotaEcon) (items bytes bI bL bS : Nat)
    (hItems : e1.quotaItems.toNat ≤ e2.quotaItems.toNat)
    (hBytes : e1.quotaBytes.toNat ≤ e2.quotaBytes.toNat)
    (h : @EconModel.canAffordStorage QuotaEcon QuotaTransfer _ e1 items bytes bI bL bS = true) :
    @EconModel.canAffordStorage QuotaEcon QuotaTransfer _ e2 items bytes bI bL bS = true := by
  simp only [EconModel.canAffordStorage, Bool.and_eq_true, decide_eq_true_eq] at h ⊢
  exact ⟨Nat.le_trans h.1 hItems, Nat.le_trans h.2 hBytes⟩

-- ============================================================================
-- canAffordStorage preservation under all operations
-- ============================================================================

/-- creditTransfer preserves canAffordStorage (trivially, since creditTransfer is identity). -/
theorem quotaEcon_creditTransfer_preserves_canAfford
    (e : QuotaEcon) (t : QuotaTransfer)
    (items bytes bI bL bS : Nat)
    (h : @EconModel.canAffordStorage QuotaEcon QuotaTransfer _ e items bytes bI bL bS = true) :
    @EconModel.canAffordStorage QuotaEcon QuotaTransfer _
      (@EconModel.creditTransfer QuotaEcon QuotaTransfer _ e t) items bytes bI bL bS = true := by
  rwa [quotaEcon_creditTransfer_id]

/-- debitTransfer preserves canAffordStorage (trivially, since debitTransfer always returns the input). -/
theorem quotaEcon_debitTransfer_preserves_canAfford
    (e e' : QuotaEcon) (amount : UInt64)
    (items bytes bI bL bS : Nat)
    (hDebit : @EconModel.debitTransfer QuotaEcon QuotaTransfer _ e amount = some e')
    (h : @EconModel.canAffordStorage QuotaEcon QuotaTransfer _ e items bytes bI bL bS = true) :
    @EconModel.canAffordStorage QuotaEcon QuotaTransfer _ e' items bytes bI bL bS = true := by
  have : e = e' := by simpa [EconModel.debitTransfer] using hDebit
  rwa [← this]

/-- absorbEjected preserves canAffordStorage (trivially, since absorbEjected is identity). -/
theorem quotaEcon_absorbEjected_preserves_canAfford
    (e ejected : QuotaEcon)
    (items bytes bI bL bS : Nat)
    (h : @EconModel.canAffordStorage QuotaEcon QuotaTransfer _ e items bytes bI bL bS = true) :
    @EconModel.canAffordStorage QuotaEcon QuotaTransfer _
      (@EconModel.absorbEjected QuotaEcon QuotaTransfer _ e ejected) items bytes bI bL bS = true := by
  rwa [quotaEcon_absorbEjected_id]

/-- debitForNewService preserves canAffordStorage (trivially, since debitForNewService always returns the input). -/
theorem quotaEcon_debitForNewService_preserves_canAfford
    (e e' : QuotaEcon) (ni nb : Nat) (ng : UInt64) (ci cb bI bL bS : Nat)
    (items bytes : Nat)
    (hDebit : @EconModel.debitForNewService QuotaEcon QuotaTransfer _ e ni nb ng ci cb bI bL bS = some e')
    (h : @EconModel.canAffordStorage QuotaEcon QuotaTransfer _ e items bytes bI bL bS = true) :
    @EconModel.canAffordStorage QuotaEcon QuotaTransfer _ e' items bytes bI bL bS = true := by
  have : e = e' := by simpa [EconModel.debitForNewService] using hDebit
  rwa [← this]

-- ============================================================================
-- newServiceEcon properties
-- ============================================================================

/-- A new coinless service starts with zero quotas. -/
theorem quotaEcon_newServiceEcon_zero (items bytes bI bL bS : Nat) (gratis : UInt64) :
    @EconModel.newServiceEcon QuotaEcon QuotaTransfer _ items bytes gratis bI bL bS
    = { quotaItems := 0, quotaBytes := 0 } := by
  rfl

/-- A new coinless service cannot afford any items (quota is zero). -/
theorem quotaEcon_newServiceEcon_cannot_afford
    (items bytes bI bL bS : Nat) (gratis : UInt64) (hItems : items > 0) :
    @EconModel.canAffordStorage QuotaEcon QuotaTransfer _
      (@EconModel.newServiceEcon QuotaEcon QuotaTransfer _ items bytes gratis bI bL bS)
      items bytes bI bL bS = false := by
  simp only [EconModel.newServiceEcon, EconModel.canAffordStorage]
  simp only [UInt64.toNat_zero, Nat.not_le.mpr hItems, decide_false, Bool.false_and]

/-- After setQuota, a coinless service can afford storage within the granted quotas.
    This is the key lifecycle property: newServiceEcon → setQuota → canAffordStorage. -/
theorem quotaEcon_setQuota_then_canAfford
    (e e' : QuotaEcon) (mi mb : UInt64)
    (items bytes bI bL bS : Nat)
    (hSet : @EconModel.setQuota QuotaEcon QuotaTransfer _ e mi mb = some e')
    (hItems : items ≤ mi.toNat) (hBytes : bytes ≤ mb.toNat) :
    @EconModel.canAffordStorage QuotaEcon QuotaTransfer _ e' items bytes bI bL bS = true := by
  simp only [EconModel.setQuota, Option.some.injEq] at hSet
  subst hSet
  simp only [EconModel.canAffordStorage, Bool.and_eq_true, decide_eq_true_eq]
  exact ⟨hItems, hBytes⟩

-- ============================================================================
-- Serialization roundtrip (deserializeEcon ∘ serializeEcon = id)
-- ============================================================================

/-- deserializeEcon (serializeEcon e) 0 recovers the original QuotaEcon.
    Combined with the codec roundtrip, this proves that the Merklization
    serialization format is lossless for QuotaEcon values. -/
theorem quotaEcon_deserialize_serialize_roundtrip [JarConfig] (e : QuotaEcon) :
    @EconModel.deserializeEcon QuotaEcon QuotaTransfer _
      (@EconModel.serializeEcon QuotaEcon QuotaTransfer _ e) 0 = some (e, 16) := by
  show (let data := Codec.encodeFixedNat 8 e.quotaItems.toNat
                    ++ Codec.encodeFixedNat 8 e.quotaBytes.toNat
        if 0 + 16 ≤ data.size then
          let quotaItems := Codec.decodeFixedNat (data.extract 0 (0 + 8))
          let quotaBytes := Codec.decodeFixedNat (data.extract (0 + 8) (0 + 16))
          some ({ quotaItems := UInt64.ofNat quotaItems, quotaBytes := UInt64.ofNat quotaBytes }, 0 + 16)
        else none) = some (e, 16)
  have hsz : (Codec.encodeFixedNat 8 e.quotaItems.toNat
              ++ Codec.encodeFixedNat 8 e.quotaBytes.toNat).size = 16 := by
    rw [byteArray_append_size, encodeFixedNat_size, encodeFixedNat_size]
  simp only [hsz, Nat.le_refl, ↓reduceIte]
  have hleft : (Codec.encodeFixedNat 8 e.quotaItems.toNat
                ++ Codec.encodeFixedNat 8 e.quotaBytes.toNat).extract 0 8
               = Codec.encodeFixedNat 8 e.quotaItems.toNat := by
    exact ByteArray.extract_append_eq_left (encodeFixedNat_size 8 e.quotaItems.toNat)
  have hright : (Codec.encodeFixedNat 8 e.quotaItems.toNat
                 ++ Codec.encodeFixedNat 8 e.quotaBytes.toNat).extract 8 16
                = Codec.encodeFixedNat 8 e.quotaBytes.toNat := by
    exact ByteArray.extract_append_eq_right (encodeFixedNat_size 8 e.quotaItems.toNat)
      (by rw [encodeFixedNat_size, encodeFixedNat_size])
  rw [hleft, hright, decodeFixedNat_encodeFixedNat, decodeFixedNat_encodeFixedNat]
  simp [UInt64.ofNat_toNat]

-- ============================================================================
-- Serialization size invariants (Merklization correctness)
-- ============================================================================

/-- serializeEcon produces exactly 16 bytes (8 for quotaItems + 8 for quotaBytes). -/
theorem quotaEcon_serializeEcon_size [JarConfig] (e : QuotaEcon) :
    (@EconModel.serializeEcon QuotaEcon QuotaTransfer _ e).size = 16 := by
  show (Codec.encodeFixedNat 8 e.quotaItems.toNat
        ++ Codec.encodeFixedNat 8 e.quotaBytes.toNat).size = 16
  rw [byteArray_append_size, encodeFixedNat_size, encodeFixedNat_size]

/-- encodeTransferAmount always produces exactly 8 bytes, even in coinless mode. -/
theorem quotaEcon_encodeTransferAmount_size [JarConfig] (t : QuotaTransfer) :
    (@EconModel.encodeTransferAmount QuotaEcon QuotaTransfer _ t).size = 8 := by
  show (Codec.encodeFixedNat 8 0).size = 8
  rw [encodeFixedNat_size]

/-- encodeInfo produces exactly 24 bytes (8 + 8 + 8 padding). -/
theorem quotaEcon_encodeInfo_size [JarConfig] (e : QuotaEcon)
    (items bytes bI bL bS : Nat) :
    (@EconModel.encodeInfo QuotaEcon QuotaTransfer _ e items bytes bI bL bS).size = 24 := by
  show (Codec.encodeFixedNat 8 e.quotaItems.toNat
        ++ Codec.encodeFixedNat 8 e.quotaBytes.toNat
        ++ Codec.encodeFixedNat 8 0).size = 24
  rw [byteArray_append_size, byteArray_append_size,
      encodeFixedNat_size, encodeFixedNat_size, encodeFixedNat_size]

end Jar.Proofs
