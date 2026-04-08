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
