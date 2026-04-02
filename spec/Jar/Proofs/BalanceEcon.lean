import Jar.Types.Accounts
import Jar.Proofs.Codec
import Jar.Proofs.QuotaEcon  -- for byteArray_append_size

/-!
# BalanceEcon Proofs — gp072 token-based economic model

Contrast proofs showing BalanceEcon ≠ QuotaEcon semantically:
- setQuota always fails (unsupported)
- debitTransfer can fail (insufficient balance)
- Same serialization size invariants hold
-/

namespace Jar.Proofs

-- ============================================================================
-- Semantic contrast with QuotaEcon
-- ============================================================================

/-- setQuota is unsupported for BalanceEcon — always returns none.
    This means the set_quota hostcall always returns RESULT_WHAT in gp072 mode. -/
theorem balanceEcon_setQuota_always_none (e : BalanceEcon) (mi mb : UInt64) :
    @EconModel.setQuota BalanceEcon BalanceTransfer _ e mi mb = none := by
  rfl

/-- debitTransfer can fail with insufficient balance — unlike QuotaEcon.
    Witness: balance=0, amount=1. -/
theorem balanceEcon_debitTransfer_can_fail :
    ∃ (e : BalanceEcon) (amount : UInt64),
      @EconModel.debitTransfer BalanceEcon BalanceTransfer _ e amount = none := by
  exact ⟨{ balance := 0, gratis := 0 }, 1, rfl⟩

-- ============================================================================
-- Serialization size invariants (same as QuotaEcon — both models produce
-- 16-byte serializeEcon and 24-byte encodeInfo)
-- ============================================================================

/-- serializeEcon produces exactly 16 bytes (8 for balance + 8 for gratis). -/
theorem balanceEcon_serializeEcon_size [JamConfig] (e : BalanceEcon) :
    (@EconModel.serializeEcon BalanceEcon BalanceTransfer _ e).size = 16 := by
  show (Codec.encodeFixedNat 8 e.balance.toNat
        ++ Codec.encodeFixedNat 8 e.gratis.toNat).size = 16
  rw [byteArray_append_size, encodeFixedNat_size, encodeFixedNat_size]

/-- encodeTransferAmount always produces exactly 8 bytes for the transfer amount. -/
theorem balanceEcon_encodeTransferAmount_size [JamConfig] (t : BalanceTransfer) :
    (@EconModel.encodeTransferAmount BalanceEcon BalanceTransfer _ t).size = 8 := by
  show (Codec.encodeFixedNat 8 t.amount.toNat).size = 8
  rw [encodeFixedNat_size]

/-- encodeInfo produces exactly 24 bytes (8 balance + 8 threshold + 8 gratis). -/
theorem balanceEcon_encodeInfo_size [JamConfig] (e : BalanceEcon)
    (items bytes bI bL bS : Nat) :
    (@EconModel.encodeInfo BalanceEcon BalanceTransfer _ e items bytes bI bL bS).size = 24 := by
  show (Codec.encodeFixedNat 8 e.balance.toNat
        ++ Codec.encodeFixedNat 8 _
        ++ Codec.encodeFixedNat 8 e.gratis.toNat).size = 24
  rw [byteArray_append_size, byteArray_append_size,
      encodeFixedNat_size, encodeFixedNat_size, encodeFixedNat_size]

end Jar.Proofs
