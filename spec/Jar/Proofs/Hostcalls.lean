import Jar.Types.Accounts
import Jar.Proofs.QuotaEcon

/-!
# Hostcall Proofs — jar1 numbering shift and gas formula

Properties of the hostcall numbering logic and gas cost formula.
The full `handleHostCall` function (1000+ lines) is impractical to prove
end-to-end, so we prove properties about the logic fragments.
-/

namespace Jar.Proofs

-- ============================================================================
-- set_quota reachability
-- ============================================================================

/-- In QuotaEcon mode, setQuota never returns none.
    This means when jar1's set_quota hostcall reaches the
    `econSetQuota` call, the RESULT_WHAT "model doesn't support" branch
    is unreachable — the operation always succeeds. -/
theorem quotaEcon_setQuota_reachable (e : QuotaEcon) (mi mb : UInt64) :
    ∃ econ', @EconModel.setQuota QuotaEcon QuotaTransfer _ e mi mb = some econ' := by
  exact ⟨{ quotaItems := mi, quotaBytes := mb }, rfl⟩

/-- In BalanceEcon mode, setQuota always returns none.
    This means when gp072's handleHostCall reaches callNum=27,
    the capability model guard catches it first,
    and even if bypassed, `econSetQuota` would return none. -/
theorem balanceEcon_setQuota_unreachable (e : BalanceEcon) (mi mb : UInt64) :
    @EconModel.setQuota BalanceEcon BalanceTransfer _ e mi mb = none := by
  rfl

-- ============================================================================
-- Gas cost formula (GasCostSinglePass.lean final expression)
-- ============================================================================

/-- The basic-block gas cost formula always produces ≥ 1.
    `if maxDone > 3 then maxDone - 3 else 1` — either branch is ≥ 1. -/
theorem block_cost_formula_ge_1 (maxDone : Nat) :
    (if maxDone > 3 then maxDone - 3 else 1) ≥ 1 := by
  split <;> omega

end Jar.Proofs
