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

/-- Block cost monotonicity: if maxDone increases, cost does not decrease.
    This ensures adding instructions to a basic block cannot reduce its gas cost. -/
theorem block_cost_formula_mono (a b : Nat) (h : a ≤ b) :
    (if a > 3 then a - 3 else 1) ≤ (if b > 3 then b - 3 else 1) := by
  split <;> split <;> omega

/-- Block cost formula never exceeds maxDone (upper bound). -/
theorem block_cost_formula_le (maxDone : Nat) :
    (if maxDone > 3 then maxDone - 3 else 1) ≤ maxDone ∨ maxDone = 0 := by
  split <;> omega

/-- Block cost strict monotonicity: for maxDone > 3, increasing maxDone
    strictly increases the gas cost. This means every additional instruction
    beyond the 3-instruction minimum actually increases the block's gas cost. -/
theorem block_cost_formula_strict_mono (a b : Nat) (h1 : 3 < a) (h2 : a < b) :
    (if a > 3 then a - 3 else 1) < (if b > 3 then b - 3 else 1) := by
  split <;> split <;> omega

end Jar.Proofs
