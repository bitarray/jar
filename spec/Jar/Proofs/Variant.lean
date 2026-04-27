import Jar.Variant

/-!
# Variant Config Proofs — compile-time regression tests

These theorems assert the configuration fields of each variant.
If someone accidentally changes a variant definition, these proofs
break at compile time — serving as a lightweight regression harness.
-/

namespace Jar.Proofs

-- ============================================================================
-- jar1 config assertions (v2 capability model)
-- ============================================================================

/-- jar1 uses the v2 capability model (capability-based execution). -/
theorem jar1_capabilityModel_v2 :
    @JarConfig.capabilityModel JarVariant.jar1.toJarConfig = .v2 := by rfl

/-- jar1 uses linear memory layout. -/
theorem jar1_memoryModel_linear :
    @JarConfig.memoryModel JarVariant.jar1.toJarConfig = .linear := by rfl

/-- jar1 uses basic-block single-pass gas metering. -/
theorem jar1_gasModel_singlePass :
    @JarConfig.gasModel JarVariant.jar1.toJarConfig = .basicBlockSinglePass := by rfl

/-- jar1 enables variable validator sets (GP#514). -/
theorem jar1_variableValidators :
    @JarConfig.variableValidators JarVariant.jar1.toJarConfig = true := by rfl

-- ============================================================================
-- gp072_full config assertions (GP v0.7.2 full, token-based)
-- ============================================================================

/-- gp072_full uses segmented memory layout (default). -/
theorem gp072_full_memoryModel_segmented :
    @JarConfig.memoryModel JarVariant.gp072_full.toJarConfig = .segmented := by rfl

/-- gp072_full uses per-instruction gas metering (default). -/
theorem gp072_full_gasModel_perInstruction :
    @JarConfig.gasModel JarVariant.gp072_full.toJarConfig = .perInstruction := by rfl

/-- gp072_full uses no capability model (flat memory, default). -/
theorem gp072_full_capabilityModel_none :
    @JarConfig.capabilityModel JarVariant.gp072_full.toJarConfig = .none := by rfl

/-- gp072_full uses fixed validator sets (default). -/
theorem gp072_full_variableValidators_false :
    @JarConfig.variableValidators JarVariant.gp072_full.toJarConfig = false := by rfl

/-- gp072_full uses compact (variable-length) blob headers. -/
theorem gp072_full_useCompactDeblob_true :
    @JarConfig.useCompactDeblob JarVariant.gp072_full.toJarConfig = true := by rfl

-- ============================================================================
-- gp072_tiny config assertions (GP v0.7.2 tiny, token-based)
-- ============================================================================

/-- gp072_tiny uses segmented memory layout (default). -/
theorem gp072_tiny_memoryModel_segmented :
    @JarConfig.memoryModel JarVariant.gp072_tiny.toJarConfig = .segmented := by rfl

/-- gp072_tiny uses per-instruction gas metering (default). -/
theorem gp072_tiny_gasModel_perInstruction :
    @JarConfig.gasModel JarVariant.gp072_tiny.toJarConfig = .perInstruction := by rfl

/-- gp072_tiny uses no capability model (flat memory, default). -/
theorem gp072_tiny_capabilityModel_none :
    @JarConfig.capabilityModel JarVariant.gp072_tiny.toJarConfig = .none := by rfl

/-- gp072_tiny uses fixed validator sets (default). -/
theorem gp072_tiny_variableValidators_false :
    @JarConfig.variableValidators JarVariant.gp072_tiny.toJarConfig = false := by rfl

/-- gp072_tiny uses compact (variable-length) blob headers (default). -/
theorem gp072_tiny_useCompactDeblob_true :
    @JarConfig.useCompactDeblob JarVariant.gp072_tiny.toJarConfig = true := by rfl

-- ============================================================================
-- Validator count consistency (isValidValCount returns true for config V)
-- ============================================================================

/-- Params.full has a valid validator count (V=1023, C=341).
    1023 ≥ 6, 1023 ≤ 3*(341+1) = 1026, 1023 % 3 = 0. -/
theorem full_validValCount :
    Params.full.isValidValCount Params.full.V = true := by decide

/-- Params.tiny has a valid validator count (V=6, C=2).
    6 ≥ 6, 6 ≤ 3*(2+1) = 9, 6 % 3 = 0. -/
theorem tiny_validValCount :
    Params.tiny.isValidValCount Params.tiny.V = true := by decide

-- ============================================================================
-- Economic model assertions (jar1 = coinless, gp072 = token-based)
-- ============================================================================

/-- jar1 uses the coinless QuotaEcon model. -/
theorem jar1_econType_quota :
    @JarConfig.EconType JarVariant.jar1.toJarConfig = QuotaEcon := by rfl

/-- gp072_full uses the token-based BalanceEcon model. -/
theorem gp072_full_econType_balance :
    @JarConfig.EconType JarVariant.gp072_full.toJarConfig = BalanceEcon := by rfl

/-- gp072_tiny uses the token-based BalanceEcon model. -/
theorem gp072_tiny_econType_balance :
    @JarConfig.EconType JarVariant.gp072_tiny.toJarConfig = BalanceEcon := by rfl

end Jar.Proofs
