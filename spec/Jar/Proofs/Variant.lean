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

theorem jar1_capabilityModel_v2 :
    @JamConfig.capabilityModel JamVariant.jar1.toJamConfig = .v2 := by rfl

theorem jar1_memoryModel_linear :
    @JamConfig.memoryModel JamVariant.jar1.toJamConfig = .linear := by rfl

theorem jar1_gasModel_singlePass :
    @JamConfig.gasModel JamVariant.jar1.toJamConfig = .basicBlockSinglePass := by rfl

theorem jar1_variableValidators :
    @JamConfig.variableValidators JamVariant.jar1.toJamConfig = true := by rfl

-- ============================================================================
-- gp072_tiny config assertions (contrast)
-- ============================================================================

theorem gp072_tiny_memoryModel_segmented :
    @JamConfig.memoryModel JamVariant.gp072_tiny.toJamConfig = .segmented := by rfl

theorem gp072_tiny_gasModel_perInstruction :
    @JamConfig.gasModel JamVariant.gp072_tiny.toJamConfig = .perInstruction := by rfl

theorem gp072_tiny_hostcallVersion_0 :
    @JamConfig.hostcallVersion JamVariant.gp072_tiny.toJamConfig = 0 := by rfl

theorem gp072_tiny_variableValidators_false :
    @JamConfig.variableValidators JamVariant.gp072_tiny.toJamConfig = false := by rfl

end Jar.Proofs
