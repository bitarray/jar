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
    @JarConfig.capabilityModel JarVariant.jar1.toJarConfig = .v2 := by rfl

theorem jar1_memoryModel_linear :
    @JarConfig.memoryModel JarVariant.jar1.toJarConfig = .linear := by rfl

theorem jar1_gasModel_singlePass :
    @JarConfig.gasModel JarVariant.jar1.toJarConfig = .basicBlockSinglePass := by rfl

theorem jar1_variableValidators :
    @JarConfig.variableValidators JarVariant.jar1.toJarConfig = true := by rfl

-- ============================================================================
-- gp072_tiny config assertions (contrast)
-- ============================================================================

theorem gp072_tiny_memoryModel_segmented :
    @JarConfig.memoryModel JarVariant.gp072_tiny.toJarConfig = .segmented := by rfl

theorem gp072_tiny_gasModel_perInstruction :
    @JarConfig.gasModel JarVariant.gp072_tiny.toJarConfig = .perInstruction := by rfl

theorem gp072_tiny_variableValidators_false :
    @JarConfig.variableValidators JarVariant.gp072_tiny.toJarConfig = false := by rfl

end Jar.Proofs
