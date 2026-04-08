import Jar.Types
import Jar.JAVM
import Jar.JAVM.Interpreter
import Jar.Codec
import Jar.Codec.Jar1

/-!
# Protocol Variant — JarVariant typeclass

`JarVariant` extends `JarConfig` with overridable JAVM execution functions.
This is the single entry point for defining a protocol variant.

Struct types and most spec functions use `[JarConfig]` (the parent class).
JAVM memory model is configured via `JarConfig.memoryModel` (see `MemoryModel` enum).

## Usage

Define a variant by creating a `JarVariant` instance:
```lean
instance : JarVariant where
  name := "gp072_tiny"
  config := Params.tiny
  valid := Params.tiny_valid
  pvmRun := JAVM.run
  pvmRunWithHostCalls := fun ctx _ prog pc regs mem gas handler context =>
    JAVM.runWithHostCalls ctx prog pc regs mem gas handler context
```
-/

namespace Jar

/-- JarVariant: extends JarConfig with overridable PVM execution.
    The single entry point for defining a protocol variant. -/
class JarVariant extends JarConfig where
  /-- Ψ : Core PVM execution loop. -/
  pvmRun : JAVM.ProgramBlob → Nat → JAVM.Registers → JAVM.Memory
           → Int64 → JAVM.InvocationResult
  /-- Ψ_H : PVM execution with host-call dispatch. -/
  pvmRunWithHostCalls : (ctx : Type) → [Inhabited ctx]
    → JAVM.ProgramBlob → Nat → JAVM.Registers → JAVM.Memory
    → Int64 → JAVM.HostCallHandler ctx → ctx
    → JAVM.InvocationResult × ctx
  /-- Codec: encode a work report (for signature verification). -/
  codecEncodeWorkReport : @WorkReport toJarConfig → ByteArray
  /-- Codec: encode an unsigned header (for hashing). -/
  codecEncodeUnsignedHeader : @Header toJarConfig → ByteArray
  /-- Codec: encode a full header. -/
  codecEncodeHeader : @Header toJarConfig → ByteArray
  /-- Codec: encode an extrinsic. -/
  codecEncodeExtrinsic : @Extrinsic toJarConfig → ByteArray
  /-- Codec: encode a block. -/
  codecEncodeBlock : @Block toJarConfig → ByteArray

-- ============================================================================
-- Standard Instances
-- ============================================================================

private def gp072FullConfig : JarConfig where
  name := "gp072_full"
  config := Params.full
  valid := Params.full_valid
  EconType := BalanceEcon
  TransferType := BalanceTransfer

/-- Full GP v0.7.2 variant with standard PVM interpreter. -/
instance JarVariant.gp072_full : JarVariant where
  toJarConfig := gp072FullConfig
  pvmRun := JAVM.run
  pvmRunWithHostCalls := fun ctx _ prog pc regs mem gas handler context =>
    JAVM.runWithHostCalls ctx prog pc regs mem gas handler context
  codecEncodeWorkReport := @Codec.encodeWorkReport gp072FullConfig
  codecEncodeUnsignedHeader := @Codec.encodeUnsignedHeader gp072FullConfig
  codecEncodeHeader := @Codec.encodeHeader gp072FullConfig
  codecEncodeExtrinsic := @Codec.encodeExtrinsic gp072FullConfig
  codecEncodeBlock := @Codec.encodeBlock gp072FullConfig

private def gp072TinyConfig : JarConfig where
  name := "gp072_tiny"
  config := Params.tiny
  valid := Params.tiny_valid
  EconType := BalanceEcon
  TransferType := BalanceTransfer

/-- Tiny GP v0.7.2 test variant with standard PVM interpreter. -/
instance JarVariant.gp072_tiny : JarVariant where
  toJarConfig := gp072TinyConfig
  pvmRun := JAVM.run
  pvmRunWithHostCalls := fun ctx _ prog pc regs mem gas handler context =>
    JAVM.runWithHostCalls ctx prog pc regs mem gas handler context
  codecEncodeWorkReport := @Codec.encodeWorkReport gp072TinyConfig
  codecEncodeUnsignedHeader := @Codec.encodeUnsignedHeader gp072TinyConfig
  codecEncodeHeader := @Codec.encodeHeader gp072TinyConfig
  codecEncodeExtrinsic := @Codec.encodeExtrinsic gp072TinyConfig
  codecEncodeBlock := @Codec.encodeBlock gp072TinyConfig

/-- JAR v2 variant — capability-based execution, basic-block gas, coinless.
    Uses Params.full with variable validator set support (GP#514).
    memoryModel = .linear retained for Lean spec test compatibility
    (initLinear parses the JAR v1 blob format used in test vectors). -/
private def jar1Config : JarConfig where
  name := "jar1"
  config := Params.full
  valid := Params.full_valid
  memoryModel := .linear
  gasModel := .basicBlockSinglePass
  useCompactDeblob := false
  variableValidators := true
  capabilityModel := .v2
  EconType := QuotaEcon
  TransferType := QuotaTransfer

instance JarVariant.jar1 : JarVariant where
  toJarConfig := jar1Config
  pvmRun := JAVM.run
  pvmRunWithHostCalls := fun ctx _ prog pc regs mem gas handler context =>
    JAVM.runWithHostCalls ctx prog pc regs mem gas handler context
  codecEncodeWorkReport := @Codec.Jar1.encodeWorkReport jar1Config
  codecEncodeUnsignedHeader := @Codec.Jar1.encodeUnsignedHeader jar1Config
  codecEncodeHeader := @Codec.Jar1.encodeHeader jar1Config
  codecEncodeExtrinsic := @Codec.Jar1.encodeExtrinsic jar1Config
  codecEncodeBlock := @Codec.Jar1.encodeBlock jar1Config

end Jar
