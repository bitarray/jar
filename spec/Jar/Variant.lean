import Jar.Types
import Jar.PVM
import Jar.PVM.Interpreter
import Jar.Codec
import Jar.Codec.Jar1

/-!
# Protocol Variant — JamVariant typeclass

`JamVariant` extends `JamConfig` with overridable PVM execution functions.
This is the single entry point for defining a protocol variant.

Struct types and most spec functions use `[JamConfig]` (the parent class).
PVM memory model is configured via `JamConfig.memoryModel` (see `MemoryModel` enum).

## Usage

Define a variant by creating a `JamVariant` instance:
```lean
instance : JamVariant where
  name := "gp072_tiny"
  config := Params.tiny
  valid := Params.tiny_valid
  pvmRun := PVM.run
  pvmRunWithHostCalls := fun ctx _ prog pc regs mem gas handler context =>
    PVM.runWithHostCalls ctx prog pc regs mem gas handler context
```
-/

namespace Jar

/-- JamVariant: extends JamConfig with overridable PVM execution.
    The single entry point for defining a protocol variant. -/
class JamVariant extends JamConfig where
  /-- Ψ : Core PVM execution loop. -/
  pvmRun : PVM.ProgramBlob → Nat → PVM.Registers → PVM.Memory
           → Int64 → PVM.InvocationResult
  /-- Ψ_H : PVM execution with host-call dispatch. -/
  pvmRunWithHostCalls : (ctx : Type) → [Inhabited ctx]
    → PVM.ProgramBlob → Nat → PVM.Registers → PVM.Memory
    → Int64 → PVM.HostCallHandler ctx → ctx
    → PVM.InvocationResult × ctx
  /-- Codec: encode a work report (for signature verification). -/
  codecEncodeWorkReport : @WorkReport toJamConfig → ByteArray
  /-- Codec: encode an unsigned header (for hashing). -/
  codecEncodeUnsignedHeader : @Header toJamConfig → ByteArray
  /-- Codec: encode a full header. -/
  codecEncodeHeader : @Header toJamConfig → ByteArray
  /-- Codec: encode an extrinsic. -/
  codecEncodeExtrinsic : @Extrinsic toJamConfig → ByteArray
  /-- Codec: encode a block. -/
  codecEncodeBlock : @Block toJamConfig → ByteArray

-- ============================================================================
-- Standard Instances
-- ============================================================================

private def gp072FullConfig : JamConfig where
  name := "gp072_full"
  config := Params.full
  valid := Params.full_valid
  EconType := BalanceEcon
  TransferType := BalanceTransfer

/-- Full GP v0.7.2 variant with standard PVM interpreter. -/
instance JamVariant.gp072_full : JamVariant where
  toJamConfig := gp072FullConfig
  pvmRun := PVM.run
  pvmRunWithHostCalls := fun ctx _ prog pc regs mem gas handler context =>
    PVM.runWithHostCalls ctx prog pc regs mem gas handler context
  codecEncodeWorkReport := @Codec.encodeWorkReport gp072FullConfig
  codecEncodeUnsignedHeader := @Codec.encodeUnsignedHeader gp072FullConfig
  codecEncodeHeader := @Codec.encodeHeader gp072FullConfig
  codecEncodeExtrinsic := @Codec.encodeExtrinsic gp072FullConfig
  codecEncodeBlock := @Codec.encodeBlock gp072FullConfig

private def gp072TinyConfig : JamConfig where
  name := "gp072_tiny"
  config := Params.tiny
  valid := Params.tiny_valid
  EconType := BalanceEcon
  TransferType := BalanceTransfer

/-- Tiny GP v0.7.2 test variant with standard PVM interpreter. -/
instance JamVariant.gp072_tiny : JamVariant where
  toJamConfig := gp072TinyConfig
  pvmRun := PVM.run
  pvmRunWithHostCalls := fun ctx _ prog pc regs mem gas handler context =>
    PVM.runWithHostCalls ctx prog pc regs mem gas handler context
  codecEncodeWorkReport := @Codec.encodeWorkReport gp072TinyConfig
  codecEncodeUnsignedHeader := @Codec.encodeUnsignedHeader gp072TinyConfig
  codecEncodeHeader := @Codec.encodeHeader gp072TinyConfig
  codecEncodeExtrinsic := @Codec.encodeExtrinsic gp072TinyConfig
  codecEncodeBlock := @Codec.encodeBlock gp072TinyConfig

/-- JAR v2 variant — capability-based execution, basic-block gas, coinless.
    Uses Params.full with variable validator set support (GP#514).
    memoryModel = .linear retained for Lean spec test compatibility
    (initLinear parses the JAR v1 blob format used in test vectors). -/
private def jar1Config : JamConfig where
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

instance JamVariant.jar1 : JamVariant where
  toJamConfig := jar1Config
  pvmRun := PVM.run
  pvmRunWithHostCalls := fun ctx _ prog pc regs mem gas handler context =>
    PVM.runWithHostCalls ctx prog pc regs mem gas handler context
  codecEncodeWorkReport := @Codec.Jar1.encodeWorkReport jar1Config
  codecEncodeUnsignedHeader := @Codec.Jar1.encodeUnsignedHeader jar1Config
  codecEncodeHeader := @Codec.Jar1.encodeHeader jar1Config
  codecEncodeExtrinsic := @Codec.Jar1.encodeExtrinsic jar1Config
  codecEncodeBlock := @Codec.Jar1.encodeBlock jar1Config

end Jar
