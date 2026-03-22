import Jar.Types
import Jar.PVM
import Jar.PVM.Interpreter

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
  /-- Ψ : Core PVM execution loop. Runs a program to completion
      (halt, panic, OOG, fault, or host-call). -/
  pvmRun : PVM.ProgramBlob → Nat → PVM.Registers → PVM.Memory
           → Int64 → PVM.InvocationResult
  /-- Ψ_H : PVM execution with host-call dispatch. Repeatedly runs
      the PVM, handling host calls via the provided handler. -/
  pvmRunWithHostCalls : (ctx : Type) → [Inhabited ctx]
    → PVM.ProgramBlob → Nat → PVM.Registers → PVM.Memory
    → Int64 → PVM.HostCallHandler ctx → ctx
    → PVM.InvocationResult × ctx

-- ============================================================================
-- Standard Instances
-- ============================================================================

/-- Full GP v0.7.2 variant with standard PVM interpreter. -/
instance JamVariant.gp072_full : JamVariant where
  toJamConfig := { name := "gp072_full", config := Params.full, valid := Params.full_valid }
  pvmRun := PVM.run
  pvmRunWithHostCalls := fun ctx _ prog pc regs mem gas handler context =>
    PVM.runWithHostCalls ctx prog pc regs mem gas handler context

/-- Tiny GP v0.7.2 test variant with standard PVM interpreter. -/
instance JamVariant.gp072_tiny : JamVariant where
  toJamConfig := { name := "gp072_tiny", config := Params.tiny, valid := Params.tiny_valid }
  pvmRun := PVM.run
  pvmRunWithHostCalls := fun ctx _ prog pc regs mem gas handler context =>
    PVM.runWithHostCalls ctx prog pc regs mem gas handler context

/-- Tiny JAR v0.8.0 variant — contiguous linear memory, basic-block gas, grow_heap. -/
instance JamVariant.jar080_tiny : JamVariant where
  toJamConfig := {
    name := "jar080_tiny"
    config := Params.tiny
    valid := Params.tiny_valid
    memoryModel := .linear
    gasModel := .basicBlockSinglePass
    heapModel := .growHeap
    hostcallVersion := 1
  }
  pvmRun := PVM.run
  pvmRunWithHostCalls := fun ctx _ prog pc regs mem gas handler context =>
    PVM.runWithHostCalls ctx prog pc regs mem gas handler context

end Jar
