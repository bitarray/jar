import Jar.Types
import Jar.PVM
import Jar.PVM.Interpreter

/-!
# Protocol Variant — JamVariant typeclass

`JamVariant` extends `JamConfig` with overridable PVM execution functions.
This is the single entry point for defining a protocol variant.

Struct types and most spec functions use `[JamConfig]` (the parent class).
Functions that call the PVM (accumulation, services) use `[JamVariant]`.

## Usage

Define a variant by creating a `JamVariant` instance:
```lean
instance : JamVariant where
  config := Config.tiny
  valid := Config.tiny_valid
  pvmRun := PVM.run
  pvmRunWithHostCalls := PVM.runWithHostCalls
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
instance JamVariant.full : JamVariant where
  config := Config.full
  valid := Config.full_valid
  pvmRun := PVM.run
  pvmRunWithHostCalls := PVM.runWithHostCalls

/-- Tiny test variant with standard PVM interpreter. -/
instance JamVariant.tiny : JamVariant where
  config := Config.tiny
  valid := Config.tiny_valid
  pvmRun := PVM.run
  pvmRunWithHostCalls := PVM.runWithHostCalls

end Jar
