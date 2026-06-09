import Jar.Basic
import Jar.Cap
import Jar.Kernel
import Jar.PVM2.Gas

namespace Jar

inductive InvocationPrimitive where
  | spawn
  | call
  | yield
  | resume
  | return
deriving Repr, DecidableEq, BEq

structure Invocation where
  primitive : InvocationPrimitive
  source : Hash
  target : SlotPath
  gas : Nat
  quota : Nat
  input : Bytes
deriving Repr, DecidableEq

inductive ExitReason where
  | returned
  | yielded
  | trapped
  | outOfGas
  | invalidCapability
deriving Repr, DecidableEq

structure ApplyResult where
  vm : Instance
  output : Bytes
  edge : EdgeSnapshot
  reason : ExitReason
deriving Repr, DecidableEq

structure PausedWellFormed (inst : Instance) : Prop where
  paused : inst.status = .paused
  rootNonempty : inst.root.slots ≠ []

def slot0StoresScratchpad (node : CNode) : Prop :=
  node.lookup scratchpadKey ≠ none

def canEnter (inst : Instance) : Prop :=
  inst.status = .runnable ∧ inst.gas > 0

def callDepthAllowed (depth : Nat) : Prop :=
  depth ≤ maxSourceDepth

def capNestingAllowed (depth : Nat) : Prop :=
  depth ≤ maxCapNesting

def applyGasCharge (inst : Instance) (cost : Nat) : Except KernelError Instance :=
  match chargeGas ⟨inst.gas⟩ cost with
  | .ok handle => .ok { inst with gas := handle.remaining }
  | .error err => .error err

theorem depth_zero_allowed : callDepthAllowed 0 := by
  unfold callDepthAllowed maxSourceDepth
  decide

theorem cap_nesting_zero_allowed : capNestingAllowed 0 := by
  unfold capNestingAllowed maxCapNesting
  decide

end Jar
