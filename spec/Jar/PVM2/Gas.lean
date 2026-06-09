import Jar.Basic
import Jar.PVM2.Instruction

namespace Jar
namespace PVM2

structure FastCost where
  fast : Nat
  memory : Nat
  spill : Nat
  ecall : Nat
deriving Repr, DecidableEq

namespace FastCost

def zero : FastCost := ⟨0, 0, 0, 0⟩

def total (c : FastCost) : Nat := c.fast + c.memory + c.spill + c.ecall

def add (a b : FastCost) : FastCost :=
  ⟨a.fast + b.fast, a.memory + b.memory, a.spill + b.spill, a.ecall + b.ecall⟩

end FastCost

def computeScale : Nat := 10
def memoryWordBytes : Nat := 8
def callFrameGas : Nat := 64
def yieldBaseGas : Nat := 32

def memCyclesFor (bytes : Nat) : Nat :=
  ceilDiv bytes memoryWordBytes

def spillCostForReg (idx : Nat) : Nat :=
  if regIsSpilled idx then 1 else 0

def instCost : Inst → FastCost
  | .load _ rs1 width _ => ⟨1, memCyclesFor width, spillCostForReg rs1, 0⟩
  | .store rs1 rs2 width _ => ⟨1, memCyclesFor width, spillCostForReg rs1 + spillCostForReg rs2, 0⟩
  | .custom0 .ecall => ⟨0, 0, 0, 1⟩
  | .custom0 .yield => ⟨0, 0, 0, yieldBaseGas⟩
  | .reserved .. => ⟨0, 0, 0, 0⟩
  | inst =>
      let regCost :=
        match inst.writesReg with
        | some r => spillCostForReg r
        | none => 0
      ⟨1, 0, regCost, 0⟩

def blockCostFromMaxDone (maxDone : Nat) (fast : FastCost) : Nat :=
  maxDone * computeScale + fast.total

def ecallDynamicCost (inputBytes outputBytes : Nat) : Nat :=
  memCyclesFor inputBytes + memCyclesFor outputBytes

def callFrameCost (depth : Nat) : Nat :=
  depth * callFrameGas

theorem empty_io_ecall_dynamic_zero : ecallDynamicCost 0 0 = 0 := by
  unfold ecallDynamicCost memCyclesFor ceilDiv memoryWordBytes
  rfl

end PVM2
end Jar
