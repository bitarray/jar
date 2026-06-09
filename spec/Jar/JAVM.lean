import Jar.Basic
import Jar.SSZ
import Jar.PVM2.Regs
import Jar.PVM2.Memory
import Jar.PVM2.Instruction
import Jar.PVM2.Gas
import Jar.Cap
import Jar.Kernel
import Jar.SubVM

namespace Jar

structure SpecVersion where
  major : Nat
  minor : Nat
  patch : Nat
deriving Repr, DecidableEq, BEq

def currentSpecVersion : SpecVersion := ⟨0, 1, 0⟩

structure JAVMImage where
  image : Image
  arena : PVM2.ImageArena
deriving Repr, DecidableEq

def JAVMImage.Valid (img : JAVMImage) : Prop :=
  img.image.Valid ∧ img.arena.Valid ∧ img.image.arenaBytes = img.arena.data.length

structure JAVMState where
  vm : Instance
  regs : PVM2.RegFile
  pc : Nat
deriving Repr, DecidableEq

def JAVMState.atInstancePc (state : JAVMState) : Prop :=
  state.pc = state.vm.pc

end Jar
