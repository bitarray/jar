import Jar.Basic

namespace Jar
namespace PVM2

def regCount : Nat := 15

inductive RegClass where
  | zero
  | gpr (slot : Fin regCount)
  | reserved
deriving Repr, DecidableEq

def regClassNat : Nat → RegClass
  | 0 => .zero
  | 1 => .gpr ⟨0, by decide⟩
  | 2 => .gpr ⟨1, by decide⟩
  | 3 => .gpr ⟨13, by decide⟩
  | 4 => .gpr ⟨14, by decide⟩
  | 5 => .gpr ⟨2, by decide⟩
  | 6 => .gpr ⟨3, by decide⟩
  | 7 => .gpr ⟨4, by decide⟩
  | 8 => .gpr ⟨5, by decide⟩
  | 9 => .gpr ⟨6, by decide⟩
  | 10 => .gpr ⟨7, by decide⟩
  | 11 => .gpr ⟨8, by decide⟩
  | 12 => .gpr ⟨9, by decide⟩
  | 13 => .gpr ⟨10, by decide⟩
  | 14 => .gpr ⟨11, by decide⟩
  | 15 => .gpr ⟨12, by decide⟩
  | _ => .reserved

def regClass (x : Fin 32) : RegClass := regClassNat x.val

def regSlot? (x : Nat) : Option (Fin regCount) :=
  match regClassNat x with
  | .gpr slot => some slot
  | _ => none

def regIsReserved (x : Nat) : Bool :=
  match regClassNat x with
  | .reserved => true
  | _ => false

def regIsSpilled (x : Nat) : Bool :=
  match regClassNat x with
  | .gpr ⟨13, _⟩ => true
  | .gpr ⟨14, _⟩ => true
  | _ => false

structure RegFile where
  slots : Vector UInt64 regCount
deriving Repr, DecidableEq

def RegFile.readSlot (regs : RegFile) (slot : Fin regCount) : UInt64 :=
  regs.slots[slot]

def RegFile.readNat (regs : RegFile) (idx : Nat) : Option UInt64 :=
  match regSlot? idx with
  | some slot => some (regs.readSlot slot)
  | none => if idx = 0 then some 0 else none

theorem x3_is_valid_spilled : regIsSpilled 3 = true := rfl

theorem x4_is_valid_spilled : regIsSpilled 4 = true := rfl

theorem x16_reserved : regIsReserved 16 = true := rfl

end PVM2
end Jar
