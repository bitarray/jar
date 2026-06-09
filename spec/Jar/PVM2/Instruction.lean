import Jar.Basic
import Jar.PVM2.Regs

namespace Jar
namespace PVM2

inductive Extension where
  | rv64i
  | m
  | zicsr
  | custom0
deriving Repr, DecidableEq

inductive Custom0Op where
  | trap
  | ecall
  | fuel
  | yield
  | capLoad
  | capStore
  | capMove
  | capDrop
deriving Repr, DecidableEq

inductive ReservedReason where
  | compressedEncoding
  | unsupportedExtension
  | reservedRegister (idx : Nat)
  | forbiddenOpcode
  | malformedCustom
deriving Repr, DecidableEq

structure Imm where
  value : Int
deriving Repr, DecidableEq

inductive Inst where
  | lui (rd : Nat) (imm : Imm)
  | auipc (rd : Nat) (imm : Imm)
  | jal (rd : Nat) (offset : Int)
  | jalr (rd rs1 : Nat) (offset : Int)
  | branch (rs1 rs2 : Nat) (offset : Int)
  | load (rd rs1 : Nat) (width : Nat) (offset : Int)
  | store (rs1 rs2 : Nat) (width : Nat) (offset : Int)
  | opImm (rd rs1 : Nat) (funct : Nat) (imm : Imm)
  | op (rd rs1 rs2 : Nat) (funct : Nat)
  | custom0 (op : Custom0Op)
  | reserved (reason : ReservedReason)
deriving Repr, DecidableEq

namespace Inst

def writesReg : Inst → Option Nat
  | .lui rd _ => some rd
  | .auipc rd _ => some rd
  | .jal rd _ => some rd
  | .jalr rd _ _ => some rd
  | .load rd _ _ _ => some rd
  | .opImm rd _ _ _ => some rd
  | .op rd _ _ _ => some rd
  | _ => none

def isTerminator : Inst → Bool
  | .jal .. => true
  | .jalr .. => true
  | .branch .. => true
  | .custom0 .trap => true
  | .custom0 .ecall => true
  | .custom0 .yield => true
  | .reserved .. => true
  | _ => false

def containsReservedReg : Inst → Bool
  | .lui rd _ => regIsReserved rd
  | .auipc rd _ => regIsReserved rd
  | .jal rd _ => regIsReserved rd
  | .jalr rd rs1 _ => regIsReserved rd || regIsReserved rs1
  | .branch rs1 rs2 _ => regIsReserved rs1 || regIsReserved rs2
  | .load rd rs1 _ _ => regIsReserved rd || regIsReserved rs1
  | .store rs1 rs2 _ _ => regIsReserved rs1 || regIsReserved rs2
  | .opImm rd rs1 _ _ => regIsReserved rd || regIsReserved rs1
  | .op rd rs1 rs2 _ => regIsReserved rd || regIsReserved rs1 || regIsReserved rs2
  | _ => false

end Inst

structure BasicBlock where
  startPc : Nat
  instructions : List Inst
  terminator : Inst
deriving Repr, DecidableEq

def BasicBlock.Valid (bb : BasicBlock) : Prop :=
  bb.startPc % 4 = 0 ∧
    bb.instructions.all (fun i => !i.isTerminator && !i.containsReservedReg) = true ∧
    bb.terminator.isTerminator = true ∧
    bb.terminator.containsReservedReg = false

def isEcallBlock (bb : BasicBlock) : Bool :=
  match bb.terminator with
  | .custom0 .ecall => true
  | _ => false

def jumpTargetPc (fromPc : Nat) (offset : Int) : Option Nat :=
  let target := Int.ofNat fromPc + offset
  if target < 0 then none else some target.toNat

def validJumpTarget (codeLen target : Nat) : Prop :=
  target % 4 = 0 ∧ target < codeLen

def bbStartsAux : Nat → List Inst → List Nat
  | _, [] => []
  | pc, inst :: rest =>
      let next := pc + 4
      if inst.isTerminator then pc :: bbStartsAux next rest else bbStartsAux next rest

def bbStarts (insts : List Inst) : List Nat :=
  0 :: bbStartsAux 0 insts

theorem bbStarts_nonempty (insts : List Inst) : bbStarts insts ≠ [] := by
  intro h
  unfold bbStarts at h
  contradiction

end PVM2
end Jar
