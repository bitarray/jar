import Std

namespace Jar

abbrev Byte := UInt8
abbrev Bytes := List Byte

structure Hash where
  bytes : Vector Byte 32
deriving Repr, DecidableEq, BEq

def zeroHash : Hash :=
  ⟨Vector.replicate 32 0⟩

structure Key where
  bytes : Bytes
deriving Repr, DecidableEq, BEq

namespace Key

def empty : Key := ⟨[]⟩

def singleton (b : Byte) : Key := ⟨[b]⟩

def isKernelYieldNamespace (k : Key) : Bool :=
  match k.bytes with
  | [] => false
  | b :: _ => b == (0xCE : UInt8)

end Key

structure SlotPath where
  steps : List Key
deriving Repr, DecidableEq, BEq

namespace SlotPath

def root (k : Key) : SlotPath := ⟨[k]⟩

def isWellFormed (p : SlotPath) : Prop := p.steps ≠ []

def targetList? : List Key → Option Key
  | [] => none
  | [k] => some k
  | _ :: rest => targetList? rest

def target? (p : SlotPath) : Option Key := targetList? p.steps

end SlotPath

def pageSize : Nat := 4096
def groupPages : Nat := 512
def groupSize : Nat := groupPages * pageSize

def codeBase : Nat := 0x00400000
def dataBase : Nat := 0x10000000
def maxCodeSize : Nat := dataBase - codeBase

def maxSourceDepth : Nat := 8
def maxCapNesting : Nat := 8

def kernelYieldNamespace : Byte := 0xCE
def scratchpadKey : Key := Key.singleton 0

def ceilDiv (a b : Nat) : Nat := (a + b - 1) / b

theorem pageSize_pos : pageSize > 0 := by decide

theorem groupSize_eq : groupSize = 2097152 := by decide

end Jar
