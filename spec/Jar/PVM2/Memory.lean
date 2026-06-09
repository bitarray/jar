import Jar.Basic

namespace Jar
namespace PVM2

def addressBits : Nat := 32
def addressSpaceSize : Nat := 2 ^ addressBits

def codeLo : Nat := codeBase
def codeHi : Nat := dataBase
def dataLo : Nat := dataBase
def dataHi : Nat := addressSpaceSize

inductive Region where
  | code
  | data
  | unmapped
deriving Repr, DecidableEq

def regionOf (addr : Nat) : Region :=
  if codeLo ≤ addr ∧ addr < codeHi then
    .code
  else if dataLo ≤ addr ∧ addr < dataHi then
    .data
  else
    .unmapped

def alias32 (addr : UInt64) : UInt32 := UInt64.toUInt32 addr

structure Arena where
  bytes : Bytes
deriving Repr, DecidableEq

structure ImageArena where
  code : Bytes
  data : Bytes
deriving Repr, DecidableEq

def ImageArena.Valid (arena : ImageArena) : Prop :=
  arena.code.length ≤ maxCodeSize

theorem code_base_region : regionOf codeBase = .code := by
  unfold regionOf codeLo codeHi codeBase dataBase
  decide

theorem data_base_region : regionOf dataBase = .data := by
  unfold regionOf codeLo codeHi dataLo dataHi codeBase dataBase addressSpaceSize addressBits
  decide

end PVM2
end Jar
