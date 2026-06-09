import Jar.Basic

namespace Jar
namespace SSZ

def offsetSize : Nat := 4
def chunkSize : Nat := 32

inductive DecodeError where
  | unexpectedEof
  | trailingBytes
  | invalidOffset
  | offsetsNotMonotonic
  | boundExceeded
  | lengthMismatch
  | invalidSelector
  | invalidBool
  | missingBitlistSentinel
  | excessBits
  | notSorted
  | custom (msg : String)
deriving Repr, DecidableEq

inductive TypeDesc where
  | bool
  | uint8
  | uint16
  | uint32
  | uint64
  | bytesN (n : Nat)
  | list (elem : TypeDesc) (limit : Nat)
  | vector (elem : TypeDesc) (n : Nat)
  | container (fields : List (String × TypeDesc))
  | union (variants : List TypeDesc)
deriving Repr

structure Encoded where
  bytes : Bytes
deriving Repr, DecidableEq

def selectorValid (variants : List TypeDesc) (selector : Nat) : Prop :=
  selector < variants.length

def offsetsMonotone : List Nat → Prop
  | [] => True
  | [_] => True
  | a :: b :: rest => a ≤ b ∧ offsetsMonotone (b :: rest)

structure ContainerLayout where
  fixedBytes : Nat
  variableFields : Nat
  offsets : List Nat
deriving Repr, DecidableEq

def ContainerLayout.Valid (layout : ContainerLayout) : Prop :=
  layout.offsets.length = layout.variableFields ∧
    offsetsMonotone layout.offsets ∧
    layout.offsets.all (fun off => layout.fixedBytes ≤ off) = true

structure Merkleized where
  root : Hash
deriving Repr, DecidableEq, BEq

axiom hashTreeRoot : Encoded → Merkleized

end SSZ
end Jar
