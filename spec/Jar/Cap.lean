import Jar.Basic
import Jar.SSZ
import Jar.PVM2.Memory

namespace Jar

structure CodeRef where
  image : Hash
  offset : Nat
  length : Nat
deriving Repr, DecidableEq, BEq

structure ArenaPageRef where
  page : Nat
deriving Repr, DecidableEq, BEq

structure DataDesc where
  arenaOffset : Nat
  length : Nat
deriving Repr, DecidableEq, BEq

def DataDesc.Valid (d : DataDesc) (arenaLen : Nat) : Prop :=
  d.arenaOffset + d.length ≤ arenaLen

structure PinnedCap where
  key : Key
  target : Hash
deriving Repr, DecidableEq, BEq

structure EndpointDef where
  key : Key
  entryPc : Nat
deriving Repr, DecidableEq, BEq

structure MemoryMapping where
  virtualPage : Nat
  page : ArenaPageRef
  writable : Bool
deriving Repr, DecidableEq, BEq

structure Image where
  code : CodeRef
  arenaBytes : Nat
  data : List DataDesc
  maps : List MemoryMapping
  imports : List Key
  pinned : List PinnedCap
  endpoints : List EndpointDef
  gasSlots : Nat
  quotaSlots : Nat
deriving Repr, DecidableEq

namespace Image

def pinnedKeys (img : Image) : List Key :=
  img.pinned.map (fun p => p.key)

def importsSatisfiedBy (img : Image) (available : List Key) : Prop :=
  img.imports.all (fun k => available.contains k) = true

def dataInArena (img : Image) : Prop :=
  ∀ d, d ∈ img.data → d.Valid img.arenaBytes

def memoryPagesUnique (img : Image) : Prop :=
  img.maps.map (fun m => m.virtualPage) |>.Pairwise (· ≠ ·)

def Valid (img : Image) : Prop :=
  img.code.length ≤ maxCodeSize ∧
    dataInArena img ∧
    memoryPagesUnique img

end Image

structure DataCap where
  arena : Hash
  desc : DataDesc
deriving Repr, DecidableEq, BEq

structure CNodeSlot where
  key : Key
  target : Hash
deriving Repr, DecidableEq, BEq

structure CNode where
  slots : List CNodeSlot
deriving Repr, DecidableEq

namespace CNode

def lookup (c : CNode) (key : Key) : Option Hash :=
  match c.slots.find? (fun slot => slot.key == key) with
  | some slot => some slot.target
  | none => none

def erase (c : CNode) (key : Key) : CNode :=
  ⟨c.slots.filter (fun slot => !(slot.key == key))⟩

def set (c : CNode) (key : Key) (target : Hash) : CNode :=
  ⟨{ key, target } :: (erase c key).slots⟩

def empty : CNode := ⟨[]⟩

theorem lookup_empty_none (key : Key) : empty.lookup key = none := rfl

end CNode

inductive InstanceStatus where
  | runnable
  | blocked
  | paused
  | exited
deriving Repr, DecidableEq

structure Instance where
  image : Hash
  root : CNode
  memoryRoot : Hash
  status : InstanceStatus
  gas : Nat
  quota : Nat
  pc : Nat
deriving Repr, DecidableEq

inductive CapKind where
  | instance
  | image
  | data
  | cnode
deriving Repr, DecidableEq, BEq

inductive Cap where
  | instance (i : Instance)
  | image (i : Image)
  | data (d : DataCap)
  | cnode (c : CNode)
deriving Repr, DecidableEq

def Cap.kind : Cap → CapKind
  | .instance _ => .instance
  | .image _ => .image
  | .data _ => .data
  | .cnode _ => .cnode

axiom hashImage : Image → Hash
axiom hashCap : Cap → Hash
axiom hashPair : Hash → Key → Hash

noncomputable def genesisImageHash (img : Image) : Hash := hashImage img

noncomputable def extendImageHash (parent : Hash) (key : Key) : Hash :=
  hashPair parent key

def deriveSpawn (imageHash : Hash) (root : CNode) (gas quota : Nat) : Instance :=
  {
    image := imageHash
    root := root
    memoryRoot := zeroHash
    status := .runnable
    gas := gas
    quota := quota
    pc := codeBase
  }

def setImage (inst : Instance) (imageHash : Hash) : Instance :=
  { inst with image := imageHash, pc := codeBase }

def copyInstance (inst : Instance) : Instance := inst

inductive MgmtError where
  | missingSource
  | missingDestination
  | destinationExists
  | sameSlot
deriving Repr, DecidableEq

def mgmtCopy (src : CNode) (dst : CNode) (fromKey toKey : Key) : Except MgmtError CNode :=
  match src.lookup fromKey, dst.lookup toKey with
  | none, _ => .error .missingSource
  | some _, some _ => .error .destinationExists
  | some target, none => .ok (dst.set toKey target)

def mgmtMove (node : CNode) (fromKey toKey : Key) : Except MgmtError CNode :=
  if fromKey == toKey then
    .error .sameSlot
  else
    match node.lookup fromKey, node.lookup toKey with
    | none, _ => .error .missingSource
    | some _, some _ => .error .destinationExists
    | some target, none => .ok ((node.erase fromKey).set toKey target)

def mgmtDrop (node : CNode) (key : Key) : Except MgmtError CNode :=
  match node.lookup key with
  | none => .error .missingSource
  | some _ => .ok (node.erase key)

def mgmtSwap (node : CNode) (left right : Key) : Except MgmtError CNode :=
  if left == right then
    .error .sameSlot
  else
    match node.lookup left, node.lookup right with
    | some l, some r => .ok ((node.set left r).set right l)
    | none, _ => .error .missingSource
    | _, none => .error .missingDestination

end Jar
