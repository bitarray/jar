import Jar.Basic
import Jar.Cap

namespace Jar

inductive KernelImage where
  | root
  | cnode
  | gas
  | quota
  | yield
  | debug
deriving Repr, DecidableEq, BEq

structure GasHandle where
  remaining : Nat
deriving Repr, DecidableEq

structure QuotaHandle where
  remaining : Nat
deriving Repr, DecidableEq

structure YieldSender where
  source : Hash
  key : Key
  payload : Bytes
deriving Repr, DecidableEq

structure YieldReceiver where
  owner : Hash
  key : Key
  target : SlotPath
deriving Repr, DecidableEq

def YieldReceiver.catches (recv : YieldReceiver) (sender : YieldSender) : Bool :=
  recv.key == sender.key

inductive RouteTarget where
  | instance (path : SlotPath)
  | kernel (image : KernelImage)
deriving Repr, DecidableEq

structure EdgeSnapshot where
  receivers : List YieldReceiver
  kernelRoot : KernelImage
deriving Repr, DecidableEq

def findReceiver (sender : YieldSender) : List YieldReceiver → Option YieldReceiver
  | [] => none
  | recv :: rest =>
      if recv.catches sender then some recv else findReceiver sender rest

def routeYield (snapshot : EdgeSnapshot) (sender : YieldSender) : Option RouteTarget :=
  match findReceiver sender snapshot.receivers with
  | some recv => some (.instance recv.target)
  | none =>
      if sender.key.isKernelYieldNamespace then
        some (.kernel snapshot.kernelRoot)
      else
        none

def kernelOogKey : Key := Key.singleton kernelYieldNamespace
def kernelDebugKey : Key := ⟨[kernelYieldNamespace, 1]⟩

inductive KernelError where
  | outOfGas
  | quotaExceeded
  | invalidCapability
  | noReceiver
  | denied
deriving Repr, DecidableEq

def chargeGas (handle : GasHandle) (amount : Nat) : Except KernelError GasHandle :=
  if amount ≤ handle.remaining then
    .ok { remaining := handle.remaining - amount }
  else
    .error .outOfGas

def consumeQuota (handle : QuotaHandle) (amount : Nat) : Except KernelError QuotaHandle :=
  if amount ≤ handle.remaining then
    .ok { remaining := handle.remaining - amount }
  else
    .error .quotaExceeded

theorem kernel_key_routes_to_kernel (snapshot : EdgeSnapshot) (sender : YieldSender)
    (h : findReceiver sender snapshot.receivers = none)
    (hk : sender.key.isKernelYieldNamespace = true) :
    routeYield snapshot sender = some (.kernel snapshot.kernelRoot) := by
  unfold routeYield
  rw [h, hk]
  simp

end Jar
