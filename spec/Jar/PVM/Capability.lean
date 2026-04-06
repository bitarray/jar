import Jar.PVM

/-!
# PVM Capability Types

Capability-based execution model for the jar1 variant. Defines five
program capability types (UNTYPED, DATA, CODE, HANDLE, CALLABLE) and
the cap table, VM state machine, and ecalli dispatch structure.

This module defines the data structures only. Execution logic is in
`Jar.PVM.Kernel`.
-/

namespace Jar.PVM.Cap

-- ============================================================================
-- Capability Types
-- ============================================================================

/-- Memory access mode, set at MAP time. -/
inductive Access where
  | ro : Access
  | rw : Access
  deriving BEq, Inhabited, Repr

/-- Cap entry type in the blob manifest. -/
inductive ManifestCapType where
  | code : ManifestCapType
  | data : ManifestCapType
  deriving BEq, Inhabited

/-- DATA capability: physical pages with exclusive mapping. Move-only. -/
structure DataCap where
  /-- Offset into the backing memfd (in pages). -/
  backingOffset : Nat
  /-- Number of pages. -/
  pageCount : Nat
  /-- Current mapping: none = unmapped, some (basePage, access) = mapped. -/
  mapped : Option (Nat × Access) := none
  deriving Inhabited

/-- UNTYPED capability: bump allocator. Copyable (shared offset). -/
structure UntypedCap where
  /-- Current bump offset (in pages). -/
  offset : Nat
  /-- Total pages available. -/
  total : Nat
  deriving Inhabited

/-- CODE capability: compiled PVM code. Copyable. -/
structure CodeCap where
  /-- Unique identifier within invocation. -/
  id : Nat
  deriving Inhabited, BEq

/-- HANDLE capability: VM owner. Unique, not copyable. -/
structure HandleCap where
  /-- VM index in the kernel's VM pool. -/
  vmId : Nat
  /-- Per-CALL gas ceiling (inherited by DOWNGRADEd CALLABLEs). -/
  maxGas : Option Nat := none
  deriving Inhabited

/-- CALLABLE capability: VM entry point. Copyable. -/
structure CallableCap where
  /-- VM index in the kernel's VM pool. -/
  vmId : Nat
  /-- Per-CALL gas ceiling. -/
  maxGas : Option Nat := none
  deriving Inhabited

/-- Protocol capability: kernel-handled, replaceable with CALLABLE. -/
structure ProtocolCap where
  /-- Protocol cap ID matching GP host call numbering. -/
  id : Nat
  deriving Inhabited, BEq

/-- A capability in the cap table. -/
inductive Cap where
  | untyped (u : UntypedCap) : Cap
  | data (d : DataCap) : Cap
  | code (c : CodeCap) : Cap
  | handle (h : HandleCap) : Cap
  | callable (c : CallableCap) : Cap
  | protocol (p : ProtocolCap) : Cap
  deriving Inhabited

/-- Whether a capability type supports COPY. -/
def Cap.isCopyable : Cap → Bool
  | .untyped _ => true
  | .code _ => true
  | .callable _ => true
  | .protocol _ => true
  | .data _ => false
  | .handle _ => false

-- ============================================================================
-- Cap Table
-- ============================================================================

/-- IPC slot index. -/
def ipcSlot : Nat := 255

/-- Cap table: 256 slots indexed by u8. -/
structure CapTable where
  slots : Array (Option Cap)
  deriving Inhabited

namespace CapTable

def empty : CapTable := { slots := Array.replicate 256 none }

def get (t : CapTable) (idx : Nat) : Option Cap :=
  if idx < t.slots.size then t.slots[idx]! else none

def set (t : CapTable) (idx : Nat) (c : Cap) : CapTable :=
  if idx < t.slots.size then { slots := t.slots.set! idx (some c) } else t

def take (t : CapTable) (idx : Nat) : CapTable × Option Cap :=
  if idx < t.slots.size then
    let c := t.slots[idx]!
    ({ slots := t.slots.set! idx none }, c)
  else (t, none)

def isEmpty (t : CapTable) (idx : Nat) : Bool :=
  if idx < t.slots.size then t.slots[idx]!.isNone else true

end CapTable

-- ============================================================================
-- VM State Machine
-- ============================================================================

/-- VM lifecycle states. -/
inductive VmState where
  | idle : VmState              -- Can be CALLed
  | running : VmState           -- Executing
  | waitingForReply : VmState   -- Blocked at CALL
  | halted : VmState            -- Clean exit (terminal)
  | faulted : VmState           -- Panic/OOG/page fault (terminal)
  deriving BEq, Inhabited, Repr

/-- A single VM instance. -/
structure VmInstance where
  state : VmState
  codeCapId : Nat
  registers : PVM.Registers
  pc : Nat
  capTable : CapTable
  caller : Option Nat           -- For REPLY routing
  entryIndex : Nat
  gas : Nat
  deriving Inhabited

/-- Call frame saved on the kernel's call stack. -/
structure CallFrame where
  callerVmId : Nat
  ipcCapIdx : Option Nat
  ipcWasMapped : Option (Nat × Access)
  deriving Inhabited

-- ============================================================================
-- ecalli Dispatch
-- ============================================================================

/-- ecalli immediate decoding. -/
inductive EcalliOp where
  /-- CALL cap[N] (N < 256, N=255 = REPLY). -/
  | call (capIdx : Nat) : EcalliOp
  /-- Management op with target cap. -/
  | mgmtMap (capIdx : Nat) : EcalliOp
  | mgmtUnmap (capIdx : Nat) : EcalliOp
  | mgmtSplit (capIdx : Nat) : EcalliOp
  | mgmtDrop (capIdx : Nat) : EcalliOp
  | mgmtMove (capIdx : Nat) : EcalliOp
  | mgmtCopy (capIdx : Nat) : EcalliOp
  | mgmtGrant (capIdx : Nat) : EcalliOp
  | mgmtRevoke (capIdx : Nat) : EcalliOp
  | mgmtDowngrade (capIdx : Nat) : EcalliOp
  | mgmtSetMaxGas (capIdx : Nat) : EcalliOp
  | mgmtDirty (capIdx : Nat) : EcalliOp
  /-- Unknown/invalid immediate. -/
  | unknown : EcalliOp

/-- Decode an ecalli immediate into an operation. -/
def decodeEcalli (imm : Nat) : EcalliOp :=
  if imm < 256 then .call imm
  else
    let op := imm / 256
    let capIdx := imm % 256
    match op with
    | 0x2 => .mgmtMap capIdx
    | 0x3 => .mgmtUnmap capIdx
    | 0x4 => .mgmtSplit capIdx
    | 0x5 => .mgmtDrop capIdx
    | 0x6 => .mgmtMove capIdx
    | 0x7 => .mgmtCopy capIdx
    | 0x8 => .mgmtGrant capIdx
    | 0x9 => .mgmtRevoke capIdx
    | 0xA => .mgmtDowngrade capIdx
    | 0xB => .mgmtSetMaxGas capIdx
    | 0xC => .mgmtDirty capIdx
    | _ => .unknown

/-- Result of CALL dispatch. -/
inductive DispatchResult where
  /-- Continue execution of active VM. -/
  | continue_ : DispatchResult
  /-- Protocol cap called — host should handle. -/
  | protocolCall (slot : Nat) (regs : PVM.Registers) (gas : Nat) : DispatchResult
  /-- Root VM halted normally. -/
  | rootHalt (value : Nat) : DispatchResult
  /-- Root VM panicked. -/
  | rootPanic : DispatchResult
  /-- Root VM out of gas. -/
  | rootOutOfGas : DispatchResult

-- ============================================================================
-- Protocol Cap Numbering (matches GP host call IDs)
-- ============================================================================

/-- Protocol cap IDs matching GP host call numbering. -/
def protocolGas := 0
def protocolFetch := 1
def protocolPreimageLookup := 2
def protocolStorageR := 3
def protocolStorageW := 4
def protocolInfo := 5
def protocolHistorical := 6
def protocolExport := 7
def protocolCompile := 8
-- 9-13 reserved (was peek/poke/pages/invoke/expunge)
def protocolBless := 14
def protocolAssign := 15
def protocolDesignate := 16
def protocolCheckpoint := 17
def protocolServiceNew := 18
def protocolServiceUpgrade := 19
def protocolTransfer := 20
def protocolServiceEject := 21
def protocolPreimageQuery := 22
def protocolPreimageSolicit := 23
def protocolPreimageForget := 24
def protocolOutput := 25
def protocolPreimageProvide := 26
def protocolQuota := 27

-- ============================================================================
-- JAR Blob Format
-- ============================================================================

/-- JAR magic: 'J','A','R', 0x02. -/
def jarMagic : UInt32 := 0x02524148

/-- Capability manifest entry from the blob. -/
structure CapManifestEntry where
  capIndex : Nat
  capType : ManifestCapType
  basePage : Nat
  pageCount : Nat
  initAccess : Access
  dataOffset : Nat
  dataLen : Nat
  deriving Inhabited

/-- Parsed JAR header. -/
structure ProgramHeader where
  memoryPages : Nat
  capCount : Nat
  invokeCap : Nat
  deriving Inhabited

-- ============================================================================
-- Limits
-- ============================================================================

/-- Maximum CODE caps per invocation. -/
def maxCodeCaps : Nat := 5

/-- Maximum VMs (HANDLEs) per invocation (u16 VM IDs). -/
def maxVms : Nat := 65535

/-- Gas cost per page for RETYPE. -/
def gasPerPage : Nat := 1500

end Jar.PVM.Cap
