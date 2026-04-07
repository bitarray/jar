import Jar.PVM

/-!
# PVM Capability Types

Capability-based execution model for the jar1 variant. Defines five
program capability types (UNTYPED, DATA, CODE, HANDLE, CALLABLE) and
the cap table, VM state machine, ecalli/ecall dispatch, and capability
indirection.

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

/-- DATA capability: physical pages with exclusive mapping and per-page bitmap.

Move-only. Each DATA cap has a single base_offset (set on first MAP) and a
per-page mapped bitmap tracking which pages are present in the address space.
Page P maps to address `base_offset + P * 4096`. -/
structure DataCap where
  /-- Offset into the backing memfd (in pages). -/
  backingOffset : Nat
  /-- Number of pages. -/
  pageCount : Nat
  /-- Base offset in address space (set on first MAP, fixed thereafter). None = unmapped. -/
  baseOffset : Option Nat := none
  /-- Access mode (set on first MAP, fixed thereafter). -/
  access : Option Access := none
  /-- Per-page mapped bitmap. True = page present in address space. -/
  mappedBitmap : Array Bool := #[]
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

/-- HANDLE capability: VM owner. Unique, not copyable.

Provides CALL (run VM) plus management ops via ecall:
DOWNGRADE, SET_MAX_GAS, DIRTY, RESUME. -/
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
  /-- Protocol cap ID. -/
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

/-- Create a copy of this cap (only for copyable types). -/
def Cap.tryCopy : Cap → Option Cap
  | .untyped u => some (.untyped u)
  | .code c => some (.code c)
  | .callable c => some (.callable c)
  | .protocol p => some (.protocol p)
  | .data _ => none
  | .handle _ => none

-- ============================================================================
-- Cap Table (CNode)
-- ============================================================================

/-- IPC slot index. CALL on slot 0 = REPLY. -/
def ipcSlot : Nat := 0

/-- Cap table: 256 slots indexed by u8. Each VM's cap table is a CNode.

The original bitmap tracks which protocol cap slots are unmodified
(for compiler fast-path inlining of ecalli on protocol caps). -/
structure CapTable where
  slots : Array (Option Cap)
  /-- Per-slot original bitmap (256 bits). True = slot holds original
  kernel-populated protocol cap. Set to false on DROP, MOVE-in, or MOVE-out. -/
  originalBitmap : Array Bool
  deriving Inhabited

namespace CapTable

def empty : CapTable :=
  { slots := Array.replicate 256 none
    originalBitmap := Array.replicate 256 false }

def get (t : CapTable) (idx : Nat) : Option Cap :=
  if idx < t.slots.size then t.slots[idx]! else none

def set (t : CapTable) (idx : Nat) (c : Cap) : CapTable :=
  if idx < t.slots.size then
    { slots := t.slots.set! idx (some c)
      originalBitmap := if idx < 29 then t.originalBitmap.set! idx false
                        else t.originalBitmap }
  else t

/-- Set a cap and mark it as original (for kernel init of protocol caps). -/
def setOriginal (t : CapTable) (idx : Nat) (c : Cap) : CapTable :=
  if idx < t.slots.size then
    { slots := t.slots.set! idx (some c)
      originalBitmap := if idx < t.originalBitmap.size then t.originalBitmap.set! idx true
                        else t.originalBitmap }
  else t

def take (t : CapTable) (idx : Nat) : CapTable × Option Cap :=
  if idx < t.slots.size then
    let c := t.slots[idx]!
    ({ slots := t.slots.set! idx none
       originalBitmap := if idx < 29 then t.originalBitmap.set! idx false
                         else t.originalBitmap }, c)
  else (t, none)

def isEmpty (t : CapTable) (idx : Nat) : Bool :=
  if idx < t.slots.size then t.slots[idx]!.isNone else true

end CapTable

-- ============================================================================
-- Capability Indirection
-- ============================================================================

/-- Indirection encoding: u32 byte-packed HANDLE chain.

```
byte 0: target cap slot (0-255)
byte 1: indirection level 0 (0x00 = end, 1-255 = HANDLE slot)
byte 2: indirection level 1 (0x00 = end, 1-255 = HANDLE slot)
byte 3: indirection level 2 (0x00 = end, 1-255 = HANDLE slot)
```

Slot 0 (IPC) cannot be used for indirection. `(u8 as u32)` = local slot. -/
def CapRef := UInt32

/-- Maximum indirection depth (3 levels). -/
def maxIndirectionDepth : Nat := 3

-- ============================================================================
-- VM State Machine
-- ============================================================================

/-- VM lifecycle states.

FAULTED is non-terminal: RESUME can restart a faulted VM,
preserving registers and PC (retries the faulting instruction). -/
inductive VmState where
  | idle : VmState              -- Can be CALLed
  | running : VmState           -- Executing
  | waitingForReply : VmState   -- Blocked at CALL
  | halted : VmState            -- Clean exit (terminal)
  | faulted : VmState           -- Panic/OOG/page fault (RESUMEable)
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
-- ecalli Dispatch (CALL a cap)
-- ============================================================================

/-- ecalli immediate decoding. ecalli is CALL-only — subject cap from
the u32 immediate (with indirection encoding). Management ops use ecall. -/
inductive EcalliOp where
  /-- CALL cap at the resolved slot. -/
  | call (capRef : CapRef) : EcalliOp

/-- Decode an ecalli immediate. Always a CALL. -/
def decodeEcalli (imm : UInt32) : EcalliOp :=
  .call imm

-- ============================================================================
-- ecall Dispatch (Management ops + dynamic CALL)
-- ============================================================================

/-- ecall operation codes (from φ[11]).

Subject and object cap references are packed in φ[12] as two u32
values with indirection encoding: subject = low u32, object = high u32. -/
inductive EcallOp where
  /-- Dynamic CALL (same semantics as ecalli, dynamic subject). -/
  | call : EcallOp
  /-- MAP pages of a DATA cap in its CNode. -/
  | map : EcallOp
  /-- UNMAP pages of a DATA cap in its CNode. -/
  | unmap : EcallOp
  /-- SPLIT a DATA cap. -/
  | split : EcallOp
  /-- DROP (destroy) a cap. -/
  | drop : EcallOp
  /-- MOVE a cap between CNodes. -/
  | move : EcallOp
  /-- COPY a cap between CNodes (copyable types only). -/
  | copy : EcallOp
  /-- DOWNGRADE a HANDLE to CALLABLE. -/
  | downgrade : EcallOp
  /-- SET_MAX_GAS on a HANDLE. -/
  | setMaxGas : EcallOp
  /-- Read dirty bitmap of a child's DATA cap. -/
  | dirty : EcallOp
  /-- RESUME a FAULTED VM. -/
  | resume : EcallOp
  /-- Unknown/invalid op. -/
  | unknown : EcallOp

/-- Decode an ecall operation from φ[11]. -/
def decodeEcall (op : Nat) : EcallOp :=
  match op with
  | 0x00 => .call
  | 0x02 => .map
  | 0x03 => .unmap
  | 0x04 => .split
  | 0x05 => .drop
  | 0x06 => .move
  | 0x07 => .copy
  | 0x0A => .downgrade
  | 0x0B => .setMaxGas
  | 0x0C => .dirty
  | 0x0D => .resume
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
-- Protocol Cap Numbering (slots 1-28, IPC at slot 0)
-- ============================================================================

/-- Protocol cap IDs. Slot 0 = IPC (REPLY). Protocol caps at slots 1-28. -/
def protocolGas := 1
def protocolFetch := 2
def protocolPreimageLookup := 3
def protocolStorageR := 4
def protocolStorageW := 5
def protocolInfo := 6
def protocolHistorical := 7
def protocolExport := 8
def protocolCompile := 9
-- 10-14 reserved (was peek/poke/pages/invoke/expunge)
def protocolBless := 15
def protocolAssign := 16
def protocolDesignate := 17
def protocolCheckpoint := 18
def protocolServiceNew := 19
def protocolServiceUpgrade := 20
def protocolTransfer := 21
def protocolServiceEject := 22
def protocolPreimageQuery := 23
def protocolPreimageSolicit := 24
def protocolPreimageForget := 25
def protocolOutput := 26
def protocolPreimageProvide := 27
def protocolQuota := 28

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
