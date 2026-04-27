import Jar.JAVM

/-!
# JAVM Capability Types

Capability-based execution model for the jar1 variant. Defines five
program capability types (UNTYPED, DATA, CODE, HANDLE, CALLABLE) and
the cap table, VM state machine, ecalli/ecall dispatch, and capability
indirection.

This module defines the data structures only. Execution logic is in
`Jar.JAVM.Kernel`.
-/

namespace Jar.JAVM.Cap

-- ============================================================================
-- Capability Types
-- ============================================================================

/-- Memory access mode, set at MAP time. -/
inductive Access where
  /-- Read-only. -/
  | ro : Access
  /-- Read-write. -/
  | rw : Access
  deriving BEq, Inhabited, Repr

/-- Cap entry type in the blob manifest. -/
inductive ManifestCapType where
  /-- Code capability entry. -/
  | code : ManifestCapType
  /-- Data capability entry. -/
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
  /-- UNTYPED: bump allocator for page allocation. -/
  | untyped (u : UntypedCap) : Cap
  /-- DATA: physical pages with exclusive mapping. -/
  | data (d : DataCap) : Cap
  /-- CODE: compiled PVM code. -/
  | code (c : CodeCap) : Cap
  /-- HANDLE: VM owner, supports CALL and management. -/
  | handle (h : HandleCap) : Cap
  /-- CALLABLE: VM entry point, copyable. -/
  | callable (c : CallableCap) : Cap
  /-- PROTOCOL: kernel-handled host call slot. -/
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
  /-- 256 slots, each optionally holding a cap. -/
  slots : Array (Option Cap)
  /-- Per-slot original bitmap (256 bits). True = slot holds original
  kernel-populated protocol cap. Set to false on DROP, MOVE-in, or MOVE-out. -/
  originalBitmap : Array Bool
  deriving Inhabited

namespace CapTable

/-- Empty cap table with 256 empty slots. -/
def empty : CapTable :=
  { slots := Array.replicate 256 none
    originalBitmap := Array.replicate 256 false }

/-- Get the cap at a slot index. -/
def get (t : CapTable) (idx : Nat) : Option Cap :=
  if idx < t.slots.size then t.slots[idx]! else none

/-- Set a cap at a slot index. Clears original bitmap for protocol slots. -/
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

/-- Take (remove) a cap from a slot, returning the cap table and the removed cap. -/
def take (t : CapTable) (idx : Nat) : CapTable × Option Cap :=
  if idx < t.slots.size then
    let c := t.slots[idx]!
    ({ slots := t.slots.set! idx none
       originalBitmap := if idx < 29 then t.originalBitmap.set! idx false
                         else t.originalBitmap }, c)
  else (t, none)

/-- Check if a slot is empty. -/
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
  /-- Idle: can be CALLed. -/
  | idle : VmState
  /-- Executing. -/
  | running : VmState
  /-- Blocked at CALL, waiting for REPLY. -/
  | waitingForReply : VmState
  /-- Clean exit (terminal). -/
  | halted : VmState
  /-- Panic/OOG/page fault (RESUMEable). -/
  | faulted : VmState
  deriving BEq, Inhabited, Repr

/-- A single VM instance. -/
structure VmInstance where
  /-- Current lifecycle state. -/
  state : VmState
  /-- Index into the kernel's codeCaps array. -/
  codeCapId : Nat
  /-- Register file (13 registers). -/
  registers : JAVM.Registers
  /-- Program counter. -/
  pc : Nat
  /-- Capability table (CNode). -/
  capTable : CapTable
  /-- Caller VM index for REPLY routing. -/
  caller : Option Nat
  /-- Entry point index within the code cap. -/
  entryIndex : Nat
  /-- Remaining gas. -/
  gas : Nat
  deriving Inhabited

/-- Call frame saved on the kernel's call stack. -/
structure CallFrame where
  /-- VM index of the caller. -/
  callerVmId : Nat
  /-- IPC cap slot index transferred during CALL. -/
  ipcCapIdx : Option Nat
  /-- Whether the IPC DATA cap had a base_offset/access mapping. -/
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
  | protocolCall (slot : Nat) (regs : JAVM.Registers) (gas : Nat) : DispatchResult
  /-- Root VM halted normally. -/
  | rootHalt (value : Nat) : DispatchResult
  /-- Root VM panicked. -/
  | rootPanic : DispatchResult
  /-- Root VM out of gas. -/
  | rootOutOfGas : DispatchResult

-- ============================================================================
-- Protocol Cap Numbering (slots 1-28, IPC at slot 0)
-- ============================================================================

-- Protocol cap IDs. Slot 0 = IPC (REPLY). Protocol caps at slots 1-28.
/-- Slot 1: Ω_G query remaining gas. -/
def protocolGas := 1
/-- Slot 2: Ω_E fetch preimage data. -/
def protocolFetch := 2
/-- Slot 3: Ω_H historical state lookup. -/
def protocolPreimageLookup := 3
/-- Slot 4: Ω_R read from own storage. -/
def protocolStorageR := 4
/-- Slot 5: Ω_W write to own storage. -/
def protocolStorageW := 5
/-- Slot 6: Ω_I service info query. -/
def protocolInfo := 6
/-- Slot 7: Ω_H historical lookup (accumulation variant). -/
def protocolHistorical := 7
/-- Slot 8: Ω_E export segment data. -/
def protocolExport := 8
/-- Slot 9: Ω_compile compile code. -/
def protocolCompile := 9
-- 10-14 reserved (was peek/poke/pages/invoke/expunge)
/-- Slot 15: Ω_B set privileged services. -/
def protocolBless := 15
/-- Slot 16: Ω_A assign core authorization. -/
def protocolAssign := 16
/-- Slot 17: Ω_D designate validator keys. -/
def protocolDesignate := 17
/-- Slot 18: Ω_C checkpoint gas. -/
def protocolCheckpoint := 18
/-- Slot 19: Ω_N create new service. -/
def protocolServiceNew := 19
/-- Slot 20: Ω_U upgrade service code. -/
def protocolServiceUpgrade := 20
/-- Slot 21: Ω_T transfer balance. -/
def protocolTransfer := 21
/-- Slot 22: Ω_Q remove service. -/
def protocolServiceEject := 22
/-- Slot 23: Ω preimage query. -/
def protocolPreimageQuery := 23
/-- Slot 24: Ω_S solicit preimage. -/
def protocolPreimageSolicit := 24
/-- Slot 25: Ω_F forget preimage. -/
def protocolPreimageForget := 25
/-- Slot 26: Ω_Y yield accumulation output. -/
def protocolOutput := 26
/-- Slot 27: Ω_P provide preimage data. -/
def protocolPreimageProvide := 27
/-- Slot 28: Ω_M quota management. -/
def protocolQuota := 28

-- ============================================================================
-- JAR Blob Format
-- ============================================================================

/-- JAR magic: 'J','A','R', 0x02. -/
def jarMagic : UInt32 := 0x02524148

/-- Capability manifest entry from the blob. -/
structure CapManifestEntry where
  /-- Capability slot index in the cap table. -/
  capIndex : Nat
  /-- Type of capability (code or data). -/
  capType : ManifestCapType
  /-- Starting page in the address space. -/
  basePage : Nat
  /-- Number of pages. -/
  pageCount : Nat
  /-- Initial access mode. -/
  initAccess : Access
  /-- Byte offset into the blob data section. -/
  dataOffset : Nat
  /-- Length of data in bytes. -/
  dataLen : Nat
  deriving Inhabited

/-- Parsed JAR header. -/
structure ProgramHeader where
  /-- Number of memory pages requested. -/
  memoryPages : Nat
  /-- Number of capabilities in the manifest. -/
  capCount : Nat
  /-- Cap slot to invoke on start. -/
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

end Jar.JAVM.Cap
