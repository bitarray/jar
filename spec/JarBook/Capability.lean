import VersoManual
import Jar.JAVM.Capability

open Verso.Genre Manual

set_option verso.docstring.allowMissing true

#doc (Manual) "JAVM Capability System" =>

The JAVM extends the base PVM with an seL4-style capability system. Code and data
are separate (Harvard architecture) — a CODE cap is opaque, you cannot read its
instructions as data. CALL is a synchronous function call between VMs, not a process
spawn. Any protocol capability (FETCH, STORAGE\_R, etc.) can be transparently
replaced with a CALLABLE to a wrapper VM for policy enforcement.

Five program capability types govern memory, code, and VM ownership. Protocol
capabilities provide kernel services (storage, preimages, transfers) via the same
CALL interface. The cap table (256 slots, u8 index) holds all capabilities for a VM.
Each cap table is a CNode — operations resolve cap references through HANDLE chains
(capability indirection), enabling cross-CNode management without GRANT/REVOKE.

Two PVM instructions handle all capability operations: `ecalli` (CALL a cap, subject
in immediate, compiler can optimize) and `ecall` (management ops + dynamic CALL,
subject/object in registers, always kernel dispatch). Registers phi\[7..10\] have
the same meaning in both instructions.

# Capability Types

Six capability variants: five program types and one protocol type. Copyable types
(UNTYPED, CODE, CALLABLE, Protocol) can be duplicated via COPY and propagated to
child VMs via CREATE bitmask. Move-only types (DATA, HANDLE) require MOVE for
cross-CNode transfer.

{docstring Jar.JAVM.Cap.Cap}

{docstring Jar.JAVM.Cap.Cap.isCopyable}

{docstring Jar.JAVM.Cap.Access}

## DATA: Physical Pages (Move-Only, Partial Mapping)

DATA caps represent physical memory pages with exclusive mapping. Only one CNode can
map a DATA cap at a time — no aliasing, no reference counting. Access mode (RO/RW)
and base offset are set on first MAP and fixed thereafter. Individual pages within
the cap can be mapped or unmapped independently via a per-page bitmap, enabling
demand paging: a parent VM maps pages one at a time through HANDLE indirection.

MOVE to a different CNode auto-unmaps all pages. DROP auto-unmaps and leaks pages.

{docstring Jar.JAVM.Cap.DataCap}

## UNTYPED: Bump Allocator

UNTYPED is a bump allocator for physical page allocation. Copyable — multiple VMs
can hold copies and allocate independently. CALL on UNTYPED = RETYPE: carves pages
from the pool and returns an unmapped DATA cap at a caller-specified destination
slot. Pages are never returned (leaky by design). Placed at fixed slot 254; omitted
when `memory\_pages == 0`.

{docstring Jar.JAVM.Cap.UntypedCap}

## CODE: Compiled PVM Code

CODE caps hold compiled PVM bytecode (interpreter or recompiler backend). Harvard
architecture — code is not in the data address space. Each CODE cap owns a 4GB
virtual window shared by all VMs running that code. CALL on CODE = CREATE: produces
a new VM with a HANDLE. The CREATE bitmask copies caps from the CODE cap's CNode
(not the caller's), so cap replacements propagate automatically to children.

{docstring Jar.JAVM.Cap.CodeCap}

## HANDLE and CALLABLE: VM References

HANDLE is the unique owner of a VM — not copyable, provides CALL plus management
operations via ecall (DOWNGRADE, SET\_MAX\_GAS, DIRTY, RESUME). CALLABLE is a
copyable entry point — CALL only. DOWNGRADE(HANDLE) creates a CALLABLE with the
HANDLE's current gas limit baked in. Different CALLABLEs to the same VM can have
different gas ceilings.

RESUME (ecall op 0x0D) restarts a FAULTED VM with fresh gas, preserving registers
and PC. This enables the pager pattern: parent fixes the environment (maps missing
pages via indirection), then RESUMEs the child transparently.

{docstring Jar.JAVM.Cap.HandleCap}

{docstring Jar.JAVM.Cap.CallableCap}

## Protocol Caps

Protocol caps are kernel-handled services (storage, preimages, transfers, etc.)
invoked via CALL — identical interface to calling a VM. Any protocol cap can be
replaced with a CALLABLE to a wrapper VM, enabling transparent policy enforcement.
The child code is identical either way.

{docstring Jar.JAVM.Cap.ProtocolCap}

{docstring Jar.JAVM.Cap.ManifestCapType}

# Capability Indirection

Cap slot references are u32 with byte-packed HANDLE chain indirection (3 levels max):

- *byte 0*: target cap slot (0-255)
- *byte 1*: indirection level 0 (0x00 = end of chain, 1-255 = HANDLE slot)
- *byte 2*: indirection level 1
- *byte 3*: indirection level 2

Slot 0 (IPC) cannot be used for indirection (byte=0x00=end of chain).
`(u8 as u32)` zero-extended = local slot, backward compatible. Each intermediate
VM must be non-RUNNING (IDLE or FAULTED).

This enables zero-copy I/O to descendant VMs (protocol caps write directly into
a child's backing pages), cross-CNode cap management (MOVE replaces GRANT/REVOKE),
and demand paging (parent MAPs pages in child's address space via indirection +
RESUME).

# Cap Table

Each VM has a 256-slot cap table (u8 index), forming a CNode. Slot layout:

- \[0\]: IPC slot — CALL on \[0\] = REPLY; caps passed via CALL arrive here
- \[1..28\]: Protocol caps (GAS=1, FETCH=2, ..., QUOTA=28; gaps at 10-14 reserved)
- \[29..63\]: Program caps (within CREATE bitmask range, u64 covers slots 0-63)
- \[64..253\]: Program caps
- \[254\]: UNTYPED (fixed slot, omitted when memory\_pages == 0)
- \[255\]: free

Child VMs receive caps from the parent: slots 0-63 via CREATE bitmask (from the
CODE cap's CNode, copyable types only), slots 64-254 via MOVE after creation.

The per-CNode *original bitmap* (256 bits) tracks which protocol cap slots are
unmodified. The compiler uses this for fast-path inlining of protocol calls.

{docstring Jar.JAVM.Cap.ipcSlot}

{docstring Jar.JAVM.Cap.CapTable}

{docstring Jar.JAVM.Cap.CapTable.empty}

{docstring Jar.JAVM.Cap.CapTable.get}

{docstring Jar.JAVM.Cap.CapTable.set}

{docstring Jar.JAVM.Cap.CapTable.take}

{docstring Jar.JAVM.Cap.CapTable.isEmpty}

# VM Lifecycle

VMs follow a strict state machine: IDLE (can be CALLed) -> RUNNING (executing) ->
WAITING\_FOR\_REPLY (blocked at CALL) or HALTED (terminal) or FAULTED (can be
RESUMEd). Only IDLE VMs can be CALLed — this prevents reentrancy by construction.
Call graphs are acyclic at all times.

CALL suspends the caller (RUNNING -> WAITING\_FOR\_REPLY), transfers gas to the
callee, and starts the callee (IDLE -> RUNNING). REPLY pops the call frame, returns
unused gas, and resumes the caller (WAITING\_FOR\_REPLY -> RUNNING).

RESUME restarts a FAULTED VM (FAULTED -> RUNNING), transferring fresh gas. Registers
and PC are preserved — the faulting instruction is retried. This enables demand
paging: the parent maps the missing page via indirection, then RESUMEs the child.

{docstring Jar.JAVM.Cap.VmState}

{docstring Jar.JAVM.Cap.VmInstance}

{docstring Jar.JAVM.Cap.CallFrame}

# ecalli / ecall Dispatch

Two PVM instructions for all capability operations:

*ecalli(imm)*: CALL a cap. The u32 immediate encodes the subject cap slot with
indirection. phi\[7..11\] = 5 args, phi\[12\] = object cap (u32, indirection).
The compiler can optimize local protocol cap calls via the original bitmap (inline
the handler if the slot is unmodified, generic dispatch otherwise).

*ecall*: management ops + dynamic CALL. phi\[11\] = operation code, phi\[12\] packs
subject (low u32) and object (high u32) with indirection. Always goes to kernel
dispatch — compiler cannot inline.

phi\[7..10\] have the same meaning in both instructions.

{docstring Jar.JAVM.Cap.EcalliOp}

{docstring Jar.JAVM.Cap.decodeEcalli}

{docstring Jar.JAVM.Cap.DispatchResult}

# Protocol Cap Numbering

Protocol cap slots are numbered 1-28 (slot 0 is IPC/REPLY). Absent caps are empty
slots (CALL returns WHAT). Services available in both refine and accumulate: GAS (1),
FETCH (2), COMPILE (9), CHECKPOINT (18). Accumulate-only: STORAGE\_R (4),
STORAGE\_W (5), INFO (6), SERVICE\_NEW (19), TRANSFER (21), OUTPUT (26), and others.
Refine-only: HISTORICAL (7), EXPORT (8).

{docstring Jar.JAVM.Cap.protocolGas}

{docstring Jar.JAVM.Cap.protocolFetch}

{docstring Jar.JAVM.Cap.protocolPreimageLookup}

{docstring Jar.JAVM.Cap.protocolStorageR}

{docstring Jar.JAVM.Cap.protocolStorageW}

{docstring Jar.JAVM.Cap.protocolInfo}

{docstring Jar.JAVM.Cap.protocolHistorical}

{docstring Jar.JAVM.Cap.protocolExport}

{docstring Jar.JAVM.Cap.protocolCompile}

{docstring Jar.JAVM.Cap.protocolBless}

{docstring Jar.JAVM.Cap.protocolAssign}

{docstring Jar.JAVM.Cap.protocolDesignate}

{docstring Jar.JAVM.Cap.protocolCheckpoint}

{docstring Jar.JAVM.Cap.protocolServiceNew}

{docstring Jar.JAVM.Cap.protocolServiceUpgrade}

{docstring Jar.JAVM.Cap.protocolTransfer}

{docstring Jar.JAVM.Cap.protocolServiceEject}

{docstring Jar.JAVM.Cap.protocolPreimageQuery}

{docstring Jar.JAVM.Cap.protocolPreimageSolicit}

{docstring Jar.JAVM.Cap.protocolPreimageForget}

{docstring Jar.JAVM.Cap.protocolOutput}

{docstring Jar.JAVM.Cap.protocolPreimageProvide}

{docstring Jar.JAVM.Cap.protocolQuota}

# Program Blob Format (JAR v2)

Programs are distributed as capability manifest blobs. The blob header declares
the total memory budget and which CODE/DATA caps to create at init. The kernel
parses the manifest, compiles CODE caps, maps DATA caps, writes arguments into
the args cap (slot 0), and invokes the program at PC=0 via CALL.

{docstring Jar.JAVM.Cap.jarMagic}

{docstring Jar.JAVM.Cap.ProgramHeader}

{docstring Jar.JAVM.Cap.CapManifestEntry}

# Limits

Capability indices are u8 (256 slots per VM). VM identifiers are u16 (max 65535
per invocation). Memory pages are u32. Indirection depth is 3 levels (u32 encoding).
These bounds define the resource envelope for a single PVM invocation.

{docstring Jar.JAVM.Cap.maxCodeCaps}

{docstring Jar.JAVM.Cap.maxVms}

{docstring Jar.JAVM.Cap.gasPerPage}
