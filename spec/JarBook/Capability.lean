import VersoManual
import Jar.PVM.Capability

open Verso.Genre Manual

set_option verso.docstring.allowMissing true

#doc (Manual) "JAVM Capability System" =>

The JAVM extends the base PVM with an seL4-style capability system. Code and data
are separate (Harvard architecture) — a CODE cap is opaque, you cannot read its
instructions as data. CALL is a synchronous function call between VMs, not a process
spawn. Any protocol capability (FETCH, STORAGE_R, etc.) can be transparently
replaced with a CALLABLE to a wrapper VM for policy enforcement.

Five program capability types govern memory, code, and VM ownership. Protocol
capabilities provide kernel services (storage, preimages, transfers) via the same
CALL interface. The cap table (256 slots, u8 index) holds all capabilities for a VM.

# Capability Types

Six capability variants: five program types and one protocol type. Copyable types
(UNTYPED, CODE, CALLABLE, Protocol) can be duplicated via COPY and propagated to
child VMs via CREATE bitmask. Move-only types (DATA, HANDLE) require GRANT for
cross-VM transfer.

{docstring Jar.PVM.Cap.Cap}

{docstring Jar.PVM.Cap.Cap.isCopyable}

{docstring Jar.PVM.Cap.Access}

## DATA: Physical Pages (Move-Only)

DATA caps represent physical memory pages with exclusive mapping. Only one VM can
map a DATA cap at a time — no aliasing, no reference counting. Access mode (RO/RW)
is set at MAP time, not at creation. GRANT/REVOKE/CALL auto-unmap DATA caps
crossing VM boundaries.

{docstring Jar.PVM.Cap.DataCap}

## UNTYPED: Bump Allocator

UNTYPED is a bump allocator for physical page allocation. Copyable — multiple VMs
can hold copies and allocate independently. CALL on UNTYPED = RETYPE: carves pages
from the pool and returns an unmapped DATA cap. Pages are never returned (leaky by
design). Placed at fixed slot 254; omitted when `memory_pages == 0`.

{docstring Jar.PVM.Cap.UntypedCap}

## CODE: Compiled PVM Code

CODE caps hold compiled PVM bytecode (interpreter or recompiler backend). Harvard
architecture — code is not in the data address space. Each CODE cap owns a 4GB
virtual window shared by all VMs running that code. CALL on CODE = CREATE: produces
a new VM with a HANDLE.

{docstring Jar.PVM.Cap.CodeCap}

## HANDLE and CALLABLE: VM References

HANDLE is the unique owner of a VM — not copyable, provides CALL plus management
operations (GRANT, REVOKE, DROP, DIRTY, SET_MAX_GAS, DOWNGRADE). CALLABLE is a
copyable entry point — CALL only. DOWNGRADE(HANDLE) creates a CALLABLE with the
HANDLE's current gas limit baked in. Different CALLABLEs to the same VM can have
different gas ceilings.

{docstring Jar.PVM.Cap.HandleCap}

{docstring Jar.PVM.Cap.CallableCap}

## Protocol Caps

Protocol caps are kernel-handled services (storage, preimages, transfers, etc.)
invoked via CALL — identical interface to calling a VM. Any protocol cap can be
replaced with a CALLABLE to a wrapper VM, enabling transparent policy enforcement.
The child code is identical either way.

{docstring Jar.PVM.Cap.ProtocolCap}

{docstring Jar.PVM.Cap.ManifestCapType}

# Cap Table

Each VM has a 256-slot cap table (u8 index). Slot layout:

- **\[0..63\]**: Protocol caps + copyable via CREATE bitmask (u64 covers these slots)
- **\[64..253\]**: Program caps (CODE, DATA, HANDLE, CALLABLE)
- **\[254\]**: UNTYPED (fixed slot, omitted when memory_pages == 0)
- **\[255\]**: IPC slot — CALL on \[255\] = REPLY; caps passed via CALL arrive here

Child VMs receive caps from the parent: slots 0-63 via CREATE bitmask (copyable
types only), slots 64-254 via GRANT after creation, slot 255 populated by each CALL.

{docstring Jar.PVM.Cap.ipcSlot}

{docstring Jar.PVM.Cap.CapTable}

{docstring Jar.PVM.Cap.CapTable.empty}

{docstring Jar.PVM.Cap.CapTable.get}

{docstring Jar.PVM.Cap.CapTable.set}

{docstring Jar.PVM.Cap.CapTable.take}

{docstring Jar.PVM.Cap.CapTable.isEmpty}

# VM Lifecycle

VMs follow a strict state machine: IDLE (can be CALLed) → RUNNING (executing) →
WAITING_FOR_REPLY (blocked at CALL) or terminal (HALTED/FAULTED). Only IDLE VMs
can be CALLed — this prevents reentrancy by construction. Call graphs are acyclic
at all times.

CALL suspends the caller (RUNNING → WAITING_FOR_REPLY), transfers gas to the
callee, and starts the callee (IDLE → RUNNING). REPLY pops the call frame, returns
unused gas, and resumes the caller (WAITING_FOR_REPLY → RUNNING).

{docstring Jar.PVM.Cap.VmState}

{docstring Jar.PVM.Cap.VmInstance}

{docstring Jar.PVM.Cap.CallFrame}

# ecalli Dispatch

All capability operations use `ecalli(imm)`. Two encoding ranges:

- **CALL** (`imm < 256`): invoke cap\[imm\]. Behavior depends on cap type — UNTYPED
  (RETYPE), CODE (CREATE), HANDLE/CALLABLE (run VM), Protocol (kernel service),
  DATA (returns WHAT). `ecalli(0xFF)` = REPLY (CALL on IPC slot).
- **Management ops** (`imm >= 256`): `op = imm >> 8`, `cap = imm & 0xFF`. Kernel-only,
  not replaceable. MAP, UNMAP, SPLIT, DROP, MOVE, COPY, GRANT, REVOKE, DOWNGRADE,
  SET_MAX_GAS, DIRTY.

Register convention: phi\[7..10\] = 4 args, phi\[12\] = DATA cap index. Return in
phi\[7\], phi\[8\]. Memory-accessing ops take offsets within the DATA cap, not VM
address space pointers — this makes protocol cap replacement transparent.

{docstring Jar.PVM.Cap.EcalliOp}

{docstring Jar.PVM.Cap.decodeEcalli}

{docstring Jar.PVM.Cap.DispatchResult}

# Protocol Cap Numbering

Protocol cap slot numbers match GP host call IDs. Absent caps are empty slots
(CALL returns WHAT). Services available in both refine and accumulate: GAS (0),
FETCH (1), COMPILE (8), CHECKPOINT (17). Accumulate-only: STORAGE_R (3),
STORAGE_W (4), INFO (5), SERVICE_NEW (18), TRANSFER (20), OUTPUT (25), and others.
Refine-only: HISTORICAL (6), EXPORT (7).

{docstring Jar.PVM.Cap.protocolGas}

{docstring Jar.PVM.Cap.protocolFetch}

{docstring Jar.PVM.Cap.protocolPreimageLookup}

{docstring Jar.PVM.Cap.protocolStorageR}

{docstring Jar.PVM.Cap.protocolStorageW}

{docstring Jar.PVM.Cap.protocolInfo}

{docstring Jar.PVM.Cap.protocolHistorical}

{docstring Jar.PVM.Cap.protocolExport}

{docstring Jar.PVM.Cap.protocolCompile}

{docstring Jar.PVM.Cap.protocolBless}

{docstring Jar.PVM.Cap.protocolAssign}

{docstring Jar.PVM.Cap.protocolDesignate}

{docstring Jar.PVM.Cap.protocolCheckpoint}

{docstring Jar.PVM.Cap.protocolServiceNew}

{docstring Jar.PVM.Cap.protocolServiceUpgrade}

{docstring Jar.PVM.Cap.protocolTransfer}

{docstring Jar.PVM.Cap.protocolServiceEject}

{docstring Jar.PVM.Cap.protocolPreimageQuery}

{docstring Jar.PVM.Cap.protocolPreimageSolicit}

{docstring Jar.PVM.Cap.protocolPreimageForget}

{docstring Jar.PVM.Cap.protocolOutput}

{docstring Jar.PVM.Cap.protocolPreimageProvide}

{docstring Jar.PVM.Cap.protocolQuota}

# Program Blob Format (JAR v2)

Programs are distributed as capability manifest blobs. The blob header declares
the total memory budget and which CODE/DATA caps to create at init. The kernel
parses the manifest, compiles CODE caps, maps DATA caps, writes arguments into
the args cap (slot 255), and invokes the program at PC=0 via CALL.

{docstring Jar.PVM.Cap.jarMagic}

{docstring Jar.PVM.Cap.ProgramHeader}

{docstring Jar.PVM.Cap.CapManifestEntry}

# Limits

Capability indices are u8 (256 slots per VM). VM identifiers are u16 (max 65535
per invocation). Memory pages are u32. These bounds define the resource envelope
for a single PVM invocation.

{docstring Jar.PVM.Cap.maxCodeCaps}

{docstring Jar.PVM.Cap.maxVms}

{docstring Jar.PVM.Cap.gasPerPage}
