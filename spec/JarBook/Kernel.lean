import VersoManual
import Jar.JAVM.Kernel

open Verso.Genre Manual
open Jar.JAVM.Kernel

set_option verso.docstring.allowMissing true

#doc (Manual) "Capability Kernel" =>

The capability kernel is the execution engine that schedules VMs, dispatches
capability operations, and mediates all inter-VM communication. It sits between
the JAVM instruction execution (which runs native code or interpreted bytecode)
and the host (grey-state's refine/accumulate logic).

In jar1, the kernel replaces gp072's flat host-call dispatch. Instead of a
single VM calling numbered host functions directly, jar1 VMs invoke capabilities
via `ecalli` (CALL a cap) and `ecall` (management ops). Protocol capabilities
(storage, preimages, transfers) exit to the host through the kernel's protocol
cap dispatch. User capabilities (HANDLE, CALLABLE) trigger synchronous VM
context switches within the kernel.

# Kernel State

{docstring KernelState}

The kernel maintains a pool of VM instances, a call stack for CALL/REPLY
routing, compiled CODE caps, a shared backing store for physical pages,
and the UNTYPED bump allocator.

# Kernel Results

When the kernel needs host interaction or the root VM terminates, it returns
a `KernelResult` to the caller.

{docstring KernelResult}

# Capability Dispatch Results

Internal dispatch within the kernel produces a `DispatchResult` that determines
whether execution continues, a protocol cap was invoked, or the root VM
terminated.

{docstring Jar.JAVM.Cap.DispatchResult}

# Capability Indirection Resolution

Cap slot references use a u32 HANDLE-chain encoding (up to 3 levels of
indirection). Resolution walks the chain, validating each intermediate
HANDLE's target VM is accessible (non-RUNNING, non-WAITING).

{docstring resolveCapRef}

# CALL and REPLY

CALL on a HANDLE or CALLABLE suspends the caller (RUNNING to WAITING\_FOR\_REPLY),
transfers gas to the callee, and starts the callee (IDLE to RUNNING). Arguments
pass via phi\[7..10\]. REPLY pops the call frame, returns unused gas, and resumes
the caller.

# VM Creation (RETYPE + CREATE)

RETYPE allocates physical pages from the UNTYPED bump allocator, producing
an unmapped DATA cap.

{docstring handleRetype}

CREATE instantiates a new VM from a CODE cap with a bitmask-selected subset
of capabilities from the CODE cap's CNode.

{docstring handleCreate}

# Memory Management

MAP and UNMAP control which pages of a DATA cap are present in a VM's address
space. Only the owning CNode can map/unmap — no aliasing across VMs.

{docstring handleMap}

{docstring handleUnmap}

# Data Transfer

CALL on a DATA cap copies pages between two DATA caps' backing store regions.
This is the kernel's memcpy primitive for inter-VM data transfer.

{docstring handleCallData}

# Cap Table Operations

{docstring handleSplit}

{docstring handleDrop}

{docstring handleMove}

{docstring handleCopy}

{docstring handleDowngrade}

{docstring handleSetMaxGas}

# RESUME

RESUME restarts a FAULTED VM with fresh gas, preserving registers and PC.
The faulting instruction is retried. This enables the pager pattern: the
parent maps the missing page via indirection, then RESUMEs the child.

{docstring handleResume}

# ecall Dispatch

The `ecall` instruction dispatches management operations and dynamic CALL.
phi\[11\] selects the operation, phi\[12\] encodes subject (high u32) and
object (low u32) with indirection.

{docstring dispatchEcall}

# Kernel Initialization and Execution

{docstring initKernel}

The main kernel loop runs the active VM, dispatches ecalli/ecall results,
handles CALL/REPLY/fault transitions, and exits to the host on protocol cap
invocations.

{docstring runKernel}
