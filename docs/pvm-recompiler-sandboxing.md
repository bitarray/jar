# PVM Recompiler Sandboxing: Design Analysis

## Problem Statement

PolkaVM's compiler backend requires spawning sandbox worker processes even when
`sandboxing_enabled = false`. This uses Linux namespaces, `clone3()`, `userfaultfd`,
and `seccomp` — syscalls commonly blocked in containers, CI runners, and locked-down
production environments. The result: **polkavm's JIT simply doesn't work** in Docker,
Kubernetes pods, GitHub Actions, devcontainers, or any environment with seccomp
profiles or restricted capabilities.

Our grey recompiler already works in these environments. This document analyzes why,
compares the approaches, and proposes how to maintain security without OS-level
sandboxing.

## PolkaVM Compiler Architecture

### Worker Process Model

PolkaVM's compiler backend is **architecturally dependent** on a separate worker
process, regardless of security settings:

```
Host Process                     Worker Process
┌──────────────────┐            ┌──────────────────┐
│ Compile PVM→x86  │            │                  │
│ into shared mem  │──memfd────▶│ Guest memory     │
│                  │            │ Guest code (RX)  │
│ Set vmctx.PC     │            │ vmctx struct     │
│ Wake futex ──────│──futex────▶│ Execute JIT code │
│ Wait futex ◀─────│──futex────│ Set exit reason  │
│ Read result      │            │                  │
└──────────────────┘            └──────────────────┘
```

The worker exists because polkavm maps guest code at **fixed low addresses**
(0x0000–0xFFFFFFFF) that would collide with the host's address space. The worker
provides a clean address space for this mapping.

### What `sandboxing_enabled = false` Actually Does

Setting `sandboxing_enabled = false` only disables:
- Security checks on memory access patterns
- Some page-permission enforcement

It does **not** disable:
- Worker process creation (`clone3` / `clone`)
- Linux namespace creation (`CLONE_NEWPID`, `CLONE_NEWNS`, etc.)
- `userfaultfd` for demand paging
- `memfd_create` for shared memory
- `futex` for host↔worker synchronization

The worker is an **execution requirement**, not a security feature.

### Syscalls That Fail in Containers

| Syscall | Purpose | Blocked By |
|---------|---------|------------|
| `clone3` / `clone` with namespace flags | Worker creation | seccomp, no `CAP_SYS_ADMIN` |
| `userfaultfd` | Demand paging | seccomp, no `CAP_SYS_PTRACE` |
| `mount` (tmpfs) | Filesystem isolation | no `CAP_SYS_ADMIN` |
| `pivot_root` | Filesystem isolation | no `CAP_SYS_ADMIN` |
| `prctl(PR_SET_SECCOMP)` | Syscall filtering | already under seccomp |
| `unshare` | Namespace separation | no `CAP_SYS_ADMIN` |

PolkaVM's `generic-sandbox` alternative runs in-process using signal handlers
(`SIGSEGV`/`SIGILL`) but is marked experimental and provides no real isolation.

## Grey Recompiler Architecture

### In-Process JIT Model

Our recompiler runs JIT code **directly in the host process** without any OS-level
isolation:

```
Host Process
┌─────────────────────────────────────────────────┐
│ Compile PVM→x86 into mmap'd buffer (RW→RX)     │
│                                                 │
│ JitContext (repr(C), heap-allocated):            │
│   regs[13], gas, memory*, exit_reason, ...      │
│                                                 │
│ entry(ctx_ptr)  ──→  Native x86-64 code         │
│   ◀── returns when exit_reason set              │
│                                                 │
│ All memory access via helper fn calls:           │
│   mem_read_u8(ctx, addr) → bounds-checked       │
│   mem_write_u32(ctx, addr, val) → bounds-checked│
└─────────────────────────────────────────────────┘
```

### Why It Works Everywhere

- **No child processes**: Single-threaded, in-process execution
- **No namespaces**: No `clone`, `unshare`, or `clone3`
- **No special syscalls**: Only `mmap`/`mprotect`/`munmap` (universally available)
- **No signal handlers**: Faults detected by Rust code in helper functions, not signals
- **No shared memory**: JitContext is a regular heap allocation

### Current Safety Model

**Memory isolation** is enforced at the *software* level, not the OS level:

1. **All guest memory accesses go through helper functions** (`mem_read_u8`, etc.)
   that call into the `Memory` struct's bounds-checked methods
2. **Guest code cannot issue arbitrary memory loads/stores** — the compiler emits
   `call` instructions to helpers, not raw `mov [addr], val`
3. **Executable memory is read-only after compilation** — `mprotect(PROT_READ | PROT_EXEC)`
   prevents the JIT code from modifying itself
4. **R15 is reserved** for the JitContext pointer; guest code cannot clobber it
   (callee-saved, restored in epilogue)
5. **Gas metering** checks at every basic block boundary prevent infinite loops
6. **The native stack (RSP) is never exposed** to guest computation

## Threat Analysis: Do We Need OS-Level Sandboxing?

### What We're Protecting Against

In the JAM protocol, PVM code comes from **untrusted service authors**. A malicious
service could submit PVM bytecode designed to:

| Threat | Risk Level | Current Mitigation |
|--------|------------|-------------------|
| Read host memory | **Low** | All loads go through helper functions |
| Write host memory | **Low** | All stores go through helper functions |
| Execute arbitrary syscalls | **None** | JIT code has no `syscall` instruction |
| Infinite loops / DoS | **None** | Gas metering at every BB |
| Stack overflow | **None** | Guest doesn't control RSP |
| JIT spray / code injection | **None** | Code buffer is RX (not RWX) |
| Corrupt JitContext | **Low** | R15 is callee-saved; only helpers write exit fields |
| Side-channel / timing | **Medium** | Not mitigated (same as polkavm) |

### The Critical Invariant

Our safety rests on one invariant:

> **Every guest memory access is mediated by a helper function call.**

If this invariant holds, guest code cannot escape the `Memory` abstraction regardless
of what instructions it contains. The compiler never emits raw memory operations
against guest addresses — it always calls a helper that validates the address
through the `Memory` struct.

### Comparison with PolkaVM's Security

| Property | PolkaVM (Linux sandbox) | Grey (in-process) |
|----------|------------------------|-------------------|
| Memory isolation | OS-level (separate address space) | Software (helper functions) |
| Syscall prevention | seccomp filter | No `syscall` emitted |
| Resource limits | rlimits (stack, heap, nproc) | Gas metering |
| Filesystem access | Mount namespace | N/A (no file ops) |
| Network access | Network namespace | N/A (no network ops) |
| Portability | Linux x86-64 only | Any x86-64 OS |
| Container support | Broken | Works everywhere |
| Performance overhead | futex handoff per exit | Direct function call |
| Side channels | Same exposure | Same exposure |

PolkaVM's sandbox defends against a broader class of attacks (kernel exploits,
speculative execution) but at the cost of portability and with the same side-channel
exposure. For blockchain consensus — where determinism matters more than
defending against kernel exploits — the software approach is more practical.

## Design Recommendations

### 1. Keep the In-Process Model

The in-process JIT model is the right choice for a blockchain node PVM:

- **Determinism**: No inter-process communication means no race conditions or
  timing variations from futex scheduling
- **Portability**: Works in containers, VMs, CI, embedded — anywhere with `mmap`
- **Performance**: No context-switch overhead for host calls (critical for
  accumulate/refine which make many host calls)
- **Simplicity**: ~500 lines of execution scaffolding vs polkavm's ~3000

### 2. Harden the Software Boundary

To strengthen the current model without OS-level sandboxing:

**A. Compiler verification pass** (recommended, low effort):
After compilation, scan the emitted x86-64 for disallowed instructions:
- `syscall` / `sysenter` (0x0F 0x05 / 0x0F 0x34)
- `int` (0xCD)
- `in` / `out` (0xE4-E7, 0xEC-EF)

This is a defense-in-depth check — our compiler should never emit these, but
verifying the output catches compiler bugs.

**B. Guard pages around JitContext** (recommended, low effort):
Allocate the JitContext with guard pages before and after:
```rust
// mmap guard page (PROT_NONE) | JitContext | mmap guard page (PROT_NONE)
```
This turns any buffer overflow from the JIT code into a hard SIGSEGV instead
of silent corruption.

**C. W^X enforcement** (already implemented):
The code buffer transitions from RW→RX before execution. Never RWX.

**D. Register contract verification** (optional, for debug builds):
In debug builds, verify after JIT returns that R15 still points to the
JitContext (catches register clobber bugs in the compiler).

### 3. Do NOT Add OS-Level Sandboxing

Adding `seccomp`, namespaces, or worker processes would:
- Break container deployments (the exact problem polkavm has)
- Add complexity with minimal security benefit for our threat model
- Introduce non-determinism through OS scheduler interactions
- Require Linux-specific code paths

The PVM threat model is **deterministic computation with bounded resources**,
not **arbitrary code execution**. Software-level mediation is sufficient and
more appropriate.

### 4. Consider `prctl(PR_SET_MDWE)` on Supported Kernels (Optional)

Linux 6.3+ supports Memory-Deny-Write-Execute at the process level:
```rust
prctl(PR_SET_MDWE, MDWE_REFUSE_EXEC_GAIN, 0, 0, 0);
```
This prevents any memory region from being both writable and executable
simultaneously, hardening the W^X guarantee at the OS level. Unlike
namespaces/seccomp, this single prctl call works in containers. It should be
applied opportunistically (best-effort, not required).

## Guest Memory Access: The Real Performance Gap

The sandboxing doc above argues our in-process model is correct for security.
But it has a significant **performance cost** for memory-heavy workloads that
must be addressed.

### The Problem

PolkaVM's compiler backend maps guest memory at a fixed base address in the
worker process. A guest load becomes a single native instruction:

```x86
; polkavm: load_u32 rd, [ra + imm]
lea  edx, [ra_reg + imm]
mov  rd_reg, dword [guest_base + rdx]     ; 1 instruction, ~1-4 cycles
```

Our recompiler now uses **inline memory access** with a flat buffer and
permission table (Option A below, implemented):

```x86
; grey: load_u32 rd, [ra + imm]  —  5 instructions (fast path)
lea  edx, [ra_reg + imm]                       ; guest address
mov  ecx, edx
shr  ecx, 12                                   ; page index
cmp  byte [r15 + rcx - 1052672], 1             ; permission check
jb   page_fault_exit
mov  rd_reg, dword [r15 + rdx]                 ; direct load
```

That is **5 instructions** vs polkavm's **1 instruction**. The gap is from
the software permission check (3 instructions) that polkavm avoids by using
hardware page protection (mprotect + SIGSEGV).

A sort benchmark (1K u32 insertion sort) measures this directly:
grey-recompiler = 846µs, polkavm-compiler = 436µs (1.94x gap).

### Design Options

Three approaches, from simplest to most aggressive:

#### Option A: Flat backing buffer + inline permission check — ✅ IMPLEMENTED

Replaced the `BTreeMap<u32, PageData>` with:
- A **contiguous backing buffer** for guest data, `mmap`'d with
  `MAP_NORESERVE` (lazy physical allocation)
- A **page permission table** — one byte per page (1MB for 2^20 pages)
- Both pointers stored in JitContext for direct access from JIT code

The compiler emits inline checks instead of helper calls:

```x86
; load_u32 rd, [ra + imm]  —  fast path: 6 instructions
lea  edx, [ra_reg + imm]          ; guest address (32-bit)
mov  eax, edx
shr  eax, 12                      ; page index
movzx eax, byte [perm_base + rax] ; load permission byte
test eax, READABLE                 ; check readable bit
jz   page_fault_exit              ; cold path, rarely taken
mov  rd_reg, dword [buf_base + rdx] ; DIRECT memory access
```

**Cost**: ~6 instructions on the fast path. No function call, no register
save/restore. The page fault path is cold (branch predictor will learn).

**Memory overhead**: One `mmap(MAP_NORESERVE)` up to 4GB virtual (but only
touched pages consume physical memory). Plus 1MB for the permission table.
Typical PVM programs use <1MB of pages, so physical usage is small.

**Security**: The guest buffer is at a known base address in the host
process. Guest code still cannot access it directly — the JIT compiler
controls what instructions are emitted and the guest address is always added
to `buf_base` (a register or context field), not used raw. A compiler bug
could produce an out-of-bounds access, but the buffer is bounded at 4GB and
the address is 32-bit, so it cannot reach host memory outside the buffer.

**Compatibility**: `mmap(MAP_NORESERVE)` works everywhere including
containers. No special syscalls required.

This is implemented. The actual improvement was **71x** on memory-heavy code
(sort benchmark: 60ms → 846µs). The implementation goes further than originally
planned: R15 points directly to guest memory (eliminating a pointer load per
access), the permission table is at a fixed negative offset from R15 (enabling
SIB+disp32 addressing in a single instruction), and RCX is freed as a second
scratch register by spilling phi[12] to context memory (eliminating push/pop
RAX per access).

#### Option B: Signal-handler page protection

Map the backing buffer and use `mprotect` to match PVM page permissions to
real OS page permissions (PROT_NONE for inaccessible, PROT_READ for
read-only, PROT_READ|PROT_WRITE for read-write). Guest accesses become a
single `mov` instruction; page faults are caught by a SIGSEGV handler.

```x86
; load_u32 rd, [ra + imm]  —  1 instruction
mov  rd_reg, dword [buf_base + ra_reg + imm]
; page fault → SIGSEGV → handler sets exit_reason, longjmp/siglongjmp back
```

**Pros**: Lowest possible per-access cost (1 instruction, same as polkavm).
No permission check overhead for valid accesses.

**Cons**:
- Signal handlers are **global and non-composable** — a SIGSEGV from a host
  bug is indistinguishable from a guest page fault
- `mprotect` must be called on every `sbrk` or page-mode change (syscall)
- `siglongjmp` from signal handler is technically unsafe in Rust
- Signal handler races in multi-threaded host code
- This is exactly what polkavm's "experimental" generic-sandbox does, and
  it's marked non-production for good reason

**Verdict**: Not recommended unless the permission-check overhead from
Option A proves to be a bottleneck (it shouldn't be — the `test`+`jz` is
essentially free on modern CPUs with branch prediction).

#### Option C: Keep helpers, but optimize them

Minimal change: replace the `BTreeMap` in `Memory` with a flat array and
remove the `std::env::var()` calls from helper functions.

**Improvement**: BTreeMap lookup (O(log n)) → array index (O(1)). The helper
call overhead (~20 instructions for save/restore) remains.

**Verdict**: Quick win as a stepping stone. Not sufficient long-term for
memory-heavy workloads due to the inherent function call overhead.

### Implementation Status for Option A — ✅ DONE

What was implemented (see `crates/javm/src/recompiler/`):

1. **`FlatMemory` struct** in `mod.rs`: contiguous mmap region containing
   permission table (1MB) + JitContext (4KB page) + guest memory (4GB).
   All MAP_NORESERVE for lazy physical allocation.

2. **R15 = guest memory base**: JitContext is at `R15 - 4096` (negative
   offset). Permission table at `R15 - 1052672`. Guest address N is at
   `[R15 + N]` — single instruction, matching polkavm.

3. **RCX freed as second scratch**: phi[12] spilled to context memory,
   freeing RCX for the permission check without push/pop overhead.

4. **Permission encoding**: `0x00`=inaccessible, `0x01`=read-only,
   `0x02`=read-write. Checked via `cmp byte [R15 + page_idx - offset], min`.

5. **Cross-page handling**: Skipped on the fast path (flat buffer is
   contiguous, so cross-page loads/stores work at the hardware level).
   Permission checked for the first byte's page only — minor spec deviation
   at page boundaries.

6. **BTreeMap bypassed**: Host-call memory access uses `read_byte`/
   `write_byte` methods that go directly to the flat buffer. The BTreeMap
   `Memory` is only synced lazily when `memory()` is explicitly called
   (debugging/compare mode).

### Cost Summary

| Approach | Per-access cost | Portability | Status |
|----------|----------------|-------------|--------|
| BTreeMap helper (original) | ~25 insn + O(log n) | Everywhere | Replaced |
| **Option A (flat + inline)** | **~5 insn + O(1)** | **Everywhere** | **✅ Deployed** |
| Option B (signal handler) | ~1 insn | Fragile | Not recommended |
| PolkaVM (separate process) | ~1 insn | Containers broken | N/A |

Option A delivered a 71x improvement on memory-heavy workloads (sort benchmark).
The remaining 1.94x gap to polkavm is from the software permission check
(3 instructions) which can only be eliminated by PVM spec changes (contiguous
linear memory model — see `pvm-redesign.md`).

## Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Execution model | In-process JIT | Portability, performance, simplicity |
| Memory safety | Inline permission check + flat buffer | Fast path without function calls |
| OS sandboxing | None required | Breaks containers, minimal benefit |
| W^X | Already enforced (RW→RX) | Defense in depth |
| Hardening | Instruction scan + guard pages | Catches compiler bugs |
| Side channels | Not mitigated | Same as polkavm; out of scope for consensus |

Our recompiler's in-process model is not a security compromise — it's a
**deliberate architectural choice** that trades OS-level isolation (which
polkavm proves is fragile in practice) for portability, determinism, and
simplicity. The flat-buffer approach closes the memory-access performance gap
to within **1.94x** of polkavm's direct mapping, while preserving the property
that **all guest memory accesses are compiler-controlled** — the JIT never
emits raw addresses from guest registers without adding R15 (the buffer base).
