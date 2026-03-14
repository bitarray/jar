# PVM Redesign: Optimizing for Recompilation + Execution Speed

An analysis of PVM's design limitations as a recompilation target, and a
proposal for what an ideal "recompiler-first" ISA would look like.

## The Premise

PVM is described as a "modified RISC-V instruction set meant to make
recompilation easy." After building a full recompiler for PVM and optimizing it,
we can assess whether this claim holds up. The conclusion: **PVM makes
recompilation possible, but not easy or fast.** Several design choices actively
work against efficient native code generation.

The pipeline is: RISC-V → (transpile) → PVM → (recompile) → x86-64. We don't
care about transpile speed (it's a one-time cost at module upload). We want to
minimize **recompile time** (PVM → native) and **execution time** (native code
performance).

## Current PVM Design Problems

### 1. Variable-Length Encoding + Bitmask: The Worst of Both Worlds

PVM uses a variable-length encoding (1-10 bytes per instruction) with a
separate **bitmask** that marks which bytes are instruction starts. This is
the most problematic design choice.

**Why it exists**: RISC-V compressed instructions are 2 or 4 bytes. The
transpiler maps each RV instruction to a variable-length PVM instruction.
The bitmask records which offsets are instruction starts vs. continuation
bytes, enabling the VM to distinguish data bytes from opcode bytes.

**Why it's bad for recompilation**:

- **O(n) decode pass required**: Before any compilation can begin, the
  recompiler must walk the entire bytecode with the bitmask to identify
  instruction boundaries. This is inherently serial — you can't decode
  instruction N without knowing where instruction N-1 ends.

- **PC-relative branches use byte offsets**: Branch targets are encoded as
  byte offsets into the variable-length stream. To resolve a branch target,
  the recompiler must check the bitmask to verify the target is a valid
  instruction start. This means branch validation requires random access
  into the bitmask.

- **Dispatch table is indexed by byte offset**: Our dispatch table (for
  host-call re-entry) must be sized to the code length in bytes, not the
  number of instructions. A 10KB program has ~400 instructions but needs a
  10K-entry dispatch table. Most entries are -1 (invalid).

- **Cache-unfriendly**: Instructions are packed tightly with variable
  widths, which is good for code size but bad for decode throughput. A
  fixed-width format lets the decoder process instructions in parallel
  with SIMD.

**Comparison**: RISC-V itself has this problem with compressed instructions
(16-bit vs 32-bit), which is why RISC-V recompilers are hard. PVM was
supposed to fix this but didn't — it just moved the problem from 2-vs-4
bytes to 1-to-10 bytes, making it worse.

### 2. Operand Encoding: Packed Nibbles with Implicit Decoding Rules

Register operands are packed into nibbles (4 bits per register) with
`min(12, ...)` clamping. Immediates use variable-length sign-extended
encoding with sizes determined by the `skip` distance. This means:

- **Decode cost per instruction**: Every instruction decode requires
  computing `skip` from the bitmask, then using `skip` to determine how
  many bytes the immediate occupies, then sign-extending. This is ~10
  operations per instruction just for decode.

- **13 registers in 4-bit field**: 4 bits can encode 0-15, but only 0-12
  are valid (clamped with `min(12, ...)`). The remaining 3 encodings (13,
  14, 15) are wasted. This isn't a register allocation problem — it's an
  encoding waste.

- **Sign extension complexity**: Immediates can be 0, 1, 2, 3, or 4 bytes
  depending on `skip`. The sign extension logic (`X_n` in the Gray Paper)
  has special cases for each size. A fixed immediate width eliminates this
  entirely.

### 3. Memory Access Requires Mediation

PVM's memory model (4KB pages with per-page R/W/Inaccessible permissions)
means every memory access must be permission-checked. With a variable-length
ISA, you can't just map guest memory to a fixed region and let the CPU handle
it — the recompiler must emit explicit checks or use helper function calls.

This is not inherently a PVM ISA problem — it's a memory model problem. But
the ISA design doesn't help: there's no way for the transpiler to annotate
which memory accesses are provably safe, and the 32-bit address space means
a full 4GB backing buffer is needed for zero-copy mapping.

### 4. Dynamic Jumps Through an Indirection Table

`jump_ind` (indirect jump) goes through a "jump table" — a separate data
structure that maps indices to valid branch targets. The encoding is:

```
addr = (φ[ra] + imm) % 2^32
if addr == 0xFFFF0000: halt
idx = addr/2 - 1
target = jump_table[idx]
```

This is **three levels of indirection**: register → address → table index →
target PC. In our recompiler, we currently exit to the host for every
dynamic jump because inlining this would clobber PVM-mapped registers. This
means every `jump_ind` is a full exit/re-entry cycle.

**Why it exists**: Safety. The jump table ensures you can only jump to valid
basic block starts. But this could be enforced at the ISA level more cheaply.

### 5. Opcode Space is Sparse

Opcodes range from 0 to 230 but many values are unused (e.g., 2-9, 11-19,
21-29, etc.). The instruction categories are numbered in decades (0-1, 10,
20, 30-33, 40, 50-62, ...) which is human-readable but wastes opcode bits.
A 256-opcode space with only ~130 valid values means:

- The opcode validation table is 256 bytes (not a problem per se, but the
  sparse layout means you can't derive the category from the opcode with
  simple arithmetic)
- The compiler's match statement has 130+ arms with gaps

### 6. 32-bit Operations Require Sign Extension

PVM has separate 32-bit and 64-bit variants of most ALU ops (Add32 vs Add64,
Mul32 vs Mul64, etc.). The 32-bit variants must produce a sign-extended
64-bit result. On x86-64, a 32-bit `add eax, ebx` naturally zero-extends to
64 bits, but PVM requires sign-extension. This means every 32-bit ALU
operation needs an extra `movsxd` instruction:

```x86
add  eax, ebx      ; 32-bit add (zero-extends to 64)
movsxd rax, eax    ; PVM requires sign-extension
```

This is a fundamental mismatch with x86-64's zero-extension convention.

### 7. Host Call Requires Full Exit/Re-Entry

`ecalli` is a basic-block terminator. Every host call causes:
1. Store all 13 PVM registers to context
2. Return to host code
3. Host processes the call
4. Re-enter native code: dispatch table lookup + load all 13 registers

Even with our O(1) dispatch table, this is ~30 instructions of overhead per
host call. Real JAM programs make thousands of host calls (memory operations,
state queries, cryptographic operations).

## Proposal: A Recompiler-First ISA

If we could redesign PVM with recompilation speed as the primary goal, here
is what the ISA would look like. The key insight is: **the transpiler
(RISC-V → PVM) can be arbitrarily slow, so we should shift all complexity
there and make PVM trivial to recompile.**

### Design Principle: Pre-Digested IR

PVM should not be a "bytecode" that needs parsing. It should be a
**pre-digested intermediate representation** — essentially a serialized
compiler IR that can be directly lowered to native code with minimal
processing. Think of it as "flatbuffered SSA" rather than "encoded
instructions."

### Change 1: Fixed-Width Instructions (8 bytes)

Every instruction is exactly 8 bytes:

```
┌──────────┬──────┬──────┬──────┬──────────────────────────┐
│ opcode   │  rd  │  ra  │  rb  │     imm32                │
│  8 bits  │ 8b   │ 8b   │ 8b   │     32 bits              │
└──────────┴──────┴──────┴──────┴──────────────────────────┘
```

**Benefits**:
- **No bitmask needed**: Instruction N starts at offset N*8. Period.
- **Parallel decode**: Can process 4 instructions per 32-byte cache line
  with SIMD (extract opcodes from bytes 0, 8, 16, 24).
- **O(1) PC-to-instruction mapping**: `inst_index = pc / 8`. No dispatch
  table needed for re-entry — just multiply.
- **Trivial branch resolution**: Branch target `T` means instruction at
  offset `T * 8`. No bitmask validation.
- **Register fields are full bytes**: No nibble packing, no `min(12, ...)`
  clamping. Register 0-12 fit in a byte; invalid values are simply illegal.
- **Fixed immediate width**: 32 bits, always. No variable-length
  sign-extension. For 64-bit immediates, use a two-instruction sequence
  (the transpiler handles this).

**Cost**: ~2x code size vs current PVM. A 10KB PVM program becomes ~20KB.
This is irrelevant — the program is on-chain as compressed RISC-V, and
PVM is only an in-memory intermediate. The native code is typically 3-5x
the PVM size anyway.

**Alternative — 4-byte fixed width**: If 32-bit immediates are too narrow,
use a 4-byte base instruction with optional 4-byte immediate extension
(indicated by a bit in the opcode). This preserves O(1) decode for
instructions without large immediates while allowing 32-bit immediates when
needed. But 8-byte fixed is simpler and the size cost is negligible.

### Change 2: Basic-Block-Indexed Branches

Branch and jump targets are not byte offsets — they are **basic block
indices**. The program is organized as a sequence of basic blocks, each
with a header:

```
Program = [Block0, Block1, Block2, ...]
Block   = { n_instructions: u16, gas_cost: u16, instructions: [Inst; n] }
```

**Benefits**:
- **Branch validation is free**: Target block index < n_blocks. No bitmask
  check, no basic-block-start verification.
- **Gas metering is pre-computed**: `gas_cost` is in the block header. No
  need to scan instructions to compute block cost at compile time.
- **Dispatch table is tiny**: For re-entry, the table has one entry per
  basic block (not one per byte). A program with 200 basic blocks needs a
  200-entry table, not a 10K-entry table.
- **Natural for SSA/CFG construction**: The recompiler can build a CFG
  directly from the block structure without any analysis.

**How branches work**: `branch_eq ra, rb, target_block` where
`target_block` is a basic block index. The recompiler emits
`cmp ra_reg, rb_reg; je block_N_label`. No offset computation, no
validation.

**Dynamic jumps**: `jump_ind ra` does `target_block = jump_table[φ[ra]]`.
The jump table maps directly to block indices. One level of indirection
instead of three.

### Change 3: Explicit Memory Regions with Annotations

Instead of a flat 32-bit address space with per-page permissions, define
explicit memory regions in the program header:

```
Program header:
  stack_region:  { base: u32, size: u32, perm: RW }
  heap_region:   { base: u32, size: u32, perm: RW }
  rodata_region: { base: u32, size: u32, perm: RO }
```

Memory instructions carry a **region hint**:

```
load_u32_stack  rd, [ra + imm]   ; known to be in stack region
load_u32_heap   rd, [ra + imm]   ; known to be in heap region
load_u32_any    rd, [ra + imm]   ; unknown region, needs full check
```

**Benefits**:
- **Stack/heap accesses can skip permission checks**: If the transpiler
  can prove the access is within a known region, the recompiler emits a
  direct memory access with only a bounds check (which is a single `cmp`).
- **The common case is fast**: Most memory accesses in real programs are
  stack or heap. Only truly dynamic accesses need full permission checks.
- **Bounds can use guard pages**: Map stack and heap regions with guard
  pages at the boundaries. Known-region accesses become a single `mov`
  with no check at all.

The transpiler performs the analysis (which is where complexity should live)
and annotates each memory operation. The recompiler just trusts the
annotation or falls back to the full check for `_any` variants.

### Change 4: Host Calls as Non-Terminating Instructions

`ecalli` should NOT be a basic block terminator. Instead:

```
ecalli imm     ; host call, execution continues at next instruction
```

The recompiler emits a call to a host-call handler as a regular function
call (not an exit/re-entry). Callee-saved PVM registers (φ[0]-φ[4], mapped
to RBX/RBP/R12-R14) survive the call automatically. Only caller-saved
registers need save/restore.

**Benefits**:
- **No exit/re-entry overhead**: No dispatch table lookup, no full register
  save/restore. The cost drops from ~30 instructions to ~10 instructions.
- **Caller-saved optimization**: With 5 callee-saved registers, only 8
  registers need save/restore (or fewer if liveness analysis is done).
- **Inlinable host calls**: Simple host calls (e.g., `gas()` which just
  reads a counter) can be inlined entirely.

**Challenge**: The host-call handler needs access to PVM state (memory,
registers). This is solved by passing the JitContext pointer (R15) as the
first argument. The handler reads/writes registers through the context.
Since caller-saved registers might be stale in the context (they're in
x86 registers), the recompiler must spill live caller-saved registers
before the call. This is exactly what a normal function call does.

**Safety**: If the host call modifies PVM state in a way that affects
control flow (e.g., modifying the PC), that's handled by the return value.
The handler returns a status code; if it indicates "redirect," the
recompiler exits to the dispatch loop. This is the rare case.

### Change 5: Unified 64-bit ALU with Explicit Truncation

Remove all 32-bit ALU instruction variants. Instead:

```
add    rd, ra, rb      ; always 64-bit
trunc32 rd             ; sign-extend lower 32 bits (when needed)
```

The transpiler emits `trunc32` only when the RISC-V source actually
requires 32-bit semantics (RV32 `addw`, `subw`, etc.). For RV64
instructions, no truncation is needed.

**Benefits**:
- **Halves the opcode count for ALU**: ~40 ALU opcodes instead of ~80.
  Simpler compiler, smaller match statements, faster dispatch.
- **Eliminates redundant sign-extension**: Most code is 64-bit. The
  current ISA forces every 32-bit op to emit a `movsxd` even when the
  result is only used as a 64-bit value later.
- **Better for x86-64**: 64-bit operations are the natural width. No
  `movsxd` unless `trunc32` is explicitly present.

### Change 6: Dense Opcode Space

Pack opcodes into a dense 0-127 range:

```
0x00-0x0F: Control flow (trap, halt, ecalli, jump, branch_*)
0x10-0x1F: Loads (load_u8, load_u16, load_u32, load_u64, load_i8, ...)
0x20-0x2F: Stores
0x30-0x4F: ALU (add, sub, mul, div, shifts, bitops)
0x50-0x5F: Comparisons (set_lt, set_gt, cmov)
0x60-0x6F: Bit manipulation (clz, ctz, popcnt, bswap, sext)
0x70-0x7F: Reserved for future extensions
```

**Benefits**:
- **7-bit opcode**: One bit free for an "immediate extension" flag (bit 7
  = 1 means the next 4 bytes are a 32-bit immediate extension, giving
  64-bit immediate capability).
- **Category from opcode**: `category = opcode >> 4`. No lookup table,
  no match statement.
- **Jump table for dispatch**: A 128-entry function pointer table for
  the interpreter. Dense, cache-friendly.

### Change 7: Pre-Computed Metadata in the Program Header

Move all analysis that the recompiler would need to do into the program
header, computed once by the transpiler:

```
Header:
  n_blocks: u32
  n_instructions: u32
  max_register_pressure: u8    ; highest register used
  has_dynamic_jumps: bool      ; whether jump_ind is used
  has_memory_access: bool      ; whether any load/store is used
  blocks: [BlockHeader; n_blocks]

BlockHeader:
  offset: u32          ; instruction offset (= index * 8)
  n_instructions: u16  ; number of instructions in block
  gas_cost: u16        ; pre-computed gas cost
  successors: [u16; 2] ; block indices of fall-through and branch target
```

**Benefits**:
- **Zero-analysis recompilation**: The recompiler doesn't need to scan
  the code to find basic blocks, compute gas costs, or build a CFG.
  Everything is in the header.
- **Parallel compilation**: With block boundaries known upfront, different
  blocks can be compiled in parallel.
- **Code size hints**: `n_instructions` lets the recompiler pre-allocate
  the native code buffer accurately.

## Impact Assessment

### Recompile Time

| Operation | Current PVM | Proposed |
|-----------|-------------|----------|
| Instruction decode | ~10 ops/inst (bitmask + skip + nibble + sext) | ~2 ops/inst (load 8 bytes, extract fields) |
| Branch validation | Bitmask lookup + BB-start check | Block index < n_blocks |
| Gas cost computation | Scan block at compile time | Read from header |
| CFG construction | Implicit from terminators | Explicit from header |
| Dispatch table build | One entry per code byte (~10K) | One entry per block (~200) |
| Memory access codegen | Helper call (~20 insn emitted) | Inline check (~6 insn) or direct (~1 insn) |

**Estimated recompile speedup**: 3-5x for the compile phase itself.

### Execution Time

| Operation | Current PVM (native) | Proposed (native) |
|-----------|---------------------|-------------------|
| Host call overhead | ~30 insn (exit/re-entry) | ~10 insn (function call) |
| Memory access | ~25 insn (helper) or ~6 insn (inline check) | ~1-6 insn (region-annotated) |
| 32-bit ALU | op + movsxd (always) | op only (trunc32 when needed) |
| Dynamic jump | Exit to host (~40 insn) | Table lookup + indirect jump (~8 insn) |
| Gas check | Load/sub/store/cmp/jcc (~5 insn) | Same (~5 insn) |

**Estimated execution speedup**: 2-5x for memory-heavy workloads, 1.3x
for compute-heavy workloads.

### Code Size

| | Current PVM | Proposed |
|---|------------|----------|
| PVM bytecode | 1x | ~2x (fixed-width) |
| Native code (fib) | ~500 bytes | ~400 bytes (fewer movsxd) |
| Native code (memory-heavy) | ~2KB | ~800 bytes (inline vs helper calls) |
| Dispatch table | ~10KB | ~800 bytes |
| Program header | ~50 bytes | ~2KB (block metadata) |

Code size increase is negligible. The PVM bytecode is not stored on-chain
(the RISC-V ELF is). The native code is smaller because the proposed ISA
generates better code.

## What Would Need to Change in the Gray Paper

1. **Instruction encoding**: Replace variable-length encoding + bitmask
   with fixed-width 8-byte instructions.
2. **Program format**: Add block-structured metadata header.
3. **Branch semantics**: Targets become block indices, not byte offsets.
4. **Memory model**: Add region annotations to load/store instructions.
5. **Host calls**: `ecalli` becomes non-terminating.
6. **Opcode table**: Dense 7-bit opcodes instead of sparse 8-bit.
7. **32-bit ops**: Remove; replace with `trunc32` instruction.

These are all **format changes** — the computational semantics are
identical. A conforming implementation produces the same results. The
transpiler absorbs all the complexity of the format change.

## Update: Empirical Results from Recompiler Optimization (March 2026)

After implementing the inline memory optimization described above, we have
concrete benchmark numbers comparing our recompiler to polkavm:

| Benchmark | grey-recompiler | polkavm-compiler | ratio |
|-----------|----------------|------------------|-------|
| **fib** (1M iter, compute-only) | 438 µs | 407 µs | 1.07x |
| **hostcall** (100K ecalli) | 626 µs | 3,192 µs | **0.20x** |
| **sort** (1K u32, memory-heavy) | 846 µs | 436 µs | **1.94x** |

The remaining 1.94x gap on memory-heavy code is almost entirely from the
**software permission check** — 3 instructions per memory access (mov+shr+cmp)
that polkavm avoids by using hardware page protection (mprotect + SIGSEGV).

### What We Implemented (Change 3 Pragmatic Version)

Instead of region annotations in the ISA, we implemented the flat buffer
approach from the sandboxing doc:

- **4GB contiguous mmap** (MAP_NORESERVE) as the guest memory backing buffer
- **1MB permission table** (1 byte per 4KB page: 0=inaccessible, 1=RO, 2=RW)
- **R15 = guest memory base** — guest address N is at `[R15 + N]`, single instruction
- **Permission table at fixed negative offset** — `cmp byte [R15 + page_idx - offset], min_perm`
- **RCX freed as second scratch** by spilling phi[12] to context memory

The inline fast path per memory access is now 5-6 x86-64 instructions:
```x86
mov  ecx, edx                         ; copy guest addr
shr  ecx, 12                          ; page index
cmp  byte [r15 + rcx - 1052672], 2    ; permission check (SIB+disp32)
jb   fault
mov  [r15 + rdx], val_reg             ; direct store
```

vs polkavm's 1 instruction:
```x86
mov  [r15 + rdx], val_reg             ; direct store (hardware checks permissions)
```

### Key Insight: Code is NOT in Guest Memory

A critical observation: **PVM code/bitmask are NOT mapped into the guest
address space.** They exist as separate arrays accessed only by the instruction
fetch mechanism (PC-indexed), not by guest load/store instructions.

The guest memory contains only:
- **RO data** (read-only) — the program's constant data
- **RW data + heap** (read-write, contiguous) — globals, dynamic allocations
- **Stack** (read-write, contiguous) — at top of address space
- **Arguments** (read-only) — input data

This means the read-only pages in guest memory are only the RO data and
arguments sections. All load/store targets are overwhelmingly RW pages
(stack, heap, RW data). The permission check is almost always checking
"is this page mapped?" rather than "is this page writable?".

### Memory Design Change: Contiguous Linear Memory

The most impactful PVM design change for recompiler performance would be
replacing the sparse paged address space with **contiguous linear memory**
(similar to WebAssembly's model):

```
[0 ................ rw_data ... heap_top → .... ← SP ... mem_size)
 |   RW data      |   heap              |  (gap)  | stack        |
```

One contiguous RW region. Stack grows down, heap grows up, within the
same allocation. No per-page permissions, no permission table.

**Permission check becomes a bounds check:**
```x86
cmp  edx, mem_size    ; 1 instruction
jae  trap             ; out of bounds
mov  eax, [r15+rdx]   ; direct access
```

Or with a guard page mapped after the region, **zero instructions** — the
hardware MMU catches out-of-bounds accesses. Unlike per-page mprotect
(which requires a SIGSEGV handler for every inaccessible page), a single
guard region at the end is safe and simple.

**Stack overflow handling:** With linear memory, stack overflow doesn't
trigger a page fault — the stack silently overwrites the heap. This is
acceptable because:
1. Gas metering prevents infinite recursion (OOG catches runaway execution)
2. PVM programs are sandboxed — memory corruption stays within the guest
3. This is the same model as WebAssembly, which has proven it works at scale

**What changes in the spec:**
- Remove per-page access modes (PageAccess enum)
- Memory is a single `[0, mem_size)` RW region
- `sbrk` just bumps a counter (no page mapping)
- Stack and heap share the region (collision = program bug, caught by gas)
- RO data and arguments are loaded into the RW region at init (the transpiler
  ensures the program doesn't write to them — or if it does, that's its own
  problem, not a security issue)

**Impact on recompiler:**
- Permission check: 3 instructions → 0 instructions (with guard page)
- Sort benchmark estimate: 846 µs → ~450 µs (matching polkavm)
- No SIGSEGV handler needed for normal operation
- mmap cost: same (one 4GB region with guard page at end)

### Multi-Region Bounds Checking Doesn't Scale

We considered keeping separate regions (RW data+heap, stack) and doing bounds
checks per region instead of a permission table lookup. With two non-contiguous
RW regions, a write check requires:

```x86
cmp  edx, rw_base        ; in RW+heap?
jb   check_stack
cmp  edx, heap_top
jb   ok
check_stack:
cmp  edx, stack_bottom   ; in stack?
jb   fault
cmp  edx, stack_top
jb   ok
```

That's 4 compares + 3 branches in the worst case — **worse** than the current
3-instruction permission table lookup. Multi-region bounds checking only wins
with a single contiguous region.

## Pragmatic Path Forward

We can't change the Gray Paper, but we can implement these ideas as an
**internal IR** between PVM decode and native code generation:

1. **Pre-decode to fixed-width IR**: We already do this (the `DecodedInst`
   struct in the interpreter). Extend this to the recompiler.
2. **Block-structured compilation**: Already partially done (basic block
   starts array). Formalize it.
3. **Region-annotated memory**: ✅ **DONE** — Implemented flat buffer +
   inline permission check (Option A from sandboxing doc). R15 points
   directly to guest memory; permission table at fixed negative offset.
   Sort benchmark improved 71x (60ms → 846µs). Remaining gap to polkavm
   (1.94x) is from the software permission check.
4. **Inline host calls**: Change `ecalli` from exit/re-entry to a function
   call within native code. This is the biggest remaining win for
   host-call-heavy workloads. Currently grey is 5x faster than polkavm
   on host calls due to in-process execution, but the overhead is still
   ~30 instructions per ecalli.
5. **Eliminate redundant sign-extension**: Peephole optimization in the
   recompiler — if a 32-bit op's result is only used as 64-bit, skip the
   `movsxd`.
6. **Short backward jumps**: ✅ **DONE** — Single-pass rel8 encoding for
   backward branches within ±127 bytes (matching polkavm's approach).
   Zero compile-time overhead.

These changes are compatible with the current PVM bytecode format. The
recompiler's internal pipeline becomes:

```
PVM bytecode → decode → IR (fixed-width, block-structured)
            → compile IR → native code
```

The decode step absorbs the complexity of PVM's variable-length encoding,
and the IR-to-native step gets all the benefits of the proposed redesign.

## Summary

PVM's design prioritizes code density and RISC-V compatibility over
recompilation speed. This is backwards: the transpile step (RISC-V → PVM)
runs once at module upload and can afford to be slow. The recompile step
(PVM → native) runs on every node, every time a service is invoked. The
ISA should be optimized for the step that runs millions of times, not the
step that runs once.

The ideal recompiler target is not a "bytecode" — it's a serialized
compiler IR with pre-computed metadata. Fixed-width instructions,
block-structured layout, region-annotated memory, and dense opcodes make
recompilation almost trivial: read the header, emit native code for each
block, patch branches. No decode, no analysis, no validation.

The good news is that most of these benefits can be captured as internal
optimizations within the recompiler, without changing the on-wire PVM
format. The decode step (which is a one-time cost per program instantiation)
can transform PVM's awkward encoding into a clean IR that the code generator
can process efficiently.
