# PVM Recompiler Optimization

Lessons learned from building and optimizing the javm x86-64 JIT recompiler
to match/beat the polkavm v0.30.0 compiler backend (March 2026).

## Benchmark Setup

Two workloads comparing grey recompiler vs polkavm v0.30.0 compiler:
- **fib**: 1M iterations of iterative Fibonacci (pure register ALU + branches)
- **hostcall**: 100K `ecalli` invocations (host-call-heavy)

Gas limit: 100M. Both produce identical results and gas counts. Every benchmark
iteration includes full compilation + execution (realistic JAM model where each
work-package arrives as a blob that must be compiled fresh).

## Performance Journey

### Host-call path (early work)

| Stage | fib | hostcall | Notes |
|-------|-----|----------|-------|
| Initial recompiler | 2.6ms | 4.9ms | host-call re-entry was O(n) |
| After dispatch table + env var caching | 2.6ms | 0.81ms | host-call path fixed |

### Compute path (gas metering + codegen)

| Stage | fib | hostcall | vs polkavm fib |
|-------|-----|----------|----------------|
| Per-instruction gas metering | ~2,700 us | ~700 us | ~6.3x slower |
| Per-basic-block gas + fused gas check | ~510 us | ~680 us | ~1.21x slower |
| Cold OOG stubs + inc/dec | **425 us** | **679 us** | **1.05x faster** |

### Final results (all backends)

| Workload | grey-interpreter | grey-recompiler | polkavm-interpreter | polkavm-compiler |
|----------|-----------------|-----------------|--------------------|--------------------|
| fib      | 10.8ms          | **425 us**      | 9.4ms              | 445 us             |
| hostcall | 0.91ms          | **679 us**      | 2.6ms              | 3,331 us           |

Grey recompiler beats polkavm compiler on both workloads: ~5% faster on pure
compute, ~4.9x faster on host-call-heavy code.

## Architecture Overview

### Register Mapping

All 13 PVM registers are mapped 1:1 to x86-64 registers, eliminating
load/store overhead for register access:

```
PVM register  x86-64 register
-----------   ---------------
phi[0]        RBX       (callee-saved)
phi[1]        RBP       (callee-saved)
phi[2]        R12       (callee-saved)
phi[3]        R13       (callee-saved)
phi[4]        R14       (callee-saved)
phi[5]        RSI
phi[6]        RDI
phi[7]        R8        (A0 — result register)
phi[8]        R9
phi[9]        R10
phi[10]       R11
phi[11]       RAX
phi[12]       RCX
```

Special registers:
- **R15** = CTX pointer (`JitContext` struct with gas, memory, PC, etc.)
- **RDX** = SCRATCH (temporary, not mapped to any PVM register)

### JitContext Layout

The `JitContext` is a `repr(C)` struct at known offsets from R15:

| Offset | Field | Size | Description |
|--------|-------|------|-------------|
| 0 | regs[0..13] | 104 | PVM registers phi[0..12] (13 x u64) |
| 104 | gas | 8 | Signed gas counter |
| 112 | memory_ptr | 8 | Guest memory pointer |
| 120 | exit_reason | 4 | Exit code |
| 124 | exit_arg | 4 | Exit argument |
| 128 | heap_base | 4 | Heap base address |
| 132 | heap_top | 4 | Current heap top |
| 136 | jt_ptr | 8 | Jump table pointer |
| 144 | jt_len | 4 | Jump table length |
| 152 | bb_starts | 8 | Basic block starts array |
| 160 | bb_len | 4 | BB starts length |
| 168 | entry_pc | 4 | Re-entry PVM PC |
| 172 | pc | 4 | Current PC on exit |
| 176 | dispatch_table | 8 | PC-to-native-offset table |
| 184 | code_base | 8 | Native code base address |

All context access is `[R15 + constant_offset]` — single-instruction memory ops.
The layout test (`test_jit_context_layout`) verifies offsets match codegen
constants at compile time.

### Compilation Pipeline

1. **Deblob**: Parse standard program blob into code bytes + bitmask
2. **Basic block analysis**: Identify instruction starts and branch targets
3. **Gas block analysis**: `compute_gas_blocks()` finds actual control-flow
   basic block boundaries (branch targets, fallthrough after terminators,
   ecalli re-entry points)
4. **Code generation**: Single-pass emit of x86-64 instructions with label
   placeholders
5. **Label resolution**: Backpatch all jump targets with resolved rel32 offsets
6. **Dispatch table**: Build PVM-PC-to-native-offset mapping for re-entry

## Optimization Details

### 1. Per-basic-block gas metering (~5.2x impact on fib)

**Problem**: The initial recompiler treated every PVM instruction as a basic
block start, emitting a gas check (memory load + subtract + compare + branch)
before every single instruction. This meant 5 extra x86 instructions per PVM
instruction — catastrophic for tight loops.

**Fix**: `compute_gas_blocks()` analyzes the PVM instruction stream to find
actual control-flow basic block boundaries:
- The first instruction (PC=0)
- Any instruction that is a branch/jump target
- The instruction after any terminator (branch, jump, ecalli, trap)

Gas is charged once at the start of each basic block for the total cost of all
instructions in that block. For the fib loop (5 PVM instructions), this means
one gas check per iteration instead of five.

**Lesson**: Per-instruction gas metering is the single biggest performance
killer in a recompiler. The gas check itself is cheap, but doing it 5x too
often means 5x the memory traffic and branch prediction pressure. Always
analyze control flow to find the actual basic block boundaries.

### 2. Fused gas check instruction (~1.3x impact)

**Problem**: The gas check was 5 x86 instructions:
```asm
mov rax, [r15 + gas_offset]    ; load gas
sub rax, cost                   ; subtract
mov [r15 + gas_offset], rax    ; store gas
cmp rax, 0                     ; check negative
js  oog_handler                ; branch if OOG
```

**Fix**: Replace with a single memory-immediate subtract that sets flags:
```asm
sub qword [r15 + gas_offset], cost   ; atomic sub + set SF
js  oog_handler                       ; branch if negative
```

This required adding `sub_mem64_imm32` to the assembler:
`REX.W 81 /5 [base+disp32] imm32`.

**Lesson**: x86 ALU instructions can operate directly on memory and set flags.
The `sub [mem], imm` form eliminates the load-modify-store sequence and the
separate compare. This is a 5-to-2 instruction reduction on the hottest path.

### 3. Cold OOG stubs (~1.2x impact)

**Problem**: Before each gas check, the codegen stored the current PVM PC to
memory (`mov dword [r15 + pc_offset], imm32`) so the OOG handler would know
which instruction ran out of gas. This 11-byte store was in every basic block's
hot path, even though OOG almost never fires.

The fib hot loop looked like:
```asm
mov dword [r15+0xac], 0x2d    ; STORE PC (11 bytes) — on hot path!
sub qword [r15+0x68], 5       ; gas check
js  shared_oog_handler
; ... loop body ...
```

**Fix**: Emit per-gas-block OOG stubs as cold code after the main function
body. Each stub stores its specific PC and jumps to the shared OOG handler:

```asm
; Hot path (no PC store):
sub qword [r15+0x68], 5
js  oog_stub_42               ; jumps to cold stub (never taken)
; ... loop body ...

; Cold code (emitted at end of function):
oog_stub_42:
  mov dword [r15+0xac], 0x2d  ; store this block's PC
  jmp shared_oog_handler
```

This moves 11 bytes out of every hot basic block. The only cost is one extra
`jmp` on the OOG path, which is essentially never taken during normal execution.

**Lesson**: Separate hot and cold paths. Any work that's only needed on an
error/exit path should not pollute the hot instruction stream. The CPU's
instruction cache and fetch bandwidth are precious — don't waste them on code
that runs once per million iterations.

### 4. inc/dec for +1/-1 (code size impact)

**Problem**: `add r64, 1` encodes as 7 bytes (`REX.W 81 /0 reg imm32`).

**Fix**: `inc r64` encodes as 3 bytes (`REX.W FF /0 reg`). Same for `dec`.
Applied to `AddImm64` when the immediate is exactly 1 or -1.

The fib loop counter increment went from 7 bytes to 3 bytes, contributing to
the overall loop body shrinking from 70 bytes to 35 bytes.

**Lesson**: Small encoding wins compound. Smaller loops mean better L1i cache
utilization and fewer instruction fetch cycles.

### 5. O(1) dispatch table for host-call re-entry (~6x impact on hostcall)

**Problem**: When re-entering native code after a host call, the prologue
jumped to the correct basic block using a linear scan:
```asm
cmp edx, 0    ; is it PC 0?
je  bb_0
cmp edx, 5    ; is it PC 5?
je  bb_5
; ... one compare+branch per basic block
```

For 100K host calls, this was O(N * 100K) total comparisons.

**Fix**: Build a dispatch table at compile time — an array indexed by PVM PC
containing the native code offset for that PC. The prologue becomes O(1):
```asm
mov edx, [r15 + entry_pc]            ; load target PC
mov rax, [r15 + dispatch_table]      ; load table pointer
movsxd rax, dword [rax + rdx*4]      ; table lookup (SIB scale=4)
add rax, [r15 + code_base]           ; absolute address
jmp rax                               ; jump to target
```

**Lesson**: Re-entry dispatch tables are standard in JIT compilers. Any time
you need to jump from the host back into JIT code at a variable PC, use a
table — never a linear scan.

### 6. Cached environment variable check (hostcall path)

**Problem**: `run()` called `std::env::var("GREY_PVM_DEBUG")` on every
invocation to check whether debug tracing was enabled. With 100K host calls
per benchmark iteration, this was ~2-3ms of overhead.

**Fix**: Cache the debug flag at `RecompiledPvm` construction time.

**Lesson**: Never call `std::env::var()` in a loop. It involves string
scanning at minimum, and may hit the kernel.

## Disassembly Comparison

### Grey fib hot loop (37 bytes)

```asm
sub qword [r15-0xf98], 5      ; 11 bytes: gas -= 5
js  oog_stub                   ;  6 bytes: OOG (forward, always rel32)
mov rsi, r12                   ;  3 bytes: temp = prev
add r13, rsi                   ;  3 bytes: temp += curr
mov r12, r13                   ;  3 bytes: prev = curr
mov rsi, r13                   ;  3 bytes: curr = temp
inc r14                        ;  3 bytes: counter++
cmp r14, rdi                   ;  3 bytes: counter < N?
jb  loop_start                 ;  2 bytes: back-edge (rel8, short jump!)
```

### PolkaVM fib hot loop (33 bytes)

```asm
sub qword [r15-0xfa0], 5      ; 11 bytes: gas -= 5
js  oog_trap                   ;  2 bytes: OOG (rel8)
mov r8, r13                    ;  3 bytes: temp = curr
add r8, r14                    ;  3 bytes: temp += prev
mov r13, r14                   ;  3 bytes: prev = curr
mov r14, r8                    ;  3 bytes: curr = temp
inc r12                        ;  3 bytes: counter++
cmp r12, r9                    ;  3 bytes: counter < N?
jb  loop_start                 ;  2 bytes: back-edge (rel8)
```

The 4-byte difference is from the forward OOG jump: grey uses rel32 (6 bytes)
because the OOG stub is far away (forward jump, distance unknown at emit time).
polkavm uses rel8 (2 bytes) — likely because polkavm emits the OOG stub
inline (close to the check) rather than as cold code at the end. The back-edge
`jb` is now rel8 in both.

## What polkavm Does Differently

1. **Single-pass short jumps for backward branches**: polkavm checks if a
   label is already bound (backward jump) and emits rel8 if it fits within
   +/-127 bytes. Forward jumps always use rel32. We now do the same.
2. **Shared engine with pre-allocated code memory**: The `Engine` object manages
   a memory pool for JIT code. Grey allocates fresh `mmap` pages per compilation.
3. **Module caching**: polkavm separates `Module` (compiled) from `Instance`
   (execution state). A module can be instantiated many times without
   recompilation. Grey currently compiles fresh each invocation.
4. **Generic sandbox**: polkavm's generic sandbox uses SIGSEGV signal handlers
   for OOG trapping in some configurations, avoiding explicit gas checks entirely.
   In the benchmarks we compare against the explicit gas metering mode
   (`GasMeteringKind::Sync`), which is the fair comparison.

## Key Architectural Decisions

### Single-pass compilation

Grey uses a single forward pass over the PVM instruction stream with
backpatching for forward jumps. Labels are allocated eagerly and their offsets
are filled in during `finalize()`. The tradeoff is that we can't use short
jump encodings (which require knowing the distance before emission).

### Host-call via exit + re-entry

When the recompiler hits an `ecalli`, it stores the next PC and exits to the
host. The host processes the call, then re-enters compiled code at the stored
PC via the dispatch table. This is simpler than inlining host-call dispatch
in generated code.

### Dynamic jumps via exit

`jump_ind` (indirect jumps through the jump table) exit to the host for
dispatch rather than inlining the table lookup. This avoids clobbering
PVM-mapped registers (especially RAX/RCX which are used for the lookup)
and keeps codegen simple.

### Compare mode for correctness

The `GREY_PVM=compare` mode runs both interpreter and recompiler in lockstep,
stepping one instruction at a time (gas=1) and comparing all register and gas
state after each instruction. This caught multiple codegen bugs during
development. All 311+ workspace tests and 101 conformance blocks pass in
compare mode.

### Design pattern: dispatch before register load

The prologue performs the dispatch table lookup *before* loading PVM registers
from the context:
1. If the dispatch fails (invalid PC), we don't waste time loading 13
   registers only to immediately store them back on exit
2. The dispatch uses RAX and RDX as scratch, which are PVM register slots
   (phi[11] and SCRATCH). Loading PVM regs first would clobber the dispatch
3. The dispatch target is pushed to the stack, PVM regs are loaded, then
   the target is popped for the final indirect jump

## Future Optimization Opportunities

### Short jumps (rel8 encoding) — ✅ DONE

Backward jumps within ±127 bytes now use rel8 encoding (2 bytes instead of 6).
Single-pass: when emitting a branch, check if the label is already bound;
if so and the distance fits in rel8, emit the short form. No two-pass needed.
Forward jumps always use rel32 since the target distance is unknown.

The remaining 4-byte gap vs polkavm on the fib hot loop is the forward OOG
branch (`js oog_stub`) which must be rel32 because the OOG stub is cold code
at the end of the function.

### Inline memory access — ✅ DONE

Replaced all helper-function-based memory access with inline code:
- **4GB flat buffer** mapped at R15 (guest address N = `[R15 + N]`)
- **1MB permission table** at fixed negative offset from R15
- **RCX freed as second scratch** by spilling phi[12] to context memory
- Fast path: 5-6 x86 instructions per access (perm check + direct load/store)
- Sort benchmark: 60ms → 846µs (71x improvement)
- Remaining gap to polkavm (1.94x) is from the software permission check

### Module caching

Currently, every `run()` call recompiles from the blob. For repeated execution
of the same program (e.g., accumulate calls to the same service), caching the
compiled native code would eliminate compilation overhead entirely.

**Implementation**: Hash the (code, bitmask) pair and cache the native code +
dispatch table in an LRU cache. The `RecompiledPvm` already owns these — just
need a cache keyed by content hash.

### Inline host-call dispatch

For common host calls (e.g., `gas`, `lookup`), inlining the dispatch in
generated code would eliminate the exit/re-entry overhead. This is most
impactful for the hostcall benchmark where grey already dominates (5.1x faster
than polkavm) due to lighter exit/re-entry machinery.

### Partial register save/restore

On ecalli exit, all 12 live PVM registers (phi[12] is spilled) are stored to
the context, and on re-entry all 12 are loaded back. A liveness analysis could
identify which registers are actually live across the host call and only
save/restore those.

### SIMD for bulk memory operations

Programs that copy or zero large memory regions could benefit from SSE2/AVX2
bulk operations. Not currently a bottleneck in benchmarks but relevant for
real-world workloads with large preimage reads.
