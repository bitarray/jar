# PVM Recompiler Optimization

Lessons learned from optimizing the grey-pvm recompiler's host-call re-entry
path (March 2026).

## Benchmark Setup

Same two workloads as the interpreter optimization doc:
- **fib**: 1M iterations of iterative Fibonacci (pure register ALU + branches)
- **hostcall**: 100K `ecalli` invocations (host-call-heavy)

Gas limit: 100M. Comparing grey interpreter, grey recompiler, and polkavm
v0.30.0 interpreter. (PolkaVM compiler backend unavailable in containers — see
`pvm-recompiler-sandboxing.md` for why.)

## Performance Journey

| Stage | fib | hostcall | hostcall vs interpreter |
|-------|-----|----------|------------------------|
| Before optimization | 2.6ms | **4.9ms** | 5.7x slower |
| After optimization | 2.6ms | **0.81ms** | 0.97x (matched) |

Final results (all backends):

| Workload | grey-interpreter | grey-recompiler | polkavm-interpreter |
|----------|-----------------|----------------|-------------------|
| fib | 9.0ms | **2.6ms** | 9.5ms |
| hostcall | 0.83ms | **0.81ms** | 2.6ms |

Grey beats polkavm on every combination.

## What Was Wrong

The recompiler was fast on compute-heavy code (fib: 3.5x faster than
interpreters) but catastrophically slow on host-call-heavy code. Every `ecalli`
instruction caused a full exit from native code and re-entry — 100K round
trips per benchmark iteration. Two bugs made each round trip expensive:

### 1. `std::env::var()` on every `run()` call (syscall in hot path)

**Problem**: The `run()` method called `std::env::var("GREY_PVM_DEBUG")` on
every invocation to check whether debug tracing was enabled. This is a libc
`getenv()` call that traverses the environment block — effectively a syscall.
Called 100K times per benchmark iteration.

**Cost**: ~20-30ns per call x 100K = 2-3ms of pure overhead.

**Fix**: Cache the debug flag at `RecompiledPvm` construction time:
```rust
struct RecompiledPvm {
    debug: bool,  // cached from std::env::var("GREY_PVM_DEBUG")
    // ...
}
```

**Lesson**: Never call `std::env::var()` in a loop. Environment variable
reads are not free — they involve string scanning at minimum, and may hit
the kernel depending on the implementation. Cache at construction time.

### 2. O(n) linear PC dispatch on re-entry (quadratic total cost)

**Problem**: When re-entering native code after a host call, the prologue
needed to jump to the correct basic block for the current PC. It did this
with a linear scan:

```x86
    mov edx, [r15 + entry_pc]    ; load target PC
    cmp edx, 0                    ; is it PC 0?
    je  bb_0
    cmp edx, 5                    ; is it PC 5?
    je  bb_5
    cmp edx, 12                   ; is it PC 12?
    je  bb_12
    ; ... one compare+branch per basic block
```

For a program with N basic blocks, each re-entry costs O(N) comparisons.
With 100K host calls, this is O(N * 100K) total comparisons. Even for the
small benchmark program (~5 basic blocks), this adds up. For real-world
programs with hundreds of basic blocks, it would be devastating.

**Fix**: Build a dispatch table at compile time — an array indexed by PVM PC
containing the native code offset for that PC (-1 for invalid PCs). Added
two new fields to `JitContext`:

```rust
pub dispatch_table: *const i32,  // PVM PC -> native code offset
pub code_base: u64,              // base address of native code buffer
```

The prologue becomes O(1):
```x86
    mov edx, [r15 + entry_pc]            ; load target PC
    mov rax, [r15 + dispatch_table]      ; load table pointer
    movsxd rax, dword [rax + rdx*4]      ; load native offset (SIB scale=4)
    add rax, [r15 + code_base]           ; add code base
    push rax                              ; save target (before loading PVM regs)
    ; ... load 13 PVM registers ...
    pop rdx
    jmp rdx                               ; indirect jump to target BB
```

**Lesson**: Re-entry dispatch tables are standard in JIT compilers. Any time
you need to jump from the host back into JIT code at a variable PC, use a
table — never a linear scan. The table costs one `i32` per PVM instruction
byte (typically a few KB), which is negligible compared to the compiled
native code size.

## Design Pattern: Dispatch Before Register Load

The new prologue performs the dispatch table lookup *before* loading PVM
registers from the context. This matters because:

1. If the dispatch fails (invalid PC), we don't waste time loading 13
   registers only to immediately store them back on exit
2. The dispatch uses RAX and RDX as scratch, which are PVM register slots
   (phi[11] and SCRATCH). Loading PVM regs first would clobber the dispatch
   computation
3. The dispatch target is pushed to the stack, PVM regs are loaded, then
   the target is popped into a scratch register for the final indirect jump

This is similar to how polkavm's generic sandbox works — resolve the
entry point first, then set up the execution context.

## JitContext Layout

The JitContext grew from 176 to 192 bytes with two new fields:

| Offset | Field | Size | Description |
|--------|-------|------|-------------|
| 0 | regs | 104 | PVM registers phi[0..12] |
| 104 | gas | 8 | Signed gas counter |
| 112 | memory | 8 | Memory pointer |
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
| **176** | **dispatch_table** | **8** | **PC-to-native-offset table** |
| **184** | **code_base** | **8** | **Native code base address** |

The layout test (`test_jit_context_layout`) verifies offsets match codegen
constants at compile time.

## x86-64 Encoding Detail: SIB Scale-4 Load

The dispatch table lookup requires `movsxd rax, dword [rax + rdx*4]` — a
sign-extending 32-bit load with SIB (Scale-Index-Base) addressing. The
encoding is:

```
REX.W  | movsxd | ModR/M       | SIB
48+rxb | 63     | (reg<<3)|04  | 0x80|(idx<<3)|base
```

Where scale=10 (binary, meaning *4), and the ModR/M rm field is 100
(SIB follows). This was added as `movsxd_load_sib4()` in the assembler.

Note: this encoding fails if base=RBP/R13 (mod=00 + base=101 means
no-base in x86), but our base is always loaded from the dispatch table
pointer (RAX/RDX), so this isn't an issue.

## Remaining Opportunities

- **Inline ecalli continuation**: Instead of exiting native code on ecalli,
  the compiler could emit a call to a Rust helper that handles the host call
  inline, avoiding the full exit/re-entry entirely. This would eliminate the
  prologue/epilogue overhead for host calls completely. The challenge is that
  host call handlers need access to the full PVM state (memory, registers),
  which currently lives in the JitContext.

- **Partial register save/restore**: On ecalli exit, all 13 PVM registers
  are stored to the context, and on re-entry all 13 are loaded back. A
  liveness analysis could identify which registers are actually live across
  the host call and only save/restore those.

- **Callee-saved register allocation**: Registers phi[0..4] are mapped to
  callee-saved x86 registers (RBX, RBP, R12-R14) and survive function calls.
  If the host call dispatch were done as a regular function call rather than
  an exit/re-entry, these 5 registers wouldn't need save/restore at all.
