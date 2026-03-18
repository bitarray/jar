# JIT Optimization Roadmap

## Current state (March 2026)

The JAVM recompiler is a **single-pass JIT** with peephole optimization.
PVM bytecode is compiled to native x86-64 code as part of each program
execution — compilation + execution time both matter.

### Benchmark results (vs polkavm generic-sandbox)

| Benchmark | grey recompiler | polkavm compiler | Ratio |
|-----------|----------------|-----------------|-------|
| fib (compute, no memory) | 418 µs | 424 µs | **0.99x** |
| hostcall (100K ecalli) | 698 µs | 3,211 µs | **4.6x faster** |
| sort (compute + memory) | 549 µs | 454 µs | **1.21x slower** |

The sort gap is from the software bounds check (2 instructions per memory
access: `cmp + jae`). polkavm uses mprotect + SIGSEGV (0 instructions).
See `/workspaces/grey/plans/sigsegv-safety.md` for why we chose software
bounds checks.

## Optimizations (one-pass, no IR)

All optimizations below can be done in a single forward pass over the PVM
instruction stream, with zero or near-zero compile-time overhead.

### O1. Scaled-index addressing ✅ IMPLEMENTED

**Pattern:** Array element access `arr[i]` generates:
```
PVM:  add64 D,A,A / add64 D,D,D / add64 D2,BASE,D / load_ind [D2]
x86:  mov+add+add+mov+add+movzx+cmp+jae+load (9 instructions)
```

**Optimization:** Lookahead peephole detects the 4-instruction pattern
(add+add+add+load/store) and fuses into:
```
x86:  lea edx,[base+idx*4] / cmp+jae+load (4 instructions)
```

Saves 5 instructions per matched array access. The peephole scans ahead
4 PVM instructions when it sees `add64 D,A,A`.

**Result:** sort 585µs → 549µs (6.2% improvement)

### O2. Fused compare-and-branch

**Pattern:** PVM branches compare two registers directly (`blt ra, rb, target`).
Our codegen emits `cmp ra, rb; jcc target` which x86 CPUs already macro-fuse
into a single µop. **No change needed — already optimal.**

### O3. Immediate-address load/store folding

**Pattern:** `LoadU32 ra, imm` loads from a compile-time constant address:
```
Current:  mov edx, imm32 / cmp+jae / mov dst, [r15+rdx]
Better:   cmp edx_with_imm / jae / mov dst, [r15+imm32]
```

If `imm` fits in a 32-bit displacement (it always does — addresses are 32-bit),
use `[r15 + imm32]` directly without loading the address into SCRATCH first.
Saves 1 instruction per immediate-address load/store.

**Applies to sort bench:** No — sort uses register-indirect addressing (LoadInd),
not immediate addresses.

### O4. Multiply-accumulate fusion (crypto: ~20-30% improvement)

**Pattern:** Big-integer field multiplication generates sequences of:
```
PVM:  mul64 lo, a, b / mul_upper hi, a, b / add64 acc, acc, lo / ...
```

**Optimization:** Detect multiply-add chains and emit x86 `mulq` (which
produces 128-bit result in RDX:RAX) followed by `add + adc` for accumulation.
Eliminates separate mul_upper and reduces the instruction count for each
multiply-accumulate from ~6 to ~3.

For newer x86 (BMI2), use `mulx` + `adox`/`adcx` for carry-chain parallelism.

**Applies to sort bench:** No. Applies to crypto workloads (field arithmetic,
hash functions).

### O5. Constant address bounds check elimination

**Pattern:** When a load/store uses an immediate address AND the address is
provably within `[0, heap_top)` at compile time (e.g., accessing the stack at
a known offset), the bounds check can be eliminated entirely.

This requires knowing `heap_top` at compile time, which is true for programs
that never call `grow_heap`. The compiler can track a "minimum guaranteed
heap_top" (initialized from the program header's stack + data sizes) and skip
bounds checks for addresses below it.

**Applies to sort bench:** Partially — the initial array setup uses known
stack offsets, but the inner loop uses dynamic indices.

### O6. Basic-block-level address range check — NOT APPLICABLE to sort

**Pattern:** Instead of checking bounds per load/store, check once at the
start of a basic block that all addresses in the block are in range.

**Analysis:** In the sort benchmark, each basic block has at most ONE memory
access (the store and load are in separate blocks, separated by gas checks
and branches). O6 requires multiple memory accesses in the same block to
merge bounds checks. This pattern would help programs with structure field
access (`load a.x; load a.y; load a.z` in one block) but not array
iteration where each access is in its own branch-separated block.

### O7. Dead move elimination

**Pattern:** `mov_rr(dst, src)` where `dst == src` is a no-op. Also,
`mov_rr(dst, src)` followed immediately by `mov_rr(dst, other)` — the first
move is dead.

We already handle the `dst == src` case in several instruction handlers. A
universal check in the assembler's `mov_rr` would catch the remaining cases.

**Applies to sort bench:** Minimally.

### O8. Permission table removal

**Status: ready to implement.**

The 1MB permission table and its sync logic are no longer needed with linear
memory + bounds check. Removing them saves 1MB virtual per PVM instance and
eliminates the permission table mmap/copy on initialization.

This is not a JIT codegen optimization but reduces compilation + initialization
overhead.

**Applies to sort bench:** Yes — reduces per-execution initialization cost
(relevant for the "compile + execute" benchmark).

## Sort benchmark progression

| Change | Time | vs polkavm | Commit |
|--------|------|-----------|--------|
| Permission table lookup (baseline) | 918 µs | 2.04x | — |
| Bounds check (replace perm table) | 665 µs | 1.47x | e98c5e7 |
| Cold fault stubs (out-of-line) | 620 µs | 1.37x | 6932e3c |
| 32-bit address arithmetic | 585 µs | 1.29x | 5e3132a |
| **Scaled-index peephole (O1)** | **549 µs** | **1.21x** | 148d48e |

Remaining gap is purely `cmp [heap_top], edx; jae fault` per memory access
(2 instructions). Only eliminable via mprotect (see `plans/sigsegv-safety.md`)
or full-4GB spec change.

## Priority order

| # | Optimization | Impact | Effort | Status |
|---|-------------|--------|--------|--------|
| O1 | Scaled-index addressing | Medium | Medium | ✅ Done |
| O8 | Permission table removal | Low | Low | Ready |
| O3 | Immediate-address folding | Low | Low | Todo |
| O6 | Block-level bounds check | N/A | Medium | Not applicable to sort |
| O4 | Multiply-accumulate fusion | High | High | Todo (crypto) |
| O5 | Constant address elision | Low | Medium | Todo |
| O7 | Dead move elimination | Low | Low | Todo |

## What requires multi-pass (NOT recommended for now)

These optimizations require building an IR or doing backward analysis, which
adds significant compile time. Only worth it for very long-running programs
where execution time >> compile time.

- Cross-block register allocation
- Loop-invariant code motion
- Common subexpression elimination
- Instruction scheduling across basic blocks
- Full strength reduction (e.g., multiply by constant → shifts + adds)

For reference, Cranelift (used by Wasmtime) adds ~10x compile-time overhead
for ~2x execution improvement. This tradeoff only pays off for programs that
execute billions of instructions.
