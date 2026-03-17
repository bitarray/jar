# PVM Interpreter Optimization

Lessons learned from optimizing the javm interpreter to match/beat the
polkavm interpreter (March 2026).

## Benchmark Setup

Two workloads comparing grey interpreter vs polkavm v0.30.0 interpreter:
- **fib**: 1M iterations of iterative Fibonacci (pure register ALU + branches)
- **hostcall**: 100K `ecalli` invocations (host-call-heavy)

Gas limit: 100M. Both interpreters produce identical results and gas counts.

## Performance Journey

| Stage | fib | hostcall | vs polkavm fib |
|-------|-----|----------|----------------|
| Baseline (before optimization) | ~70ms est. | ~8ms est. | ~7x slower |
| After Vec elimination + O(1) opcode | 17.2ms | 1.13ms | 1.9x slower |
| After pre-decode + BB gas charging | 10.1ms | 0.99ms | 1.12x slower |
| After inline flat-operand + pre-resolved branches | **8.8ms** | **0.82ms** | **1.04x faster** |

polkavm interpreter: fib=9.1ms, hostcall=2.5ms (constant across all stages).

## Optimization Details

### 1. Eliminate heap allocations in decode_args (~4x impact)

**Problem**: `decode_args()` collected code bytes into a `Vec<u8>` on every
instruction decode. This was an allocation per instruction — millions of
allocations per second in the hot loop.

**Fix**: Replace `Vec<u8>` collection with inline `read_le_at(code, offset, n)`
that builds a `u64` directly from the code bytes using shifts. Zero allocations.

**Lesson**: Never allocate in the interpreter hot path. Build values in
registers, not on the heap. The compiler can't optimize away Vec allocations
even for small, fixed-size byte sequences.

### 2. O(1) opcode validation (minor impact)

**Problem**: `Opcode::from_byte()` used `VALID_OPCODES.contains(&byte)` — a
linear scan of ~130 entries on every instruction decode.

**Fix**: Static `OPCODE_TABLE: [u8; 256]` lookup table initialized at compile
time. `from_byte()` becomes a single array index + transmute.

**Lesson**: For enum-from-integer conversion with sparse valid values, a 256-byte
lookup table is both simpler and faster than a match or linear scan.

### 3. Pre-decoded instruction cache (~1.7x impact)

**Problem**: Every `step()` call re-decoded the instruction from raw bytecode:
parse opcode, compute skip, decode args. This is pure overhead when executing
the same loop body millions of times.

**Fix**: At VM initialization, pre-decode ALL instructions into a
`Vec<DecodedInst>` with a `pc_to_idx: Vec<u32>` mapping. The `run()` loop
indexes into this array instead of parsing bytecode.

**Lesson**: polkavm does exactly this — it pre-compiles bytecode into an
internal representation at module load time. The one-time cost of pre-decoding
is negligible compared to the per-instruction savings.

### 4. Basic-block gas charging (~1.3x impact)

**Problem**: Gas was charged per instruction: `if self.gas < 1 { return OOG; }
self.gas -= 1;` — a branch and subtract on every single instruction.

**Fix**: At pre-decode time, compute the gas cost of each basic block (sum of
instruction costs within the block). Store `bb_gas_cost` in the first
instruction of each block. Charge gas once at block entry; non-entry
instructions have `bb_gas_cost = 0` and skip the check entirely.

**Lesson**: Basic-block gas charging is standard in production VMs. The gas
check branch is rarely taken but still costs a branch prediction slot on every
instruction. Amortizing it over blocks eliminates this overhead.

### 5. Inline flat-operand execution (~1.15x impact)

**Problem**: The pre-decoded `DecodedInst` stored args as the `Args` enum
(tagged union). Executing an instruction required matching the enum to extract
operands, then matching the opcode to execute — two levels of dispatch.

**Fix**: Store flat operands directly in `DecodedInst`: `ra: u8, rb: u8,
rd: u8, imm1: u64, imm2: u64`. The `run()` loop inlines ~70 common opcodes
(all ALU, branches, register ops) using these flat fields directly, bypassing
the `Args` enum entirely. Complex ops (memory loads/stores, div/rem, sbrk)
still fall back to `execute()`.

**Lesson**: Flat structs beat tagged unions in hot loops. The CPU can load
`inst.ra` with a fixed offset from the struct pointer — no discriminant check,
no branch. The `Args` enum is still kept for the slow path and tracing.

### 6. Pre-resolved branch targets (~1.05x impact)

**Problem**: On every taken branch, the interpreter did
`pc_to_idx[target_pc]` + `is_basic_block_start(target_pc)` — two array lookups
plus bounds checks.

**Fix**: At pre-decode time, resolve branch/jump targets to instruction indices
and store as `target_idx: u32` in the `DecodedInst`. Branches become
`if inst.target_idx != u32::MAX { idx = inst.target_idx; }` — a single
comparison and assignment.

**Important caveat**: For sequential advance, `idx += 1` is faster than
`idx = inst.next_idx` even though both are "pre-resolved". The CPU can
execute an increment without a memory load, while loading `next_idx` from the
struct adds a data dependency. Only use pre-resolved indices for non-sequential
transitions (branches/jumps).

## Key Architectural Decisions

### DecodedInst struct layout

```rust
pub struct DecodedInst {
    pub opcode: Opcode,   // 1 byte
    pub args: Args,        // kept for slow-path/tracing
    pub ra: u8, pub rb: u8, pub rd: u8,  // flat register operands
    pub imm1: u64, pub imm2: u64,        // flat immediates
    pub pc: u32,           // byte offset in code
    pub next_pc: u32,      // next sequential byte offset
    pub next_idx: u32,     // pre-resolved next instruction index
    pub target_idx: u32,   // pre-resolved branch target index
    pub bb_gas_cost: u64,  // gas to charge at BB entry (0 for non-entry)
}
```

This is ~64 bytes per instruction. For a 1KB program (~40 instructions), the
entire decoded array fits in L1 cache.

### Dual-path execution

The `run()` method checks `tracing_enabled` once at entry and dispatches to
either the fast path (pre-decoded + inline execution) or the slow path
(`run_stepping()` which calls `step()` per instruction). This keeps the tracing
infrastructure intact without polluting the fast path.

### Branch target validation

Only `Jump` and `BranchEq/Ne/LtU/LtS/GeU/GeS` store `imm1` as the target PC.
Other terminators (`JumpInd`, `LoadImmJump`, `BranchEqImm`, etc.) use `imm1`
for different purposes. The pre-resolution pass must be opcode-aware.

`JumpInd` goes through the jump table (`djump()`) at runtime since the target
depends on a register value. It cannot be pre-resolved.

## What polkavm Does Differently

polkavm's interpreter advantage comes from:
1. **Handler function pointers**: Each instruction is a function pointer call,
   avoiding the large match statement. This is the "threaded interpreter"
   pattern. Rust's match compiles to a jump table which is comparable.
2. **Module-level pre-compilation**: The `Module` object pre-processes bytecode
   once and can be instantiated multiple times cheaply.
3. **No Args enum**: polkavm's internal instruction format stores operands
   inline, similar to our flat operand approach.

Our advantage on hostcall comes from lighter-weight instance creation and
host-call dispatch overhead.

## Remaining Optimization Opportunities

- **Computed goto / threaded dispatch**: Rust doesn't natively support computed
  goto, but using a function pointer table could eliminate the match overhead.
  Diminishing returns given the match already compiles to a jump table.
- **SIMD for memory operations**: Bulk memory copies could use SIMD.
- **Profile-guided optimization (PGO)**: Could improve branch prediction for
  the opcode match.
- **Smaller DecodedInst**: The struct is 64+ bytes; a more compact 32-byte
  layout might improve cache utilization for larger programs.
