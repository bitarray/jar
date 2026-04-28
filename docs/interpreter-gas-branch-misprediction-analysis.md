# Interpreter Hot-Loop: Gas-Block Branch Misprediction Analysis

**Issue:** [#400 — Optimize javm interpreter performance](https://github.com/jarchain/jar/issues/400)

## Summary

This document profiles and analyses the branch behaviour of the `bb_gas_cost` check
inside the `run()` hot-loop in `crates/javm/src/interpreter/mod.rs`.

The question we answer: **is the `if inst.bb_gas_cost > 0` guard a significant
branch-misprediction source, and if so, what can we do about it?**

---

## The Code Under Analysis

```rust
// crates/javm/src/interpreter/mod.rs  line 1589-1596
if inst.bb_gas_cost > 0 {
    if self.gas < inst.bb_gas_cost as u64 {
        self.pc = inst.pc;
        return (ExitReason::OutOfGas, initial_gas - self.gas);
    }
    self.gas -= inst.bb_gas_cost as u64;
}
```

This outer guard fires **only at gas-block boundaries** — i.e. at PC=0 and every
post-terminator instruction start. Branch targets are *not* gas-block starts
(JAR v0.8.0 semantics).

---

## Frequency Analysis

### How often is `bb_gas_cost > 0`?

A *gas block* is the span between consecutive gas-block-start PCs.
`bb_gas_cost` is stored pre-decoded inside `DecodedInst` and is 0 for every
non-boundary instruction.

For representative workloads we estimate the fraction of instructions that are
gas-block starts:

| Benchmark | Approx instructions/block | Gas-charge frequency |
|-----------|--------------------------|----------------------|
| `fib`     | ~6–10 ALU+branch ops     | ~12–17 %             |
| `sieve`   | ~8–14 inner-loop ops     | ~7–12 %              |
| `blake2b` | ~20–30 ops per block     | ~3–5 %               |
| `keccak`  | ~15–25 ops per block     | ~4–6 %               |
| `ed25519` | ~10–20 ops per block     | ~5–10 %              |

**Finding:** For most non-trivial workloads the outer branch (`bb_gas_cost > 0`)
is **biased FALSE** ~85–97 % of the time. Modern branch predictors handle
strongly-biased branches well (< 1 % misprediction rate), so this is **unlikely
to be a dominant cost source** in steady state.

### The rare-taken inner branch

The inner `if self.gas < inst.bb_gas_cost as u64` is the OOG exit path. It is
taken only on out-of-gas, making it almost-never-taken and thus extremely well
predicted. This branch can be safely annotated with `[[unlikely]]`-equivalent
(Rust: `[[cold]]` + `#[inline(never)]` on the return path), but its contribution
is already minimal.

---

## Cache Impact: `bb_gas_cost` Field in `DecodedInst`

`DecodedInst` is currently **40 bytes** (verified by the compile-time assert on
line 43):

```rust
const _: () = assert!(core::mem::size_of::<DecodedInst>() == 40);
```

Field layout:
| Field       | Type  | Size |
|-------------|-------|------|
| `opcode`    | u8    | 1 B  |
| `ra`        | u8    | 1 B  |
| `rb`        | u8    | 1 B  |
| `rd`        | u8    | 1 B  |
| (padding)   | —     | 4 B  |
| `imm1`      | u64   | 8 B  |
| `imm2`      | u64   | 8 B  |
| `pc`        | u32   | 4 B  |
| `next_pc`   | u32   | 4 B  |
| `next_idx`  | u32   | 4 B  |
| `target_idx`| u32   | 4 B  |
| `bb_gas_cost`| u32  | 4 B  |

40 bytes per instruction means **a 64-byte cache line holds 1.6 instructions**.
Every fetch already loads `bb_gas_cost` for free — no extra cache miss.

**Finding:** The `bb_gas_cost` field does not introduce additional cache misses
since it lives in the same cache line as the opcode and operands.

---

## Micro-architectural Cost Estimate

Even though the branch is well-predicted, there is a small cost from the
conditional subtract:

```
; Pseudo-assembly for the hot path
test  [inst + bb_gas_cost_offset], 0xFFFFFFFF   ; load + test
je    .no_gas_charge                             ; predicted-not-taken (fast)
; ... OOG check + subtract (rarely reached)
.no_gas_charge:
```

On modern x86-64 (Zen4 / Golden Cove), a well-predicted conditional branch has
~0 cycle throughput penalty when not taken (branch folded in decode). The load
of `bb_gas_cost` is already in-flight since `inst` was fetched for the opcode
dispatch. **Net estimated overhead: < 0.5 cycles per instruction.**

---

## Comparison: Eliminating the Guard

One theoretical approach: **separate instructions into two parallel arrays** —
one for gas-block starts (with cost), one for regular instructions — and use a
bitmask to select the dispatch path. However:

1. This destroys the sequential `idx += 1` advance that makes branch prediction
   on the main loop trivially predictable.
2. It doubles memory traffic for the instruction stream.
3. It adds a bitmask lookup per instruction.

**Verdict: the cure is worse than the disease.** The current design is close to
optimal for this pattern.

---

## Alternative Worth Investigating: `likely`/`unlikely` Intrinsic

Rust nightly provides `core::intrinsics::likely` / `unlikely`. Marking the gas
guard:

```rust
// In run() hot loop — proposed change
if unsafe { core::intrinsics::unlikely(inst.bb_gas_cost > 0) } {
    if self.gas < inst.bb_gas_cost as u64 {
        self.pc = inst.pc;
        return (ExitReason::OutOfGas, initial_gas - self.gas);
    }
    self.gas -= inst.bb_gas_cost as u64;
}
```

This hint allows LLVM to:
- Lay out the not-taken path (sequential) as the fall-through (faster fetch).
- Move the taken path (gas charging) to a cold section, reducing I-cache
  pressure in the main loop.

**Expected benefit: 1–3 % throughput improvement** on instruction-dense
workloads (blake2b, keccak) where I-cache pressure matters most.

> **Note:** The project already uses nightly (`rust-toolchain.toml` pins nightly
> edition 2024), so `core::intrinsics::unlikely` is available without any
> feature gate.

---

## Recommendations

| Priority | Action | Expected gain |
|----------|--------|---------------|
| ✅ Low-risk / High-confidence | Add `unlikely()` hint to `bb_gas_cost > 0` branch | ~1–3 % I-cache improvement |
| 🔬 Investigate | Profile with `valgrind --tool=callgrind` or `perf stat -e branch-misses` on Linux to verify misprediction rate empirically | Ground truth |
| ❌ Not recommended | Splitting instruction stream / dual-array design | Net regression |

---

## Next Steps

1. Apply the `unlikely` hint and benchmark with `cargo bench -p grey-bench --bench pvm_bench -- 'interpreter'`.
2. Compare criterion output before/after.
3. If improvement is ≥ 1 % on at least two benchmarks, submit as a PR referencing #400.

---

*Analysis by [@zhoutianxia1](https://github.com/zhoutianxia1) — April 28, 2026*
