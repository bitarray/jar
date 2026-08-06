# Lazy Pre-decode PR Proposal for JAR Chain

## Overview

**Issue**: [#400 - Optimize javm interpreter performance](https://github.com/jarchain/jar/issues/400)

**PR Title**: `feat(javm): add optional lazy pre-decode for short-lived programs`

**Author**: TBD

**Status**: Draft

---

## Problem Statement

The current `predecode_instructions()` function in `interpreter/mod.rs` performs full pre-decoding of all instructions whenever `InterpreterProgram::predecode()` is called. For short-lived programs that execute only a small number of basic blocks, this upfront decoding cost represents a significant overhead.

**Evidence**:
```rust
// Current implementation - full pre-decode every time
let (decoded_insts, pc_to_idx) = predecode_instructions(
    code, bitmask, &basic_block_starts, 
    &gas_block_starts, &block_gas_costs
);
```

---

## Solution

Implement **Lazy Pre-decode**: decode basic blocks on-demand during execution, rather than upfront.

### Architecture

```
Before (Eager Pre-decode):
┌─────────────────────────────────────┐
│ InterpreterProgram::predecode()     │
│   └─ predecode_instructions()       │  ← O(n) every call
│       └─ decode ALL instructions    │
└─────────────────────────────────────┘

After (Lazy Pre-decode):
┌─────────────────────────────────────┐
│ InterpreterProgram::predecode()     │
│   └─ compute block structure only   │  ← O(n) once
│       (no instruction decoding)     │
└─────────────────────────────────────┘
           ↓
┌─────────────────────────────────────┐
│ Interpreter::run_segment()         │
│   └─ get_decoded(pc)                │  ← O(k) per first access
│       └─ lazy_decode_block()        │    k = block size
└─────────────────────────────────────┘
```

### Auto-switch Strategy

When >50% of blocks have been decoded, switch to eager mode for remaining execution:

```rust
pub fn should_eager_decode(&self) -> bool {
    self.decoded_block_count as f32 / self.total_block_count as f32 > 0.5
}
```

---

## Implementation Details

### Modified Files

| File | Changes | Lines |
|------|---------|-------|
| `grey/crates/javm/src/backend.rs` | Add cache fields + constructor | ~80 |
| `grey/crates/javm/src/interpreter/mod.rs` | Lazy decode core logic | ~120 |
| `grey/crates/javm/src/interpreter/mod.rs` | Modify run_segment | ~10 |
| `grey/crates/javm/Cargo.toml` | Add feature flag | ~3 |
| `grey/crates/javm/benches/lazy_predecode.rs` | Benchmark | ~50 |

**Total**: ~263 lines

### New Fields in InterpreterProgram

```rust
pub struct InterpreterProgram {
    // ... existing fields ...
    
    // Lazy pre-decode support
    pub decoded_cache: Vec<Option<DecodedInst>>,  // None = not decoded
    pub cache_valid_until: Vec<u32>,                // Block boundary cache
    pub decoded_block_count: u32,                   // Decoded block counter
    pub total_block_count: u32,                     // Total block counter
    pub lazy_enabled: bool,                         // Toggle switch
}
```

### Key Functions

1. `get_decoded(pc: u32) -> &DecodedInst` - Lazy access point
2. `lazy_decode_block(start_pc: u32)` - Decode single block on-demand
3. `should_eager_decode() -> bool` - Auto-switch threshold
4. `switch_to_eager_mode()` - Migrate to eager pre-decode

---

## Performance Impact

| Program Type | Blocks Executed | Pre-decode Cost | Improvement |
|--------------|-----------------|-----------------|-------------|
| Very short (<10 blocks) | <10% | 100% → 10% | ~40% |
| Short (10-50 blocks) | 10-50% | 100% → 50% | ~20% |
| Long (>50% coverage) | >50% | Auto-switch | ~0% |

> Note: Actual numbers require benchmark validation

---

## Backwards Compatibility

- **Default**: `lazy_enabled = true`
- **Feature Flag**: `#[feature(lazy-predecode)]`
- **Environment Variable**: `GREY_PVM_LAZY=false` to disable
- **No breaking changes** to existing API

---

## Testing Plan

```bash
# 1. Functional tests
cargo test -p javm

# 2. Consistency tests (interpreter vs recompiler)
cargo test -p grey-bench

# 3. Benchmark comparison
cargo bench -p grey-bench --bench pvm_bench -- 'interpreter'

# 4. Lazy vs Eager comparison
GREY_PVM_LAZY=true cargo bench -p grey-bench --bench pvm_bench
GREY_PVM_LAZY=false cargo bench -p grey-bench --bench pvm_bench
```

---

## Risk Assessment

| Risk | Level | Mitigation |
|------|-------|------------|
| Introducing bugs | Medium | All existing tests must pass |
| Memory overhead | Low | Cache is optional, released after eager switch |
| Compatibility | Low | Feature flag controlled, defaults to eager-like behavior |

---

## Related PRs

- #812: `feed_gas_direct()` optimization (Gas metering)
- #813: `feed_direct()` optimization (Gas metering)
- #810: `unlikely()` hint optimization (Branch prediction)

---

## References

- [Issue #400](https://github.com/jarchain/jar/issues/400) - javm interpreter performance
- [Gray Paper](https://github.com/jarchain/gray) - JAM protocol specification
- [CONTRIBUTING.md](https://github.com/jarchain/jar/blob/master/CONTRIBUTING.md) - Contribution guidelines
