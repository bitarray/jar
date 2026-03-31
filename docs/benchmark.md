# Grey PVM Benchmark Results

Grey's RISC-V recompiler vs PolkaVM's compiler backend, measured on 8 workloads covering compute, memory, crypto, and host call patterns.

## Methodology

**Gas metering model:** Pipeline gas metering (`POLKAVM_DEFAULT_COST_MODEL=full-l1-hit`). This charges gas per basic block based on instruction count, matching the JAR v0.8.0 specification. Both Grey and PolkaVM use synchronous gas metering under this model.

**Why compile+execute matters:** In JAM, every work-package arrives as a PVM blob that must be compiled and executed from scratch. There is no persistent code cache across invocations -- each validator independently compiles the blob before execution. The compile+execute measurement reflects this real-world cost. We report exec-only numbers separately for engineering insight, but the full pipeline is the metric that determines block processing time.

**Benchmark fairness:**
- Both VMs compile from the same source (Rust, compiled to RISC-V, transpiled to PVM for Grey / compiled to PolkaVM format for PolkaVM)
- Grey recompiler uses `mprotect`-based bounds checking (`--features javm/signals`)
- PolkaVM uses generic sandbox with `POLKAVM_ALLOW_EXPERIMENTAL=1`
- Criterion statistical framework, 100 samples per benchmark (10 for ecrecover)
- Same host machine, same gas limit, same workload parameters

**Reproduction:**
```bash
POLKAVM_ALLOW_EXPERIMENTAL=1 POLKAVM_DEFAULT_COST_MODEL=full-l1-hit \
  cargo bench -p grey-bench --features javm/signals
```

## Results: Compile + Execute (full pipeline)

This is the number that matters for blockchain performance.

| Benchmark | Grey | PolkaVM | Speedup |
|-----------|------|---------|---------|
| fib | 414 us | 428 us | 1.03x |
| hostcall | 799 us | 3,175 us | 3.97x |
| sort | 398 us | 460 us | 1.16x |
| sieve | 351 us | 353 us | 1.01x |
| blake2b | 90 us | 276 us | 3.07x |
| keccak | 51 us | 140 us | 2.75x |
| ed25519 | 977 us | 1,349 us | 1.38x |
| ecrecover | 1,465 us | 3,319 us | 2.27x |

Grey wins all 8 benchmarks. The advantage ranges from 1.01x (sieve) to 3.97x (hostcall), with a geometric mean speedup of ~1.9x.

The primary driver is compilation speed: Grey's single-pass x86-64 code generator compiles PVM bytecode approximately 3x faster than PolkaVM's compiler backend. For short programs (blake2b, keccak) where compilation dominates total time, this translates directly into large end-to-end wins. For long-running programs (fib, sieve) where execution dominates, the two VMs converge.

## Results: Execution Only

Compilation performed in setup (untimed). Measures native code quality in isolation.

| Benchmark | Grey | PolkaVM | Speedup |
|-----------|------|---------|---------|
| fib | 408 us | 409 us | 1.00x |
| hostcall | 816 us | 3,213 us | 3.94x |
| sort | 398 us | 436 us | 1.10x |
| sieve | 304 us | 320 us | 1.05x |
| blake2b | 13.2 us | 27.0 us | 2.05x |
| keccak | 18.1 us | 35.9 us | 1.98x |
| ed25519 | 140 us | 158 us | 1.13x |
| ecrecover | 630 us | 579 us | 0.92x |

Grey wins 7 of 8 benchmarks on exec-only. PolkaVM's only win is ecrecover (1.09x). Grey generates notably better native code for hash functions (blake2b 2.0x, keccak 2.0x) and host call dispatch (3.9x). The hostcall result is notable: PolkaVM's compiled code (3,213 us) is actually slower than its own interpreter (2,526 us) on this workload, suggesting high overhead in its compiler's host call dispatch path.

## Results: Interpreters

| Benchmark | Grey | PolkaVM | Speedup |
|-----------|------|---------|---------|
| fib | 9.0 ms | 9.1 ms | 1.01x |
| hostcall | 795 us | 2,526 us | 3.18x |
| sort | 8.1 ms | 11.8 ms | 1.46x |
| sieve | 2.7 ms | 3.0 ms | 1.14x |
| blake2b | 194 us | 341 us | 1.76x |
| keccak | 182 us | 211 us | 1.16x |
| ed25519 | 5.1 ms | 3.2 ms | 0.63x |
| ecrecover | 21.0 ms | 19.3 ms | 0.92x |

Grey's interpreter wins 6 of 8. PolkaVM wins ed25519 (1.6x) and ecrecover (1.1x).

## Workload Descriptions

| Benchmark | Description | Character |
|-----------|-------------|-----------|
| fib | Iterative Fibonacci, 1M iterations | Pure compute (add, branch) |
| hostcall | 100K ecalli invocations | Host call dispatch overhead |
| sort | Insertion sort, 1K u32 elements | Compute + memory interleaved |
| sieve | Sieve of Eratosthenes to 100K | Memory + branching |
| blake2b | Blake2b-256, 1KB message | Crypto: rotate, xor, add |
| keccak | Keccak-256, 1KB message | Crypto: rotate, xor, and |
| ed25519 | Ed25519 signature verify | Crypto: multiply-heavy |
| ecrecover | secp256k1 ECDSA key recovery | Crypto: heavy multi-precision |

## Environment

- Date: 2026-03-30
- Grey: javm recompiler with `signals` feature
- PolkaVM: v0.18.0, generic sandbox, `full-l1-hit` cost model
- Rust: 1.94.1, release mode
- Hardware: Intel Core i9-13900K
