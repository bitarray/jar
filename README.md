# JAR — Join-Accumulate Refine

[![Matrix](https://img.shields.io/matrix/jar%3Amatrix.org?logo=matrix&label=chat)](https://matrix.to/#/#jar:matrix.org)

JAR is a blockchain protocol based on JAM (Join-Accumulate Machine). This monorepo contains both the formal specification and a full node implementation.

## PVM Recompiler

Grey's x86-64 JIT recompiler outperforms polkavm v0.32.0 on all workloads with pipeline gas metering. Benchmarks include full compile+execute each iteration (realistic JAM model where each work-package is compiled fresh):

| Benchmark | Grey Recompiler | PolkaVM Generic | PolkaVM Linux | Grey vs best PolkaVM |
|-----------|-----------------|-----------------|---------------|--------------|
| Fibonacci (1M iter) | **416 µs** | 429 µs | 414 µs | 1.00x |
| Host calls (100K ecalli) | **834 µs** | 3,177 µs | 30,164 µs | **3.8x faster** |
| Sort (500 elements) | **434 µs** | 463 µs | 452 µs | **1.04x faster** |
| Ecrecover (secp256k1) | **2,078 µs** | 3,122 µs | 2,958 µs | **1.42x faster** |

Key optimizations: per-basic-block pipeline gas simulation, peephole instruction fusion, mprotect+SIGSEGV memory bounds checking (zero-instruction hot path), register-mapped PVM state, cold OOG/fault stubs.

## Repository Structure

| Directory | Description |
|-----------|-------------|
| [spec/](spec/) | Lean 4 formal specification — executable, machine-checked, tested against conformance vectors |
| [rust/](rust/) | Rust workspace — jar-kernel, javm (PVM), nub, scale, subsoil |

## Genesis — Proof of Intelligence

JAR uses a Proof-of-Intelligence model for its genesis token distribution. Every merged PR is scored on difficulty, novelty, and design quality by ranked comparison against past commits. See [GENESIS.md](GENESIS.md) for the full protocol design.

## Quick Start

### Spec (Lean 4)

```sh
cd spec
cd crypto-ffi && cargo build --release && cd ..
lake build
make test
```

### Rust workspace

```sh
cargo test --workspace
```

## License

Apache-2.0
