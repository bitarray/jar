# Grey

[![Matrix](https://img.shields.io/matrix/jar%3Amatrix.org?logo=matrix&label=chat)](https://matrix.to/#/#jar:matrix.org)

A JAM (Join-Accumulate Machine) blockchain node implementation in Rust, following the [JAR v0.8.0 specification](https://github.com/bitarray/jar).

## Highlights

- **382+ tests passing** across all crates, **101/101 conformance blocks**
- **Multi-node testnet** — 6 validators, GRANDPA finality, full work package pipeline
- **PVM recompiler faster than polkavm** — grey's x86-64 JIT recompiler outperforms polkavm v0.32.0's compiler backend on all workloads with pipeline gas metering (`POLKAVM_DEFAULT_COST_MODEL=full-l1-hit`). Benchmarks include full compile+execute each iteration (realistic JAM model where each work-package is compiled fresh):

  | Benchmark | Grey Recompiler | PolkaVM Generic | PolkaVM Linux | Grey vs best PolkaVM |
  |-----------|-----------------|-----------------|---------------|--------------|
  | Fibonacci (1M iter) | **416 µs** | 429 µs | 414 µs | 1.00x |
  | Host calls (100K ecalli) | **834 µs** | 3,177 µs | 30,164 µs | **3.8x faster** |
  | Sort (500 elements) | **434 µs** | 463 µs | 452 µs | **1.04x faster** |
  | Ecrecover (secp256k1) | **2,078 µs** | 3,122 µs | 2,958 µs | **1.42x faster** |

  Key optimizations: per-basic-block pipeline gas simulation, peephole instruction fusion, mprotect+SIGSEGV memory bounds checking (zero-instruction hot path), register-mapped PVM state, cold OOG/fault stubs.

## Building

```bash
cargo build --release
```

## Running a Multi-Node Testnet

Grey can run a local test network with 6 validators connected via libp2p gossipsub, demonstrating the complete JAM work package pipeline.

### Quick Start

```bash
# Run multi-node testnet for 60 seconds
cargo run --bin grey -- --testnet 60
```

This spawns 6 validators (V=6, C=2, E=12) in a star topology on ports 19000-19005. Each validator:
- Authors blocks when it's the slot leader (fallback key schedule, 6s slots)
- Propagates blocks to all peers via gossipsub
- Runs GRANDPA finality (prevote/precommit with 2/3+1 threshold)
- Generates and broadcasts Safrole tickets
- Processes work packages through the full pipeline

### Work Package Pipeline

The testnet includes a pre-installed PVM service (ID 1000) that demonstrates the complete JAM work package lifecycle:

1. **Submit** — Validator 0 creates a work package with a payload
2. **Refine** (Section 14) — The PVM executes the service's refine code (identity function)
3. **Erasure code** (Appendix H) — Work package bundle is Reed-Solomon encoded into 6 chunks
4. **Guarantee** — Validator 0 signs the work report with 2 guarantor credentials
5. **Broadcast** — Guarantee is propagated to all validators via gossipsub
6. **Assurance** — Each validator generates an availability assurance for the core
7. **Accumulate** (Section 12) — When 5/6 assurances are collected, the PVM executes the service's accumulate code (writes to storage via `host_write`)
8. **Finalize** — GRANDPA finalizes the block containing the accumulated result

### Sequential Test (No Networking)

```bash
# Run a single-machine end-to-end test
cargo run --bin grey -- --test

# Customize block count
cargo run --bin grey -- --test --test-blocks 30
```

This produces 20 blocks with 9 work packages submitted and accumulated, verifying the full pipeline without networking.

### Running Individual Validators

```bash
# Start validator 0 (boot node)
cargo run --bin grey -- -i 0 -p 9000

# Start validator 1 (connects to boot node)
cargo run --bin grey -- -i 1 -p 9001 -b /ip4/127.0.0.1/tcp/9000

# Start more validators
cargo run --bin grey -- -i 2 -p 9002 -b /ip4/127.0.0.1/tcp/9000
```

All validators on the same genesis time will form a network and begin block production.

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `-i, --validator-index` | 0 | Validator index (0 to V-1) |
| `-p, --port` | 9000 | Network listen port |
| `-b, --peers` | — | Boot peer multiaddresses (comma-separated) |
| `--testnet <secs>` | — | Run networked testnet for N seconds |
| `--test` | — | Run sequential block production test |
| `--test-blocks` | 20 | Number of blocks in test mode |
| `--rpc-port` | 9933 | JSON-RPC server port (0 to disable) |
| `--db-path` | ./grey-db | Database path for persistent storage |
| `--genesis-time` | current time | Unix timestamp for genesis (0 = now) |
| `--info` | — | Show node configuration and exit |

## Services

Services are RISC-V programs compiled to PVM bytecode. Two example services are included:

- `services/sample-service/` — Minimal service: echo refine + `host_write` accumulate
- `services/counter-service/` — Counter service: writes to two storage keys during accumulate

Services are cross-compiled to RISC-V and transpiled to PVM bytecode by `grey-transpiler`.

## Test Status

**382+ tests passing** across all crates.

| Category | Crate | Tests | Status |
|----------|-------|------:|--------|
| Codec (Appendix C) | `grey-codec` | 32 | All passing |
| Cryptography (Section 3.8) | `grey-crypto` | 15 | All passing |
| PVM — Join-Accumulate VM (Appendix A) | `javm` | 41 | All passing |
| Merkle tries (Appendices D & E) | `grey-merkle` | 14 | All passing |
| Erasure coding (Appendix H) | `grey-erasure` | 24 | All passing |
| Safrole consensus (Section 6) | `grey-consensus` | 25 | All passing |
| STF — Safrole | `grey-state` | 21 | All passing |
| STF — Disputes | `grey-state` | 28 | All passing |
| STF — Reports | `grey-state` | 42 | All passing |
| STF — Assurances | `grey-state` | 10 | All passing |
| STF — Accumulate | `grey-state` | 30 | All passing |
| STF — History | `grey-state` | 4 | All passing |
| STF — Preimages | `grey-state` | 8 | All passing |
| STF — Authorizations | `grey-state` | 3 | All passing |
| STF — Statistics | `grey-state` | 3 | All passing |
| State core | `grey-state` | 10 | All passing |
| Services | `grey-services` | 11 | All passing |

### Conformance Testing

Grey includes a conformance target binary (`grey-conform`) that speaks the JAM fuzz-proto v1 protocol over Unix domain sockets, compatible with [minifuzz](https://github.com/davxy/jam-conformance), Polkajam, and Jamzig fuzzers.

**Status: 101/101 blocks passing** on the `0.7.2/no_forks` trace (tiny config: V=6, C=2, E=12). Grey passes the full conformance block test suite.

```bash
# Quick test: replay trace and show pass/fail per block
python3 scripts/run_conform.py

# Compare state with a reference implementation at any block
python3 scripts/compare_with_ref.py 68

# Dump state at a specific block for debugging
python3 scripts/dump_state.py --block 8
```

See [docs/conformance-testing.md](docs/conformance-testing.md) for the full debugging guide, protocol details, and script reference.

### Known Spec Issues

- [docs/pvm-sbrk.md](docs/pvm-sbrk.md) — Ambiguity in the Gray Paper's `sbrk` definition (`sbrk(0)` is undefined; all implementations use a heap-pointer tracking model)
- [docs/host-call-ordering.md](docs/host-call-ordering.md) — GP requires host calls to read guest memory before privilege checks; memory faults take priority over error sentinels

## Project Structure

```
crates/
  grey/              # Binary — node executable + conformance target
  grey-types/        # Core protocol types and constants
  grey-codec/        # JAM serialization (Appendix C)
  grey-crypto/       # Blake2b, Keccak, Ed25519, Bandersnatch, BLS
  javm/          # Join-Accumulate VM (Appendix A)
  grey-merkle/       # Binary Patricia trie, MMR, state serialization (Appendices D & E)
  grey-erasure/      # Reed-Solomon erasure coding (Appendix H)
  grey-state/        # Chain state transitions (Sections 4–13)
  grey-consensus/    # Safrole block production & authoring (Section 6)
  grey-services/     # Service accounts, accumulation (Sections 9, 12)
  grey-network/      # P2P networking — gossipsub, request-response
  grey-store/        # Persistent storage (redb backend)
  grey-rpc/          # JSON-RPC server (jsonrpsee)
  grey-transpiler/   # RISC-V ELF → PVM bytecode transpiler
services/
  sample-service/    # Minimal PVM service (echo refine, host_write accumulate)
  counter-service/   # Counter PVM service (dual-key storage writes)
```

## License

See [LICENSE](LICENSE) for details.
