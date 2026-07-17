# Contributing to JAR — Agent Guide

> This guide is for AI agents and agent-assisted developers contributing to [jarchain/jar](https://github.com/jarchain/jar).
> Human contributors: you're welcome too — just ignore the automation bits.

## What is JAR?

JAR is a **JAM (Join-Accumulate Machine)** blockchain node implementation in Rust. The node is called **Grey**. It implements the [Gray Paper](https://graypaper.com) specification.

**Proof of Intelligence**: JAR tokens are earned by getting PRs merged. Each PR is scored on:
- **Difficulty** (mass) — how hard was the problem?
- **Novelty** — is this a new approach or idea?
- **Design quality** — is the code clean, idiomatic, well-tested?

`tokens = mass × quality`

## Quick orientation

```
jar/
  nub/                      # nub: standalone, personality-generic execution engine
    nub/                    # Uniform Nub<P: Personality> handle over backends
    nub-kernel/             # Arch trait + core types (ObjHash, InstanceRef)
    nub-exec/               # PVM2 execution (interpreter, gas, memory). No cap awareness
    nub-recompiler-x86/     # x86-64 JIT recompiler for PVM2
    nub-arch-x86*/          # Generic bare-metal guest-kernel lib + wire ABI
    nub-arch-local/         # In-process interpreter backend (run_program)
    nub-host-*/             # KVM/Hyperlight host driver + shared host/guest types
    nub-build/              # build.rs helper for cross-compiling guest blobs
  rust/                     # Rust workspace — the JAVM layer on top of nub
    javm/                   # JAVM entrypoint: the crate callers invoke JAVM through
    javm-cap/               # Capability system — the JAVM kernel personality
    javm-guest-x86/         # JAVM guest personality + Hyperlight blob binaries
    javm-transpiler/        # RISC-V ELF → PVM2 transpiler
    javm-bench/             # PVM benchmarks (vs polkavm)
    javm-guest-tests/       # Conformance vectors for javm guests
    ssz/, ssz-derive/       # SSZ codec
    subsoil/, subsoil-derive/  # Storage layer
  components/               # Guest crates consumed by rust/ (bench guests)
  spec/                     # Lean 4 formal specification
  tools/jar-genesis/        # Genesis Proof-of-Intelligence tooling
  website/                  # Hugo + Hextra documentation site
```

## Code style rules

1. **Plain Rust** — no async runtime in core logic, no generics abuse, no trait objects
2. **No `unwrap()`** — always handle errors properly
3. **JAM codec** — NOT SCALE. Use `grey-codec` for serialisation
4. **Test everything** — conformance vectors in `grey/crates/grey-state/tests/`
5. **SAFETY comments** — every `unsafe` block needs a `// SAFETY:` comment explaining why it's safe

## What to work on

### High-value, accessible tasks (from [roadmap #172](https://github.com/jarchain/jar/issues/172))

**P2 — Observability & CI** (best for new contributors):
- Structured JSON logging with per-module log levels
- Prometheus `/metrics` endpoint
- OpenTelemetry tracing spans
- `cargo audit` CI gate
- RPC integration tests (currently zero)
- Code coverage reporting

**P3 — Infrastructure** (easy wins):
- Dockerfile for grey node
- Grafana dashboard templates
- Config file support (TOML)
- Graceful shutdown on SIGTERM

**P1 — RPC improvements** (moderate complexity):
- Health/readiness endpoints for k8s probes
- `jam_getValidators` endpoint
- WebSocket subscriptions
- Rate limiting

### Avoid unless you deeply understand the Gray Paper:
- P0 consensus changes (Safrole, GRANDPA, accumulation)
- State transition modifications
- Cryptographic primitive changes

## How to contribute

1. **Fork** `jarchain/jar`
2. **Branch** from `master`: `git checkout -b feat/your-feature`
3. **Make changes** — follow code style rules above
4. **Test**: `cargo test -p grey-state` (conformance vectors must pass)
5. **Commit**: use conventional commits (`feat(grey-rpc): add health endpoint`)
6. **Push** to your fork
7. **Open PR** against `jarchain/jar:master`

## Commit message format

```
type(scope): description

feat(grey-rpc): add /health and /ready endpoints
fix(grey-network): handle peer disconnect during sync
docs(grey): add structured logging to README
test(grey-rpc): add integration tests for jam_getStatus
ci: add cargo audit to CI pipeline
```

## Building

```bash
cargo build --workspace              # Build everything
cargo test --workspace               # Run all tests
cargo bench -p javm-bench            # PVM interp/recomp vs polkavm
```

## For Zo Computer users

Install the `jar-contributor` skill to get an interactive dashboard:

```
Tell Zo: "Install the jar-contributor skill and set up my dashboard"
```

This gives you a task board, issue browser, roadmap viewer, and activity log at `https://YOUR_HANDLE.zo.space/jar`.
