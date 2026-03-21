# JAR — Codebase Guide

Lean 4 formalization of the JAM (Join-Accumulate Machine) protocol from the Gray Paper v0.7.2.

## Structure

```
Jar/                  Core protocol (Lean 4)
Genesis/              Proof-of-Intelligence distribution protocol
crypto-ffi/           Rust FFI for cryptographic primitives
tests/vectors/        JSON conformance test vectors
tools/                Utility scripts
fuzz/                 Differential fuzzing (Rust)
```

## Build

```bash
cd crypto-ffi && cargo build --release   # Rust crypto library
lake build                                # Lean (default: Jar library)
make test                                 # All 15 test binaries
```

Genesis tools build independently (no Rust needed):
```bash
lake build genesis_select_targets genesis_evaluate genesis_check_merge genesis_finalize genesis_validate
```

## Jar Module — Protocol Spec

| Module | GP Section | Purpose |
|--------|-----------|---------|
| `Jar.Types` | §3–4 | Core types: Constants, Numerics, Validators, Work, Accounts, Header, State |
| `Jar.Notation` | §3 | Custom notation matching Gray Paper conventions |
| `Jar.Codec` | Appendix C | Serialization: fixed-width LE ints, variable-length nats, bit packing |
| `Jar.Crypto` | §3.8, F–G | Blake2b, Keccak256, Ed25519, Bandersnatch VRF, BLS (via FFI) |
| `Jar.PVM` | Appendix A | Polkadot Virtual Machine: rv64em instruction set, gas metering, memory model |
| `Jar.Merkle` | Appendix D–E | Merkle trees and tries for state commitment |
| `Jar.Erasure` | Appendix H | Reed-Solomon erasure coding (GF(2^16), Cantor basis FFT) |
| `Jar.Consensus` | §6, §19 | Safrole block production, GRANDPA finalization |
| `Jar.Services` | §9, §12, §14 | Service accounts, authorization, refinement, work reports |
| `Jar.Accumulation` | §12 | On-chain accumulation: host calls Ω_0–Ω_26, gas tracking |
| `Jar.State` | §4–13 | Block-level state transition Υ(σ, B) = σ' |
| `Jar.Json` | — | ToJson/FromJson instances for all types (hex-encoded byte data) |
| `Jar.Variant` | — | Protocol variant typeclass: `gp072_full`, `gp072_tiny`, `jar080_tiny` |

## Genesis Module — PoI Distribution

Standalone protocol for token distribution via ranked code review. No crypto-ffi dependency.

| File | Purpose |
|------|---------|
| `Genesis/Types.lean` | ContributorId, CommitId, CommitScore, SignedCommit, Contributor, etc. |
| `Genesis/Scoring.lean` | Percentile ranking, weighted lower-quantile (1/3), meta-review filtering |
| `Genesis/State.lean` | evaluate, reconstructState, finalWeights, genesis constants |
| `Genesis/Json.lean` | FromJson/ToJson for all Genesis types |
| `Genesis/Design.lean` | Deferred features: machine metrics, emission decay, impact pool |
| `Genesis/Cli/` | 5 CLI tools: select-targets, evaluate, check-merge, finalize, validate |

CLI tools read JSON stdin, write JSON stdout. Error → `{"error": "..."}` to stderr, exit 1.

## crypto-ffi

Rust static library (`libjar_crypto_ffi.a`) + C bridge (`bridge.c`).

Provides: blake2b, keccak256, ed25519_{sign,verify}, bandersnatch_{sign,verify,ring_*}, bls_{sign,verify}.

Lean declarations in `Jar/Crypto.lean` use `@[extern "jar_*"]`. Bridge in `bridge.c` marshals Lean OctetSeq ↔ raw bytes.

## Testing

### JSON conformance tests
Test vectors in `tests/vectors/<subsystem>/` with `*.input.json` / `*.output.json` pairs.

Subsystems: safrole, statistics, authorizations, history, disputes, assurances, preimages, reports, accumulate.

Each has a `lean_exe` (e.g., `safrolejsontest`) that loads vectors, runs the transition, compares output.

### Bless mode (regenerate expected outputs)
```bash
lake build jarstf
.lake/build/bin/jarstf --bless safrole tests/vectors/safrole/tiny
```

### Property-based tests
`Test/Properties.lean` + `Test/Arbitrary.lean` — uses Plausible for random generation + invariant checking.

### Other tests
`blocktest` (full blocks), `codectest` (roundtrips), `erasuretest` (Reed-Solomon), `trietest` (Merkle), `shuffletest` (Safrole permutations), `cryptotest` (crypto verification).

## Conventions

- **Byte data**: `0x`-prefixed hex strings in JSON
- **Variable naming**: follows Gray Paper (τ → timeslot, η → entropy, κ → validators)
- **Bounded types**: `OctetSeq n`, `Fin n` for indices
- **Error handling**: `Exceptional α` for ok/none/error (GP ∅ ∇)
- **Maps**: `Dict K V` (sorted association lists)
- **Lean toolchain**: v4.27.0 (pinned in `lean-toolchain`)

## GitHub Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | push master, PRs | Build crypto-ffi + `make test` |
| `genesis-pr-opened.yml` | PR opened (master) | Post comparison targets + review template |
| `genesis-review.yml` | `/review` comment | Parse rankings, tally merge votes, auto-merge on quorum |
| `genesis-merge.yml` | quorum or `/merge` | Evaluate commit, update cache, merge PR |

Genesis bot identity: `JAR Bot <legal@bitarray.dev>`.
