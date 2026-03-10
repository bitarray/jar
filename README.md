# JAR — JAM Axiomatic Reference

[![Matrix](https://img.shields.io/matrix/jar%3Amatrix.org?logo=matrix&label=chat)](https://matrix.to/#/#jar:matrix.org)

Lean 4 formalization of the JAM (Join-Accumulate Machine) protocol as specified
in the [Gray Paper v0.7.2](https://github.com/gavofyork/graypaper/releases/download/v0.7.2/graypaper-0.7.2.pdf).

## Goals

1. **Correctness proofs** — prove key invariants (codec roundtrips, gas safety, state transition properties)
2. **Readable specification** — serve as an alternative, machine-checked notation for the Gray Paper
3. **Executable reference** — `#eval`-able definitions that can be tested against conformance vectors

## Module Structure

| Module | Gray Paper | Description |
|--------|-----------|-------------|
| `Jar.Notation` | §3 | Custom notation matching GP conventions |
| `Jar.Types` | §3–4 | Core types, constants, data structures |
| `Jar.Codec` | Appendix C | JAM serialization codec |
| `Jar.Crypto` | §3.8, App F–G | Cryptographic primitives |
| `Jar.PVM` | Appendix A | Polkadot Virtual Machine |
| `Jar.Merkle` | Appendices D–E | Merklization and Merkle tries |
| `Jar.Erasure` | Appendix H | Reed-Solomon erasure coding |
| `Jar.State` | §4–13 | State transition function |
| `Jar.Consensus` | §6, §19 | Safrole and GRANDPA |
| `Jar.Services` | §9, §12, §14 | Service accounts and work pipeline |

## Building

```sh
cd jar
lake build
```

## Toolchain

Lean 4.27.0 — pinned in `lean-toolchain`.
