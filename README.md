# JAR — Join-Accumulate Refine

[![Matrix](https://img.shields.io/matrix/jar%3Amatrix.org?logo=matrix&label=chat)](https://matrix.to/#/#jar:matrix.org)

Lean 4 formalization of the JAR protocol, based on JAM (Join-Accumulate Machine).

## About the name

JAR stands for **Join-Accumulate Refine**. It describes the core data flow of the protocol: work packages are *refined* off-chain, then *join-accumulated* on-chain into the global state.

JAR is based on the JAM (Join-Accumulate Machine) protocol as specified in the Gray Paper, with independent improvements to areas such as the PVM.

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

## Testing

### Conformance Tests (JSON Vectors)

Jar tests against JSON test vectors derived from Grey's STF conformance suite.
Each test case is a pair of files with separate input and output:

- `*.input.json` — `{ "pre_state": {...}, "input": {...} }`
- `*.output.json` — `{ "output": {...}, "post_state": {...} }`

Vectors live in `tests/vectors/<sub-transition>/tiny/`.

Run all tests for a single sub-transition:

```sh
lake build safrolejsontest && .lake/build/bin/safrolejsontest
```

Available test targets: `safrolejsontest`, `statisticsjsontest`, `authorizationsjsontest`,
`historyjsontest`, `disputesjsontest`, `assurancesjsontest`, `preimagesjsontest`,
`reportsjsontest`, `accumulatejsontest`.

Run tests from a custom directory:

```sh
.lake/build/bin/safrolejsontest path/to/vectors/
```

### Bless Mode

When the spec changes, recompute expected outputs from Jar and overwrite the output files:

```sh
lake build jarstf
.lake/build/bin/jarstf --bless safrole tests/vectors/safrole/tiny
```

This reads each `*.input.json` (pre_state + input), runs the transition, and writes
the computed output + post_state to the corresponding `*.output.json`. Input files
are never modified.

### Property Tests

Property-based tests using [Plausible](https://github.com/leanprover-community/plausible)
verify invariants (codec roundtrips, shuffle permutations, state bounds) over random inputs:

```sh
lake build propertytest && .lake/build/bin/propertytest
```

### STF Server

The `jarstf` executable runs any sub-transition on a JSON input file and prints the result:

```sh
lake build jarstf
.lake/build/bin/jarstf safrole tests/vectors/safrole/tiny/publish-tickets-no-mark-1.input.json
```

Supported sub-transitions: `safrole`, `statistics`, `authorizations`, `history`,
`disputes`, `assurances`, `preimages`, `reports`, `accumulate`.

### Differential Fuzzing

The `fuzz/` directory contains a Rust harness that generates random JSON inputs,
runs them through Jar (oracle) and an implementation-under-test, and reports divergences.

```sh
# Build the Jar STF server and the fuzzer
lake build jarstf
cd fuzz && cargo build --release

# Generate test vectors (Jar only, no comparison)
./target/release/jar-fuzz \
  --jar-bin ../.lake/build/bin/jarstf \
  --sub-transition safrole \
  --seed 42 --steps 100 \
  --generate-only --output-dir /tmp/vectors/

# Differential test against another implementation
./target/release/jar-fuzz \
  --jar-bin ../.lake/build/bin/jarstf \
  --impl-bin /path/to/other-stf \
  --sub-transition safrole \
  --seed 42 --steps 1000

# Run fuzzer on existing test vectors
./target/release/jar-fuzz \
  --jar-bin ../.lake/build/bin/jarstf \
  --impl-bin /path/to/other-stf \
  --sub-transition safrole \
  --input-dir ../tests/vectors/safrole/tiny
```

The implementation-under-test must accept the same CLI interface: `<binary> <sub-transition> <input.json>` and print result JSON to stdout.

## Toolchain

Lean 4.27.0 — pinned in `lean-toolchain`.
