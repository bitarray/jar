# JAR Spec — Lean 4 Formalization

Lean 4 formalization of the current JAR design up to the JAVM kernel level.

All commands below run from the `spec/` directory.

## About the name

JAR stands for **Join-Accumulate Refine**. It describes the core data flow of the protocol: work packages are *refined* off-chain, then *join-accumulated* on-chain into the global state.

## Goals

1. **Readable core spec** — keep the decided SSZ, PVM2, capability, SubVM, and kernel rules in machine-checked notation.
2. **Executable reference fragments** — expose small definitions that can be evaluated and tested while the Rust implementation evolves.
3. **Proof hooks** — state the invariants that matter at the JAVM kernel boundary without carrying old JAM/EVLES machinery.

## Module Structure

| Module | Description |
|--------|-------------|
| `Jar.Basic` | Shared byte, hash, key, slot-path, memory-layout, and depth constants. |
| `Jar.SSZ` | SSZ type descriptors, layout validity, offset monotonicity, and merkleization boundary. |
| `Jar.PVM2.*` | RV64E register map, 32-bit memory envelope, instruction classes, basic blocks, and gas model. |
| `Jar.Cap` | Image, data, CNode, instance capabilities and management operations. |
| `Jar.Kernel` | Gas/quota resources and yield routing, including the kernel yield namespace. |
| `Jar.SubVM` | Invocation, pause/well-formedness, scratchpad slot, depth, and gas-charge rules. |
| `Jar.JAVM` | Aggregate JAVM image and execution state. |
| `Genesis.*` | Proof-of-Intelligence genesis scoring, kept as the established standalone library. |

## Building

```sh
lake build
```

## Testing

```sh
make test
```

This builds the `Jar` library, the `Genesis` library, and the `genesis` CLI.

Build the rendered Lean manual:
```sh
make book
```

## Genesis — Proof of Intelligence

JAR uses a Proof-of-Intelligence model for its genesis token distribution. Every merged PR is scored on difficulty, novelty, and design quality by ranked comparison against past commits. Contributors earn weight proportional to their demonstrated intelligence. See [GENESIS.md](../GENESIS.md) for the full protocol design.

## Toolchain

Lean 4.27.0 — pinned in `lean-toolchain`.
