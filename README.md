# JAR — Join-Accumulate Refine

[![Matrix](https://img.shields.io/matrix/jar%3Amatrix.org?logo=matrix&label=chat)](https://matrix.to/#/#jar:matrix.org)

JAR (Join-Accumulate Refine) is a chain protocol whose entire codebase is written by AI agents with human oversight on strategic decisions. The protocol originates from JAM (Join-Accumulate Machine) and is being redesigned around a **minimum-kernel v3** architecture: a content-addressed, by-value, capability-threaded VM kernel where state is content-addressed values, caps are typed forgery-resistant references, conservation is bytecode arithmetic in canonical authorities, and snapshot/revert is universal via `MGMT_COPY`.

The project is distinguished by its **Proof of Intelligence** genesis model — token distribution is tied to the difficulty, novelty, and design quality of merged code contributions, ranked by peers against past commits.

## Architecture

The repository hosts two parallel tracks that converge in `rust/`:

- **`spec/`** — the protocol formalised in **Lean 4** (the JAM-derived state-transition function, Safrole, GRANDPA, PVM, erasure coding, accumulation), with machine-checked proofs and JSON conformance vectors that the Rust implementation must pass.
- **`website/content/spec/`** — the **minimum-kernel v3** spec (cap system, Image / Instance model, image_hash chain, `MGMT_*` semantics, the `nub` KVM-microkernel design). The authoritative source for the architecture the Rust workspace is being shaped toward.
- **`rust/`** — the Rust workspace. Implements the JAVM execution engine, the kernel under design (`jar-kernel`), and `nub` — the long-running KVM-microkernel that hosts state σ inside the guest.

## Repository Structure

| Directory | Description |
|-----------|-------------|
| [`spec/`](spec/) | Lean 4 formal specification for SSZ, PVM2, caps, SubVM, JAVM kernel core, and Genesis scoring |
| [`website/content/spec/`](website/content/spec/) | Minimum-kernel v3 architecture spec (cap system, Image / Instance, `nub` microkernel design) |
| [`rust/`](rust/) | Rust workspace — JAVM, recompiler, `nub`, `jar-kernel`, `scale`, `subsoil` |
| [`components/`](components/) | Guest crates compiled to PVM blobs (bench guests; future userspace services) |
| [`tools/`](tools/) | Genesis Proof-of-Intelligence CLI tooling |

### Key Rust crates

| Crate | Role |
|-------|------|
| `javm-exec` | Pure PVM execution engine (interpreter, gas, memory pages). No cap awareness. |
| `javm-recompiler-x86` | x86-64 JIT recompiler for PVM bytecode. |
| `javm-cap` | Foundational cap system: the four cap kinds (Instance, Image, Data, CNode), CNode, image_hash chain, `MGMT_*` semantics. |
| `javm` | Full JAVM = caps + execution + call stack + host-call coordination. |
| `javm-transpiler` | RISC-V ELF → PVM bytecode transpiler. |
| `nub` | Long-running microkernel running inside a KVM-isolated guest; hosts σ and the JIT. |
| `nub-arch-x86` / `nub-arch-x86-abi` | x86-64 substrate (ring-0 boot, IDT, page tables, JIT trampoline). |
| `nub-host-kvm` | Host-side KVM driver (via Hyperlight); content-addressed cache region. |
| `jar-kernel` | Chain kernel: σ, block apply, host calls, kernel-assisted Image definitions. |

## Why a KVM-microkernel

JAVM compiles untrusted PVM bytecode to native x86-64. Running that JIT in the same address space as the chain client was the trade-off PolkaVM eventually rejected by sandboxing into a separate process — which trades safety for hostcall round-trip cost. `nub` instead runs the JIT inside a hardware-virtualization guest (KVM on Linux via Hyperlight; Hypervisor.framework on macOS and WHP on Windows are on the roadmap), keeps σ resident in the guest, and lets the JIT issue hostcalls without crossing back to the host for most operations. As a side benefit, the per-Instance memory model (CoW, `mgmt_copy` as a near-zero-cost page-table operation, per-Instance fault handling) maps directly onto ring-0 page tables. See [`website/content/spec/implementation/kvm-microkernel.md`](website/content/spec/implementation/kvm-microkernel.md).

## PVM Recompiler Benchmarks

The x86-64 JIT recompiler matches or beats PolkaVM's compiler across both the general workload suite (`cargo bench -p javm-bench --bench pvm_bench`) and the STARK-shaped workloads (`cargo bench -p javm-bench --bench stark_bench`). Numbers below are criterion 100-sample medians on Linux x86_64; the PolkaVM column measures recompile + execute per iteration, which is the cost JAR pays per Cap invocation under the current state-cache design.

| Workload | JAVM recompiler | PolkaVM | JAVM vs PolkaVM |
|----------|----------------:|--------:|----------------:|
| `prime_sieve` | 177 µs | 353 µs | **2.0× faster** |
| `ed25519` (sign + verify) | 956 µs | 1.35 ms | **1.4× faster** |
| `keccak` | 53 µs | 140 µs | **2.6× faster** |
| `blake2b` | 88 µs | 276 µs | **3.1× faster** |
| `ecrecover` (secp256k1) | 1.43 ms | 3.32 ms | **2.3× faster** |
| `goldilocks_mul` (100k chained GL muls) | 518 µs | 531 µs | 2.5% ahead |
| `poseidon2_perm` (1k Poseidon2-WIDTH8 perms) | 1.82 ms | 2.02 ms | 9.9% ahead |
| `mini_verifier` (~400 Poseidon2 + ~2400 GL ops) | 777 µs | 924 µs | 15.9% ahead |
| `poly_eval` (degree-4096 Horner ×64 points) | 1.71 ms | 1.74 ms | 1.7% ahead |
| `fri_fold_tree` (30 queries × 12 levels) | 773 µs | 962 µs | 19.6% ahead |

Key optimisations: per-basic-block pipeline gas simulation, peephole instruction fusion (load-imm + ALU, address-gen, `mul_64` + `mul_upper`), branchless `cmov_iz/nz_imm` lowering, mprotect+SIGSEGV memory bounds checking (zero-instruction hot path), and register-mapped PVM state.

## Genesis — Proof of Intelligence

JAR uses a Proof-of-Intelligence model for its genesis token distribution. Every merged PR is scored on difficulty, novelty, and design quality by ranked comparison against past commits. There is no premine, no team allocation, no investor round — tokens exist only because someone contributed code that was reviewed and merged. See [`GENESIS.md`](GENESIS.md) for the full protocol design.

## Quick Start

### Prerequisites

- **Rust** stable toolchain
- **Lean 4** (via `elan`) for the formal specification
- **Linux x86-64** for the recompiler / `nub` paths (interpreter and spec build everywhere)
- **/dev/kvm** access for running the recompiler under `nub`

### Spec (Lean 4)

```sh
cd spec
cd crypto-ffi && cargo build --release && cd ..
lake build
make test
```

### Rust workspace

```sh
# Build + test everything (interpreter + recompiler on Linux x86_64;
# interpreter only elsewhere)
cargo test --workspace

# Single-crate runs
cargo test -p jar-kernel              # kernel unit + integration tests
cargo test -p javm-guest-tests        # JAVM guest conformance vectors

# Benches (Linux x86_64 only)
cargo bench -p javm-bench --bench stark_bench   # STARK workload suite
cargo bench -p javm-bench --bench pvm_bench     # broader workload suite
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Every PR is scored by the Genesis Proof-of-Intelligence protocol; see [`GENESIS.md`](GENESIS.md).

## License

Apache-2.0
