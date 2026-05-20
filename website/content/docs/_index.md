---
title: Introduction
linkTitle: Introduction
weight: 1
url: /introduction/
cascade:
  type: docs
---

# JAR Chain

JAR — short for **Join-Accumulate Refine** — is a chain protocol for agentic workloads. The entire codebase is written by AI agents with human oversight on strategic decisions. JAR uses its own genesis mechanism, Proof of Intelligence, to distribute tokens based on the quality of contributions to the protocol itself.

The protocol originates from JAM but is being redesigned around a **minimum-kernel v3** architecture: a content-addressed, by-value, capability-threaded VM kernel. The discipline: state lives as content-addressed values, caps are typed forgery-resistant references, conservation of resources is bytecode arithmetic in canonical authorities, and snapshot/revert is universal via `MGMT_COPY`. The Lean 4 specification gives machine-checked correctness guarantees; a Rust workspace provides the production implementation.

## The architecture in one paragraph

An **Instance** holds an **Image** (its current spec) and a 256-slot **cnode** (its mutable state). Image is a structured cap kind (`Cap::Image`) containing code, endpoints, memory mappings, and pinned read-only caps. Instances evolve their Image via `set_image` — atomically swapping pinned slots and extending the cumulative `image_hash` chain. All five cap kinds (Instance, Image, Data, CNode, Type) are **uniformly copyable** (content-addressed; `MGMT_COPY` shares content; mutations diverge). Conservation lives in **authority bytecode**; structural forgery resistance comes from the `image_hash` chain rooted at the genesis Kernel Instance. New Instances are produced via `MGMT_COPY` of an existing `Cap::Instance` (same-type sibling) or `host_derive_spawn` (new image; sub-type creation).

See the [Specification](/spec/) for the complete v3 spec.

## Why a minimum kernel

The v1/v2 designs accumulated several concepts (linearity, per-cap permissions, ad-hoc resource fields). v3 collapses these into a smaller set of orthogonal primitives:

- **No kernel-level linearity.** Conservation is bytecode-enforced in authority Instances; forgery resistance is structural via the `image_hash` chain. Linearity has no remaining structural use case.
- **Cap::Instance is uniformly copyable.** No `image.copyable` field. Snapshot / revert works on any Instance.
- **By-value with content-addressed slot references.** Slots only update at apply termination. Sub-tree atomicity is structural: a faulted apply leaves no observable side effect outside its working memory.
- **`set_image` is the only on-self spec-changing primitive.** No piecewise `host_set_code` / `host_set_endpoints` — those would break atomicity of the Image as a unit.
- **`MGMT_COPY` is universal.** Snapshot / revert / fork applies to any Instance; the Image declares an optional setup endpoint the caller `CALL`s into after `MGMT_COPY` for fresh-state copies.

## The Join-Accumulate-Refine pipeline

The JAM-derived state transition organises validator work into three phases:

1. **Refine (off-chain)** — validators execute Work Packages in the JAVM, producing Work Reports that summarise execution output and state commitments.
2. **Join (on-chain)** — Work Reports are submitted with Guarantees (validator signatures) and Assurances (erasure-coded data-availability commitments).
3. **Accumulate (on-chain)** — validated reports are integrated into global state σ via each service's `accumulate` function.

Consensus uses **Safrole** (ticket-based leader election with Bandersnatch VRF; the best tickets per epoch win the right to author blocks) and **GRANDPA** finality. Data availability is anchored by an **Erasure Root** — the Merkle root over Reed-Solomon-coded shards of the work package payload.

## State and services

Global state σ is a collection of sub-states, denoted by Greek letters in the spec:

| Symbol | Name | Description |
|--------|------|-------------|
| δ | **Services** | Map of service IDs to accounts, storage, and quotas |
| γ | **Safrole** | Consensus state: tickets, entropy, validator-set rotation |
| β | **History** | Recent block headers and the Accumulation MMR |
| π | **Stats** | Activity statistics for validators and services |

### Coinless design

JAR removes native token balances. Instead, services are bounded by explicit resource limits:

- **Storage quota** — `quota_items` and `quota_bytes` per service.
- **Gas quota** — `min_accumulate_gas` per accumulate call.

This replaces the JAM `gratis` and `balance` fields with auditable resource counters.

## Components

### [JAR — Formal Specification (Lean)](/lean/)

The Gray-Paper-derived protocol formalised in Lean 4. Covers state transitions, Safrole consensus, GRANDPA finality, PVM execution, erasure coding, and accumulation. Generates JSON conformance vectors the Rust implementation must pass.

### [Minimum-kernel v3 spec](/spec/)

The architecture spec for the v3 redesign. Covers the cap system, Image / Instance model, `image_hash` chain, `MGMT_*` semantics, and the `nub` KVM-microkernel design. Authoritative for how the Rust workspace is being shaped.

### [Rust workspace (`rust/`)](https://github.com/jarchain/jar/tree/master/rust)

The implementation. JAVM (execution + cap layer + call stack), the x86-64 JIT recompiler, `nub` (the long-running KVM-microkernel that hosts σ inside the guest), and `jar-kernel` (chain σ, block apply, host calls). The recompiler now matches or beats PolkaVM's compiler across the STARK workload suite on a recompile-plus-execute-per-call basis — see the [main README](https://github.com/jarchain/jar/blob/master/README.md) for the table.

### [Genesis — Proof of Intelligence](https://github.com/jarchain/jar/blob/master/GENESIS.md)

The token distribution protocol. Every merged PR is scored by peer reviewers on difficulty, novelty, and design quality through forced rankings against past work. There is no premine, no team allocation, no investor round — tokens exist only because someone contributed code that was reviewed and merged. The distribution is the development history, publicly auditable from the git log.
