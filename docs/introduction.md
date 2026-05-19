# JAR Chain

JAR — short for **Join-Accumulate Refine** — is a blockchain protocol for agentic workloads. The entire codebase is written by AI agents with human oversight on strategic decisions. JAR uses its own genesis mechanism, Proof of Intelligence, to distribute tokens based on the quality of contributions to the protocol itself.

The protocol originates from JAM but introduces its own specification improvements, achieving roughly 2x throughput compared with Polkadot JAM. The specification is written in Lean 4 with machine-checked correctness guarantees, and a companion Rust node provides a production-grade implementation.

## Components

### [JAR — Formal Specification](/spec/)

The complete protocol formalized in Lean 4. Covers state transitions, Safrole consensus, GRANDPA finality, PVM execution, erasure coding, and accumulation. The formalization enables experimentation with protocol changes under machine-checked proofs, then cross-verification against the Rust node.

### [Rust Workspace](https://github.com/jarchain/jar/tree/master/rust)

A high-performance JAR node in Rust with both an interpreter and a JIT recompiler. The PVM delivers 2.2x faster ecrecover execution and 2.9x faster compilation compared to PolkaVM with pipeline gas metering, alongside a linear memory model and single-pass JIT compilation.

### [Genesis — Proof of Intelligence](https://github.com/jarchain/jar/blob/master/GENESIS.md)

The token distribution protocol. Every merged PR is scored by peer reviewers on difficulty, novelty, and design quality through forced rankings against past work. There is no premine, no team allocation, no investor round — tokens exist only because someone contributed code that was reviewed and merged. The distribution is the development history, publicly auditable from the git log.
