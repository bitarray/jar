# Grey — Codebase Guide

JAM protocol node in Rust, based on the JAR specification (`../spec/`). Test vectors come from `../spec/tests/vectors/`.

## Crates

```
crates/
  grey/              # Node binary
  grey-types/        # Protocol types and constants
  grey-codec/        # JAM serialization (Appendix C)
  grey-crypto/       # Blake2b, Keccak, Ed25519, Bandersnatch, BLS
  javm/              # PVM — RISC-V rv64em VM (Appendix A)
  grey-merkle/       # Binary Patricia trie, MMR (Appendix D & E)
  grey-erasure/      # Reed-Solomon erasure coding (Appendix H)
  grey-state/        # State transition logic (Sections 4-13)
  grey-consensus/    # Safrole & GRANDPA (Sections 6, 19)
  grey-services/     # Service accounts, accumulation (Sections 9, 12)
  grey-network/      # P2P networking
  grey-transpiler/   # RISC-V ELF to PVM blob transpiler
  grey-bench/        # Benchmarks (criterion)
  grey-rpc/          # RPC interface
  grey-store/        # Storage backend
```

## Build & Test

All commands run from the `grey/` directory.

```bash
cargo test --workspace                  # all tests (interpreter)
GREY_PVM=recompiler cargo test --workspace  # all tests (recompiler)
```

## Benchmarks

```bash
cargo bench -p grey-bench --features javm/signals                        # full suite
cargo bench -p grey-bench --features javm/signals -- 'fib/|sort/'        # skip ecrecover
cargo bench -p grey-bench --features javm/signals -- ecrecover           # ecrecover only
```

## Guidelines

- `#[cfg(test)]` for unit tests
- `thiserror` for errors, `tracing` for logging (not `eprintln!`)
- Strong typing: newtypes for hashes, keys, indices
- Prefer `no_std` where feasible
- Implement PVM from first principles — do not use `polkavm` or `polkavm-common` crates
