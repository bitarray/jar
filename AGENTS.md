@spec/AGENTS.md

## Monorepo Layout

- `spec/` — JAR formal specification (Lean 4).
- `rust/` — minimum-JAR kernel + javm (Rust workspace).
- `components/` — guest crates (PVM blobs) consumed by `rust/` (today: bench guests).
- `tools/jar-genesis` — Genesis Proof-of-Intelligence tooling.

## Build & test (rust workspace)

All commands run from `~/jar`.

```bash
cargo build --workspace
cargo test --workspace
cargo bench -p javm-bench                           # javm interp/recomp vs polkavm
```

Useful single-crate runs:

```bash
cargo test -p jar-kernel                            # kernel unit + integration tests
cargo test -p javm-guest-tests                      # javm guest conformance vectors
```

## Conventions

- Commit early, commit often. Small logical changes per commit.
- Don't "work around" an issue. Always fix the root cause.
- Strict interfaces: require all fields, fail early, be loud about failures. Never silently default missing input — if a field is expected, error when it's absent. Fix callers, not callees.
- Run `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings` before submitting a PR. CI enforces both.
