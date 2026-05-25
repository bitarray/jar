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

## Test organisation

Tests live in **`<crate>/tests/`** by default — one integration-test file per module under test, named after the module (e.g. `javm-cap/src/cap_hash.rs` → `javm-cap/tests/cap_hash.rs`). They run as separate binaries against the crate's public API, which keeps the source tree free of `#[cfg(test)] mod tests { ... }` boilerplate and forces the API to be reachable through `pub` paths.

Inline `mod tests` is the **exception**, reserved for tests that genuinely need module-private access:

- Private fields on a struct (e.g. `Assembler::labels`, `SandboxMemoryLayout::code_size`).
- Private fns or consts (e.g. `parse_signed_imm`, `reg_bit`, `RegSet::one`).
- `#[cfg(test)]`-only helpers defined on a public type (e.g. `Assembler::code_bytes`) — these don't exist in the integration-test build configuration.
- `pub(crate)` / `pub(super)` / `pub(in crate::foo)` items.

`_tests.rs` sidecar files are not used — pick one of the two forms above.
