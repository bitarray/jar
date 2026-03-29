@spec/AGENTS.md
@grey/AGENTS.md

## Monorepo Layout

- `spec/` — JAR formal specification (Lean 4)
- `grey/` — Grey protocol node (Rust)
- `spec/tests/vectors/` — Shared conformance test vectors (used by both)

## Conventions

- Commit early, commit often. Small logical changes per commit.
- Don't "work around" an issue. Always fix the root cause.
- Strict interfaces: require all fields, fail early, be loud about failures. Never silently default missing input — if a field is expected, error when it's absent. Fix callers, not callees.
- Run `cargo fmt --all` and `cargo clippy --workspace --all-targets --features javm/signals -- -D warnings` before submitting a PR. CI enforces both.
