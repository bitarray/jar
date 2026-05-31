# `res/vectors/` — committed regression vectors

Each `*.json` here is a **real** interpreter ↔ recompiler ↔ oracle divergence
that `live.rs` surfaced, **shrunk to a minimal reproducer** and minted with the
Spike oracle's golden `x10`. `tests/vectors.rs` replays every vector and asserts
both engines match the gold — so a fixed bug can never silently regress.

This is **not** a place for bulk random-minted corpora (the `mint` binary can
regenerate those on demand). Only curated, real failing cases belong here, one
file per bug.

Vector schema: see `javm_fuzz::VectorFile`. Regenerate a vector with
`cargo run -p javm-fuzz --bin live -- res/vectors/<name>.json`.
