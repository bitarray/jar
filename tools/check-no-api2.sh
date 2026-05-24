#!/usr/bin/env bash
# Workspace invariant check: no member crate may depend on
# `allocator-api2`.
#
# `allocate` is the single source of allocator-aware types
# (Box/Vec/Arc/HashMap + the Allocator trait wrapper). Internally it
# uses the real `core::alloc::Allocator` via RUSTC_BOOTSTRAP (set in
# `.cargo/config.toml`, scoped to `allocate, talc, hashbrown,
# foldhash` only). Pulling in `allocator-api2` would re-introduce the
# dual-trait split we explicitly designed `allocate` to eliminate.
#
# This check is intended for CI. Exits non-zero if any allocator-api2
# dependency is found anywhere in the resolved workspace graph.

set -euo pipefail

cd "$(dirname "$0")/.."

if cargo tree --workspace --prefix none 2>/dev/null \
     | awk '{ print $1 }' | grep -qx 'allocator-api2'; then
  echo "ERROR: workspace depends on allocator-api2." >&2
  echo "       The only sanctioned allocator-trait source is the" >&2
  echo "       \`allocate\` crate, which goes through core::alloc::Allocator" >&2
  echo "       via RUSTC_BOOTSTRAP. Re-introducing allocator-api2 conflicts" >&2
  echo "       with that design." >&2
  echo >&2
  echo "Reverse-dep paths:" >&2
  cargo tree --workspace --invert allocator-api2 >&2 || true
  exit 1
fi

echo "OK: no allocator-api2 in workspace."
