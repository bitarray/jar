#!/usr/bin/env bash
# Workspace invariant: no workspace member crate (besides `allocate`)
# may *directly* depend on `allocator-api2`, and no source file may
# import it.
#
# `allocate` is the single source of allocator-aware types
# (Box/Vec/Arc/HashMap + the Allocator trait wrapper). It internally
# pins `talc 4.4.3` (with the `allocator-api2` feature) plus
# `hashbrown 0.17` (also api2-flavoured) plus `allocator-api2 0.2`
# itself, and re-exports everything through the `allocate::*` façade.
# This check enforces the "all api2 lives in `allocate`" invariant.
#
# Re-introducing a direct `allocator-api2` dep elsewhere — or
# importing `allocator_api2::*` from outside `allocate` — would split
# the workspace across two allocator-trait views and undo the façade.

set -euo pipefail

cd "$(dirname "$0")/.."

failed=0

# Check 1: no workspace member's Cargo.toml declares allocator-api2.
cargo_tomls=$(find rust -maxdepth 2 -name Cargo.toml -not -path '*/allocate/*')
direct_deps=$(grep -l '^\s*allocator-api2\b' $cargo_tomls 2>/dev/null || true)
if [ -n "$direct_deps" ]; then
  echo "ERROR: workspace members directly depend on allocator-api2:" >&2
  echo "$direct_deps" >&2
  failed=1
fi

# Check 2: no source file imports allocator_api2::*.
src_imports=$(grep -rln 'allocator_api2::' rust 2>/dev/null \
                | grep -v '/allocate/' | grep -v '/target/' || true)
if [ -n "$src_imports" ]; then
  echo "ERROR: source files import allocator_api2:" >&2
  echo "$src_imports" >&2
  failed=1
fi

if [ $failed -ne 0 ]; then
  echo >&2
  echo "The only sanctioned allocator-trait source is the \`allocate\`" >&2
  echo "crate, which depends on allocator-api2 0.2 internally and" >&2
  echo "re-exports the Allocator trait + Box/Vec/HashMap. Add the" >&2
  echo "type you need to the \`allocate\` façade instead of pulling" >&2
  echo "api2 in directly." >&2
  exit 1
fi

echo "OK: no direct allocator-api2 deps in workspace members; no allocator_api2:: imports in source."
echo "    (api2 0.2 is encapsulated inside \`allocate\` and re-exported through the workspace façade.)"
