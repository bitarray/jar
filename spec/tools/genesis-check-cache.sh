#!/usr/bin/env bash
# Check that the genesis-state cache matches git history.
#
# Usage: tools/genesis-check-cache.sh <cache_file>
#   cache_file: path to genesis.json (from genesis-state branch)
#
# Exit 0 if cache matches, 1 if stale.
# Prints mismatch details to stderr.

set -euo pipefail

CACHE_FILE="${1:?usage: genesis-check-cache.sh <cache_file>}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GENESIS_COMMIT=$(grep 'def genesisCommit' "$SCRIPT_DIR/../Genesis/State.lean" | grep -oP '"[0-9a-f]{40}"' | tr -d '"')

if [ -z "$GENESIS_COMMIT" ] || [ "$GENESIS_COMMIT" = "0000000000000000000000000000000000000000" ]; then
  # Genesis not launched — cache should be empty or absent
  exit 0
fi

EXPECTED=$(git log --merges --format="%B" "${GENESIS_COMMIT}..HEAD" | grep -c '^Genesis-Index: ' || true)
ACTUAL=$(jq 'length' "$CACHE_FILE")

if [ "$EXPECTED" -ne "$ACTUAL" ]; then
  echo "ERROR: genesis cache stale — $ACTUAL entries cached, $EXPECTED in git history" >&2
  exit 1
fi
