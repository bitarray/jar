#!/usr/bin/env bash
# Replay genesis state from git history.
#
# Usage: tools/genesis-replay.sh [--verify | --verify-cache | --rebuild]
#   --verify        Re-evaluate each SignedCommit and compare against stored CommitIndex (default)
#   --verify-cache  Rebuild from git history and compare against genesis-state branch cache
#   --rebuild       Re-evaluate all SignedCommits and output rebuilt genesis.json to stdout
#
# Requires: jq, genesis_evaluate and genesis_validate built
#   lake build genesis_evaluate genesis_validate
#
# The script walks merge commits from genesisCommit forward, extracting
# Genesis-Commit (SignedCommit) and Genesis-Index (CommitIndex) trailers.
# All data is self-contained in merge commit messages — no external dependencies.

set -euo pipefail

MODE="${1:---verify}"

# Read genesis commit from the Lean spec
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GENESIS_COMMIT=$(grep 'def genesisCommit' "$SCRIPT_DIR/../Genesis/State.lean" | grep -oP '"[0-9a-f]{40}"' | tr -d '"')

if [ -z "$GENESIS_COMMIT" ] || [ "$GENESIS_COMMIT" = "0000000000000000000000000000000000000000" ]; then
  echo "Genesis not launched (genesisCommit is unset or zero)." >&2
  exit 0
fi

# Collect all merge commits after genesis
MERGE_COMMITS=$(git log --merges --reverse --format="%H" "${GENESIS_COMMIT}..HEAD")

SIGNED_COMMITS="[]"
STORED_INDICES="[]"

for MERGE_HASH in $MERGE_COMMITS; do
  MSG=$(git log -1 --format="%B" "$MERGE_HASH")

  # Extract Genesis-Index trailer
  INDEX_LINE=$(echo "$MSG" | grep '^Genesis-Index: ' | sed 's/^Genesis-Index: //' || true)
  if [ -z "$INDEX_LINE" ]; then
    continue  # Not a genesis merge commit
  fi

  # Extract Genesis-Commit trailer
  COMMIT_LINE=$(echo "$MSG" | grep '^Genesis-Commit: ' | sed 's/^Genesis-Commit: //' || true)

  if [ -z "$COMMIT_LINE" ]; then
    echo "WARNING: No Genesis-Commit trailer for merge $MERGE_HASH. Cannot replay." >&2
    STORED_INDICES=$(echo "$STORED_INDICES" | jq --argjson idx "$INDEX_LINE" '. + [$idx]')
    continue
  fi

  SIGNED_COMMITS=$(echo "$SIGNED_COMMITS" | jq --argjson c "$COMMIT_LINE" '. + [$c]')
  STORED_INDICES=$(echo "$STORED_INDICES" | jq --argjson idx "$INDEX_LINE" '. + [$idx]')
done

TOTAL=$(echo "$STORED_INDICES" | jq 'length')
REPLAYABLE=$(echo "$SIGNED_COMMITS" | jq 'length')

if [ "$MODE" = "--rebuild" ]; then
  REBUILT="[]"
  for i in $(seq 0 $((REPLAYABLE - 1))); do
    COMMIT=$(echo "$SIGNED_COMMITS" | jq -c ".[$i]")
    INPUT=$(jq -n --argjson commit "$COMMIT" --argjson pastIndices "$REBUILT" \
      '{commit: $commit, pastIndices: $pastIndices}')
    INDEX=$(echo "$INPUT" | .lake/build/bin/genesis_evaluate)
    REBUILT=$(echo "$REBUILT" | jq --argjson idx "$INDEX" '. + [$idx]')
  done
  echo "$REBUILT" | jq .
  echo "Rebuilt $REPLAYABLE of $TOTAL indices." >&2

elif [ "$MODE" = "--verify" ]; then
  INPUT=$(jq -n \
    --argjson indices "$STORED_INDICES" \
    --argjson signedCommits "$SIGNED_COMMITS" \
    '{indices: $indices, signedCommits: $signedCommits}')
  RESULT=$(echo "$INPUT" | .lake/build/bin/genesis_validate)
  echo "$RESULT" | jq .
  VALID=$(echo "$RESULT" | jq -r '.valid')
  ERRORS=$(echo "$RESULT" | jq '.errors | length')
  if [ "$VALID" = "true" ]; then
    echo "Verified $REPLAYABLE of $TOTAL indices. All match." >&2
  else
    echo "Verification failed: $ERRORS errors in $REPLAYABLE replayable indices." >&2
    exit 1
  fi

elif [ "$MODE" = "--verify-cache" ]; then
  # Rebuild from git history, then compare against genesis-state branch cache
  REBUILT="[]"
  for i in $(seq 0 $((REPLAYABLE - 1))); do
    COMMIT=$(echo "$SIGNED_COMMITS" | jq -c ".[$i]")
    INPUT=$(jq -n --argjson commit "$COMMIT" --argjson pastIndices "$REBUILT" \
      '{commit: $commit, pastIndices: $pastIndices}')
    INDEX=$(echo "$INPUT" | .lake/build/bin/genesis_evaluate)
    REBUILT=$(echo "$REBUILT" | jq --argjson idx "$INDEX" '. + [$idx]')
  done

  # Fetch cache from genesis-state branch
  git fetch origin genesis-state 2>/dev/null || { echo "ERROR: cannot fetch genesis-state branch." >&2; exit 1; }
  CACHE=$(git show origin/genesis-state:genesis.json 2>/dev/null || echo "[]")

  CACHE_LEN=$(echo "$CACHE" | jq 'length')
  REBUILT_LEN=$(echo "$REBUILT" | jq 'length')

  if [ "$REBUILT_LEN" -ne "$CACHE_LEN" ]; then
    echo "MISMATCH: rebuilt $REBUILT_LEN indices but cache has $CACHE_LEN." >&2
    exit 1
  fi

  ERRORS=0
  for i in $(seq 0 $((REBUILT_LEN - 1))); do
    R=$(echo "$REBUILT" | jq -c ".[$i]")
    C=$(echo "$CACHE" | jq -c ".[$i]")
    if [ "$R" != "$C" ]; then
      R_HASH=$(echo "$R" | jq -r '.commitHash')
      echo "MISMATCH at index $i (commit $R_HASH):" >&2
      echo "  rebuilt: $R" >&2
      echo "  cache:   $C" >&2
      ERRORS=$((ERRORS + 1))
    fi
  done

  if [ "$ERRORS" -eq 0 ]; then
    echo "Cache verified: $REBUILT_LEN indices match rebuilt state." >&2
  else
    echo "Cache verification failed: $ERRORS mismatches in $REBUILT_LEN indices." >&2
    exit 1
  fi

else
  echo "Usage: tools/genesis-replay.sh [--verify | --verify-cache | --rebuild]" >&2
  exit 1
fi
