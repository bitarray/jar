#!/usr/bin/env bash
# Replay genesis state from git history.
#
# Usage: tools/genesis-replay.sh [--verify | --verify-cache | --rebuild]
#   --verify        Re-evaluate each SignedCommit and compare against stored CommitIndex (default)
#   --verify-cache  Rebuild from git history and compare against genesis-state branch cache
#   --rebuild       Re-evaluate all SignedCommits and output rebuilt genesis.json to stdout
#
# Requires: jq, genesis_evaluate, genesis_validate, and genesis_ranking built
#   lake build genesis_evaluate genesis_validate genesis_ranking
#
# The script walks merge commits from genesisCommit forward, extracting
# Genesis-Commit (SignedCommit) and Genesis-Index (CommitIndex) trailers.
# All data is self-contained in merge commit messages — no external dependencies.

set -euo pipefail

MODE="${1:---verify}"

# Temp files for accumulating large JSON (avoids ARG_MAX limits with --argjson)
TMPDIR_REPLAY=$(mktemp -d)
trap 'rm -rf "$TMPDIR_REPLAY"' EXIT
TMP_COMMITS="$TMPDIR_REPLAY/commits.json"
TMP_INDICES="$TMPDIR_REPLAY/indices.json"
TMP_RANKING="$TMPDIR_REPLAY/ranking.json"

# Read genesis commit from the Lean spec
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GENESIS_COMMIT=$(grep 'def genesisCommit' "$SCRIPT_DIR/../Genesis/State.lean" | grep -oP '"[0-9a-f]{40}"' | tr -d '"')

if [ -z "$GENESIS_COMMIT" ] || [ "$GENESIS_COMMIT" = "0000000000000000000000000000000000000000" ]; then
  echo "Genesis not launched (genesisCommit is unset or zero)." >&2
  exit 0
fi

# Collect all merge commits after genesis
MERGE_COMMITS=$(git log --merges --reverse --format="%H" "${GENESIS_COMMIT}..HEAD")

TMP_SIGNED="$TMPDIR_REPLAY/signed_commits.json"
TMP_STORED="$TMPDIR_REPLAY/stored_indices.json"
echo '[]' > "$TMP_SIGNED"
echo '[]' > "$TMP_STORED"

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
    jq --argjson idx "$INDEX_LINE" '. + [$idx]' "$TMP_STORED" > "$TMP_STORED.tmp" && mv "$TMP_STORED.tmp" "$TMP_STORED"
    continue
  fi

  # Expand short hashes in review rankings to full hashes.
  # Reviews may use 8-char short hashes; the Lean spec needs full 40-char SHAs.
  COMMIT_LINE=$(echo "$COMMIT_LINE" | jq -c '
    .id as $head |
    .comparisonTargets as $targets |
    ($targets + [$head]) as $all |
    .reviews |= [.[] |
      .difficultyRanking |= [.[] | . as $h |
        if ($h | length) < 40 then ($all[] | select(startswith($h))) // $h else . end] |
      .noveltyRanking |= [.[] | . as $h |
        if ($h | length) < 40 then ($all[] | select(startswith($h))) // $h else . end] |
      .designQualityRanking |= [.[] | . as $h |
        if ($h | length) < 40 then ($all[] | select(startswith($h))) // $h else . end]
    ]')

  jq --argjson c "$COMMIT_LINE" '. + [$c]' "$TMP_SIGNED" > "$TMP_SIGNED.tmp" && mv "$TMP_SIGNED.tmp" "$TMP_SIGNED"
  jq --argjson idx "$INDEX_LINE" '. + [$idx]' "$TMP_STORED" > "$TMP_STORED.tmp" && mv "$TMP_STORED.tmp" "$TMP_STORED"
done

SIGNED_COMMITS=$(cat "$TMP_SIGNED")
STORED_INDICES=$(cat "$TMP_STORED")
TOTAL=$(echo "$STORED_INDICES" | jq 'length')
REPLAYABLE=$(echo "$SIGNED_COMMITS" | jq 'length')

if [ "$MODE" = "--rebuild" ]; then
  echo '[]' > "$TMP_INDICES"
  echo '{}' > "$TMP_RANKING"
  echo '[]' > "$TMP_COMMITS"
  for i in $(seq 0 $((REPLAYABLE - 1))); do
    COMMIT=$(echo "$SIGNED_COMMITS" | jq -c ".[$i]")
    PR_CREATED_AT=$(echo "$COMMIT" | jq -r '.prCreatedAt // .mergeEpoch')
    RANKING_SNAPSHOT=$(jq -c --argjson epoch "$PR_CREATED_AT" --slurpfile ranking "$TMP_RANKING" '
      [.[] | select(.epoch < $epoch)] | last | .commitHash // empty |
      . as $hash | $ranking[0][$hash] // empty
    ' "$TMP_INDICES")
    if [ -z "$RANKING_SNAPSHOT" ] || [ "$RANKING_SNAPSHOT" = "null" ]; then
      RANKING_SNAPSHOT="null"
    fi
    INPUT=$(jq -n --argjson commit "$COMMIT" --slurpfile pastIndices "$TMP_INDICES" \
      --argjson ranking "$RANKING_SNAPSHOT" \
      'if $ranking == null then {commit: $commit, pastIndices: $pastIndices[0]}
       else {commit: $commit, pastIndices: $pastIndices[0], ranking: $ranking} end')
    INDEX=$(echo "$INPUT" | .lake/build/bin/genesis_evaluate)
    jq --argjson idx "$INDEX" '. + [$idx]' "$TMP_INDICES" > "$TMP_INDICES.tmp" && mv "$TMP_INDICES.tmp" "$TMP_INDICES"
    jq --argjson c "$COMMIT" '. + [$c]' "$TMP_COMMITS" > "$TMP_COMMITS.tmp" && mv "$TMP_COMMITS.tmp" "$TMP_COMMITS"
    SNAPSHOT=$(jq -n --slurpfile sc "$TMP_COMMITS" --slurpfile idx "$TMP_INDICES" \
      '{signedCommits: $sc[0], indices: $idx[0]}' | .lake/build/bin/genesis_ranking | jq -c '.ranking')
    COMMIT_HASH=$(echo "$INDEX" | jq -r '.commitHash')
    jq --arg key "$COMMIT_HASH" --argjson val "$SNAPSHOT" '. + {($key): $val}' "$TMP_RANKING" > "$TMP_RANKING.tmp" && mv "$TMP_RANKING.tmp" "$TMP_RANKING"
  done
  echo "=== genesis.json ===" >&2
  jq . "$TMP_INDICES"
  echo "=== ranking.json ===" >&2
  jq . "$TMP_RANKING"
  echo "Rebuilt $REPLAYABLE of $TOTAL indices." >&2

elif [ "$MODE" = "--verify" ]; then
  # Compute ranking map incrementally for v2 target validation
  echo '[]' > "$TMP_INDICES"
  echo '{}' > "$TMP_RANKING"
  echo '[]' > "$TMP_COMMITS"
  for i in $(seq 0 $((REPLAYABLE - 1))); do
    COMMIT=$(echo "$SIGNED_COMMITS" | jq -c ".[$i]")
    PR_CREATED_AT=$(echo "$COMMIT" | jq -r '.prCreatedAt // .mergeEpoch')
    RANKING_SNAPSHOT=$(jq -c --argjson epoch "$PR_CREATED_AT" --slurpfile ranking "$TMP_RANKING" '
      [.[] | select(.epoch < $epoch)] | last | .commitHash // empty |
      . as $hash | $ranking[0][$hash] // empty
    ' "$TMP_INDICES")
    if [ -z "$RANKING_SNAPSHOT" ] || [ "$RANKING_SNAPSHOT" = "null" ]; then
      RANKING_SNAPSHOT="null"
    fi
    INPUT=$(jq -n --argjson commit "$COMMIT" --slurpfile pastIndices "$TMP_INDICES" \
      --argjson ranking "$RANKING_SNAPSHOT" \
      'if $ranking == null then {commit: $commit, pastIndices: $pastIndices[0]}
       else {commit: $commit, pastIndices: $pastIndices[0], ranking: $ranking} end')
    VERIFY_INDEX=$(echo "$INPUT" | .lake/build/bin/genesis_evaluate)
    jq --argjson idx "$VERIFY_INDEX" '. + [$idx]' "$TMP_INDICES" > "$TMP_INDICES.tmp" && mv "$TMP_INDICES.tmp" "$TMP_INDICES"
    jq --argjson c "$COMMIT" '. + [$c]' "$TMP_COMMITS" > "$TMP_COMMITS.tmp" && mv "$TMP_COMMITS.tmp" "$TMP_COMMITS"
    SNAPSHOT=$(jq -n --slurpfile sc "$TMP_COMMITS" --slurpfile idx "$TMP_INDICES" \
      '{signedCommits: $sc[0], indices: $idx[0]}' | .lake/build/bin/genesis_ranking | jq -c '.ranking')
    COMMIT_HASH=$(echo "$VERIFY_INDEX" | jq -r '.commitHash')
    jq --arg key "$COMMIT_HASH" --argjson val "$SNAPSHOT" '. + {($key): $val}' "$TMP_RANKING" > "$TMP_RANKING.tmp" && mv "$TMP_RANKING.tmp" "$TMP_RANKING"
  done

  INPUT=$(jq -n \
    --slurpfile indices "$TMP_STORED" \
    --slurpfile signedCommits "$TMP_SIGNED" \
    --slurpfile rankings "$TMP_RANKING" \
    '{indices: $indices[0], signedCommits: $signedCommits[0], rankings: $rankings[0]}')
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
  echo '[]' > "$TMP_INDICES"
  echo '{}' > "$TMP_RANKING"
  echo '[]' > "$TMP_COMMITS"
  for i in $(seq 0 $((REPLAYABLE - 1))); do
    COMMIT=$(echo "$SIGNED_COMMITS" | jq -c ".[$i]")
    PR_CREATED_AT=$(echo "$COMMIT" | jq -r '.prCreatedAt // .mergeEpoch')
    RANKING_SNAPSHOT=$(jq -c --argjson epoch "$PR_CREATED_AT" --slurpfile ranking "$TMP_RANKING" '
      [.[] | select(.epoch < $epoch)] | last | .commitHash // empty |
      . as $hash | $ranking[0][$hash] // empty
    ' "$TMP_INDICES")
    if [ -z "$RANKING_SNAPSHOT" ] || [ "$RANKING_SNAPSHOT" = "null" ]; then
      RANKING_SNAPSHOT="null"
    fi
    INPUT=$(jq -n --argjson commit "$COMMIT" --slurpfile pastIndices "$TMP_INDICES" \
      --argjson ranking "$RANKING_SNAPSHOT" \
      'if $ranking == null then {commit: $commit, pastIndices: $pastIndices[0]}
       else {commit: $commit, pastIndices: $pastIndices[0], ranking: $ranking} end')
    INDEX=$(echo "$INPUT" | .lake/build/bin/genesis_evaluate)
    jq --argjson idx "$INDEX" '. + [$idx]' "$TMP_INDICES" > "$TMP_INDICES.tmp" && mv "$TMP_INDICES.tmp" "$TMP_INDICES"
    jq --argjson c "$COMMIT" '. + [$c]' "$TMP_COMMITS" > "$TMP_COMMITS.tmp" && mv "$TMP_COMMITS.tmp" "$TMP_COMMITS"
    SNAPSHOT=$(jq -n --slurpfile sc "$TMP_COMMITS" --slurpfile idx "$TMP_INDICES" \
      '{signedCommits: $sc[0], indices: $idx[0]}' | .lake/build/bin/genesis_ranking | jq -c '.ranking')
    COMMIT_HASH=$(echo "$INDEX" | jq -r '.commitHash')
    jq --arg key "$COMMIT_HASH" --argjson val "$SNAPSHOT" '. + {($key): $val}' "$TMP_RANKING" > "$TMP_RANKING.tmp" && mv "$TMP_RANKING.tmp" "$TMP_RANKING"
  done

  # Fetch cache from genesis-state branch
  git fetch origin genesis-state 2>/dev/null || { echo "ERROR: cannot fetch genesis-state branch." >&2; exit 1; }
  CACHE=$(git show origin/genesis-state:genesis.json 2>/dev/null || echo "[]")

  CACHE_LEN=$(echo "$CACHE" | jq 'length')
  REBUILT_LEN=$(jq 'length' "$TMP_INDICES")

  if [ "$REBUILT_LEN" -ne "$CACHE_LEN" ]; then
    echo "MISMATCH: rebuilt $REBUILT_LEN indices but cache has $CACHE_LEN." >&2
    exit 1
  fi

  ERRORS=0
  for i in $(seq 0 $((REBUILT_LEN - 1))); do
    R=$(jq -c ".[$i]" "$TMP_INDICES")
    C=$(echo "$CACHE" | jq -c ".[$i]")
    if [ "$R" != "$C" ]; then
      R_HASH=$(echo "$R" | jq -r '.commitHash')
      echo "MISMATCH at index $i (commit $R_HASH):" >&2
      echo "  rebuilt: $R" >&2
      echo "  cache:   $C" >&2
      ERRORS=$((ERRORS + 1))
    fi
  done

  # Verify ranking.json
  CACHED_RANKING=$(git show origin/genesis-state:ranking.json 2>/dev/null || echo '{}')
  CACHED_RANKING_KEYS=$(echo "$CACHED_RANKING" | jq -r 'keys | length')
  REBUILT_RANKING_KEYS=$(jq -r 'keys | length' "$TMP_RANKING")

  if [ "$CACHED_RANKING_KEYS" != "0" ]; then
    if [ "$REBUILT_RANKING_KEYS" -ne "$CACHED_RANKING_KEYS" ]; then
      echo "RANKING MISMATCH: rebuilt $REBUILT_RANKING_KEYS entries but cache has $CACHED_RANKING_KEYS." >&2
      ERRORS=$((ERRORS + 1))
    else
      for KEY in $(jq -r 'keys[]' "$TMP_RANKING"); do
        R=$(jq -c --arg k "$KEY" '.[$k]' "$TMP_RANKING")
        C=$(echo "$CACHED_RANKING" | jq -c --arg k "$KEY" '.[$k]')
        if [ "$R" != "$C" ]; then
          echo "RANKING MISMATCH for commit ${KEY:0:8}:" >&2
          echo "  rebuilt: $R" >&2
          echo "  cache:   $C" >&2
          ERRORS=$((ERRORS + 1))
        fi
      done
    fi
  else
    echo "ranking.json not found or empty — skipping ranking verification." >&2
  fi

  if [ "$ERRORS" -eq 0 ]; then
    echo "Cache verified: $REBUILT_LEN indices match rebuilt state." >&2
  else
    echo "Cache verification failed: $ERRORS mismatches." >&2
    exit 1
  fi

else
  echo "Usage: tools/genesis-replay.sh [--verify | --verify-cache | --rebuild]" >&2
  exit 1
fi
