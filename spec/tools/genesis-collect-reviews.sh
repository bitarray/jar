#!/usr/bin/env bash
# Collect all /review comments and their meta-reviews (reactions)
# from a GitHub PR.
#
# Usage: genesis-collect-reviews.sh <pr_number> [head_sha] [targets_json]
# Requires: GH_TOKEN, gh cli, jq
#
# If head_sha is provided, "currentPR" in rankings is replaced with the SHA.
# If targets_json is provided (JSON array of full commit hashes), short hashes
# in rankings are expanded to full hashes by prefix matching.
#
# Output (JSON to stdout):
#   {"reviews": [...], "metaReviews": [...]}

set -euo pipefail

PR_NUMBER="$1"
HEAD_SHA="${2:-}"
TARGETS_JSON="${3:-[]}"
REPO="${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner --jq '.nameWithOwner')}"

to_json_array() { echo "$1" | tr ',' '\n' | jq -R . | jq -s .; }

# Expand short hashes to full hashes using TARGETS_JSON and HEAD_SHA.
expand_hashes() {
  local CSV="$1"
  local RESULT=""
  local FIRST=true
  for HASH in $(echo "$CSV" | tr ',' ' '); do
    local EXPANDED="$HASH"
    if [ "${#HASH}" -lt 40 ]; then
      if [ -n "$HEAD_SHA" ] && [[ "$HEAD_SHA" == "$HASH"* ]]; then
        EXPANDED="$HEAD_SHA"
      else
        local MATCH=$(echo "$TARGETS_JSON" | jq -r --arg h "$HASH" '.[] | select(startswith($h))' | head -1)
        if [ -n "$MATCH" ]; then
          EXPANDED="$MATCH"
        fi
      fi
    fi
    if [ "$FIRST" = true ]; then
      RESULT="$EXPANDED"
      FIRST=false
    else
      RESULT="${RESULT},${EXPANDED}"
    fi
  done
  echo "$RESULT"
}

parse_review() {
  local BODY="$1"
  local AUTHOR="$2"
  local RAW_DIFF=$(echo "$BODY" | grep -i '^difficulty:' | sed 's/^difficulty:\s*//' | tr -d ' ')
  local RAW_NOV=$(echo "$BODY" | grep -i '^novelty:' | sed 's/^novelty:\s*//' | tr -d ' ')
  local RAW_DES=$(echo "$BODY" | grep -i '^design:' | sed 's/^design:\s*//' | tr -d ' ')
  local VERD=$(echo "$BODY" | grep -i '^verdict:' | sed 's/^verdict:\s*//' | tr -d ' ')
  # Replace "currentPR" with actual commit SHA if provided
  if [ -n "$HEAD_SHA" ]; then
    local DIFF=$(echo "$RAW_DIFF" | sed "s/currentPR/$HEAD_SHA/g")
    local NOV=$(echo "$RAW_NOV" | sed "s/currentPR/$HEAD_SHA/g")
    local DES=$(echo "$RAW_DES" | sed "s/currentPR/$HEAD_SHA/g")
  else
    local DIFF="$RAW_DIFF"
    local NOV="$RAW_NOV"
    local DES="$RAW_DES"
  fi
  # Expand short hashes to full hashes
  DIFF=$(expand_hashes "$DIFF")
  NOV=$(expand_hashes "$NOV")
  DES=$(expand_hashes "$DES")
  if [ -n "$DIFF" ] && [ -n "$NOV" ] && [ -n "$DES" ] && [ -n "$VERD" ]; then
    jq -n \
      --arg reviewer "$AUTHOR" \
      --argjson diff "$(to_json_array "$DIFF")" \
      --argjson nov "$(to_json_array "$NOV")" \
      --argjson des "$(to_json_array "$DES")" \
      --arg verdict "$VERD" \
      '{reviewer: $reviewer, difficultyRanking: $diff, noveltyRanking: $nov, designQualityRanking: $des, verdict: $verdict}'
  fi
}

# Fetch all comments on the PR with their IDs, authors, and bodies
# gh pr view --json comments doesn't include comment IDs, so use the API
COMMENTS_JSON=$(gh api "repos/${REPO}/issues/${PR_NUMBER}/comments" --paginate --jq \
  '[.[] | select(.body | startswith("/review")) | {id: .id, author: .user.login, body: .body}]')

# Parse reviews (last review per author wins)
REVIEWS="[]"
# Track comment IDs for each reviewer's latest review (for meta-review collection)
REVIEW_COMMENT_IDS="[]"

for row in $(echo "$COMMENTS_JSON" | jq -r '.[] | @base64'); do
  COMMENT=$(echo "$row" | base64 -d)
  COMMENT_ID=$(echo "$COMMENT" | jq -r '.id')
  AUTHOR=$(echo "$COMMENT" | jq -r '.author')
  BODY=$(echo "$COMMENT" | jq -r '.body')

  REVIEW=$(parse_review "$BODY" "$AUTHOR")
  if [ -n "$REVIEW" ]; then
    # Replace existing review from same reviewer
    REVIEWS=$(echo "$REVIEWS" | jq --arg r "$AUTHOR" --argjson rev "$REVIEW" \
      '[.[] | select(.reviewer != $r)] + [$rev]')
    # Track the comment ID for this reviewer's latest review
    REVIEW_COMMENT_IDS=$(echo "$REVIEW_COMMENT_IDS" | jq \
      --arg r "$AUTHOR" --argjson id "$COMMENT_ID" \
      '[.[] | select(.reviewer != $r)] + [{reviewer: $r, commentId: $id}]')
  fi
done

# Collect meta-reviews: 👍/👎 reactions on the latest /review comment per reviewer
META_REVIEWS="[]"

for row in $(echo "$REVIEW_COMMENT_IDS" | jq -r '.[] | @base64'); do
  ENTRY=$(echo "$row" | base64 -d)
  COMMENT_ID=$(echo "$ENTRY" | jq -r '.commentId')
  TARGET_REVIEWER=$(echo "$ENTRY" | jq -r '.reviewer')

  # Fetch reactions for this comment
  REACTIONS=$(gh api "repos/${REPO}/issues/comments/${COMMENT_ID}/reactions" --jq \
    '[.[] | {user: .user.login, content: .content}]' 2>/dev/null || echo "[]")

  # Map +1 → approve:true, -1 → approve:false
  for reaction_row in $(echo "$REACTIONS" | jq -r '.[] | select(.content == "+1" or .content == "-1") | @base64'); do
    REACTION=$(echo "$reaction_row" | base64 -d)
    META_REVIEWER=$(echo "$REACTION" | jq -r '.user')
    CONTENT=$(echo "$REACTION" | jq -r '.content')

    if [ "$CONTENT" = "+1" ]; then
      APPROVE=true
    else
      APPROVE=false
    fi

    META_REVIEW=$(jq -n \
      --arg metaReviewer "$META_REVIEWER" \
      --arg targetReviewer "$TARGET_REVIEWER" \
      --argjson approve "$APPROVE" \
      '{metaReviewer: $metaReviewer, targetReviewer: $targetReviewer, approve: $approve}')

    META_REVIEWS=$(echo "$META_REVIEWS" | jq --argjson mr "$META_REVIEW" '. + [$mr]')
  done
done

# Output
jq -n \
  --argjson reviews "$REVIEWS" \
  --argjson metaReviews "$META_REVIEWS" \
  '{reviews: $reviews, metaReviews: $metaReviews}'
