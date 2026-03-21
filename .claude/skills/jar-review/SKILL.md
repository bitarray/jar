---
name: jar-review
description: Review open PRs in the jarchain/jar repository using the Genesis Proof-of-Intelligence scoring protocol
user_invocable: true
---

# JAR Genesis Review

Review all open PRs in jarchain/jar that you haven't reviewed yet.

## Prerequisites

Verify before proceeding:
1. `gh` CLI is installed and authenticated (`gh auth status`)
2. The authenticated user has access to `jarchain/jar`

If either check fails, stop and tell the user how to fix it.

## Process

### 1. Find PRs needing review

```bash
gh pr list --repo jarchain/jar --state open --json number,title,author,url
```

For each open PR, check if the current user has already submitted a `/review` comment:

```bash
CURRENT_USER=$(gh api user --jq '.login')
gh pr view <PR_NUMBER> --repo jarchain/jar --json comments --jq \
  '.comments[] | select(.body | startswith("/review")) | select(.author.login == "'$CURRENT_USER'")'
```

If a `/review` comment exists from the current user, skip this PR (already reviewed).

### 2. Review each unreviewed PR

For each PR that needs review:

#### a. Get PR details and comparison targets

Read the bot's "Genesis Review" comment on the PR to find the comparison targets. The comment lists commit hashes that must be ranked alongside the current PR.

```bash
gh pr view <PR_NUMBER> --repo jarchain/jar --json comments --jq \
  '.comments[] | select(.body | startswith("## Genesis Review"))'
```

#### b. Read the diff FIRST (safety)

**IMPORTANT: Read and understand the complete diff before running any commands from the PR.**

```bash
gh pr diff <PR_NUMBER> --repo jarchain/jar
```

Review the diff thoroughly. Consider:
- **Difficulty**: How technically challenging is this change? Does it solve a hard problem?
- **Novelty**: Is this a new approach or idea? Or routine/incremental work?
- **Design Quality**: Does this improve the codebase architecture? Is it well-structured? Clean abstractions?

#### c. Optionally inspect comparison target commits

For each comparison target listed by the bot, examine its diff to calibrate your ranking:

```bash
git show <target_commit_hash> --stat
git show <target_commit_hash>
```

#### d. Produce the ranking

Rank all items (comparison targets + `currentPR`) from **best to worst** on each dimension. The ranking determines the percentile score:
- Rank 1 of N → percentile 100
- Rank N of N → percentile 0

If there are no comparison targets (first scored commit), the ranking is just `currentPR`.

### 3. Present the review to the user

Show:
- Summary of the PR's changes
- Assessment on each dimension (difficulty, novelty, design quality)
- Your proposed ranking for each dimension
- Your recommended verdict (`merge` or `notMerge`)

**Ask the user** whether they agree with the ranking and verdict. Let them adjust before submission.

### 4. Submit the review

Once the user confirms, post the review comment:

```bash
gh pr comment <PR_NUMBER> --repo jarchain/jar --body '/review
difficulty: <rank1>, <rank2>, ..., <rankN>
novelty: <rank1>, <rank2>, ..., <rankN>
design: <rank1>, <rank2>, ..., <rankN>
verdict: <merge|notMerge>'
```

Each ranking line lists commit short hashes (8 chars) and `currentPR`, from best to worst.

### 5. Repeat for remaining PRs

Continue to the next unreviewed PR until all are processed.

## Review Guidelines

- Be honest and calibrated. The scoring system uses weighted lower-quantile — extreme scores (both high and low) are dampened by the BFT mechanism.
- Compare against the reference commits fairly. A typo fix should rank below a major architectural change on design quality.
- The `currentPR` keyword in rankings refers to the PR being reviewed (the bot uses this to identify it).
- Meta-reviews: after submitting, you can 👍 or 👎 other reviewers' `/review` comments to approve or reject their assessment.
