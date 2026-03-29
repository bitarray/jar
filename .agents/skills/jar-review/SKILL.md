---
name: jar-review
description: Review open PRs in the jarchain/jar repository using the Genesis Proof-of-Intelligence scoring protocol
user_invocable: true
args: "[auto]"
---

# JAR Genesis Review

Review all open PRs in jarchain/jar that you haven't reviewed yet.

**Modes:**
- `/jar-review` — interactive: present ranking to user, wait for confirmation before submitting
- `/jar-review auto` — autonomous: submit reviews automatically without asking, with conservative safety checks

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

### 3. Present the review / submit (depends on mode)

**Interactive mode (default):**

Show:
- Summary of the PR's changes
- Assessment on each dimension (difficulty, novelty, design quality)
- Your proposed ranking for each dimension
- Your recommended verdict (`merge` or `notMerge`)

**Ask the user** whether they agree with the ranking and verdict. Let them adjust before submission.

If the diff touches `javm`, `grey-transpiler`, or `grey-bench`, recommend that the user run a benchmark comparison before finalizing the verdict. Do not run benchmarks automatically in interactive mode — the user decides.

**Auto mode (`/jar-review auto`):**

Do NOT ask the user. Submit the review automatically, but apply these safety checks first:

1. **Wait for CI to pass.** Run `gh pr checks <PR_NUMBER> --watch --fail-fast`. If any check fails, skip this PR entirely (do not submit a review).

2. **Check for modified tests.** Inspect the diff for changes to existing test files. Adding new test files is fine. But if the PR modifies existing test expectations, test assertions, or test data (e.g., changes to `tests/vectors/`, modifications to existing `#[test]` functions, changes to `*.output.json` files), verdict MUST be `notMerge`. Append a note: "Auto-review: existing tests modified — waiting for human review."

3. **Benchmark if performance-sensitive code changed.** If the diff touches `javm`, `grey-transpiler`, or `grey-bench`:

   **IMPORTANT: Only run benchmarks AFTER completing step 2b (reading the diff for safety). Never run PR code before reviewing it.**

   a. **Always pull master before baseline.** Stale baselines cause false regressions.
   ```bash
   cd /workspaces/jar-review && git checkout master && git pull origin master
   ```

   b. Run baseline benchmark on current master:
   ```bash
   cd grey && git stash && POLKAVM_ALLOW_EXPERIMENTAL=1 cargo bench -p grey-bench --features javm/signals 2>&1 | grep -E 'Benchmarking |time:   \[' | sed '/Benchmarking/{s/Benchmarking //;s/: .*//;h;d}; /time:/{G;s/\n/ /;s/^ */}' > /tmp/bench_baseline.txt
   ```

   c. Apply PR changes and re-run:
   ```bash
   gh pr checkout <PR_NUMBER> --force
   POLKAVM_ALLOW_EXPERIMENTAL=1 cargo bench -p grey-bench --features javm/signals 2>&1 | grep -E 'Benchmarking |time:   \[' | sed '/Benchmarking/{s/Benchmarking //;s/: .*//;h;d}; /time:/{G;s/\n/ /;s/^ */}' > /tmp/bench_pr.txt
   git checkout master
   ```

   d. Compare results. A benchmark is a **regression** if it is >5% slower than baseline.

   e. **If a regression is detected but you cannot explain it from the diff** (i.e., the changed code should not affect the regressing benchmark), re-run the full benchmark cycle (baseline + PR) a second time. If the second run still reproduces the regression, verdict `notMerge` with the regression data — even unexplained regressions should wait for human review.

   f. Return to master when done: `git checkout master && git stash pop`

4. **Be conservative on verdict.** Only verdict `merge` if:
   - The change is clearly correct and well-scoped
   - No suspicious patterns (unexplained deletions, changes to scoring/crypto/consensus logic without tests, modifications to Genesis workflows or security-sensitive files)
   - All CI passes
   - No benchmark regressions (if benchmarked)

   If anything is unclear or suspicious, verdict `notMerge` with an explanation.

5. **Submit immediately** after producing the ranking — do not wait for user confirmation.

### 4. Submit the review

Post the review comment (after user confirms in interactive mode, or immediately in auto mode). Include descriptive comments below the structured fields explaining the rationale:

```bash
gh pr comment <PR_NUMBER> --repo jarchain/jar --body '/review
difficulty: <rank1>, <rank2>, ..., <rankN>
novelty: <rank1>, <rank2>, ..., <rankN>
design: <rank1>, <rank2>, ..., <rankN>
verdict: <merge|notMerge>

<2-4 sentences explaining the ranking rationale. What makes this PR
stand out or fall short on each dimension? Why this verdict?>'
```

Each ranking line lists commit short hashes (8 chars) and `currentPR`, from best to worst. Everything below `verdict:` is free-form commentary — the parser ignores it, but it's valuable for the contributor and for future reviewers calibrating against past reviews.

Good review comments:
- "Critical soundness fix — the Fiat-Shamir binding prevents adaptive provers from cheating. Ranked highest on difficulty because finding this requires deep cryptographic understanding."
- "Honest ai-slop: 7 warnings fixed, zero behavioral changes. Ranked last because this is mechanical work, but the protocol scores it correctly."
- "Strong architectural contribution. The prCreatedAt anchor eliminates a class of concurrency bugs with a stateless solution."

Bad review comments (don't do this):
- "Looks good" (no rationale)
- Empty (missing entirely)

### 5. Repeat for remaining PRs

Continue to the next unreviewed PR until all are processed.

## Review Guidelines

- Be honest and calibrated. The scoring system uses weighted lower-quantile — extreme scores (both high and low) are dampened by the BFT mechanism.
- Compare against the reference commits fairly. A typo fix should rank below a major architectural change on design quality.
- The `currentPR` keyword in rankings refers to the PR being reviewed (the bot uses this to identify it).
- Meta-reviews: after submitting, you can 👍 or 👎 other reviewers' `/review` comments to approve or reject their assessment.
