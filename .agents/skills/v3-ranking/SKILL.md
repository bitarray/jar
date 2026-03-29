---
name: v3-ranking
description: Compute and publish v3 Bradley-Terry ranking to a GitHub issue for monitoring
user_invocable: true
---

# v3 Bradley-Terry Ranking Monitor

Compute the v3 (online BT) global ranking on the current commit history and update a GitHub issue with the results. This is for monitoring v3 before activation.

## Process

### 1. Build the genesis tool

```bash
cd jar/spec && lake build genesis
```

### 2. Collect signed commits and indices from git trailers

Parse all `Genesis-Commit` and `Genesis-Index` trailers from merge commits on master:

```bash
cd jar
git fetch origin master
```

Use Python to extract the data:

```python
import json, subprocess

result = subprocess.run(
    ['git', 'log', 'origin/master', '--reverse', '--grep=Genesis-Commit', '--format=%B'],
    capture_output=True, text=True)

signed_commits = []
indices = []
for line in result.stdout.split('\n'):
    line = line.strip()
    if line.startswith('Genesis-Commit:'):
        signed_commits.append(json.loads(line[len('Genesis-Commit:'):].strip()))
    elif line.startswith('Genesis-Index:'):
        indices.append(json.loads(line[len('Genesis-Index:'):].strip()))
```

### 3. Expand short hashes in reviews

Some early commits have 8-char short hashes or GitHub URLs in review rankings. Expand them:

```python
all_full_hashes = set(sc['id'] for sc in signed_commits)
for sc in signed_commits:
    for t in sc.get('comparisonTargets', []):
        all_full_hashes.add(t)

def expand_hash(h):
    if h.startswith('https://'):
        h = h.split('/')[-1]
    if len(h) < 40:
        matches = [fh for fh in all_full_hashes if fh.startswith(h)]
        if len(matches) == 1:
            return matches[0]
    return h

for sc in signed_commits:
    for r in sc['reviews']:
        for key in ['difficultyRanking', 'noveltyRanking', 'designQualityRanking']:
            r[key] = [expand_hash(h) for h in r[key]]
```

### 4. Call genesis ranking with --force-variant v3

Pipe the collected data to the genesis ranking CLI:

```python
input_json = json.dumps({"signedCommits": signed_commits, "indices": indices})

result = subprocess.run(
    ['spec/.lake/build/bin/genesis', 'ranking', '--force-variant', 'v3'],
    input=input_json, capture_output=True, text=True)

output = json.loads(result.stdout)
ranking = output['ranking']
scores = output['scores']  # [{commit, mu, sigma2}, ...]
```

### 5. Fetch PR titles

For each commit in the ranking, look up the PR number (from signed commits) and fetch the title:

```python
sc_by_id = {sc['id']: sc for sc in signed_commits}
idx_by_hash = {idx['commitHash']: idx for idx in indices}

pr_titles = {}
for sc in signed_commits:
    pr_id = sc['prId']
    if pr_id not in pr_titles:
        r = subprocess.run(['gh', 'pr', 'view', str(pr_id), '--repo', 'jarchain/jar',
                           '--json', 'title', '--jq', '.title'],
                          capture_output=True, text=True, timeout=10)
        if r.stdout.strip():
            pr_titles[pr_id] = r.stdout.strip()
```

### 6. Format as markdown table

```python
import math

BT_SCALE = 1000000
lines = []
lines.append("| Rank | Score (μ) | ±σ | Contributor | PR | Description |")
lines.append("|---:|---:|---:|---|---|---|")

for i, score_entry in enumerate(scores):
    ch = score_entry['commit']
    mu = score_entry['mu'] / BT_SCALE
    sigma = math.sqrt(score_entry['sigma2'] / BT_SCALE)
    sc = sc_by_id.get(ch, {})
    idx = idx_by_hash.get(ch, {})
    pr_id = sc.get('prId', 0)
    title = pr_titles.get(pr_id, '?')
    contrib = sc.get('author', '?')
    lines.append(f"| {i+1} | {mu:.2f} | {sigma:.2f} | {contrib} | #{pr_id} | {title[:50]} |")

table = '\n'.join(lines)
```

### 7. Create or update GitHub issue

Look for an existing issue titled "v3 Bradley-Terry Ranking Monitor":

```bash
ISSUE=$(gh issue list --repo jarchain/jar --state open --search "v3 Bradley-Terry Ranking Monitor" --json number --jq '.[0].number')
```

If it exists, update the body. If not, create it:

```bash
# Create
gh issue create --repo jarchain/jar \
  --title "v3 Bradley-Terry Ranking Monitor" \
  --body "$BODY"

# Or update
gh issue edit $ISSUE --repo jarchain/jar --body "$BODY"
```

The body should include:
- Last updated timestamp
- The ranking table
- Summary stats (total commits, contributor breakdown)
- A note that v3 is not yet activated — this is preview data

### 8. Output

Print the issue URL when done.

## Notes

- The `--force-variant v3` flag overrides the epoch-based variant selection, applying v3's online BT algorithm to all commits regardless of their actual epoch.
- The ranking may differ from production (v2 net-wins) — that's the point. We're comparing to decide if v3 is ready for activation.
- Scores (μ) can be negative. Higher is better.
- σ represents uncertainty. New/rarely-compared commits have high σ.
