# jar-genesis

Rust CLI for Genesis Proof-of-Intelligence workflows. Called by GitHub Actions (`genesis-merge.yml`, `genesis-pr-opened.yml`, `genesis-review.yml`).

## Commands

```bash
cargo run -p jar-genesis -- workflow pr-opened --pr <N> --created-at <ISO8601>
cargo run -p jar-genesis -- workflow merge --pr <N> [--founder-override]
cargo run -p jar-genesis -- workflow review --pr <N> --comment-author <user> --comment-body <body>
cargo run -p jar-genesis -- replay --mode verify          # trailers self-consistent
cargo run -p jar-genesis -- replay --mode verify-cache    # cache matches full rebuild
cargo run -p jar-genesis -- replay --mode rebuild         # output rebuilt ranking to stdout
cargo run -p jar-genesis -- check-cache <path>            # check cache file vs git history
```

## State

- `genesis-state` branch holds `genesis.json` (cache) and `ranking.json`
- `genesis.json`: array of CommitIndex entries, one per scored merge
- `ranking.json`: map of commitHash → ranking snapshot (sorted contributor list at time of merge)
- Authoritative source of truth: git trailers (`Genesis-Commit`, `Genesis-Index`) on merge commits in master

## Rebuilding Cache

When `genesis-state` is corrupted (duplicate entries, ranking mismatch, etc.):

```bash
# Must be on latest master (HEAD must have all merge commits)
git checkout origin/master --detach
git fetch origin genesis-state

# 1. Verify current state
cargo run -p jar-genesis -- replay --mode verify        # checks trailers
cargo run -p jar-genesis -- replay --mode verify-cache  # checks cache vs rebuild

# 2. Rebuild ranking from scratch (outputs JSON to stdout)
cargo run -p jar-genesis -- replay --mode rebuild 2>/dev/null | sed '/^{/,$ !d' > /tmp/ranking_rebuilt.json

# 3. Fix genesis.json if needed (e.g. remove duplicates)
#    Use python to load, deduplicate, and rewrite

# 4. Push to genesis-state branch
git worktree add /tmp/genesis-fix origin/genesis-state
cd /tmp/genesis-fix
git checkout -B genesis-state origin/genesis-state
cp /tmp/ranking_rebuilt.json ranking.json
# cp fixed genesis.json if needed
git config user.name "JAR Bot" && git config user.email "legal@bitarray.dev"
git add genesis.json ranking.json
git commit -m "fix: rebuild cache"
git push origin genesis-state
cd - && git worktree remove /tmp/genesis-fix

# 5. Verify after push
git fetch origin genesis-state
cargo run -p jar-genesis -- replay --mode verify-cache
```

## Key Invariants

- `len(genesis.json)` must equal the number of `Genesis-Index` trailers between `genesisCommit..HEAD` on master
- Each commitHash in `genesis.json` must be unique
- `ranking.json` entries are computed from `signedCommits` + `indices` via `genesis_ranking` Lean tool — review hashes are expanded before computation
- The `replay --mode rebuild` output is the authoritative ranking; the `genesis_ranking` Lean tool called directly may differ if review hash expansion is skipped

## Known Pitfalls

- `GITHUB_SHA` in `pull_request_target` and `issue_comment` events is frozen at event creation time. Jobs queued behind the `genesis` concurrency group check out stale master. Fix: `git pull origin master --ff-only` after checkout.
- `gh pr merge` on an already-merged PR may silently succeed. The confirm-merge loop sees `state == MERGED` and proceeds to update cache, creating duplicates. Guard: check PR state before merging.
- The `replay --mode rebuild` command outputs only `ranking.json` content (a map), not `genesis.json`. To fix `genesis.json`, edit it directly (e.g. remove duplicates with python).
