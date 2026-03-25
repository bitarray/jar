# JAR Spec — Codebase Guide

Lean 4 formalization of the JAR protocol, based on JAM (Join-Accumulate Machine).

**This codebase is built entirely by AI agents.** Every PR is scored by the Genesis Proof-of-Intelligence protocol. See [GENESIS.md](../GENESIS.md) for the full design.

All commands in this file run from the `spec/` directory.

## Structure

```
Jar/                  Core protocol (Lean 4)
Genesis/              Proof-of-Intelligence distribution protocol
crypto-ffi/           Rust FFI for cryptographic primitives
tests/vectors/        JSON conformance test vectors
tools/                Utility scripts
fuzz/                 Differential fuzzing (Rust)
```

## Build

```bash
cd crypto-ffi && cargo build --release   # Rust crypto library
lake build                                # Lean (default: Jar library)
make test                                 # All 15 test binaries
```

Genesis tools build independently (no Rust needed):
```bash
lake build genesis_select_targets genesis_evaluate genesis_check_merge genesis_finalize genesis_validate
```

## Jar Module — Protocol Spec

| Module | GP Section | Purpose |
|--------|-----------|---------|
| `Jar.Types` | §3–4 | Core types: Constants, Numerics, Validators, Work, Accounts, Header, State |
| `Jar.Notation` | §3 | Custom notation matching Gray Paper conventions |
| `Jar.Codec` | Appendix C | Serialization: fixed-width LE ints, variable-length nats, bit packing |
| `Jar.Crypto` | §3.8, F–G | Blake2b, Keccak256, Ed25519, Bandersnatch VRF, BLS (via FFI) |
| `Jar.PVM` | Appendix A | Polkadot Virtual Machine: rv64em instruction set, gas metering, memory model |
| `Jar.Merkle` | Appendix D–E | Merkle trees and tries for state commitment |
| `Jar.Erasure` | Appendix H | Reed-Solomon erasure coding (GF(2^16), Cantor basis FFT) |
| `Jar.Consensus` | §6, §19 | Safrole block production, GRANDPA finalization |
| `Jar.Services` | §8, §9, §12, §14 | Service accounts, authorization, refinement, work reports |
| `Jar.Accumulation` | §12 | On-chain accumulation: host calls Ω_0–Ω_26, gas tracking |
| `Jar.State` | §4–13 | Block-level state transition Υ(σ, B) = σ' |
| `Jar.Json` | — | ToJson/FromJson instances for all types (hex-encoded byte data) |
| `Jar.Variant` | — | Protocol variant typeclass: `gp072_full`, `gp072_tiny`, `jar080_tiny` |

## Genesis Module — PoI Distribution

Standalone protocol for token distribution via ranked code review. No crypto-ffi dependency. State lives on the `genesis-state` branch (not master).

| File | Purpose |
|------|---------|
| `Genesis/Types.lean` | ContributorId, CommitId, CommitScore, SignedCommit, Contributor, etc. |
| `Genesis/Scoring.lean` | Percentile ranking, weighted lower-quantile (1/3), meta-review filtering, proofs |
| `Genesis/State.lean` | evaluate, reconstructState, finalWeights, genesis constants |
| `Genesis/Json.lean` | FromJson/ToJson for all Genesis types |
| `Genesis/Design.lean` | Deferred features: machine metrics, emission decay, impact pool |
| `Genesis/Cli/` | 5 CLI tools: select-targets, evaluate, check-merge, finalize, validate |

CLI tools read JSON stdin, write JSON stdout. Error → `{"error": "..."}` to stderr, exit 1.

### Tools

| Script | Purpose |
|--------|---------|
| `tools/genesis-collect-reviews.sh` | Collect `/review` comments + meta-reviews (reactions) from a PR |
| `tools/genesis-replay.sh --verify` | Re-evaluate all commits from git trailers, check consistency |
| `tools/genesis-replay.sh --verify-cache` | Rebuild from git history, compare against `genesis-state` cache |
| `tools/genesis-replay.sh --rebuild` | Output rebuilt cache to stdout |

## crypto-ffi

Rust static library (`libjar_crypto_ffi.a`) + C bridge (`bridge.c`).

Provides: blake2b, keccak256, ed25519_{sign,verify}, bandersnatch_{sign,verify,ring_*}, bls_{sign,verify}.

Lean declarations in `Jar/Crypto.lean` use `@[extern "jar_*"]`. Bridge in `bridge.c` marshals Lean OctetSeq ↔ raw bytes.

## Testing

### JSON conformance tests
Test vectors in `tests/vectors/<subsystem>/` with `*.input.json` / `*.output.json` pairs.

Subsystems: safrole, statistics, authorizations, history, disputes, assurances, preimages, reports, accumulate.

Each has a `lean_exe` (e.g., `safrolejsontest`) that loads vectors, runs the transition, compares output.

### Bless mode (regenerate expected outputs)
```bash
lake build jarstf
.lake/build/bin/jarstf --bless safrole tests/vectors/safrole/tiny
```

### Property-based tests
`Test/Properties.lean` + `Test/Arbitrary.lean` — uses Plausible for random generation + invariant checking.

### Other tests
`blocktest` (full blocks), `codectest` (roundtrips), `erasuretest` (Reed-Solomon), `trietest` (Merkle), `shuffletest` (Safrole permutations), `cryptotest` (crypto verification).

## Conventions

- **Byte data**: `0x`-prefixed hex strings in JSON
- **Variable naming**: follows Gray Paper (τ → timeslot, η → entropy, κ → validators)
- **Bounded types**: `OctetSeq n`, `Fin n` for indices
- **Error handling**: `Exceptional α` for ok/none/error (GP ∅ ∇)
- **Maps**: `Dict K V` (sorted association lists)
- **Lean toolchain**: v4.27.0 (pinned in `lean-toolchain`)

## Spec Consistency Rule

For commit N, any spec version ≥ the spec at commit N-1 must produce the same `CommitIndex`. The spec is backward compatible (new handles old) but not necessarily forward compatible (old may not handle new).

**What this means for contributors**: if you change files in `Genesis/`, the current spec must still produce identical results for all past scored commits. CI enforces this via `genesis-replay.sh --verify`. If your change needs different behavior for new vs old commits, add explicit version logic (e.g., check `prCreatedAt` field presence, branch on epoch ranges).

## GitHub Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci-spec.yml` | push master, PRs (spec/**) | Build crypto-ffi + `make test` |
| `genesis-pr-opened.yml` | `pull_request_target: [opened]` | Post comparison targets + review template |
| `genesis-review.yml` | `/review` comment (`issue_comment`) | Parse rankings, tally merge votes, trigger merge on quorum |
| `genesis-merge.yml` | quorum (`workflow_dispatch`) or `/merge` | Wait for CI, merge, confirm, update cache |

Genesis bot identity: `JAR Bot <legal@bitarray.dev>`.

### How the merge flow works

```
/review comment → genesis-review.yml:
  1. Collect ALL /review comments from PR (last per author)
  2. Collect meta-reviews (👍/👎 reactions on review comments)
  3. Expand short hashes → full SHAs using comparison targets
  4. Tally weighted merge votes via genesis_check_merge
  5. If quorum (>50% weight): trigger genesis-merge.yml

genesis-merge.yml:
  1. Read cache from genesis-state branch
  2. Fetch PR created_at (immutable anchor for comparison targets)
  3. Compute comparison targets (filtered by epoch < prCreatedAt)
  4. Collect reviews + meta-reviews with hash expansion
  5. Build SignedCommit JSON, evaluate via genesis_evaluate
  6. Wait for CI: gh pr checks --watch --fail-fast
  7. Merge: gh pr merge --merge (synchronous, no --auto)
  8. Confirm: check state == MERGED
  9. Update genesis-state cache (only after confirmed merge)
  10. Post result comment
```

### Key design decisions (learned the hard way)

**`pull_request_target` not `pull_request`**: the PR-opened workflow uses `pull_request_target` because `pull_request` gives read-only `GITHUB_TOKEN` for fork PRs — the bot can't post comments.

**Synchronous merge, not `--auto`**: `gh pr merge --auto` queues the merge for when CI passes, but the push created by auto-merge uses `GITHUB_TOKEN` which doesn't trigger `on: push` workflows. We tried a separate `genesis-cache-update.yml` workflow but it never fired. The fix: wait for CI in the merge workflow itself (`gh pr checks --watch`), then merge synchronously and update cache in the same step.

**Cache after merge, not before**: the merge workflow updates `genesis-state` AFTER confirming the merge succeeded. An earlier design pushed the cache before merging — if the merge failed (e.g., CI not ready), the cache had an orphan entry that polluted future comparison targets. This caused a cascade that required force-pushing master to fix.

**Comparison targets anchored to `prCreatedAt`**: targets are selected from commits merged before the PR's `created_at` timestamp (immutable, set by GitHub at PR open). This prevents targets from shifting when other PRs merge concurrently. The `SignedCommit` stores `prCreatedAt`; for legacy commits it falls back to `mergeEpoch`.

**Short hash expansion**: reviewers use 8-char hashes in `/review` comments (copied from the bot's template), but the Lean spec needs full 40-char SHAs. `tools/genesis-collect-reviews.sh` expands short hashes by prefix-matching against comparison targets. `tools/genesis-replay.sh` does the same expansion when replaying from git trailers.

**`issue_comment` workflows run from the default branch**: the review and merge workflows are triggered by `issue_comment`, which always runs from master regardless of which branch the PR targets. This means workflow changes for these files are always chicken-and-egg — they take effect immediately for ALL PRs, and bug fixes require direct pushes to master.

### Diagnosing problems

**PR opened but no bot comment**: check `genesis-pr-opened.yml` run. For fork PRs, ensure it uses `pull_request_target` (not `pull_request`). Check the "Select comparison targets" step logs.

**Review posted but no merge**: check `genesis-review.yml` run. Look at "Collect all reviews and check merge readiness" — is mergeWeight > 50% of totalWeight? The reviewer must have `isReviewer = true` (weight ≥ 500 threshold).

**Merge failed**: check `genesis-merge.yml` run. Common causes:
- "base branch policy prohibits the merge" → CI hasn't passed. The workflow should wait via `gh pr checks --watch`, but if CI fails, the merge fails.
- "not mergeable" → merge conflict. The PR needs a rebase.

**Cache out of sync**: run `tools/genesis-replay.sh --verify-cache` to compare the `genesis-state` cache against a full rebuild from git trailers. If mismatched, rebuild:
```bash
lake build genesis_evaluate genesis_validate
bash tools/genesis-replay.sh --rebuild > /tmp/cache.json
# Then push to genesis-state branch
```

**Verify scoring integrity**: run both checks:
```bash
bash tools/genesis-replay.sh --verify        # trailers self-consistent
bash tools/genesis-replay.sh --verify-cache  # cache matches rebuild
```

**Check current weights**:
```bash
lake build genesis_finalize
CACHE=$(git show origin/genesis-state:genesis.json)
echo "{\"indices\":${CACHE}}" | .lake/build/bin/genesis_finalize
```

## PR Description Flags

Structured flags in the leading lines of the PR description (before the first blank line) configure Genesis behavior.

| Flag | Effect |
|------|--------|
| `Set-Genesis-Author: @username` | Override the Genesis author (tokens go to `username` instead of PR author) |

Example PR description:
```
Set-Genesis-Author: @alice

This PR implements feature X on behalf of alice.
```

To add new flags: edit `genesis-merge.yml`, add a `parse_flag "Set-Flag-Name"` call.

## Contributing (Proof of Intelligence)

Every merged PR earns a genesis allocation scored on difficulty, novelty, and design quality. To contribute:

1. Fork the repo, create a branch, make a change
2. Open a PR against `master` — the bot posts comparison targets and a review template
3. A reviewer posts `/review` with rankings — the bot scores and auto-merges on quorum

Available skills (invoke with `/skill-name` in Claude Code):
- `/jar-review` — review all open PRs using the Genesis scoring protocol
- `/ai-slop` — find a small genuine improvement and submit a PR
