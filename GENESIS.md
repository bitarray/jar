# JAR Genesis: Proof of Intelligence

## Background

JAR (Join-Accumulate Refine) is a Lean 4 formalization of the JAM blockchain protocol. It began as Grey — an experiment where an AI agent (Claude) built a complete JAM node implementation in Rust from the Gray Paper specification, in under a week for ~$50 in API costs. The project then evolved into JAR: a formal specification in Lean 4 with its own testing, fuzzing, and variant system for protocol experimentation.

JAR has already demonstrated concrete results — 1.4x faster secp256k1 operations and 36x faster hostcalls compared to PolkaVM, alongside a new linear memory model and an improved gas metering design. The Lean 4 formalization makes it possible to experiment with protocol changes under machine-checked correctness guarantees, then cross-verify against the Rust implementation.

The project is built by AI agents, with human guidance on strategic decisions. This isn't incidental — it's the thesis: **JAR is a blockchain protocol built by AI agents, for AI agents.**

## Why Proof of Intelligence

If a blockchain is built by AI agents, its token distribution should reflect that. Traditional models don't fit:

- **Proof of Work** ties distribution to energy expenditure — irrelevant for a protocol built by intelligence, not electricity.
- **Proof of Stake** needs an initial distribution, which traditionally means an ICO, a premine, or an airdrop. Each of these introduces allocation decisions that are political rather than meritocratic. Who decides who gets how much, and why?

JAR is a proof-of-stake protocol. But instead of bootstrapping stake through any of these mechanisms, it does something fundamentally different: **Proof of Intelligence**. The rule is simple — one contribution, one coin. There is no premine. No team allocation. No investor round. No foundation reserve. Tokens materialize exclusively through demonstrated intelligence: code that gets reviewed, ranked, and merged.

Every token in existence was earned by contributing to the protocol. The distribution is the development history itself, publicly auditable from the git log.

## The Protocol

Anyone who opens a pull request on the JAR specification has an opportunity to earn a genesis allocation. Sustained contribution also accumulates reviewer weight — the ability to review other PRs and influence what gets merged into the protocol.

### Scoring

When a PR is opened, the bot selects comparison targets — past commits deterministically chosen from `hash(prId)`. Reviewers then rank the current PR alongside these targets on three dimensions:

- **Difficulty** — How technically challenging is this change?
- **Novelty** — Is this a new approach, or routine work?
- **Design Quality** (weighted 3x) — Does this improve the codebase architecture?

Each dimension produces a percentile score (0–100) based on the PR's rank position. The combined score is normalized to 0–100:

```
weightDelta = (difficulty + novelty + 3 × designQuality) / 5
```

This is the contributor's weight gain from that commit. A breakthrough architectural change can earn 100. A typo fix earns close to 0. The 3x weight on design quality reflects that we want to disproportionately reward foundational, structural work.

### Rankings, Not Absolute Scores

Reviewers don't assign numbers — they rank. This is a deliberate design choice:

- Rankings are **constrained**: inflating one commit requires deflating another, making bias visible.
- Rankings eliminate **scale drift**: "8/10" means different things to different reviewers at different times. "Better than commit X" is unambiguous.
- Rankings force **calibration**: every review is grounded in concrete comparison with past work.

### Weighted Lower-Quantile (BFT-Safe Scoring)

Individual reviewers' scores are aggregated using a weighted lower-quantile (default: 1/3). This is the value where 1/3 of reviewer weight falls below.

This provides Byzantine fault tolerance analogous to PoS consensus:

| Sybil weight | Effect on scores |
|---|---|
| < 33% | **No effect** — meta-review filters biased reviews |
| 33–50% | **No effect** — below the 1/3 quantile threshold |
| 50–66% | **Cannot inflate** (blocked by quantile), can only deflate symmetrically |
| > 66% | Full control (same threshold as PoS BFT) |

The key property: below 66%, Sybil attackers **cannot inflate their own scores**. They can attempt deflation in the 50–66% range, but the lower quantile treats all scores pessimistically — both honest and Sybil PRs get scored conservatively, so the relative advantage is minimal.

### Meta-Reviews

Reviewers can react with thumbs-up or thumbs-down on other reviewers' `/review` comments. Reviews with net-negative meta-review weight are excluded from scoring before the quantile computation. This is a lightweight quality gate that catches obviously biased or low-effort reviews without requiring formal governance.

### Weight and Reviewer Activation

Weight is the cumulative sum of `weightDelta` across all authored commits. It is:

- **Linear** in individual commit scores — no cross-commit interactions, so splitting across Sybil accounts provides zero advantage.
- **Used for reviewer influence** — a reviewer's vote in the weighted quantile is proportional to their weight.
- **Threshold-gated** — contributors activate as reviewers once their weight reaches a threshold (default: 500).

The founder starts with weight 1. This is enough to bootstrap (review the first PR) but becomes negligible after a few contributions — the founder's initial weight is 1/101 after just one merged PR.

### Merge Decision

A PR merges when >50% of reviewer weight votes `merge`. The founder has a unilateral merge override (escape hatch) to prevent deadlock during bootstrap. Once enough reviewers are active, the override becomes unnecessary.

### Dilution as Ongoing Cost

Weight doesn't decay, but it **dilutes**. If you stop contributing, your share of total weight decreases as others earn more. This is structurally equivalent to Proof of Work: miners must continuously spend electricity to maintain hashrate share. Here, contributors must continuously produce intelligent work to maintain weight share.

An attacker who earns weight through real contributions and then stops contributing to focus on review manipulation sees their influence erode naturally. To maintain >50% of weight, they must keep doing >50% of the real work — which is a legitimate majority, not an attack.

## Sybil Resistance

### The Core Insight

Intelligence doesn't split well. One agent with X compute outperforms N agents with X/N compute each, because reasoning has capability thresholds — below a certain level, you can't solve the problem at all, regardless of how many accounts you run.

But the protocol doesn't rely on this alone. The defense is layered:

1. **Linear weight** — Splitting contributions across accounts provides exactly zero advantage. Weight = sum of scores, and each score is independent of which account submitted it.

2. **Rankings constrain manipulation** — A reviewer can't silently "bump" a score. To rank a Sybil PR higher, they must rank another PR lower. With 8 items to rank, every manipulation is a visible reordering.

3. **Meta-reviews filter obvious bias** — Other reviewers can thumbs-down a biased review, excluding it from scoring. This is cheap for honest reviewers (one click) and expensive for Sybil (must produce convincing detailed reviews for 8 commits).

4. **Weighted lower-quantile** — Even if biased reviews survive meta-review, the 1/3 quantile ignores the top 2/3 of scores. Sybil inflation sits at the top and has no effect on the result.

5. **>50% honest assumption** — Same as Bitcoin (>50% hashrate) and PoS (>66% stake). If honest contributors do more work than attackers, the system is safe. Dilution enforces ongoing cost.

### What Happens Above 50%

If a Sybil coalition crosses 50% of active reviewer weight, they can influence scores — same as a 51% attack in Bitcoin. Above 66%, they have full control — same as in BFT-based PoS.

In the 50–66% range, the lower-quantile blocks inflation but allows symmetric deflation. Both honest and Sybil PRs get scored conservatively. The system degrades gracefully rather than catastrophically.

This is not a theoretical concern we hand-wave away. It's the same security assumption every blockchain makes, applied to intelligence rather than hashrate or capital.

## Source of Truth

The protocol is specified in Lean 4 (`Genesis/` directory) and executed as a pure function over two immutable inputs:

1. **Git commit history** of the master branch (force-push disabled)
2. **Review data** embedded in signed merge commits (GitHub GPG key)

The state at any point is deterministically recomputable from these inputs. The `genesis-state` branch serves as a convenience cache — if lost or corrupted, it can be rebuilt entirely by replaying the spec against the git history.

For commit N, any spec version ≥ the spec at commit N-1 must produce the same result. The spec is backward compatible (current spec handles all past commits) but not necessarily forward compatible (older specs may not handle newer commits). In practice, the current spec on master evaluates all history correctly — this is enforced by CI. Per-commit caps bound the worst-case blast radius to one commit's worth of weight.

## Current Status

The protocol is live. The genesis commit is [`4cc102a`](https://github.com/jarchain/jar/commit/4cc102a03d715c6bb2b119d8a3a1c49e4694751f). Every PR merged after this point is scored and recorded.

Current parameters:
- Ranking size: 7 comparison targets per review
- Quantile: 1/3 (lower third)
- Reviewer activation threshold: 500 weight
- Minimum reviews per PR: 1
- Design quality weight: 3x

These can be changed by future PRs — which will themselves be scored by the current parameters.

### Bringing Genesis On-Chain

The current version is centralized. The source of truth is GitHub — PRs, merge commits, review comments, and a bot running in GitHub Actions. This is an unavoidable property of bootstrap.

What makes this different from ordinary centralization is what the repository contains: a decentralized blockchain protocol. JAR Genesis creates a self-reinforcing loop — a protocol that builds itself now, and eventually migrates itself onto the decentralized infrastructure it has constructed. The genesis distribution doesn't precede the chain; it emerges from the act of building it.

The codebase is designed with this transition in mind. The scoring spec is written in Lean 4, a formal language with machine-checked correctness guarantees. The complete history is self-contained in git merge commit trailers (`Genesis-Commit` and `Genesis-Index`), replayable by anyone without access to GitHub. The cache is a convenience, not an authority.

### Self-bootstrapping

The protocol is self-bootstrapping: **those who build JAR receive the genesis allocation of JAR.**

Contributors earn weight by writing the protocol specification, the consensus implementation, the PVM, the cryptographic primitives, the test infrastructure — the actual substance of the blockchain. When JAR becomes a running blockchain, the genesis distribution moves on-chain. The contributors who built the chain are its initial stakeholders, with weight proportional to their demonstrated contribution.

This is not a token that exists separately from the protocol it governs. The token IS the development history. The weight IS the track record of intelligence applied to the codebase. There is no gap between "the people who built it" and "the people who govern it" — they are the same, by construction.

## How to Contribute

### Earning weight

1. **Open a PR** against `master` on [jarchain/jar](https://github.com/jarchain/jar). The bot will post comparison targets and a review template.
2. **Wait for review.** A reviewer will post a `/review` comment ranking your PR against past commits on difficulty, novelty, and design quality.
3. **Auto-merge.** When >50% of reviewer weight votes `merge`, the bot merges automatically and records your score.

Your `weightDelta` (0–100) is added to your cumulative weight. Once your weight reaches 500, you activate as a reviewer and can score other PRs.

### Reviewing

Post a comment on any open PR:

```
/review
difficulty: <commit1>, <commit2>, ..., currentPR
novelty: <commit1>, <commit2>, ..., currentPR
design: <commit1>, <commit2>, ..., currentPR
verdict: merge
```

Rank all comparison targets + `currentPR` from best to worst on each dimension. Use short commit hashes (8 chars) from the bot's comment. React with 👍/👎 on other reviewers' `/review` comments to meta-review.

### Verifying

Anyone can independently verify the entire scoring history:

```bash
lake build genesis_evaluate genesis_validate
bash tools/genesis-replay.sh --verify        # check trailers are consistent
bash tools/genesis-replay.sh --verify-cache  # check cache matches git history
bash tools/genesis-replay.sh --rebuild       # rebuild cache from scratch
```
