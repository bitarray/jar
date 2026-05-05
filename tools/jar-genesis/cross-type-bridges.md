# Cross-Type Bridges — First Concrete Use of Genesis 2.0

*Design document — operationalises Genesis 2.0's "7+1 comparison" model with **ingestion contributions** as the first non-code contribution type. Supports the Network Public §1 separation. Requesting external feedback.*

## Context

[JAR Genesis 2.0](https://gist.github.com/sorpaas/f8cef1590402a6f4b1b8481419d466e4) generalises Proof of Intelligence to multiple contribution types via a single global Bradley-Terry ranking with confidence-weighted scoring. The mechanism is well-specified, but at present there are no non-code contribution types in production. Genesis 2.0 behaves identically to Genesis 1.0 today.

This document specifies the **first non-code contribution type**: an **ingestion contribution**. The choice is deliberate — ingestion is the simplest possible non-code type to bridge against code. It has objective parts (the contribution exists, it has a content hash, it has a signature) and subjective parts (was the ingested content valuable?). It exercises every part of the Genesis 2.0 mechanism without inventing complex new domains like PoW, PoS, or marketing all at once.

## Ingestion Contributions

### What is an ingestion contribution

An **ingestion contribution** is a signed event submitted to the JAR base layer through the ingestion service described in `docs/network-public.md` §1. Each ingestion event has:

- A **content hash** of the ingested artefact (a dataset, an attestation, a deliberative note, a retraction).
- A **timestamp** anchored on-chain.
- A **signer** — a contributor with active reviewer status.
- A **type tag** (`dataset`, `attestation`, `note`, `retraction`).
- A **manifest** — a small JSON describing what the artefact is, its license, its provenance, and any prior contributions it depends on.

The ingestion service does not score the contribution. It records it. Scoring is what this document is about.

### Why ingestion is the right first type

Ingestion is the right first non-code type because:

- **It has an obvious objective component.** A signed event either exists or it doesn't. Within-type ranking can be partially automated by content-addressed deduplication (re-submitting the same content twice doesn't double the score).
- **It has an obvious subjective component.** Whether an ingested dataset is *valuable* — foundational, novel, well-curated — is a judgement that requires a reviewer.
- **It is independently useful.** Ingestion contributions are a precondition for the rest of the Network Public agenda. Operationalising them now is on the critical path.
- **It exercises the full Genesis 2.0 mechanism.** Same-type comparison among ingestion contributions, cross-type comparison against code, BT lower-bound scoring, the 66% bridge threshold — all of it.

Other candidate first types (PoW deposits, PoS stake, marketing campaigns) are either too objective (no reviewer needed → doesn't exercise the bridge mechanism) or too subjective (no automatable component → high reviewer burden).

## Scoring Workflow

### Same-type comparisons (7 of 8)

When an ingestion contribution is submitted, the PoI bot selects 7 historical ingestion contributions as comparison targets, deterministically chosen from `hash(contributionId)` over the set of ingestion contributions already scored.

For the first ~50 ingestion contributions, fewer than 7 historical ingestion contributions exist. The bot relaxes to whatever is available (up to 7), and the BT confidence interval naturally widens to reflect this. This is the cold-start period; the system is designed to behave gracefully through it.

Reviewers rank the new contribution against the targets on three dimensions, mirroring Genesis 1.0's code review:

- **Foundational value** — is this likely to be traversed by future work? (analogue of difficulty/mass)
- **Novelty** — is this a new dataset/attestation/note, or duplicative of existing material?
- **Curation quality** (weighted 3x) — is the artefact well-formed, well-documented, properly licensed, with clean provenance?

```
weightDelta = (foundationalValue + novelty + 3 × curationQuality) / 5
```

The 3x weight on curation quality plays the role that "design quality" plays in code review: foundational, structural work is rewarded disproportionately.

### Cross-type comparison (1 of 8)

The 8th comparison target is a **code contribution**, deterministically selected from `hash(contributionId)` over the set of merged code commits.

Reviewers vote one of three values: **higher**, **lower**, or **not sure**. The cross-type comparison only counts if `>= 66%` of participating reviewers voted non-"not-sure". If too many reviewers cannot compare (because they understand code but not datasets, or vice versa), the bridge is discarded.

Over many submissions, surviving bridges accumulate. The relative weight of an ingestion contribution to a code contribution emerges from collective reviewer judgement — not from a constitutional parameter.

### Confidence-weighted scoring

Per Genesis 2.0, weight gain is computed from the **lower confidence bound** of the BT estimate. An ingestion contribution with few reviewers and few surviving bridges has a wide confidence interval and earns less than its point estimate. As more reviewers participate and more bridges survive, the interval tightens and the discount fades.

This is the core property that makes opening a new type safe: an ill-formed type cannot meaningfully affect governance because its weight gains are heavily discounted until enough cross-type comparisons accumulate.

## Bot / Tooling Implementation

The existing PoI bot lives at `tools/jar-genesis/`. To support ingestion contributions, three additions are needed (specified at the doc level here; implementation in a follow-up):

### 1. Submission intake

A new submission path: in addition to PR-based code submissions, the bot accepts ingestion submissions via a signed JSON payload posted to a dedicated GitHub issue label (e.g. `ingestion-contribution`).

The issue body contains the ingestion event (content hash, manifest, signature). The bot validates the signature, anchors the event on-chain via the ingestion service, and creates the scoring round.

### 2. Comparison-target selection

The bot's existing target selection logic operates over merged commits. For ingestion contributions, the target pool is the set of already-scored ingestion contributions plus, for slot 8, the set of merged commits. Selection is deterministic (`hash(contributionId)`), preserving the property from Genesis 1.0 that selection is auditable and not gameable.

### 3. Cross-type review aggregation

The bot's existing aggregation computes a weighted lower-quantile over numerical ranks. For cross-type comparisons, the bot additionally:

- Counts the number of non-"not-sure" votes.
- If `>= 66%` of participants voted non-"not-sure", the bridge is recorded with the majority direction (higher or lower).
- Otherwise, the bridge is discarded.
- Recorded bridges feed into the global BT model (per Genesis 2.0).

A small extension to the bot's data model adds a `bridges` table and an aggregation pass.

## Sybil Resistance

Genesis 2.0's defences carry over unchanged. Two ingestion-specific concerns:

- **Spam ingestion.** A contributor could flood the system with low-value ingestion contributions hoping that even small per-submission weight gains add up. Defence: per-contributor ingestion rate is limited (e.g. 1 per day for new contributors, scaling with weight). Submissions exceeding the rate are queued, not rejected — but they enter a single scoring round per period, so the per-submission discount applies aggressively.
- **Bridge manipulation.** A coalition could attempt to coordinate cross-type votes to elevate ingestion contributions relative to code. Defence: the 66% bridge threshold means manipulation requires either a 66% reviewer coalition (the standard BFT bound) or fragmenting reviews so few clear majorities form (which discards the bridges, harming the manipulator's own type).

## Worked Example

A contributor curates a foundational dataset of historical scientific retractions and submits it as an ingestion contribution.

- The bot validates the signature, anchors the event, opens a scoring round.
- 7 historical ingestion contributions are selected as same-type targets. (Suppose there are only 3 — the bot uses what it has.)
- 1 code commit is selected as the cross-type target.
- 12 reviewers participate. They rank the dataset against the 3 historical ingestion targets (consensus: higher than 2, lower than 1) and vote on the cross-type bridge: 8 say "higher than the code commit", 1 says "lower", 3 say "not sure".
- 9 of 12 voted non-"not-sure" — `9/12 = 75%` ≥ 66%, so the bridge is recorded as "ingestion contribution > selected code commit."
- The within-type rank percentile is high. The cross-type bridge contributes one signal to the global BT model. The contribution earns a lower-confidence-bound weight that is meaningful but discounted (because cross-type bridges are still few).
- As more ingestion contributions are submitted and more bridges accumulate, this contribution's effective weight rises (its confidence interval tightens).

## Relationship to Existing Issues

- **[#168](https://github.com/jarchain/jar/issues/168) (Bradley-Terry ranking monitor).** This document specifies the first non-code inputs to the global BT model. The monitor naturally extends to display per-type rankings and bridge density.
- **[#383](https://github.com/jarchain/jar/issues/383) (first-principles audit).** The cross-type bridge mechanism answers part of the calcification concern: governance broadens beyond code contributors as new types accumulate confidence.

## Open Questions

**1. Cold-start mechanics.** With <7 historical ingestion contributions, the BT confidence interval is very wide. Is there a better cold-start than "rely on confidence-discounting"? Possible alternative: import a small set of historical curated datasets as a seed corpus.

**2. Reviewer eligibility.** Not every code reviewer can usefully review ingestion contributions. Should reviewer eligibility be type-specific, or do we trust the 66% bridge threshold to discard uninformed votes?

**3. Manifest standard.** What goes in the manifest is constitutional-ish. License, provenance, and dependencies are clearly required. What else? OpenDataset? Croissant? A bespoke format?

**4. Rate limit calibration.** 1 per day for new contributors is a starting point. Higher rates risk spam; lower rates discourage contributors. Worth modelling against expected submission patterns.

**5. Order of subsequent types.** After ingestion, what's next? PoW (objective, automated within-type) is a natural follow-up because it tests the cross-type bridge against an automated type. Or PoS (also objective). Or governance attestations (most subjective). Different orderings stress different parts of the mechanism.

## How to Give Feedback

Open an issue on [jarchain/jar](https://github.com/jarchain/jar) or comment on this PR. Particular interest in: ingestion as the first type (vs. alternatives), the 3-dimension scoring (foundational/novelty/curation), and the manifest standard.

---

*Related:*
- *`docs/network-public.md` — parent thesis*
- *`docs/genesis.md` — Genesis 1.0 (current production)*
- *[JAR Genesis 2.0](https://gist.github.com/sorpaas/f8cef1590402a6f4b1b8481419d466e4) — the framework this implements*
- *[Issue #168](https://github.com/jarchain/jar/issues/168) — Bradley-Terry ranking monitor*
- *`tools/jar-genesis/` — the bot to extend*
