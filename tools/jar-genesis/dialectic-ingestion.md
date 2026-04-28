# Dialectic Ingestion — Matrix-Anchored Deliberation as a First Concrete `note` Subtype

*Design document — follow-on to [#801](https://github.com/jarchain/jar/pull/801) (cross-type bridges). Operationalises the `note` ingestion subtype using the existing `#jar:matrix.org` deliberation as a starting corpus, with formal agent-compliance attestations as the curation-quality input. Requesting external feedback.*

## Context

[PR #801](https://github.com/jarchain/jar/pull/801) specifies **ingestion contributions** as the first non-code contribution type and enumerates four subtype tags: `dataset`, `attestation`, `note`, `retraction`. The worked example in #801 leans on datasets because they are the easiest case (clear content hashing, clear curation criteria, well-understood manifest formats).

This document specifies the **`note` subtype**, concretely: structured ingestion of **deliberative discourse** — argument, dissent, sensemaking — produced by the JAR community itself. The proposal is twofold:

1. **Anchor existing discourse.** Begin by ingesting the existing `#jar:matrix.org` archive as a proof-of-concept corpus. The collective's sensemaking apparatus already exists; it is simply unanchored, unindexed, and entirely dependent on `matrix.org` as a hosting party.
2. **Open the substrate to agent-augmented deliberation.** Allow agent-mediated debate (translation, citation, summarisation, optionally second-seat speech) into a dedicated room, ingested under the same scoring path. This expands the deliberative corpus beyond English defaults and produces material that is structurally more amenable to JAR's review mechanism — provided the participating agents are subject to a verifiable compliance regime.

Curation quality is the binding constraint. #801's rubric weights it 3×. For datasets this is a question of license and provenance hygiene. For deliberation it is a question of *who said what, under what constraints, with what verifiable behaviour*. This document proposes [Chimera](https://chimera-protocol.com)-style formal constraints (CSL-Core + Z3 verification + runtime enforcement) as the natural supplier of that curation signal for agent participants.

## Why Deliberation is the Right First `note` Subtype

A `note` could in principle anchor anything that isn't a dataset, attestation, or retraction. Deliberation is the right *first* concrete instantiation because:

- **It already exists in the open.** `#jar:matrix.org` (linked from the project README) has accumulated discussion that materially shaped JAR's design — coinless thesis, refusal pathways, cross-type bridges, the patience tax. None of it is currently anchored. This PR proposes to fix that.
- **It exercises the rubric in a way datasets do not.** "Foundational value" of a dataset is a question of likely future traversal. For a deliberation it is a sharper claim: *did this argument change the project's direction?* That is observable in subsequent commits.
- **It tests the cross-type bridge harder.** Dataset-vs-code is conceptually clean. Deliberation-vs-code is exactly the comparison the 66% threshold was designed to discard cleanly when reviewers cannot judge it. If the mechanism survives this comparison it survives most.
- **It addresses an asymmetry the project tacitly reproduces.** Code commits are scored, anchored, and weighted. The thinking that *generated* the code is currently unanchored and effectively unrewarded. Ingesting deliberation closes that gap without changing the consensus layer.

## Phase 1 — Anchoring Existing Matrix Discourse

The existing `#jar:matrix.org` room is the starting corpus. Concretely:

- A reviewer (or a coalition) selects a thread from room history that they judge to have foundational value — for example, a discussion that influenced the inference-shapes framing, or the cross-type-bridges design.
- The thread is exported as a content-addressed transcript (Matrix event IDs are already cryptographically signed by the homeserver, providing strong source-of-record properties even though `matrix.org` is the current homeserver of record).
- The transcript is wrapped in an ingestion manifest: type tag `note`, subtype `dialectic`, source room, event ID range, participant identities (Matrix user IDs), language, and a one-paragraph reviewer statement on why the thread is worth anchoring.
- The ingestion event is submitted on the path specified in #801. Scoring proceeds normally: 7 same-type targets (other anchored deliberations), 1 cross-type target (a code commit), 3-dimension rubric.

For curation quality, Phase 1 deliberations are scored on the conventional axes: clean transcript, accurate participant attribution, intelligible scope, no redactions of substantive content. This is a tractable judgement for human reviewers even without any agent-compliance machinery, because the participants in existing Matrix history are predominantly humans.

Phase 1 is therefore independently shippable and answers the question *"what does it look like to score deliberation?"* without committing to any of the agent-augmentation that follows.

## Phase 2 — Agent-Augmented Deliberation Rooms

A separate, dedicated room (e.g. `#jar-dialectic:<homeserver>`, ideally not on `matrix.org` so the project owns the substrate) admits agent participants alongside humans. The room operates under stated norms; ingestion is opt-in per thread and reviewer-curated, identical to Phase 1.

The interesting properties Phase 2 produces:

- **Language-agnostic deliberation.** Agents in translator-only mode render each human's contribution in the room's set of supported languages, alongside the original. The English-default tax — currently invisible but real — is removed without imposing a single working language.
- **Ambient citation and provenance.** Agents annotate empirical claims with sources at write-time; this is materially harder to do well after the fact.
- **Asynchronous catch-up at low cost.** Late joiners reconstruct argument state via their own agent without relitigating from scratch.

The risks were enumerated in the prior conversation that prompted this design doc and are restated here for the reviewer record:

- **Voice homogenisation.** If every contribution passes through an LLM rewrite, the room converges to a mid-LLM register and loses information carried in cadence and choice of words. Mitigation: translator-only mode is the default; second-seat (agent-as-proxy) is opt-in and clearly tagged.
- **Asymmetric augmentation.** A participant with a better-tooled agent silently outperforms peers. Mitigation: agent capability is declared per participant in the room state; reviewers can weight or discount accordingly at ingestion time.
- **Cadence flooding.** Per-agent rate limiting is wrong (it is per-human cost that matters). Limits are imposed per human identity, regardless of how many agents act on their behalf.

## Curation Quality via Formal Agent Compliance

The 3× weighting on curation quality in #801 is what makes Phase 2 ingestable at all. Without a verifiable signal about agent behaviour, "agent-mediated deliberation" reduces to "more LLM output", which a reviewer cannot sensibly score. The proposal here is to make the signal **machine-verifiable** rather than reviewer-attested.

[Chimera Protocol](https://chimera-protocol.com) is built precisely for this shape of problem. Its components map onto the requirements as follows:

- **CSL-Core (Constraint Specification Language)** expresses room-level policies as formal constraints. Examples relevant to dialectic ingestion:
  - *No agent shall post an empirical claim without a citation.*
  - *Translator agents shall preserve modal verbs, hedges, and uncertainty markers from the source utterance.*
  - *Every agent post shall declare model identifier, system prompt hash, and the human identity (if any) it is acting on behalf of.*
  - *Per-human posting rate ≤ N over window W.*
- **Chimera Runtime** enforces these constraints at the point of action. Violations are *blocked at runtime*, not detected after the fact — agents that would post non-compliant content cannot post at all. This produces a stream of allow/block decisions with sub-millisecond latency and a structured audit log.
- **Z3 verification** allows policies to be machine-checked for consistency before they are deployed in the room, ruling out contradictory constraints that would silently disable enforcement.

For ingestion, the relevant artefact is the **compliance attestation**: a signed statement from the runtime that, over the event-ID range being ingested, every participating agent action passed enforcement under the declared CSL policy, and that the policy itself verified clean. This attestation is included in the ingestion manifest. Curation-quality scoring then has both a human dimension (was the deliberation substantively well-conducted?) and a machine dimension (did the agents behave inside the declared envelope?).

This is the only part of the proposal that is genuinely novel relative to #801. The rest — types, scoring, manifests, rate limits — is unchanged.

## Manifest Extensions for `note:dialectic`

In addition to the base manifest fields specified in #801 (license, provenance, dependencies):

- `source.platform` — `matrix` for both phases.
- `source.homeserver` — the homeserver of record (`matrix.org` for Phase 1; project-controlled for Phase 2).
- `source.room` — Matrix room ID and human-readable alias.
- `source.event_range` — first and last anchored event IDs.
- `participants[]` — list of `{ matrix_user_id, kind: human|agent, acts_for?: matrix_user_id }`.
- `languages[]` — set of languages present in the transcript.
- `compliance` (Phase 2 only) — `{ policy_hash, runtime_version, attestation_signature, decisions_summary: { allowed, blocked } }`.
- `reviewer_statement` — the curating reviewer's one-paragraph case for foundational value.

## Bot / Tooling Implementation Notes

The `tools/jar-genesis/` extensions specified in #801 (submission intake, comparison-target selection, cross-type review aggregation) cover this subtype with no structural change. Two additions specific to `note:dialectic`:

1. **Manifest validator** for the extended fields above, including a verification step against the compliance attestation signature for Phase 2 submissions.
2. **Reviewer eligibility hint.** The bot annotates the scoring round with the languages present in the manifest so that reviewers self-select where they can usefully judge. This is a hint, not a gate — #801's 66% bridge threshold is the actual filter.

Implementation is a follow-up. This PR is the design proposal.

## Sybil Resistance

Inherits from #801. Two subtype-specific concerns:

- **Self-anchoring.** A contributor could submit their own Matrix posts as ingestable deliberation. Mitigation: the curating reviewer must not be a participant in the anchored thread. (Enforced by manifest check against `participants[]`.)
- **Compliance laundering.** A Phase 2 room could declare a permissive CSL policy and produce attestations of meaningless rigour. Mitigation: the policy hash is part of the manifest, the policy text is on-chain by reference, and reviewers score curation quality with full visibility of what was actually enforced. Permissive policies are not forbidden — they are simply scored lower on curation.

## Relationship to Existing Issues and PRs

- **[#801](https://github.com/jarchain/jar/pull/801) (cross-type bridges).** This document is a follow-on. The `note` subtype enumerated there is given a concrete operational specification here.
- **[#803](https://github.com/jarchain/jar/issues/803) (Network Public design-doc tracking).** Adds dialectic ingestion to the series.
- **`docs/network-public.md`.** The parent thesis explicitly contemplates ingestion of non-dataset artefacts; this is the first one.
- **`docs/inference-shapes.md` ([#800](https://github.com/jarchain/jar/pull/800)).** Reflective interruption is structurally adjacent to the agent-compliance regime proposed here; both are about making model behaviour legible at the substrate.

## Open Questions

**1. Compliance language scope.** Is CSL-Core (or a profile of it) the right policy language, or does JAR want a native subset? CSL-Core is general-purpose; a JAR-native subset would be smaller and easier to reason about, at the cost of forking a maturing standard.

**2. Homeserver of record.** Phase 1 leans on `matrix.org` as host. The strong form of this proposal eventually moves the room to a project-controlled homeserver so that the substrate is not a third-party dependency. Worth deciding before Phase 2.

**3. Compliance attestation for human-only Phase 1 ingestion.** Phase 1 has no agents and therefore no compliance attestation. Should it carry an explicit *null compliance* marker so that the manifest schema is uniform, or should the field be absent for Phase 1?

**4. Translation provenance and dissent.** When an agent translates, which model translated, can dissenters see the original alongside the translation, and is the translation itself an ingestable artefact independent of the source utterance? This is structurally similar to the question of whether commit messages are ingestable independent of the commit.

**5. Second-seat policy.** Does the project want to permit agent-as-proxy speech at all, or is translator-only the permanent norm? The voice-homogenisation risk is real and the upside of second-seat is empirically untested. Recommendation: forbid in the first six months; revisit with data.

**6. Order of subsequent `note` subtypes.** After `dialectic`, what's next? Candidates: `review` (long-form post-mortems), `synthesis` (cross-thread summaries), `dissent` (formally registered objection without consensus). Different orderings stress different parts of the rubric.

## How to Give Feedback

Open an issue on [jarchain/jar](https://github.com/jarchain/jar) or comment on this PR. Particular interest in: whether dialectic is the right first `note` subtype, whether formal agent-compliance is the right curation-quality input (vs. reviewer attestation alone), and the homeserver-of-record question.

---

*Related:*
- *[PR #801](https://github.com/jarchain/jar/pull/801) — cross-type bridges (parent design)*
- *[PR #800](https://github.com/jarchain/jar/pull/800) — inference shapes (sibling)*
- *`docs/network-public.md` — parent thesis*
- *`tools/jar-genesis/cross-type-bridges.md` — added by #801*
- *[Chimera Protocol](https://chimera-protocol.com), [CSL-Core](https://chimera-protocol.com/csl-core), [Chimera Runtime](https://runtime.chimera-protocol.com) — proposed agent-compliance layer*
