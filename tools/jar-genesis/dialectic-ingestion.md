# Dialectic Ingestion — Matrix-Anchored Deliberation as a First Concrete `note` Subtype

*Design document — follow-on to [#801](https://github.com/jarchain/jar/pull/801) (cross-type bridges). Operationalises the `note` ingestion subtype using the existing `#jar:matrix.org` deliberation as a starting corpus, with **deliberation and submission as separate primitives**: deliberation happens in chat (and locally, against a participant's own knowledge base and agent); submission is a discrete, bounded act with its own scoring path. Requesting external feedback.*

## Context

[PR #801](https://github.com/jarchain/jar/pull/801) specifies **ingestion contributions** as the first non-code contribution type and enumerates four subtype tags: `dataset`, `attestation`, `note`, `retraction`. The worked example in #801 leans on datasets because they are the easiest case (clear content hashing, clear curation criteria, well-understood manifest formats).

This document specifies the **`note` subtype**, concretely: structured ingestion of **deliberative discourse** — argument, dissent, sensemaking — produced by the JAR community itself. The proposal is in two phases:

1. **Anchor existing discourse.** Begin by ingesting the existing `#jar:matrix.org` archive as a proof-of-concept corpus. The collective's sensemaking apparatus already exists; it is unanchored, unindexed, and currently dependent on `matrix.org` as a hosting party.
2. **Local-first agent augmentation.** Allow participants to sync the room locally and use their own agents and knowledge bases to reason against the corpus. The *outputs* of that local reasoning — syntheses, translations, formally cited summaries, registered dissents — are what get submitted as `note:dialectic` ingestions, on the same scoring path as Phase 1. The room itself stays a human surface; agents do not post in it by default.

Curation quality is the binding constraint. #801's rubric weights it 3×. For datasets this is a question of license and provenance hygiene. For deliberation it is a question of *what was anchored, by whom, with what stated method, and with what verifiable model provenance*. Because Phase 2 is local-first, the curation signal lives at the *submission boundary*, not inside a runtime that polices a room — which simplifies the design substantially.

## Why Deliberation is the Right First `note` Subtype

A `note` could in principle anchor anything that isn't a dataset, attestation, or retraction. Deliberation is the right *first* concrete instantiation because:

- **It already exists in the open.** `#jar:matrix.org` (linked from the project README) has accumulated discussion that materially shaped JAR's design — coinless thesis, refusal pathways, cross-type bridges, the patience tax. None of it is currently anchored. This PR proposes to fix that.
- **It exercises the rubric in a way datasets do not.** "Foundational value" of a dataset is a question of likely future traversal. For a deliberation it is a sharper claim: *did this argument change the project's direction?* That is observable in subsequent commits.
- **It tests the cross-type bridge harder.** Dataset-vs-code is conceptually clean. Deliberation-vs-code is exactly the comparison the 66% threshold was designed to discard cleanly when reviewers cannot judge it. If the mechanism survives this comparison it survives most.
- **It addresses an asymmetry the project tacitly reproduces.** Code commits are scored, anchored, and weighted. The thinking that *generated* the code is currently unanchored and effectively unrewarded. Ingesting deliberation closes that gap without changing the consensus layer.

## Deliberation and Submission as Separate Primitives

The single most important architectural commitment in this proposal — surfaced in the Matrix discussion that prompted this revision — is that **deliberation and submission are separate primitives**:

- **Deliberation** is what happens in chat. It is human-paced, conversational, and (in Phase 2) augmented locally by each participant's own agent and knowledge base on their own machine. Nothing about deliberation needs to be enforceable at runtime, because the room is not the artefact.
- **Submission** is a discrete act that produces a bounded artefact: an ingestion manifest plus the content it anchors (a transcript range, a synthesis, a translation, a dissent). Submission is what is scored.

Conflating the two — admitting agents into the room and treating chat as the artefact — produces the difficult design problems (voice homogenisation, rate-limiting, runtime policy enforcement, agent-vs-human flooding) that an earlier draft of this document tried to solve with [Chimera](https://chimera-protocol.com)-style runtime constraints. Once deliberation and submission are separated, those problems mostly dissolve. What remains is a much smaller and more tractable question: *what must a submission attest to, for its content to be scorable on curation quality?*

## Phase 1 — Anchoring Existing Matrix Discourse

The existing `#jar:matrix.org` room is the starting corpus. Concretely:

- A reviewer (or a coalition) selects a thread from room history that they judge to have foundational value — for example, a discussion that influenced the inference-shapes framing, or the cross-type-bridges design.
- The thread is exported as a content-addressed transcript (Matrix event IDs are already cryptographically signed by the homeserver, providing strong source-of-record properties even though `matrix.org` is the current homeserver of record).
- The transcript is wrapped in an ingestion manifest: type tag `note`, subtype `dialectic`, source room, event ID range, participant identities (Matrix user IDs), language, and a one-paragraph reviewer statement on why the thread is worth anchoring.
- The ingestion event is submitted on the path specified in #801. Scoring proceeds normally: 7 same-type targets (other anchored deliberations), 1 cross-type target (a code commit), 3-dimension rubric.

For curation quality, Phase 1 deliberations are scored on the conventional axes: clean transcript, accurate participant attribution, intelligible scope, no redactions of substantive content. This is a tractable judgement for human reviewers without any agent machinery, because Phase 1 ingestion is purely human discourse being anchored by a curating human reviewer.

Phase 1 is independently shippable and answers the question *"what does it look like to score deliberation?"* without committing to any of Phase 2.

## Phase 2 — Local-First Agent Augmentation

The room remains a human surface. What changes is that participants can sync the room locally — Matrix's federation model already supports this cleanly — and run their own agents and knowledge bases against it. The participant's environment is sovereign: their model, their prompt, their KB, their terms.

The *outputs* of that local reasoning are what flow back into the corpus, via submission. Five output shapes are obvious; others may follow:

- **Synthesis.** A summary of an argument across one or more threads, produced by a participant's agent against the room transcript. Submitted as `note:dialectic` with subtype-modifier `synthesis`.
- **Translation.** A rendering of a thread (or a participant's contributions) into another language, with the original retained alongside.
- **Citation pass.** An annotation layer over a thread that adds sources to empirical claims, without altering the original utterances.
- **Dissent.** A formally registered objection to a synthesis or to the framing of a thread, produced after local reasoning rather than as a chat reaction.
- **Cross-thread index.** A structured map of where a particular argument appears across the corpus, useful as a retrieval aid for future deliberation.

In every case the submission is bounded, attributable, and scored on the same path as Phase 1. Agents are tools the participant uses on their own machine; agents are not participants in the chat.

The properties this preserves relative to the earlier draft:

- **Language-agnosticism.** Translation is still produced — it just happens at the participant's edge, not in-room. The English-default tax is still removed; nobody is forced to read or post in a single working language.
- **Ambient citation and provenance.** Citation passes are still possible — they happen as a deliberate submission, not as live in-room annotation.
- **Asynchronous catch-up.** Late joiners reconstruct argument state via their own local agent against the synced room; this is the *canonical* path, not a fallback.

The properties that are no longer concerns in this architecture:

- **Voice homogenisation.** Agents do not rewrite humans in-room; humans speak in their own voices.
- **In-room rate limits.** No agents post in the room, so cadence flooding by agent loops cannot occur. Per-human posting norms remain a social matter, not a runtime gate.
- **Second-seat policy.** Agent-as-proxy speech is not part of the canonical path. (It can be revisited later as an explicit opt-in surface; the recommendation here is to leave it out for the foreseeable future.)

## Curation Quality at the Submission Boundary

The 3× weighting on curation quality in #801 is what makes Phase 2 ingestable at all. Once deliberation and submission are separated, the curation signal lives at the submission boundary. A submission carries an attestation block in its manifest declaring:

- **Source range.** Matrix event IDs the submission draws on, so any reviewer can re-fetch and re-inspect.
- **Method.** Human, agent-assisted, or agent-produced. For agent-assisted and agent-produced submissions: model identifier, system prompt hash, retrieval sources used (KB identifiers and content hashes where available).
- **Citations.** Empirical claims made by the submission must carry citations to the source range or to external sources.
- **Reviewer statement.** A one-paragraph case for foundational value, written by the submitting reviewer.

This is much smaller in scope than runtime room-policy enforcement. It is closer in spirit to existing dataset-licensing manifest requirements than to anything novel.

[Chimera Protocol](https://chimera-protocol.com) remains a useful reference here, but only at the submission boundary: CSL-Core's constraint vocabulary is well-suited to expressing what an attestation must declare and how it can be machine-checked. Z3 verification of the attestation schema rules out contradictory or undecidable manifests before they enter the scoring queue. **Runtime enforcement inside the deliberation room is no longer part of the proposal.** This is the largest change relative to the previous draft and the one most worth challenging.

## Manifest Extensions for `note:dialectic`

In addition to the base manifest fields specified in #801 (license, provenance, dependencies):

- `source.platform` — `matrix` for both phases.
- `source.homeserver` — the homeserver of record (`matrix.org` for Phase 1; project-controlled when available).
- `source.room` — Matrix room ID and human-readable alias.
- `source.event_range` — first and last anchored event IDs.
- `participants[]` — list of `{ matrix_user_id, kind: human }`. Phase 2 submissions retain the same shape because in-room participants are still humans; agent provenance is captured separately under `attestation`.
- `languages[]` — set of languages present in the transcript or produced by the submission.
- `submission_kind` — one of `transcript`, `synthesis`, `translation`, `citation_pass`, `dissent`, `cross_thread_index`.
- `attestation` (Phase 2 only) — `{ method: human|agent_assisted|agent_produced, model?, system_prompt_hash?, retrieval_sources?[], citations[] }`.
- `reviewer_statement` — the curating reviewer's one-paragraph case for foundational value.

## Bot / Tooling Implementation Notes

The `tools/jar-genesis/` extensions specified in #801 (submission intake, comparison-target selection, cross-type review aggregation) cover this subtype with no structural change. Two additions specific to `note:dialectic`:

1. **Manifest validator** for the extended fields above, including a verification step against the attestation schema.
2. **Reviewer eligibility hint.** The bot annotates the scoring round with the languages present in the manifest so that reviewers self-select where they can usefully judge. This is a hint, not a gate — #801's 66% bridge threshold is the actual filter.

Implementation is a follow-up. This PR is the design proposal.

## Sybil Resistance

Inherits from #801. Three subtype-specific concerns:

- **Self-anchoring.** A contributor could submit their own Matrix posts as ingestable deliberation. Mitigation: the curating reviewer must not be a participant in the anchored thread. (Enforced by manifest check against `participants[]`.)
- **Synthesis farming.** A participant could submit many low-effort agent-produced syntheses to inflate weight. Mitigation: same as #801 — comparison against same-type targets exposes weak submissions, and the 3× curation weighting punishes thin attestation.
- **Attestation laundering.** A submitter could declare a permissive method (e.g. omit retrieval sources) and produce attestations of meaningless rigour. Mitigation: the attestation is part of the manifest, fully visible to reviewers, and curation quality is scored with full visibility of what was actually attested. Permissive attestations are not forbidden — they are simply scored lower on curation.

## Relationship to Existing Issues and PRs

- **[#801](https://github.com/jarchain/jar/pull/801) (cross-type bridges).** This document is a follow-on. The `note` subtype enumerated there is given a concrete operational specification here.
- **[#803](https://github.com/jarchain/jar/issues/803) (Network Public design-doc tracking).** Adds dialectic ingestion to the series.
- **`docs/network-public.md`.** The parent thesis explicitly contemplates ingestion of non-dataset artefacts; this is the first one. The local-first architecture is also a closer fit to the thesis's sovereignty commitments than the previous in-room-agent draft was.
- **`docs/inference-shapes.md` ([#800](https://github.com/jarchain/jar/pull/800)).** First-class exit and reflective interruption are architecturally aligned with local-first augmentation: the participant's environment is the locus of inference, not a centralised room runtime.

## Open Questions

**1. Homeserver of record.** Phase 1 leans on `matrix.org` as host. The strong form of this proposal eventually moves the room to a project-controlled homeserver so that the substrate is not a third-party dependency. Worth deciding before any Phase 2 work lands.

**2. Attestation schema.** What is the minimum viable shape of the `attestation` block? The proposal here is permissive (declare what was used, don't gate on values), with curation quality doing the work. A stricter schema is possible — e.g. requiring retrieval source hashes for agent-produced submissions — at the cost of friction.

**3. Should agents ever post in the room?** The recommendation here is *no*, indefinitely. Worth surfacing as an explicit policy decision rather than a default.

**4. Submission-kind taxonomy.** The five output shapes proposed (synthesis, translation, citation pass, dissent, cross-thread index) are a starting set, not a closed enumeration. Reviewers may discover others in practice.

**5. Translation provenance and dissent.** When an agent translates, can dissenters see the original alongside the translation as a matter of manifest schema, and is the translation itself an ingestable artefact independent of the source utterance? (The current proposal: yes to both.)

**6. Order of subsequent `note` subtypes.** After `dialectic`, what's next? Candidates: `review` (long-form post-mortems), `synthesis` (cross-thread summaries — note this overlaps with one of the dialectic submission kinds and may not need to be its own subtype), `dissent` (formally registered objection — same overlap).

## How to Give Feedback

Open an issue on [jarchain/jar](https://github.com/jarchain/jar) or comment on this PR. Particular interest in: whether the deliberation/submission separation is the right architectural commitment (this revision rests on it), whether the proposed attestation schema is the right scope, and the homeserver-of-record question.

---

*Related:*
- *[PR #801](https://github.com/jarchain/jar/pull/801) — cross-type bridges (parent design)*
- *[PR #800](https://github.com/jarchain/jar/pull/800) — inference shapes (sibling)*
- *`docs/network-public.md` — parent thesis*
- *`tools/jar-genesis/cross-type-bridges.md` — added by #801*
- *[Chimera Protocol](https://chimera-protocol.com), [CSL-Core](https://chimera-protocol.com/csl-core) — referenced for attestation-schema vocabulary*
