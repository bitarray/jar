# JAR as a Network Public

*Design document — extends [Coinless JAR](https://gist.github.com/sorpaas/1b75f635850667456d2efbc2f8fe9820) and [JAR Genesis 2.0](https://gist.github.com/sorpaas/f8cef1590402a6f4b1b8481419d466e4). Requesting external feedback.*

## Context

Two existing JAR design documents describe a base layer with no native token (Coinless JAR) and a contribution-scoring system that generalises Proof of Intelligence to non-code work via a single Bradley-Terry ranking with confidence-weighted scoring (Genesis 2.0).

This document proposes a third frame that completes the picture: **JAR as a Network Public**. A network public is the digital analogue of a public commons — a substrate over which information is recorded, governed, owned, and allocated according to rules that prevent any one party (including the substrate's operators) from privately enclosing the value generated on it.

The Network Public thesis (v4.3, 2026-04) identifies four functional separations that make this concrete. JAR already implements two of them and is a natural home for the other two.

## The Four Separations

### 1. Ingestion — record everything, decide later

A network public must accept signed contribution events from anyone — code, ranked judgements, dataset commitments, attestations of presence, retractions — and anchor them as first-class history. Selection of *what is later used* is a separate concern from *what is recorded*.

- **In JAR today.** Code contributions are recorded (git history) and ranked (Genesis 1.0). Other contribution types are described in Genesis 2.0 but are not yet ingested.
- **Gap.** A general signed-event ingestion service. Each event has a content hash, a timestamp anchored on-chain, an identity reference (weight-bearing contributor), and a type tag. Ingestion does not score; it commits.
- **JAM mapping.** Heavy event processing (deduplication, content addressing, validation) runs in `refine`. The on-chain anchor — `(contentHash, timestamp, signer, type)` — accumulates.

### 2. Governance with a right to refuse

A network public must be able to say no — to a use case, a deployment, a recipient — without that decision being a unilateral act by operators. Governance must own *whether to act*, not only *how to settle*.

- **In JAR today.** Weight-based NPoS selects validators. PoI scoring distributes governance influence. There is no formal mechanism to **pause** the chain or refuse a specific service.
- **Gap.** A pause/refusal primitive: contributors representing some quorum (the paper proposes 15%) can trigger a fixed deliberative window during which a specified action does not proceed. After the window, the action resumes by default unless a higher quorum extends or terminates it.
- **JAM mapping.** Pause requests accumulate as state-modifying transactions; the deliberative window is a fixed number of slots; resumption is automatic.

### 3. Inference ownership via traversal-weighted allocation

If the network produces inferences (models, indices, derived datasets), ownership of the resulting value must be a function of contribution traversal, not authorship of the final artefact. Whoever's data, code, or judgement was traversed during inference earns a share of revenue from that inference, proportional to how much it was used.

- **In JAR today.** Coinless JAR's "Protocol Guild" mechanism is voluntary. Genesis 2.0's confidence-weighted Bradley-Terry framework supplies the substrate for tracking provenance.
- **Gap.** A traversal-accounting service that, when an inference is served, emits an attribution graph and routes a fraction of revenue to the upstream contributors that the inference traversed.
- **JAM mapping.** Inference + traversal accounting runs in `refine`; revenue settlement and attribution-graph commitments accumulate.

### 4. Deliberative allocation — a negation layer

Some allocation decisions are too consequential to be settled by automated scoring or majority vote: which scientific datasets are foundational, which use cases the network refuses, which retractions are honoured. A network public has a separate **deliberative layer** of rotated reviewer cohorts whose pay is independent of whether their picks later traverse, and whose terms are shorter than the patience-tax window so individual cohorts cannot self-deal.

- **In JAR today.** Genesis 1.0's reviewer system is a partial analogue: it filters merges, but reviewers are not rotated and their compensation is implicitly tied to their own future contributions.
- **Gap.** A separately incentivised deliberative cohort, drawn by VRF from a pool of weighted contributors, with fixed-length terms shorter than the revenue-attribution window, paid out of a dedicated escrow.
- **JAM mapping.** Cohort selection and rotation accumulate; deliberative reviews are signed events ingested via (1).

## The Patience Tax

The four separations are funded by a single revenue mechanism: a small fixed share — the paper proposes 3–5% — of inference revenue and core-time payments is held in escrow for a fixed window (the paper proposes one year). During the window:

- A portion is allocated by **traversal** to upstream contributors.
- The remainder is allocated by the **negation layer** to deliberative purposes — datasets, refusals, retractions, public-good infrastructure.

The patience tax is not a fee charged to users. It is a delay imposed on revenue that has already been earned, so that the network has time to learn what each inference *actually* depended on. Rapid settlement gives nothing up; patient settlement learns from the pattern of traversal across the window.

## Inference Shapes (§7.3)

A network public refuses to host inferences that are themselves enclosing. The paper identifies three minimum properties for any inference service running on the substrate. These are **service-author obligations**, enforced by the right to refuse, not by consensus:

- **Session-length neutrality.** A service must not derive durable advantage from the length of any single user session. Continuous sessions, frequent short sessions, and intermittent sessions must be priced identically per unit of compute.
- **First-class exit.** Users must be able to retrieve their data and migrate to a different service without loss of context. The service must provide a portable export at a price not exceeding the cost of producing it.
- **Reflective interruption.** A service must surface its own uncertainty: where its inference is unstable, where its training data is sparse, where a user's question has historically produced inconsistent answers. Confidence is not a UI nicety; it is a substrate-level requirement.

Failures of these properties are admissible grounds for the §2 right to refuse.

## What Already Exists

JAR's current design supplies the substrate for everything above:

- **PoI weight** is the contribution-traversal accounting unit.
- **Bradley-Terry confidence intervals** (Genesis 2.0) are the basis for the negation layer's reviewer scoring.
- **Refine-Accumulate** is the natural execution model for ingestion, traversal, and settlement.
- **Lean 4 specification** is the natural home for proving the invariants of cohort rotation, escrow conservation, and exit-portability.

What the existing documents do not yet cover is the *integration* of these pieces into a coherent network public. This document is that integration.

## What Needs to Be Added

- A general signed-event ingestion service. (See `docs/network-public/ingestion.md` — to be added.)
- A pause/refusal primitive with a 15% quorum and a fixed deliberative window. (See `docs/governance-refusal.md`.)
- A negation-layer cohort selector with rotation and pay-independence. (See `docs/negation-layer.md`.)
- A patience-tax escrow with traversal-weighted allocation. (See `docs/patience-tax.md`.)
- Inference-shape obligations as a JIP-style RFC. (See `docs/inference-shapes.md`.)

Each is small enough to specify, prove, and review independently. None of them touch consensus-critical code.

## Why This Framing Matters

JAR's coinless thesis answers *who pays*. Genesis 2.0 answers *who is recognised*. The Network Public framing answers *what kind of system we are building* — and makes it easier to refuse pull requests, services, and use cases that would, intentionally or not, re-enclose what JAR is meant to keep open.

## Narrative Sovereignty

A failure mode this document had previously left implicit, surfaced in discussion: every prior decentralised network has allowed its narrative to be defined *exogenously*. Bitcoin's public meaning was shaped by financial-press cycles. Ecosystem-funded marketing in token-governed networks (Polkadot, Cosmos, etc.) is structurally exogenous — produced by outside contractors against outside briefs, not by the embedded culture of the contributor base. The cost is incremental at first and decisive over time: the network's public meaning drifts toward whatever narrative special interests are most willing to fund, while the embedded culture that actually constitutes it goes uncatalogued and undefended.

A protocol that produces collective intelligence and cannot speak about itself in its own voice has surrendered its most important contribution. The Network Public framing claims that **narrative sovereignty is the highest-order property the protocol must preserve** — and that, in turn, is what protects every other property listed here from being narrated away by special interests with the budget to do so.

Concretely for JAR:

- **Ingestion (Separation 1)** is the substrate of narrative sovereignty — the network's accumulated decisions, references, and disagreements are the raw material from which it speaks.
- **Inference ownership via traversal (Separation 3)**, in its world-shaped form (Network Public §7.1), is how the network produces its self-account directly from that substrate, in a form no exogenous party can replicate or substitute.
- **The right to refuse (Separation 2)** must include the standing to refuse exogenously-defined campaigns or services that capture the network's public voice — even when they are revenue-positive in the short term.
- **The negation layer (Separation 4)** must include long-form synthesis, retrospective, and self-narration as fundable contribution types — these are the contributions through which a community catalogues and defends its embedded culture.

This framing does not add a new mechanism. It identifies which existing mechanisms, taken together, constitute the protocol's defence against narrative capture, and names that defence as the property worth defending.

## Open Questions

**1. Calibration of the patience-tax rate.** 3–5% is the paper's proposal. Higher rates fund more deliberation; lower rates leave more revenue with services. Is there a principled way to set this without governance choosing a number?

**2. Cohort size for the negation layer.** Too small invites capture; too large slows deliberation. Genesis 2.0's confidence-bound mechanism suggests cohort size should be a function of the bridge-comparison density of the relevant contribution type. Worth specifying.

**3. Pause-quorum manipulation.** A 15% pause quorum is low enough that a coordinated minority can repeatedly stall the chain. Are graduated cooldowns sufficient, or is a different threshold model needed?

**4. Compatibility with high-throughput inference.** Inference services that run at scale produce enormous traversal graphs. Aggregating these on-chain at full fidelity is not feasible. What is the right summarisation — Merkle commitments to off-chain traversal logs, with periodic on-chain anchors?

**5. Relationship to issue [#383](https://github.com/jarchain/jar/issues/383).** The first-principles audit of inherited assumptions (staking, coretime, L2 coins) is largely answered by the Network Public framing. Should this document supersede parts of `coinless.md`, or sit alongside it?

## How to Give Feedback

This is an early design document. Open an issue on [jarchain/jar](https://github.com/jarchain/jar) or comment on this PR. We especially want feedback on the four separations, the patience tax mechanism, and the inference-shape obligations.

---

*References:*
- *The Network Public, v4.3 (2026-04).*
- *[Coinless JAR](https://gist.github.com/sorpaas/1b75f635850667456d2efbc2f8fe9820).*
- *[JAR Genesis 2.0](https://gist.github.com/sorpaas/f8cef1590402a6f4b1b8481419d466e4).*
