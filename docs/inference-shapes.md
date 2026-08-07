# Inference Shapes — Service-Author Obligations

*Design document — defines minimum properties for inference services running on JAR. Supports the Network Public §7.3 separation. Requesting external feedback.*

## Context

JAR's coinless thesis pushes economic complexity to the service layer: services launch their own tokens (or none), users choose their economics, the base layer stays neutral. This is correct as a default — but it has a corollary the original document only gestures at: **the base layer must still refuse services that re-enclose what JAR is meant to keep open.**

A service that, intentionally or not, captures users into long-running sessions, withholds their data on exit, or hides its own uncertainty is an enclosing service. It defeats the purpose of running on a network public.

The Network Public thesis (§7.3) identifies three minimum properties — "inference shapes" — that any inference service running on JAR must satisfy. This document defines those properties precisely enough that a service can be evaluated against them, and refused under `docs/governance-refusal.md` if it fails.

These are **service-author obligations**, not protocol-level enforcement. A service that violates them is not blocked by consensus; it is admissible grounds for the right to refuse.

## The Three Shapes

### 1. Session-Length Neutrality

**Statement.** A service must not derive durable advantage from the length of any single user session. Continuous sessions, frequent short sessions, and intermittent sessions must be priced identically per unit of compute.

**What it rules out.**
- Sessions that get cheaper the longer they run (rewarding continuous engagement).
- Sessions that get more capable the longer they run, where the capability is not portable (rewarding lock-in).
- Pricing models that explicitly or implicitly penalise session interruption.

**What it permits.**
- Caching that benefits any user equally — a session that reuses recently-computed results pays the same per unit compute as a session that doesn't, but the second session naturally requires more compute.
- Personalisation that is portable: a service can build a per-user model, but the model must be exportable under §2.

**How to evaluate.** A service publishes its pricing function `cost(compute, session_state) → tokens`. Session-length neutrality holds iff `cost` does not have `session_length` as an argument and is invariant under arbitrary session restarts.

### 2. First-Class Exit

**Statement.** Users must be able to retrieve their data and migrate to a different service without loss of context. The service must provide a portable export at a price not exceeding the cost of producing it.

**What it rules out.**
- Services that retain user data but provide no export path.
- Services that provide an export path priced punitively (above the cost of producing the export).
- Services that export data in a non-portable format that can only be consumed by the originating service.
- Services that retain pieces of user state ("we'll keep your conversation history; you can take a transcript") rather than the full state needed to continue.

**What it permits.**
- A service may decline to export aggregate or derived data that involves other users' data — but it must clearly say so, and the user-specific portion must still export.
- A service may charge for the compute cost of producing an export, including bandwidth. This must be transparent and not exceed the actual cost.

**Portable format.** "Portable" means: the export is in a format another service running on JAR could ingest to continue the user's context. This is concretely achievable today via content-addressed structures: a session export is a Merkle commitment to the relevant ingested events plus the service's own computed state, signed by the service.

**How to evaluate.** A service publishes its export specification: format, scope, price function. First-class exit holds iff the format is portable (ingestible by at least one other service on JAR), the scope is complete (all user-specific state, with documented exclusions for unavoidable cross-user data), and the price function is bounded above by the publishable compute cost of producing the export.

### 3. Reflective Interruption

**Statement.** A service must surface its own uncertainty: where its inference is unstable, where its training data is sparse, where a user's question has historically produced inconsistent answers. Confidence is not a UI nicety; it is a substrate-level requirement.

**What it rules out.**
- Services that present all outputs with uniform confidence.
- Services that hide internal disagreement (e.g. ensemble disagreement, model-versus-retrieval disagreement) when it materially affects the answer.
- Services that decline to mark the boundary between *what they know* and *what they are extrapolating*.

**What it permits.**
- A service is not required to have perfect calibration. It is required to *attempt* surface-level reflection: at minimum, a per-output confidence indicator and a flag for "out of distribution."
- A service may use whatever signal it has — entropy of its softmax, retrieval coverage, ensemble agreement, training-data density — to construct the indicator. The choice of signal is the service author's, but the indicator must be present.

**Reflective interruption** specifically means the service can be configured to **interrupt itself** when its confidence falls below a user-set threshold. The user can opt out of this. The service cannot disable it.

**How to evaluate.** A service publishes its uncertainty model: what signal it uses, how the signal maps to the surfaced indicator, how the threshold is exposed to users. Reflective interruption holds iff there exists a documented signal-to-indicator mapping, the indicator is exposed to users, and a user-controllable interruption threshold exists.

## Why These Three

The three shapes correspond to three different ways an inference service can re-enclose what the network public is meant to keep open:

| Enclosure mechanism | Inference shape that rules it out |
|---|---|
| Lock-in via session continuity | Session-length neutrality |
| Lock-in via data hostage | First-class exit |
| Lock-in via opacity | Reflective interruption |

They are minimum properties, not a complete account of good inference. A service can satisfy all three and still be a poor service. But a service that fails any of them is enclosing in a structurally unfixable way, and is admissible grounds for refusal.

## Enforcement (Soft)

The base layer does not enforce these properties at consensus. Instead:

1. **Service registration.** A service registering on JAR submits a **shape declaration**: a signed statement that its design satisfies the three shapes, with links to its pricing function, export specification, and uncertainty model.
2. **Public review.** The shape declaration is ingested as a signed event (per `docs/network-public.md` §1) and is reviewable by anyone.
3. **Refusal pathway.** A service that does not satisfy the shapes — by declaration, in implementation, or as evidenced by user behaviour — can be paused under `docs/governance-refusal.md` (15% quorum) and potentially refused (>66% participating-weight quorum).
4. **Negation-layer guidance.** The negation-layer cohort active at refusal time may issue a written record explaining the basis for refusal — useful precedent for future shape evaluations.

The intent is *not* to litigate every service. Most services will satisfy the shapes trivially. The intent is that the substrate is allowed to refuse services that don't, without needing a special-purpose veto.

## Worked Examples

### Example: A typical chat service

- **Session-length neutrality.** Pricing is per token; restarting a session costs the same per token. ✅
- **First-class exit.** User can download their conversation history as JSON-with-Merkle-commitments. Other services can ingest it. Export is free or priced at compute cost. ✅
- **Reflective interruption.** Each response includes a confidence indicator derived from softmax entropy. User can set a threshold below which the model says "I'm not sure" instead of answering. ✅

This service satisfies the shapes.

### Example: A service that doesn't

- **Session-length neutrality.** Sessions running >2 hours unlock features (longer context, faster responses) that reset on session end. ❌

This service is enclosing via session continuity — even though it is otherwise reasonable. It is admissible grounds for refusal under `docs/governance-refusal.md`.

## JAM Mapping

- **Shape declaration.** A signed event ingested via Network Public §1. Content-addressed.
- **Shape evaluation.** A signed review event, ingested via §1. Reviewers' weight is proportional to PoI weight, same as code review.
- **Pause/refusal of a non-conforming service.** Standard right-to-refuse flow per `docs/governance-refusal.md`.

No protocol changes are needed for shape declarations to be ingested — the ingestion service handles arbitrary signed events. Shape-specific evaluation is a service-layer concern.

## Lean Invariants

Inference shapes are properties of services, not the protocol, so most invariants live at the service-spec level rather than the JAR-spec level. One protocol-level invariant is worth proving:

- **Refusal terminality (carry-over from `docs/governance-refusal.md`).** A service marked REFUSED on grounds of shape failure cannot have new work-packages executed by any validator until a constitutional change reverts the refusal.

## Open Questions

**1. Are three shapes enough?** The paper proposes these three. Other candidates include: data-residency commitments, training-data provenance disclosures, and explicit treatment of derivative inferences. Should the list be extensible by negation-layer recognition?

**2. Granularity.** Is "the service" the right unit, or should shapes apply at the per-feature level (a service may comply for some features and not others)?

**3. Self-evaluation vs. external evaluation.** A service author declares shape compliance. External reviewers may disagree. Is the disagreement resolved by the same PoI scoring as code review (weighted lower-quantile), or does shape evaluation need a different aggregation?

**4. Migration path for existing services.** If JAR launches with services that don't satisfy the shapes, is there a grace period? A migration guide?

**5. Cost-of-export pricing transparency.** "Bounded by compute cost" requires the service to publish its compute cost. How is this audited without exposing service-internal economics?

## How to Give Feedback

Open an issue on [jarchain/jar](https://github.com/jarchain/jar) or comment on this PR. Particular interest in: whether the three shapes are correctly named, whether the soft enforcement model is the right approach, and what to do about services launched before this document is adopted.

---

*Related:*
- *`docs/network-public.md` — parent thesis*
- *`docs/governance-refusal.md` — the refusal pathway*
- *`docs/negation-layer.md` — deliberative review of shape compliance*
- *[Issue #105](https://github.com/jarchain/jar/issues/105) — CoreVM service runtime, the natural place inference services land*
