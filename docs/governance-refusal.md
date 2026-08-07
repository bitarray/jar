# Governance: The Right to Refuse

*Design document — proposes a pause/refusal primitive for JAR. Extends [Coinless JAR](https://gist.github.com/sorpaas/1b75f635850667456d2efbc2f8fe9820) and supports the Network Public §2 separation. Requesting external feedback.*

## Context

JAR's governance today selects validators (NPoS over PoI weight) and merges code (PoI scoring with weighted lower-quantile aggregation). It can decide *who runs the chain* and *what gets merged*. It cannot, today, **refuse a specific use case once it is running**: there is no mechanism to pause an action, suspend a service, or hold a deployment for deliberation.

Issue [#383](https://github.com/jarchain/jar/issues/383) raised this gap from a different angle: if validators are selected by reputation rather than stake, the threat model changes — and the protocol's decision-making affordances should change with it. Reputation-selected validators don't need stake-based slashing for safety, but they do need a structured way to be told "stop, this needs more thought."

This document specifies that mechanism.

## The Right to Refuse

A small quorum of weighted contributors can **pause** a specific action. Pause initiates a fixed-length deliberative window during which the action does not proceed. At the end of the window, the action resumes by default; a higher quorum can extend or terminate it.

The mechanism has three deliberate properties:

- **Asymmetric quorum.** The pause threshold (proposed: **15% of active reviewer weight**) is much lower than the resume-override threshold (proposed: **>50% of participating reviewer weight**, mirroring Genesis 2.0's merge rule). Stopping is cheap. Extending the stop is normal. Permanently refusing requires majority deliberation.
- **Bounded window.** The deliberative window is a constitutional parameter (proposed: **2 weeks** in slot count). Pause is not a veto; it is a forced pause for collective consideration.
- **Auto-resume.** If the window expires with no further action, the paused action resumes. The protocol prefers motion to inertia: the price of refusing is that you have to keep refusing.

## What Can Be Paused

A pause primitive is meaningful only if there are well-typed actions to pause. The following are first-class:

- **Service deployment.** A new service that has been registered on-chain but whose first work-package has not yet executed.
- **Service upgrade.** A code-hash change for an existing service.
- **Validator-set rotation.** A scheduled rotation that is about to take effect.
- **Genesis 2.0 type onboarding.** The introduction of a new contribution type (per §"Self-Regulating Openness" in Genesis 2.0) that is about to start admitting events.
- **Patience-tax disbursement.** A scheduled disbursement from the escrow described in `docs/patience-tax.md`.
- **Exogenously-defined narrative campaigns.** A service, treasury action, or Genesis 2.0 contribution type whose effect is to import an outside account of what the network is — paid marketing whose brief is set outside the contributor base, brand campaigns funded against the network's revenue but produced by external agencies, services that pre-shape the network's self-narration toward an outside audience. Refusal on these grounds is predicated on the Network Public claim that narrative sovereignty is a first-order property the protocol must preserve; revenue-positive operation is not a sufficient defence.

Each of these is already a discrete state transition. Pause is a wrapper around the transition that introduces a deliberative gap.

## State Machine

```
               pause(quorum >= 15%)
   ACTIVE ────────────────────────────► PAUSED
      ▲                                    │
      │ resume(quorum > 50% participating)  │
      │ or window expires                   │
      └────────────────────────────────────┘

   PAUSED ────► REFUSED  (quorum > 66% during window)
```

- **ACTIVE**: action proceeds normally on its scheduled slot.
- **PAUSED**: action is held; a deliberative window of fixed length begins. The window is a constitutional parameter (proposed 2 weeks).
- **REFUSED**: action is permanently rejected. Requires the BFT-safe threshold (>66% of participating reviewer weight) during the deliberative window.

## Why 15% / >50% / >66%

These mirror the asymmetry of safety thresholds throughout JAR:

- **15% to pause** is large enough that a single contributor cannot stall the protocol but small enough that a serious minority concern can be heard. It is calibrated against the lower 1/3 quantile already used in PoI scoring — at 15%, a pause cannot be repeatedly triggered by a coalition below the quantile threshold.
- **>50% participating to resume early** matches Genesis 2.0's time-bounded participation merge. Participation, not total weight, gates outcomes — preventing gatekeeping by abstention.
- **>66% participating to refuse permanently** matches the BFT-safe threshold already established in the Genesis document.

## Sybil Resistance

The standard PoI defences carry over. Specifically:

- **Linear weight** means split accounts provide zero advantage in reaching the 15% threshold.
- **The threshold is denominated in active reviewer weight**, not total weight. Inactive contributors do not contribute to the denominator, preventing dormant-weight inflation attacks.
- **Pause cooldowns.** A pause that auto-resumes (window expires with no further action) cannot be re-triggered against the same action within a cooldown period (proposed: equal to the window itself). This prevents a 15%-coalition from indefinitely stalling by repeatedly re-pausing.

## Relationship to Validator Slashing

A common reflex is to ask "what about slashing?" In a coinless protocol, slashing of stake is meaningless — there is no stake. The right-to-refuse takes its place for the use case slashing actually serves: stopping a Byzantine action *while* deliberation occurs.

For the use case slashing serves *after* deliberation — punishing the actor — JAR has a different mechanism: weight reduction or removal, applied through the same PoI scoring that admitted the contributor. Refusal is the structural pause; weight reduction is the consequence.

## JAM Mapping

- A pause request is a state-modifying extrinsic. It accumulates.
- The deliberative window is counted in slots; the on-chain state holds `(actionId, pauseExpiresSlot, refusedFlag)`.
- During the window, executive logic (block authoring, work-package execution) checks whether the target action is paused and skips/blocks accordingly.
- All gating is in `accumulate` — no protocol changes needed to `refine` paths.

## Lean Invariants

The following properties should be machine-checked once a Lean stub is added (proposed location: `spec/Jar/Refusal.lean`):

1. **Conservation of state.** A pause does not modify any state outside `(pauseFlag, pauseExpiresSlot, refusedFlag)`.
2. **Window monotonicity.** `pauseExpiresSlot` strictly increases per pause; cannot be decreased by any non-refusal action.
3. **Auto-resume.** For any slot `s > pauseExpiresSlot`, if `refusedFlag = false`, the action proceeds.
4. **Refusal terminality.** Once `refusedFlag = true`, no path returns the action to ACTIVE without a constitutional change (separate higher-threshold mechanism, out of scope here).
5. **Quorum adequacy.** Pause requires `>= 15%` of the active reviewer weight at the slot; refusal requires `> 66%` of participating reviewer weight during the window.

## Open Questions

**1. Granularity of `actionId`.** Should pauses be addressable per-action only, or also per-actor (pause everything from a specific service)? The latter is more powerful but harder to reason about.

**2. Window length.** 2 weeks may be too long for fast-moving inference services and too short for protocol upgrades. A typed window — different lengths for different action types — may be appropriate.

**3. Cooldown calibration.** A cooldown equal to the window prevents simple re-pause attacks but also prevents legitimate re-pause when new information arrives. A graduated cooldown (cooldown grows with each successive pause-without-refuse on the same action) may be a better default.

**4. Interaction with the negation layer.** When a pause triggers, does the deliberative window automatically convene a negation-layer cohort? Or is cohort selection a separate, optional process? The first is more automatic; the second leaves room for non-cohort deliberation (e.g. open community discussion).

**5. UX.** A right to refuse is only as good as its discoverability. What is the minimum on-chain or off-chain surface for a contributor to see "this action is currently pausable, here is the threshold, here is who has signed pause"?

## How to Give Feedback

Open an issue on [jarchain/jar](https://github.com/jarchain/jar) or comment on this PR. We particularly want feedback on the threshold calibration (15% / 50% / 66%), the auto-resume default, and the cooldown design.

---

*Related:*
- *[Issue #383](https://github.com/jarchain/jar/issues/383) — first-principles audit of inherited assumptions*
- *`docs/network-public.md` — parent thesis*
- *`docs/genesis.md` — PoI scoring and reviewer weight*
- *[Coinless JAR](https://gist.github.com/sorpaas/1b75f635850667456d2efbc2f8fe9820)*
