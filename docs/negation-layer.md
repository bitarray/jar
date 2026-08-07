# The Negation Layer

*Design document — extends [JAR Genesis 2.0](https://gist.github.com/sorpaas/f8cef1590402a6f4b1b8481419d466e4) with a deliberative-allocation mechanism. Supports the Network Public §4 separation. Requesting external feedback.*

## Context

Genesis 2.0 generalises Proof of Intelligence to multiple contribution types via a single global Bradley-Terry ranking with confidence-weighted scoring. It answers *which contributions earn weight, and how much*.

It does not answer a different class of question: *which contributions does the network choose to celebrate, fund, or refuse* — beyond what scoring alone selects. These are deliberative choices: which scientific datasets to mark as foundational, which services to refuse, which retractions to honour, which public-good infrastructure to fund out of escrow.

Automated scoring is the wrong tool for these decisions, because the right answer depends on judgement about the network's purpose, not on ranking against past work. Majority vote is also the wrong tool, because it lets the network's largest weight-holders self-deal.

The Network Public thesis names this missing piece: a **negation layer** — a separately incentivised deliberative cohort whose pay is independent of whether their picks later traverse, and whose terms are shorter than the revenue-attribution window so cohorts cannot self-deal across the very window they decide.

## Design

### Cohorts, not standing committees

The negation layer is composed of **cohorts**: rotating groups of weighted contributors selected for fixed-length terms. There is no permanent council. There is no re-election. A cohort's term ends, a new cohort begins, and decisions made by a previous cohort are not revisited by their successors except through the same deliberative process.

- **Cohort size.** Initial proposal: **9 members**. Small enough to deliberate, large enough that bribing 5 is meaningfully harder than bribing 3.
- **Term length.** Initial proposal: **3 months** — strictly shorter than the **12-month** patience-tax window proposed in `docs/patience-tax.md`. This is the structural property that prevents self-dealing: a cohort decides allocation for a window that outlasts its own term.
- **Selection.** VRF-weighted draw from the set of contributors with active reviewer status (PoI weight ≥ activation threshold). Weight enters as a probability multiplier, not an outright qualification — a contributor with twice the weight is twice as likely to be drawn, but not guaranteed.
- **Rotation cadence.** Cohorts overlap: one new member rotates in roughly every two weeks, so institutional memory is preserved without entrenchment.

### Pay independence

Negation-layer compensation is **independent of the decisions the cohort makes**. A cohort member is paid a fixed amount for serving the term, drawn from the patience-tax escrow, regardless of whether the contributions they recognise later traverse, generate revenue, or are themselves recognised by future cohorts.

This is the second structural property: a member cannot increase their own pay by allocating to themselves, by allocating to friends who will reciprocate, or by predicting future revenue patterns.

### What cohorts decide

Each cohort, during its term, decides on the disbursement of its share of the patience-tax escrow's **deliberative slice**. The traversal-weighted slice is allocated automatically (see `docs/patience-tax.md`); only the residual is deliberative.

Cohorts decide using ranked comparison, the same primitive used in PoI scoring. Each disbursement decision is a ranked vote among candidate allocations, aggregated using the weighted lower-quantile from Genesis 1.0. Decisions are signed events, ingested by the network like any other contribution (see `docs/network-public.md` §1).

Categories of deliberative allocation include — non-exhaustively:

- **Foundational dataset recognition.** A dataset is marked as foundational; its contributors receive a one-time recognition disbursement and the network commits to ongoing access guarantees.
- **Public-good infrastructure.** Funding for tooling that benefits the protocol but does not directly traverse user inferences (documentation, fuzzing, formal proofs of new components).
- **Refusal endorsements.** A pause from `docs/governance-refusal.md` becomes a refusal when the cohort signals — formally — that the action ought not proceed. The cohort's signal is one input to the >66% participating-weight refusal vote.
- **Retraction honouring.** When a contributor retracts work that has already been ingested (and possibly traversed), the cohort decides how to handle downstream attribution.

### How cohorts deliberate

Deliberation runs on the same substrate as the rest of the protocol: signed events, content-addressed, ingested via §1. A cohort member can publish:

- A **proposal** for a specific allocation.
- A **review** ranking proposals against each other (Genesis 1.0 ranked comparison).
- A **note** — unranked deliberative writing, ingested as a foundational record but not affecting allocation directly.

Allocations are settled at the end of each cohort term. Proposals not settled by then are passed to the next cohort with no priority — the new cohort is free to take them up or not.

## Why cohorts can't self-deal

The structural property is the **term/window mismatch**:

- A cohort's term is **shorter** than the patience-tax window.
- A patience-tax disbursement is settled at the *end* of its window.
- Therefore: every disbursement the cohort decides is settled **after** the cohort has rotated out.
- A cohort member who allocates to themselves is allocating to a contributor whose later traversal — the only thing that would make the allocation pay off in expectation — is judged by a different cohort.

Combined with pay-independence (a cohort member's compensation does not depend on the decisions they make), the only remaining incentive to self-deal is reputation laundering. That is policed by the same mechanism that polices reviewer behaviour today: meta-review and weight reduction.

## Sybil Resistance

Standard PoI defences carry over:

- **Linear weight** in cohort selection probability — splitting weight provides zero advantage.
- **Selection by VRF**, not self-nomination, prevents Sybil concentration via campaigning.
- **Term length is constitutional** — a cohort cannot extend its own term.
- **Cohort size is constitutional** — a cohort cannot pack itself.

The 33%/50%/66% thresholds from Genesis 1.0 apply to within-cohort decisions: a cohort coalition below 33% cannot influence outcomes; above 66% has full control. Random selection of cohort members from the larger pool of active reviewers means achieving 66% within a cohort requires either >66% in the underlying pool (the standard BFT bound) or significant luck of the draw — and even then, only for one cohort term.

## JAM Mapping

- Cohort selection: a state-modifying extrinsic that draws from the active-reviewer set using VRF over a recent block hash. **Accumulates.**
- Cohort decisions: signed events ingested via §1. Heavy validation (signature checks, ranked-comparison aggregation) runs in `refine`; final allocation outcomes accumulate.
- Pay disbursement: a fixed transfer at term end from patience-tax escrow to cohort members. **Accumulates.**

## Lean Invariants

Proposed location: `spec/Jar/NegationLayer.lean`. Properties to prove:

1. **Term/window separation.** For all valid configurations, `cohortTermLength < patienceTaxWindow`.
2. **Pay independence.** Cohort member compensation is a function of `(termId, memberId)` only, not of any allocation decision the cohort makes during the term.
3. **Selection unbiasedness.** Over many terms, the distribution of cohort membership matches the weight distribution of the active-reviewer pool, up to VRF noise.
4. **Term boundedness.** A cohort cannot extend its own term; only a higher-threshold constitutional change can.
5. **Cohort-quorum adequacy.** All cohort decisions require participation from `>= 2/3` of cohort members; no decision can pass with `< 1/3`.

## Relationship to Existing Issues

- **[#168](https://github.com/jarchain/jar/issues/168) (Bradley-Terry ranking monitor).** The negation layer's deliberative ranked comparisons feed the same BT model the monitor tracks. Cohort decisions become labelled inputs in the global ranking.
- **[#374](https://github.com/jarchain/jar/issues/374) (Lean theorem coverage).** The invariants above are natural targets for the proof-coverage work.

## Open Questions

**1. Cohort size and term length.** 9 members / 3 months is a starting point. The right calibration likely depends on the patience-tax window length and the volume of deliberative decisions per term. Worth modelling.

**2. Mid-term replacement.** If a cohort member becomes inactive or compromised, do we replace them mid-term or run with the reduced cohort? Replacement preserves capacity but adds a vector for manipulation; running short prevents that but can stall.

**3. Appeal mechanism.** A cohort decision today has no appeal. Should later cohorts be able to revisit specific decisions, perhaps with a higher quorum? The trade-off is between protocol stability and correction of obvious errors.

**4. Confidentiality of deliberation.** Some deliberative topics (refusal of a use case, recognition of a sensitive dataset) may benefit from confidentiality. The current design records all deliberation publicly. Is partial confidentiality desirable, and if so, how is it bounded?

**5. Compensation source.** Drawing cohort pay from the patience-tax escrow ties cohort funding to revenue. If revenue is low, cohort pay is low — a self-correcting feature, but possibly under-resourced for serious deliberation. Should there be a floor funded from elsewhere?

## How to Give Feedback

Open an issue on [jarchain/jar](https://github.com/jarchain/jar) or comment on this PR. Particular interest in: cohort sizing, the term/window mismatch, and the exact set of deliberative categories.

---

*Related:*
- *`docs/network-public.md` — parent thesis*
- *`docs/patience-tax.md` — escrow and traversal allocation*
- *`docs/governance-refusal.md` — the right to refuse, which cohort decisions inform*
- *[Genesis 2.0](https://gist.github.com/sorpaas/f8cef1590402a6f4b1b8481419d466e4)*
- *[Issue #168](https://github.com/jarchain/jar/issues/168) — Bradley-Terry ranking monitor*
