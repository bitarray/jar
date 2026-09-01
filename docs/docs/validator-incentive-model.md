# Validator Incentive Model: Agentic Development Era

## Motivation

JAM/ELVES inherits a binary node classification from classical BFT literature:
nodes are either **adversarial** or **non-adversarial**.

This assumption made sense when modifying a node implementation required
significant engineering effort — making mass deployment of modified nodes
practically unlikely.

**This assumption no longer holds.**

Agentic development means a rational validator can produce a modified node
implementation in hours, not months. The question is no longer *can* they
do it — it is *will* they do it, given the incentives.

---

## Formal Model

Define validator expected utility as:

```
EV(honest)       = R × p_h
EV(cheat)        = G × p_s  −  P × p_d
EV(cheat, agent) = G × (1 + α) × p_s  −  P × p_d
```

### Parameters

| Symbol | Meaning |
|--------|---------|
| `R`    | Honest block reward |
| `p_h`  | Probability of being selected / reward success |
| `G`    | Gain from cheating (MEV extraction, equivocation, etc.) |
| `p_s`  | Probability cheat succeeds undetected |
| `P`    | Penalty on detection (slashing) |
| `p_d`  | Probability of detection |
| `α`    | AI cost reduction factor (0 = no reduction, 1 = near-zero cost) |

### Safety Condition

The protocol is safe only when:

```
EV(honest) > EV(cheat, agent)   for all rational validators
```

Expanding:

```
R × p_h  >  G × (1 + α) × p_s  −  P × p_d
```

---

## The Soundness Gap

JAM's current security analysis does not explicitly state values for these
parameters. As `α` increases — which it will, as agentic tooling matures —
the safety margin silently erodes.

This is structurally similar to the **LayerZero degradation pattern**:
the system appears safe under one set of assumptions, but those assumptions
are not formally verified against economic reality.

### Worked Example

| Parameter | Conservative | Agentic era |
|-----------|-------------|-------------|
| `R × p_h` (honest reward) | 300 | 300 |
| `G` (cheat gain) | 1000 | 1000 |
| `α` (AI cost reduction) | 0.0 | 0.7 |
| `p_s` (success prob) | 0.30 | 0.30 |
| `P × p_d` (expected penalty) | 1200 | 1200 |

```
EV(cheat, before) = 1000 × 1.0 × 0.30 − 1200 = −900   ← safe
EV(cheat, agent)  = 1000 × 1.7 × 0.30 − 1200 = −690   ← still safe, but margin shrinks
```

As `α → 1.0` and `p_s` increases due to lower detection cost:

```
EV(cheat, agent)  > EV(honest)   ← protocol becomes unsafe
```

---

## Proposed Changes to the Specification

This does not require changing the consensus mechanism. It requires being
explicit about what the current design assumes.

1. **Define the validator utility function** formally in the spec
2. **State parameter bounds** under which safety holds
3. **Quantify `α`** — the agentic cost reduction factor — as a protocol variable
4. **Revisit the claimed safety bound** with these parameters made explicit
5. **Add a threat model section** covering rational (non-binary) node behavior

---

## Relation to Proof of Intelligence

The same reasoning applies to the reviewer incentive model in Proof of
Intelligence. As agentic tooling matures, the cost of producing low-quality
reviews at scale also approaches zero. The weighted lower-quantile provides
some protection, but the boundary conditions should be formally quantified.

---

## Next Steps

A Lean 4 formalization of this utility model could be added to `spec/` as:

```
spec/ValidatorIncentives.lean
```

This would allow the safety condition to be machine-checked alongside the
rest of the protocol specification.
