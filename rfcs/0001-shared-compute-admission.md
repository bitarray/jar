# RFC-0001: Shared Compute Admission Without a Universal Numeraire

| Field      | Value                                      |
|------------|--------------------------------------------|
| RFC        | 0001                                       |
| Title      | Shared Compute Admission Without a Universal Numeraire |
| Status     | Draft                                      |
| Date       | 2026-06-09                                 |
| Affects    | — (introduces new semantics; amends no existing document. If adopted, lands in `spec/` and `website/content/spec/`.) |

---

## Abstract

This RFC defines how shared compute is admitted and governed in JAR without
a universal economic numeraire. Admission compares only canonical gas
demand — never heterogeneous economic value. Gas quotas are conserved
quantities held in issuer authority state and debited by authority
bytecode, in line with JAR's discipline that conservation is bytecode
arithmetic in canonical authorities. Credit references held by Instances
are content-addressed values that name a quota; copying the reference
never copies the balance.

Quota semantics are specified here. Record encoding, storage layout, and
atomic debit mechanics are deferred.

---

## Requirements Language

> The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
> "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
> "OPTIONAL" in this document are to be interpreted as described in
> BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all
> capitals, as shown here.

---

## Motivation

Most chain admission designs price access through a market-clearing token
price, coupling consensus liveness to external economic conditions. Three
properties of JAR's minimum-kernel v3 architecture make that coupling
unnecessary and harmful:

- **`MGMT_COPY` shares content; mutations diverge.** All cap kinds are
  uniformly copyable content-addressed values. Any balance embedded in a
  cap's value is duplicated by every copy — a structural over-issuance
  vector. Balances therefore cannot live inside cap values at all.
- **Conservation is bytecode arithmetic in canonical authorities.** JAR
  already states where conserved quantities belong: in authority
  bytecode, not in the values that reference them. Gas quotas are
  conserved quantities and must follow the same discipline.
- **Execution is heterogeneous; gas is canonical.** The JAVM interpreter
  and the x86-64 JIT recompiler must charge identically, and future
  backends must too. A single canonical gas measure already serves this;
  layering a price on top adds nothing to admission and imports market
  volatility into liveness.

Separately, constitutional operations — contesting a governance decision,
or refusing one and exiting — must remain accessible to Instances that
hold no credit. Gating them behind balances turns them into plutocratic
levers.

---

## Specification

### 1. Governance Domains

A **governance domain** is an analytical grouping of:

- one or more Instances sharing a common authority lineage — an
  `image_hash` chain rooted at a common ancestor;
- the Image lineages governed under that root;
- the issuer and policy records those Instances hold.

Domains introduce no new cap kind and no new on-chain object. They are an
organisational lens over existing Instance and lineage relationships.

### 2. Gas Quota Records

A **gas quota record** is a conserved-quantity record held in the state
(cnode) of an **issuer authority Instance**, keyed by a domain-unique
`quota_id`. It stores:

- `remaining`: canonical gas units still available;
- `ceiling`: maximum ever valid, set at issuance and immutable under
  delegation.

Quota records live only in issuer authority state. They MUST NOT be
embedded in any content-addressed cap value. All arithmetic on
`remaining` MUST be performed by the issuer authority's bytecode,
consistent with conservation being bytecode arithmetic in canonical
authorities.

### 3. Gas Credit References

A **gas credit reference** is a content-addressed value (carried as
`Cap::Data`) naming a quota:

```
GasCreditRef = { issuer_instance, quota_id }
```

It introduces no fifth cap kind; the four kinds (Instance, Image, Data,
CNode) are unchanged.

`MGMT_COPY` applied to a value containing a `GasCreditRef` MUST copy the
reference only; the quota record MUST NOT be duplicated, because it never
resided in the copied value. All references naming the same
`(issuer_instance, quota_id)` MUST draw from one record. Delegation
narrows what a holder may spend; it MUST NOT create independent gas: a
narrower reference still names the original quota identity.

### 4. Metering and Debit

Gas is debited in canonical gas units as committed by execution. This
measure MUST be identical across the JAVM interpreter and the JIT
recompiler, and any future backend MUST charge the same canonical unit.
This RFC does not change the gas model itself.

Record encoding, concurrency rules, atomic debit, fault behaviour, and
migration are deferred (§Deferred Work, item 1).

### 5. Admission

An operation MUST be admitted only if the quota record named by its
credit reference has sufficient `remaining` at admission time. Admission
reads the record and MUST NOT modify it. Debit occurs at execution
commitment.

Multiple accepted issuer authorities MUST be permitted within and across
domains. Proof-of-Intelligence contribution attestation is one initial
issuance route and MUST NOT be treated as mandatory or exclusive.

Consensus compares canonical gas demand only. Issuer policies, and any
assets or accounting internal to a domain, MUST NOT be observable by
consensus and MUST NOT influence metering.

### 6. Issuer Governance

Changes to the set of accepted issuer authorities MUST use a
**two-authority procedure**, defined here:

1. A ballot record identifying the proposed change, produced by an
   Instance in one authority lineage.
2. An independent quorum witness attesting the ballot's quorum, produced
   by an Instance whose `image_hash` lineage root is distinct from the
   ballot producer's.
3. Both records MUST be retained so the change is auditable end to end.

A single lineage MUST NOT supply both records.

Issuer-policy proposals are ordinary admissions: they MUST consume normal
credit under §5. Contesting such a proposal is a constitutional operation
under §7. The asymmetry is intentional (see Discussion).

### 7. Constitutional Budget

The **constitutional budget** is a reserved gas allowance, independent of
any issuer's quota, that funds exactly two operation classes:

- **Contestation**: challenging a pending or enacted governance decision,
  including issuer-policy changes.
- **Refusal and exit**: declining an authority succession and exporting
  state.

The budget MUST NOT fund issuer-policy proposals or any other ordinary
admission.

| Operation                        | Funding               |
|----------------------------------|-----------------------|
| Propose issuer-policy change     | Ordinary credit (§5)  |
| Contest a governance decision    | Constitutional budget |
| Refuse a succession / exit       | Constitutional budget |

A delayed constitutional operation MUST eventually be includable without
the consent of the authority it contests. The mechanism guaranteeing this
(forced inclusion after a timeout) is an open dependency of this RFC and
is not specified here (§Deferred Work, item 2).

**Exit guarantee.** An **exit artifact** is a minimal self-contained
export of an Instance: its current Image and the contents of its cnode,
verifiable against its `image_hash` chain. Exit-artifact creation,
verification, and minimal import into another domain MUST NOT be
conditioned on an external agreement or on the caller's credit balance.

### 8. Out of Scope

The following are explicitly outside kernel and consensus semantics:

- Issuance valuation, exchange, transfer, redemption, collateralization,
  and merging of credit;
- provider capacity allocation and leases;
- core-time assignment, scheduling markets, and capacity authorities.

Nothing in this RFC adds a cap kind, changes `MGMT_COPY`, or alters the
`image_hash` chain rules.

---

## Acceptance Criteria

The following MUST hold before this RFC is considered satisfied:

1. **No quota duplication.** `MGMT_COPY` involving a `GasCreditRef` MUST
   NOT increase the `remaining` of any quota record.
2. **Shared-identity bound.** Two delegated references naming the same
   `quota_id` MUST NOT collectively cause `remaining` to go negative.
3. **Domain opacity.** Distinct issuer policies and domain-internal
   assets MUST NOT be observable by consensus and MUST NOT influence gas
   metering.
4. **Admission symmetry.** A normally funded issuer-policy proposal MUST
   use ordinary admission; a credit-starved challenge of that same policy
   MUST be able to use the constitutional budget with no market-price
   gate.
5. **Exit independence.** A credit-starved Instance MUST be able to
   create, verify, and minimally import exit artifacts without acquiring
   credit from any external party.
6. **No overclaiming.** Normative text in this RFC MUST NOT claim
   guaranteed market plurality, coinlessness, core-time allocation, or
   stronger censorship resistance than baseline JAR.

---

## Security Considerations

| Threat | Status | Notes |
|--------|--------|-------|
| Balance duplication via `MGMT_COPY` | Mitigated | Quota records never reside in copied values (§2, §3) |
| Collective overspend through delegation | Mitigated | One record per quota identity; debit is issuer-authority bytecode (§3) |
| Issuer accept-list capture by a single lineage | Partial | Two-authority procedure with distinct lineage roots (§6); collusion across lineages remains possible |
| Quota exhaustion under adversarial issuance timing | Partial | Admission-time check only; atomic debit mechanics deferred |
| Exit blocked by quota shortage in the receiving domain | Partial | Minimal import is credit-free (§7); richer import is not guaranteed |
| Constitutional-budget spam (repeated low-cost contests) | Open | Eligibility, rate limits, and deduplication deferred |
| Budget eligibility, sizing, replenishment, exhaustion unspecified | Open | Deferred Work, item 2 |
| Forced inclusion of delayed constitutional operations | Open | Mechanism not specified here; named dependency of §7 |

---

## Deferred Work

The following are intentionally out of scope for this RFC and MUST be
addressed in subsequent work:

1. **Quota record mechanics.** Encoding, storage layout within the issuer
   cnode, concurrency rules, atomic debit, fault behaviour, and migration
   path.
2. **Constitutional budget design.** Eligibility, sizing, per-Instance
   rate limits, deduplication, replenishment cadence, funding source or
   authority, rollover, exhaustion semantics, and the forced-inclusion
   mechanism for delayed constitutional operations.
3. **Issuer onboarding.** Evidence requirements and the
   contribution-attestation issuance policy.
4. **Multidimensional metering.** Any future extension to multiple
   resource dimensions MUST be specified independently, with canonical
   units and cross-architecture charging proofs.

---

## Discussion

This RFC deliberately avoids the word "token" in normative context. Gas
quota records are protocol-internal conserved quantities, not
transferable bearer instruments. Whether any external economic layer maps
onto them is a product decision outside kernel semantics.

The placement of quota records follows directly from two v3 commitments:
values are content-addressed and uniformly copyable, and conservation is
bytecode arithmetic in canonical authorities. Put together, a balance can
only live where bytecode guards it — in an authority Instance's state —
and anything an ordinary Instance holds can only be a name for it.

The two-authority procedure reuses the structural forgery resistance JAR
already has: lineage identity is the `image_hash` chain, so "independent
authority" is checkable as "distinct lineage root" without introducing a
registry.

The constitutional-budget asymmetry (ordinary credit for proposals, free
access for challenges) is not a quirk — it is the mechanism that prevents
a well-capitalised issuer coalition from buying immunity to challenge.
Proposals cost credit because spam prevention matters. Challenges are
free because the ability to contest must not depend on the outcome of the
thing being contested.

A note on naming: this RFC says "contestation" and "refusal/exit" for the
constitutional operation classes, and never "commitment", which in JAR
already means a Merkle commitment/root/proof over CNode state.

---

## Status History

| Date       | Status | Note |
|------------|--------|------|
| 2026-06-09 | Draft  | Initial filing |
| 2026-06-09 | Draft  | Rewritten self-contained against JAR's v3 model; external cross-references removed |
