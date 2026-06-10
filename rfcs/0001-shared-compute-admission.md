# RFC-0001: Shared Compute Admission Without a Universal Numeraire

| Field      | Value                                      |
|------------|--------------------------------------------|
| RFC        | 0001                                       |
| Title      | Shared Compute Admission Without a Universal Numeraire |
| Status     | Draft (v0.2)                               |
| Date       | 2026-06-10                                 |
| Affects    | Elaborates the `GasLedger` sketch in `spec/principles/kernel-assisted-instances.md` (lazy-load OOG-catch) and `spec/principles/cap-scopes.md`; applies `spec/userspace/generic-authority-pattern.md`; positions itself against `docs/coinless.md`. Changes **no** kernel semantics: `spec/_index.md` §22, `spec/gas-cost.md`, the four cap kinds, and all `kernel:*` syscalls are used as-is. |

---

## Abstract

This RFC specifies the chain-orchestrator layer for admitting shared
compute without a universal economic numeraire. Admission compares only
canonical gas demand — never heterogeneous economic value. Persistent gas
quotas live in the chain's `GasLedger` (chain σ), extended from
per-user balances to multi-issuer `(issuer, quota_id)` records. Spending
rights are conveyed by the generic authority-capability pattern —
`Cap::Instance` with an embedded `YieldSender` — never by data content or
type identity. Execution metering is the existing kernel-assisted
`GasMeter` flow, unchanged: the chain loads a meter from the quota at
admission and harvests the remainder at completion.

Quota semantics and the admission discipline are specified here. Ledger
encoding and issuer onboarding policy are deferred.

---

## Requirements Language

> The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
> "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
> "OPTIONAL" in this document are to be interpreted as described in
> BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all
> capitals, as shown here.

---

## Relationship to the Existing Design

This RFC adds **no kernel mechanism**. It builds on four things v3
already specifies, and changes none of them:

1. **The kernel-assisted `GasMeter`** (`spec/_index.md` §22,
   `gas-cost.md`): per-block fast-path debiting against an ephemeral
   kernel table; `Gas{meter_key}` unit handles whose copies all name the
   same meter; `kernel:mint_gas` / `kernel:set_gas_meter`; the
   `kernel:oog` yield. Conservation already lives in the meter, not the
   cap. This RFC sits entirely *above* that flow.
2. **The `GasLedger`** (`kernel-assisted-instances.md`, `cap-scopes.md`):
   the chain's own σ-resident Instance holding persistent balances,
   lazy-loaded into meters per invocation via the OOG-catch pattern, and
   harvested back with the atomic set+read of `kernel:set_gas_meter`.
   This RFC is a specification of that ledger's record structure and
   admission discipline.
3. **The generic authority pattern**
   (`userspace/generic-authority-pattern.md`): privileged rights are
   conveyed by possession of `Cap::Instance[AuthorityCap]` with a
   `YieldSender` embedded opaquely in its cnode. Type identity
   (`image_hash`) identifies and never authorizes. Spending rights here
   follow this pattern exactly.
4. **Coinless allocation** (`docs/coinless.md`): transactions are free by
   default; validators allocate core-time under congestion through a
   bilateral market. This RFC governs *metering of admitted execution*,
   not inclusion, and does not replace that market (§7).

---

## Motivation

Most chain admission designs price access through a market-clearing token
price, coupling consensus liveness to external economic conditions. JAR
already avoids this for execution metering — gas is canonical, kernel
charged, and identical across the interpreter and recompiler — and for
inclusion, which is free by default. What v3 leaves open is the layer
between them: *who may draw how much gas, granted by whom, under what
governance*. The `GasLedger` is sketched as "persistent gas balances per
user" with policy explicitly unspecified.

Filling that gap badly would import a numeraire: a single mandatory
issuer, a market-priced balance, or admission gated on economic value
would each couple liveness to economics. This RFC fills it without one:
multiple issuers, canonical-gas-denominated quotas, possession-based
spending authority, and a constitutional reserve that keeps contestation
and exit credit-free.

---

## Specification

### 1. Governance Domains

A **governance domain** is an analytical grouping: one or more issuer
authority Instances together with the Instances whose gas access they
govern and the policy records they hold. Domains introduce no new cap
kind and no new object; they are an organisational lens. Domain
membership and issuer policy are chain-orchestrator state, opaque to the
kernel.

### 2. Quota Records (GasLedger Extension)

The `GasLedger` record is keyed by `(issuer, quota_id)` rather than by
user alone:

```
GasLedger : Map<(IssuerId, QuotaId), QuotaRecord>
QuotaRecord = { remaining : u64    -- canonical gas units
              , ceiling   : u64 }  -- set at issuance; immutable thereafter
```

- `IssuerId` names an accepted issuer authority Instance (§5).
- `remaining` and all arithmetic on it live in the ledger — chain σ —
  never in any cap value, mirroring the meter discipline ("conservation
  lives in GasMeter, not in the cap").
- The ledger is the chain's own Instance state; updates occur inside the
  chain's sequential accumulate, so ledger operations are serialized by
  construction.

### 3. Spending Authority (QuotaCap)

A **QuotaCap** is an AuthorityCap per the generic authority pattern:

```
QuotaCap = Cap::Instance[QuotaCapImage]
  state:
    sender    : YieldSender{quota:draw}   -- embedded in cnode, opaque
    issuer    : IssuerId
    quota_id  : QuotaId
    limits    : { per_call_max : u64      -- attenuation fields
                , expiry       : BlockNo
                , ...           }
  bytecode:
    draw(requested) → status
      -- clamp requested against limits; compose
      -- {issuer, quota_id, requested}; host_yield(sender)
```

- Spending authority is **possession** of the QuotaCap, conveyed by
  cap-flow. `image_hash` identifies the QuotaCap's type and MUST NOT be
  treated as the credential; the credential is the embedded
  `YieldSender`, accessible only to the QuotaCap's own bytecode.
- The `quota:draw` key is registered in the chain's `YieldReceiver` at
  chain init. The chain MUST honor a draw only when it arrives as a
  yield under that key — i.e. only through a QuotaCap's bytecode. Data
  content claiming `(issuer, quota_id)` carries no authority.
- `MGMT_COPY` of a QuotaCap copies the Instance; all copies share the
  embedded sender and name the same `(issuer, quota_id)` record, so a
  copy can never increase any balance — the same property the
  `Gas{meter_key}` handle already has.
- **Delegation** is derivation: a holder spawns a child QuotaCap
  (`host_derive_spawn`) whose `limits` are equal or narrower and whose
  bytecode clamps before yielding. The child names the same quota
  identity; narrowing MUST NOT create independent gas. Revocation
  follows cap-scopes discipline: the issuer requests key drop or the
  chain expires the cap by `expiry`.

### 4. Admission, Load, and Harvest

Admission extends the existing lazy-load OOG-catch flow. For an
operation presenting a QuotaCap:

```
1. Caller's QuotaCap.draw(requested) yields quota:draw.
2. Chain catches; looks up GasLedger[(issuer, quota_id)].
3. RESERVE: if remaining < requested → refuse admission.
   Else remaining -= requested.                   -- the reservation
4. Chain mints/reuses meter_key; emit kernel:set_gas_meter(meter_key,
   requested); CALL target with the Gas cap in its gas_slots.
5. Execution debits the meter per block (kernel fast path, unchanged).
   On kernel:oog the chain MAY repeat 2–4 for a further reservation.
6. On HALT/fault: harvested = emit kernel:set_gas_meter(meter_key, 0).
7. GasLedger[(issuer, quota_id)].remaining += harvested.
```

The reservation at step 3 is the admission decision. Because reserve and
refund are ledger writes inside the chain's sequential accumulate, two
operations drawing on one quota cannot both pass against the same
`remaining` — there is no check/debit window. Gas consumed by a faulted
apply is not refunded beyond the harvest, consistent with the meter's
STM-exemption.

Multiple accepted issuers MUST be permitted. Proof-of-Intelligence
contribution attestation is one issuance route and MUST NOT be treated
as mandatory or exclusive. Issuer policies and domain-internal
accounting MUST NOT influence metering: the kernel sees only meters.

### 5. Issuer Governance

The chain maintains an **issuer accept-list**: the set of `IssuerId`s
whose quotas the chain will load. Changes to the accept-list MUST use a
**two-authority procedure**:

1. A **ballot**: a yield under a governance key (e.g. `gov:ballot`)
   identifying the proposed change, emitted via an AuthorityCap held by
   the proposing authority Instance.
2. An independent **quorum witness**: a yield under a distinct key
   (e.g. `gov:witness`) attesting the ballot's quorum, emitted via an
   AuthorityCap whose `YieldSender` was minted under a separately
   controlled key and granted to a different authority Instance.

Independence is **possession of separately controlled yield keys** —
never lineage: two Instances of distinct `image_hash` roots may be under
one party's control, and `image_hash` MUST NOT be read as a credential.
The chain MUST verify the two yields arrived under the two distinct
registered keys, and MUST retain both records so the change is auditable
end to end. A single AuthorityCap holder MUST NOT be granted both keys.

Issuer-policy proposals are ordinary admissions: they MUST draw on
normal quota under §4. Contesting such a proposal is a constitutional
operation under §6.

### 6. Constitutional Reserve

The **constitutional reserve** is a ledger record under the chain's own
authority — seeded per chain spec like `root_meter_key`'s block budget,
not issued by any accept-listed issuer — that funds exactly two
operation classes:

- **Contestation**: challenging a pending or enacted governance
  decision, including issuer accept-list changes.
- **Refusal and exit**: declining a governance succession and exporting
  state (§7).

The reserve MUST NOT fund issuer-policy proposals or other ordinary
admissions.

| Operation                        | Funding               |
|----------------------------------|-----------------------|
| Propose issuer-policy change     | Ordinary quota (§4)   |
| Contest a governance decision    | Constitutional reserve |
| Refuse a succession / exit       | Constitutional reserve |

A delayed constitutional operation MUST eventually be includable without
the consent of the authority it contests. Because inclusion is
validator discretion (`docs/coinless.md`), this requires a
protocol-level inclusion guarantee for reserve-funded operations; that
mechanism is an open dependency, not specified here (§Deferred Work,
item 2).

### 7. Relationship to Coinless Allocation

This RFC **complements** `docs/coinless.md`; it does not amend it:

- **Inclusion stays free by default.** Quota admission gates how much
  *execution* an operation may perform once the chain processes it; it
  is not an inclusion fee and MUST NOT be used as one.
- **The core-time market is untouched.** Under congestion, validators
  allocate inclusion via bilateral core-time payment, before and
  independently of quota admission. Quota does not price, replace, or
  guarantee core-time.
- Both gates apply in sequence: core-time (who gets included, under
  congestion) then quota (how much gas the included operation may
  draw). A zero-congestion chain with generous issuers reproduces
  coinless's free-by-default behaviour exactly.

### 8. Exit

An **exit artifact** is a self-contained export of an Instance:

```
ExitArtifact = { image          : Image        -- current spec
               , cnode          : CNode        -- current state
               , lineage_witness : [ImageHash] -- ordered, root-first
               }
```

Because `image_hash` is the cumulative chain hash and lineage walking is
off-chain or userspace (there is no `host_is_template_of`), the artifact
MUST carry a **lineage witness**: the ordered image hashes from root
such that folding `hash(acc || hash(image))` reproduces the Instance's
attested `image_hash`. Verification is that re-fold plus a content check
of `image` against the final element.

**Guarantees.** Exit-artifact creation and verification MUST NOT be
conditioned on an external agreement or on the holder's quota balance
(reserve-funded, §6). Import is subject to the destination's acceptance
policy; what is guaranteed is narrower: a destination that accepts the
artifact format MUST be able to verify and instantiate it without the
*originator* holding quota in either domain. Unconditional import
everywhere is **not** claimed.

### 9. Out of Scope

- Issuance valuation, exchange, transfer, redemption, collateralization,
  and merging of quota;
- provider capacity allocation and leases;
- core-time assignment and scheduling markets (governed by
  `docs/coinless.md`'s bilateral market, untouched per §7);
- any change to kernel semantics: no new cap kind, no new `kernel:*`
  syscall, no change to `GasMeter`, gas costs, or `MGMT_COPY`.

---

## Acceptance Criteria

The following MUST hold before this RFC is considered satisfied:

1. **No quota duplication.** No sequence of `MGMT_COPY` on QuotaCaps
   increases the `remaining` of any `GasLedger` record.
2. **Shared-identity bound.** Two QuotaCaps naming one
   `(issuer, quota_id)` cannot collectively over-reserve it: the §4
   reservation serializes in chain accumulate.
3. **No data-forged authority.** A `Cap::Data` containing
   `(issuer, quota_id)` bytes obtains no draw: only a yield under the
   registered `quota:draw` key is honored.
4. **Domain opacity.** Issuer policies and domain-internal accounting
   are invisible to the kernel and do not alter any meter charge.
5. **Admission symmetry.** A normally funded issuer-policy proposal
   draws ordinary quota; a quota-starved challenge of that same policy
   draws the constitutional reserve, with no market-price gate.
6. **Exit independence.** A quota-starved Instance can create and verify
   an exit artifact (with lineage witness), and a format-accepting
   destination can instantiate it, without the originator holding quota.
7. **Coinless preserved.** Under zero congestion and sufficient quota,
   observable behaviour matches `docs/coinless.md`'s free-by-default
   model; the core-time market is unmodified.
8. **No overclaiming.** Normative text MUST NOT claim guaranteed market
   plurality, core-time allocation, or stronger censorship resistance
   than baseline JAR.

---

## Security Considerations

| Threat | Status | Notes |
|--------|--------|-------|
| Balance duplication via `MGMT_COPY` | Mitigated | Balances live in `GasLedger`/`GasMeter`, never in cap values (§2, §3) |
| Forged spending authority from data content | Mitigated | Authority is possession of the embedded `YieldSender` (§3); data carries none |
| Check/debit race on one quota | Mitigated | Reservation at admission inside sequential accumulate (§4) |
| Collective overspend through delegation | Mitigated | Children name the same record; clamps only narrow (§3) |
| Issuer accept-list capture | Partial | Two separately controlled yield keys (§5); collusion between the two holders remains possible |
| Lineage-as-credential confusion | Mitigated | §5 forbids it explicitly, matching the v3 footgun warning |
| Exit verification spoofing | Partial | Lineage witness re-fold (§8); the destination still needs the trusted root out of band |
| Constitutional-reserve spam | Open | Eligibility, rate limits, deduplication deferred |
| Reserve sizing, replenishment, exhaustion | Open | Deferred Work, item 2 |
| Censorship of reserve-funded operations | Open | Inclusion is validator discretion; the §6 inclusion guarantee is an unspecified dependency |

---

## Deferred Work

The following are intentionally out of scope for this RFC and MUST be
addressed in subsequent work:

1. **Ledger record encoding** within the chain's σ, `IssuerId`
   derivation, and migration from the per-user `GasLedger` sketch.
2. **Constitutional reserve design.** Eligibility, sizing, per-Instance
   rate limits, deduplication, replenishment cadence, rollover,
   exhaustion semantics, and the protocol-level inclusion guarantee for
   reserve-funded operations under validator-discretion inclusion.
3. **Issuer onboarding.** Evidence requirements and the
   contribution-attestation issuance policy.
4. **Multidimensional metering.** Any extension beyond gas (e.g. storage
   quota issuance through the same ledger) MUST be specified
   independently, with canonical units and cross-architecture charging
   proofs.

---

## Discussion

This RFC deliberately avoids the word "token" in normative context.
Quota records are protocol-internal conserved quantities denominated in
canonical gas, not transferable bearer instruments; whether any economic
layer maps onto them is a service-layer concern, where `coinless.md`
already places token economics.

v0.1 of this draft reinvented both halves of the machinery this version
reuses: it held balances in issuer cnode records referenced by
`Cap::Data` content, and checked authority independence by `image_hash`
lineage. Both were architecture violations — data content is forgeable
by construction, and v3 states flatly that type identity never
authorizes. The corrected design is smaller: the kernel meter already
solves copy-safe debiting, the `GasLedger` already names the persistence
layer, and the authority pattern already solves unforgeable spending
rights. What remained genuinely unspecified — and is this RFC's actual
content — is the record structure, the issuer plurality, the
reservation discipline, and the constitutional asymmetry.

That asymmetry (ordinary quota for proposals, reserve access for
challenges) is the mechanism that prevents a well-capitalised issuer
coalition from buying immunity to challenge. Proposals cost quota
because spam prevention matters. Challenges are reserve-funded because
the ability to contest must not depend on the outcome of the thing being
contested.

A note on naming: this RFC says "contestation" and "refusal/exit" for
the constitutional operation classes, and never "commitment", which in
JAR already means a Merkle commitment/root/proof over CNode state.

---

## Status History

| Date       | Status | Note |
|------------|--------|------|
| 2026-06-09 | Draft  | Initial filing |
| 2026-06-09 | Draft  | Rewritten self-contained against JAR's v3 model; external cross-references removed |
| 2026-06-10 | Draft (v0.2) | Re-founded on existing machinery after review: quota as `GasLedger` extension with load/harvest bridge, spending authority via the generic AuthorityCap pattern, key-possession independence (not `image_hash`), reservation at admission, lineage-witness exit artifacts, explicit coinless positioning, honest `Affects` |
