# RFC-0001: Shared Compute Admission Without a Universal Numeraire

| Field      | Value                                      |
|------------|--------------------------------------------|
| RFC        | 0001                                       |
| Title      | Shared Compute Admission Without a Universal Numeraire |
| Status     | Draft (v0.12)                              |
| Date       | 2026-06-10                                 |
| Affects    | Elaborates the `GasLedger` sketch in `website/content/spec/principles/kernel-assisted-instances.md` (lazy-load OOG-catch) and `website/content/spec/principles/cap-scopes.md`; applies `website/content/spec/userspace/generic-authority-pattern.md`; positions itself against `website/content/docs/coinless.md`. Changes **no** kernel semantics: `website/content/spec/_index.md` §22, `website/content/spec/gas-cost.md`, the four cap kinds, and all `kernel:*` syscalls are used as-is. |

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

1. **The kernel-assisted `GasMeter`** (`website/content/spec/_index.md` §22,
   `website/content/spec/gas-cost.md`): per-block fast-path debiting against an ephemeral
   kernel table; `Gas{meter_key}` unit handles whose copies all name the
   same meter; `kernel:mint_gas` / `kernel:set_gas_meter`; the
   `kernel:oog` yield. Conservation already lives in the meter, not the
   cap. This RFC sits entirely *above* that flow.
2. **The `GasLedger`** (`website/content/spec/principles/kernel-assisted-instances.md`,
   `website/content/spec/principles/cap-scopes.md`):
   the chain's own σ-resident Instance holding persistent balances,
   lazy-loaded into meters per invocation via the OOG-catch pattern, and
   harvested back with the atomic set+read of `kernel:set_gas_meter`.
   This RFC is a specification of that ledger's record structure and
   admission discipline.
3. **The generic authority pattern**
   (`website/content/spec/userspace/generic-authority-pattern.md`): privileged rights are
   conveyed by possession of `Cap::Instance[AuthorityCap]` with a
   `YieldSender` embedded opaquely in its cnode. Type identity
   (`image_hash`) identifies and never authorizes. Spending rights here
   follow this pattern exactly.
4. **Coinless allocation** (`website/content/docs/coinless.md`): transactions are free by
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
    sender    : YieldSender{quota:draw}     -- embedded in cnode, opaque
    dsender   : YieldSender{quota:delegate} -- likewise opaque
    issuer    : IssuerId
    quota_id  : QuotaId
    grant_id  : GrantId                   -- chain-issued; never self-minted
    limits    : { per_call_max : u64      -- attenuation fields
                , expiry       : BlockNo
                , ...           }
  bytecode:
    draw(requested) → status
      -- clamp requested against limits (first-line only; the
      --  GrantRecord below is authoritative); compose
      -- {issuer, quota_id, grant_id, requested}; host_yield(sender)
    delegate(narrower_limits) → Cap::Instance[QuotaCap]
      -- validate narrower_limits ⊆ self.limits, else fault;
      -- compose {issuer, quota_id, grant_id, narrower_limits};
      -- host_yield(dsender) — chain verifies this grant is authorized
      --   (below), creates the child's GrantRecord, returns the
      --   chain-issued child grant_id (else refuses);
      -- host_derive_spawn the child with both senders,
      --   self.(issuer, quota_id), the returned grant_id,
      --   narrower_limits
```

The authoritative record of every grant is chain-side, created at
issuance (root grants, when an issuer registers a quota) and at
delegation (children):

```
GrantRecords : Map<GrantId, GrantRecord>      -- chain σ, like the ledger
GrantRecord  = { issuer   : IssuerId
               , quota_id : QuotaId
               , limits   : { per_call_max : u64
                            , expiry       : BlockNo }
               , parent   : Option<GrantId>
               , depth    : u32              -- root = 0; child = parent + 1
               , issuer_gen : u64            -- accept-list generation (§5)
               , revoked  : bool }
```

Every `GrantRecord` field is **immutable after creation except
`revoked`**, which transitions monotonically `false → true`. There is
no un-revoke and no limit mutation, so neither attenuation nor ancestry
can be bypassed after issuance.

A grant is **authorized** iff it and every ancestor (via `parent`) is
unrevoked, it is unexpired, and its `issuer_gen` equals the issuer's
current generation in the **issuer registry** (§5) with the issuer
currently `accepted`. Delegation enforces `child.limits ⊆ parent.limits`
including `expiry` (chain-side, below), so the child's own expiry
suffices. The limits carried in a QuotaCap's
state are a first-line clamp for caller convenience; the `GrantRecord`
is what the chain enforces.

The authorization check is **bounded before any gas is reserved**:
delegation MUST refuse a child whose `depth` would exceed
`MAX_DELEGATION_DEPTH` (a chain-spec parameter whose selection and
worst-case validation cost are deferred — §Deferred Work, item 1), so
every ancestry walk at draw, delegation, or top-up is
O(`MAX_DELEGATION_DEPTH`). An implementation MAY additionally cache
effective authorization under a revocation **generation counter** —
bumped on every revoke. The counter tracks revocation only: a cache hit
MUST still independently check `expiry` against the current block
**and that the grant's `issuer_gen` is still current in the issuer
registry (§5)** — or both MUST be part of the cache key — and a
revocation-counter mismatch MUST fall back to the bounded ancestry
walk. The cache is O(1) only on warm, valid hits.

- Spending authority is **possession** of the QuotaCap, conveyed by
  cap-flow. `image_hash` identifies the QuotaCap's type and MUST NOT be
  treated as the credential; the credential is the embedded
  `YieldSender`, accessible only to the QuotaCap's own bytecode.
- The `quota:draw` **and** `quota:delegate` keys are both registered in
  the chain's `YieldReceiver` at chain init, per the generic authority
  pattern. The chain MUST honor a draw or delegation only when it
  arrives as a yield under the respective key — i.e. only through a
  QuotaCap's bytecode. Data content claiming `(issuer, quota_id)`
  carries no authority.
- `MGMT_COPY` of a QuotaCap copies the Instance; all copies share the
  embedded sender and name the same `(issuer, quota_id)` record, so a
  copy can never increase any balance — the same property the
  `Gas{meter_key}` handle already has.
- **Delegation** is chain-mediated, through the QuotaCap's own
  endpoint. The embedded senders are opaque to the holder, so only the
  QuotaCap's bytecode can initiate `delegate(narrower_limits)`, and the
  endpoint MUST fault unless `narrower_limits` is equal or narrower —
  but local checks alone are not sufficient: `grant_id`s MUST be
  chain-issued, never minted by the cap. On a `quota:delegate` yield
  the chain MUST independently require, against the records alone:
  a fresh chain-issued child `grant_id`; that the parent record exists
  and is authorized — which includes the issuer being on the
  accept-list at the grant's generation (§5); that the child's
  `(issuer, quota_id)` equals the parent's; and that the child's limits
  are within the **parent record's** limits — the cap's local narrowing
  check is convenience, not enforcement. Only then is the child's
  `GrantRecord` created (with `parent`, `depth`, and `issuer_gen`
  set from the parent). A revoked or expired grant
  therefore cannot launder itself into a fresh one, and revoking a
  grant covers all its descendants through the ancestry check.
  Narrowing MUST NOT create independent gas.
- **Revocation** has two granularities, and the coarse one is global
  but prospective, with a snapshot-precise boundary: dropping
  `quota:draw` from the chain's `YieldReceiver` (the cap-scopes
  key-drop discipline) blocks draws routed via owner edges snapshotted
  **after** the drop. A QuotaCap invoked under a pre-drop snapshot
  retains its catch set and may still complete its yield, and an
  already-admitted operation's top-ups never pass through `quota:draw`
  at all (§4), so in-flight reservations run to a terminal state under
  their bindings. A drop intended as a kill switch SHOULD remove
  `quota:draw` and `quota:delegate` together. An implementation that
  wants a kill switch should be clear about what it achieves:
  **immediate authorization revocation, not immediate execution
  halt** — gas already loaded into a meter runs to HALT or OOG
  regardless. For immediate revocation an implementation MAY add a
  global **authorization epoch** `auth_epoch` in chain σ, bumped at
  key drop: the draw and delegation handlers MUST refuse a yield
  arriving under a key the chain has since dropped (a stale pre-drop
  snapshot can still route one in, so the handler checks its own
  current catch set, not the snapshot); each binding records
  `auth_epoch` at admission (§4 step 4); and a top-up requires the
  binding's epoch to equal the current one. A dropped governance key
  MUST NOT be re-added: recovery after a kill switch mints fresh keys
  (rotation), since a current-catch-set check cannot distinguish a
  stale pre-drop yield once the same key is restored. Rotation is not
  complete until **re-issuance**: existing QuotaCaps still embed the
  old senders and are permanently inert, so the chain MUST mint new
  caps holding the fresh senders and redistribute them via cap-flow,
  per the generic authority pattern. Per-grant
  revocation is setting
  `GrantRecords[g].revoked`; the chain MUST refuse draws and top-ups
  whose grant is not authorized. An implementation MAY instead mint
  per-grant yield keys to make key drop fine-grained, at the cost of
  one catch-list entry per grant.

### 4. Admission, Load, and Harvest

Admission extends the existing lazy-load OOG-catch flow. For an
operation presenting a QuotaCap:

```
1. Caller's QuotaCap.draw(requested) yields quota:draw.
2. Chain catches; g = GrantRecords[grant_id]; requires g to be
   authorized (unrevoked incl. ancestors, unexpired, issuer at
   current accept-list generation — §3/§5) and to match
   (issuer, quota_id); requires requested ≤ g.limits.per_call_max;
   looks up GasLedger[(issuer, quota_id)].
3. RESERVE: if remaining < requested → refuse admission.
   Else remaining -= requested.                   -- the reservation
4. Chain picks a meter_key that is LIVE-UNIQUE — bound by no other
   active reservation (meter_key collisions silently alias) — and
   records the binding; grant_id links it to the authoritative
   GrantRecord:
     ActiveReservations[meter_key] :=
       { issuer, quota_id, grant_id, reserved: requested, residue: 0
       , epoch: auth_epoch }       -- iff the §3 epoch is adopted
   emit kernel:set_gas_meter(meter_key, requested);
   CALL target with the Gas cap in its gas_slots.
5. Execution debits the meter per block (kernel fast path, unchanged).
   On kernel:oog the target is Waiting with its origin slot reserved;
   the chain MUST NOT CALL it again. The kernel:oog payload carries
   only the Gas handle, so all authorization context for a top-up is
   reached through the binding. To continue with `additional`:
     b = ActiveReservations[meter_key]
     g = GrantRecords[b.grant_id]
     re-check g authorized (incl. issuer at current
       accept-list generation — §3/§5)            -- else DROP_RESUME
     require b.epoch = auth_epoch (iff adopted)   -- else DROP_RESUME
     require b.reserved + additional ≤ g.limits.per_call_max
       (checked add)                              -- else DROP_RESUME
     RESERVE additional from GasLedger[(b.issuer, b.quota_id)] (as in 3)
     residue = emit kernel:set_gas_meter(meter_key, 0)
     emit kernel:set_gas_meter(meter_key, residue + additional)
     b.reserved += additional
   CALL_RESUME. To stop, DROP_RESUME and fall through to 6–7.
6. On HALT/fault/drop:
     harvested = emit kernel:set_gas_meter(meter_key, 0)
7. Refund through the binding, never by recomputing the key's owner:
     { issuer, quota_id, .. } = ActiveReservations[meter_key]
     GasLedger[(issuer, quota_id)].remaining += harvested
     delete ActiveReservations[meter_key]   -- key reusable again
```

**Checked arithmetic.** Every addition and subtraction in this section —
`remaining -= requested`, `b.reserved + additional`,
`residue + additional`, `remaining += harvested`, `depth + 1` — MUST be
checked: an operation that would overflow or underflow `u64` (or `u32`
for `depth`) is refused before any mutation. The chain MUST maintain
`remaining ≤ ceiling` on every quota record as an invariant. A refund
that would exceed `ceiling` indicates an accounting fault and has a
**defined outcome** — the meter is already harvested at that point, so
the operation cannot simply abort: refund up to `ceiling`, append an
**immutable per-fault quarantine record**
`{ issuer, quota_id, excess, block, meter_key }` for governance
inspection — append-only, so there is no accumulator whose own
arithmetic could overflow after the harvest — delete the binding, and
emit an auditable trace. Never clamp silently, never strand the
binding, never mint.

The reservation at step 3 is the admission decision. Because reserve and
refund are ledger writes inside the chain's sequential accumulate, two
operations drawing on one quota cannot both pass against the same
`remaining` — there is no check/debit window. A `meter_key` MUST NOT be
bound by two active reservations at once: `kernel:set_gas_meter` sets
absolutely and `kernel:mint_gas` collisions silently alias, so a shared
live key would overwrite one operation's meter and route its harvest to
the wrong quota. Keys MAY be reused once their binding is deleted. Gas
consumed by a faulted apply is not refunded beyond the harvest,
consistent with the meter's STM-exemption.

**Block boundaries.** `GasMeter` is discarded at block end — the kernel
is stateless across blocks — while a yield may be preserved across
blocks as a persistent pause. A reservation MUST NOT rely on meter state
surviving a block boundary; the binding, which lives in chain σ and
persists, is what carries a reservation across. For every
`ActiveReservations` entry whose operation remains paused at block end,
the chain MUST pre-harvest before the block closes:

```
residue = emit kernel:set_gas_meter(meter_key, 0)
ActiveReservations[meter_key].residue := residue
```

and on resuming in a later block MUST **revalidate before reloading** —
the same authorization checks as a top-up (grant authorized at the
current accept-list generation, epoch equality if adopted). Reload is a
gas load, and §5 forbids loading for a removed issuer. On failure,
refund the residue through the binding (as in step 7) and
`DROP_RESUME`. Only on success:

```
emit kernel:set_gas_meter(meter_key, ActiveReservations[meter_key].residue)
ActiveReservations[meter_key].residue := 0      -- now loaded, not parked
```

Resetting `residue` is what distinguishes a parked reservation from a
loaded one; without it a second resume would reload the same gas twice.
Note the boundary wipes the meter-table **entry**, not the handle:
`kernel:set_gas_meter` recreates the entry ("if no entry exists … the
entry is created"), while the `Gas{meter_key}` **handle** is a cap the
chain retains across blocks — inert while its entry is absent, it names
the recreated entry again, so no re-mint is needed. Live-uniqueness of
`meter_key`s is judged against the persistent bindings, not the
per-block meter table. An implementation MAY instead refund the residue
to the quota at block end and re-reserve at resume; either way, no gas
is created or lost at a boundary.

Multiple accepted issuers MUST be permitted. Proof-of-Intelligence
contribution attestation is one issuance route and MUST NOT be treated
as mandatory or exclusive. Issuer policies and domain-internal
accounting MUST NOT influence metering: the kernel sees only meters.

### 5. Issuer Governance

The chain maintains a persistent **issuer registry** — the accept-list
is its `accepted` view:

```
IssuerRegistry : Map<IssuerId, { accepted   : bool
                               , generation : u64 }>
```

The record **persists while the issuer is absent**, so the generation
survives removal: removal sets `accepted := false` and bumps
`generation` with a **checked** increment; re-acceptance sets
`accepted := true` at the already-bumped generation. If the increment
would overflow, the `IssuerId` is **retired permanently** and MUST NOT
be re-accepted — wrapping could resurrect ancient grants.
Membership-at-current-generation gates the whole lifecycle: issuance
(registering a quota and its root grant) stamps the grant's
`issuer_gen`; every draw (§4 step 2), delegation (§3), and top-up or
cross-block reload (§4) requires the grant to be authorized, which
includes its generation equalling the issuer's current one. Removal
therefore **permanently invalidates every existing grant** — no draw,
delegation, top-up, or reload referencing a prior generation ever
succeeds again. Re-acceptance resumes at the generation already bumped
at removal: quota balances are preserved in the ledger, but grants MUST
be re-issued; resurrection of old grants is impossible by construction. Gas already loaded into a
meter runs to a terminal state. Changes to the accept-list MUST use a
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
validator discretion (`website/content/docs/coinless.md`), this requires a
protocol-level inclusion guarantee for reserve-funded operations; that
mechanism is an open dependency, not specified here (§Deferred Work,
item 2).

### 7. Relationship to Coinless Allocation

This RFC **complements** `website/content/docs/coinless.md`; it does not amend it:

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

An **exit artifact** is an export of an Instance — self-contained in
its `Closure` form; a `Manifest` artifact is a *reference* export, not
self-contained:

```
ExitArtifact = { image           : Image          -- current spec
               , cnode           : CNode          -- current state (root)
               , content         : Closure(Map<Hash, Value>)  -- values
                                 | Manifest(Set<Hash>)        -- hashes only
               , lineage_witness : [ImageHash]    -- ordered, root-first
               , provenance      : Option<
                   { source_root     : Hash       -- a source new_state_root
                   , inclusion_proof : Proof }>   -- Instance content ∈ root
               }
```

Because `image_hash` is the cumulative chain hash and lineage walking is
off-chain or userspace (there is no `host_is_template_of`), the artifact
MUST carry a **lineage witness** `[h₀ … hₙ]`: the ordered image hashes
from root, each `hᵢ = hash(imageᵢ)`. The fold is over the
already-hashed entries, with the genesis accumulator defined as the
root entry:

```
acc₀ = h₀
accᵢ = hash(accᵢ₋₁ || hᵢ)        for i = 1 … n
```

(equivalent to the spec's `hash(acc || hash(image))` with `hᵢ`
substituted for `hash(imageᵢ)`). Verification is that `accₙ` equals the
Instance's attested `image_hash`, plus the content check
`hash(image) = hₙ`.

The root cnode is not self-contained: its slots hold caps referencing
further content-addressed values (Instance, Image, Data, CNode), which
in turn reference others. The `content` field carries this in one of
two variants: **`Closure`** — every value transitively referenced from
the root cnode and `image` — or **`Manifest`** — the content hashes of
that closure only, importable only where those entries are already
installed or supplied alongside. Content entries are self-verifying by
content hash; the lineage witness attests the *root* Instance only —
nested Instances in the content are imported as values, with no lineage
claim of their own.

**Verification has two levels, and the artifact alone gives only the
first.** The re-fold and content checks above establish **internal
consistency**: that `image`, `cnode`, `content`, and the witness agree
with one another. For a `Closure` artifact this is checkable locally.
For a `Manifest` artifact it is **conditional**: hashes alone cannot
prove the listed set is the complete transitive closure — and resolving
every listed value still cannot prove no reachable value was *omitted*
from the list. Internal consistency is established only by resolving
every listed entry and **traversing from the root**: the hash set
discovered by the traversal MUST equal the manifest set exactly,
nothing missing and nothing extra. Until then the artifact is a
self-consistent claim over the root and witness only. Neither level establishes that the Instance ever
existed in any source domain — a fabricator can manufacture a mutually
consistent artifact wholesale. Establishing **provenance** requires
binding the artifact to source state: the OPTIONAL `provenance` field
carries a source `new_state_root` (the hash of the source chain's cnode
root) and an inclusion proof of the exported Instance's content under
it. A destination that requires provenance MUST verify the inclusion
proof against a source root it accepts; *which* roots it accepts is
destination policy, established out of band. Where this RFC says
credit-free "verification" (§6, acceptance criterion 6), it means
internal consistency; provenance verification additionally needs an
accepted root, which no credit can substitute for.

**Import is re-instantiation, not identity transfer.**
`host_derive_spawn` always extends the *spawner's* `image_hash` chain,
so a destination cannot recreate the source Instance's identity without
new kernel semantics — which this RFC does not propose. What import
means here: the destination verifies the artifact, then instantiates a
**new** Instance under its own lineage whose Image and cnode content
match the verified artifact. Continuity with the source is established
by the verified lineage witness carried in the artifact, not by chain
identity. Identity recreation is **not** claimed.

**Guarantees.** Exit-artifact creation and verification MUST NOT be
conditioned on an external agreement or on the holder's quota balance
(reserve-funded, §6). Import is subject to the destination's acceptance
policy; what is guaranteed is narrower: a destination that accepts the
artifact format MUST be able to verify it and re-instantiate its content
under the destination's own lineage, without the *originator* holding
quota in either domain — for a `Manifest` artifact, after every listed
value resolves and the resulting closure traverses successfully.
Unconditional import everywhere is **not** claimed.

### 9. Out of Scope

- Issuance valuation, exchange, transfer, redemption, collateralization,
  and merging of quota;
- provider capacity allocation and leases;
- core-time assignment and scheduling markets (governed by
  `website/content/docs/coinless.md`'s bilateral market, untouched per §7);
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
6. **Exit independence.** A quota-starved Instance can create an exit
   artifact and verify its internal consistency — locally for a
   `Closure` artifact; for a `Manifest`, conditionally on resolving and
   traversing every listed value — and a format-accepting destination
   can re-instantiate its content under the destination's own lineage,
   without the originator holding quota. Provenance acceptance is
   destination policy and is not credit-gated either.
7. **Coinless preserved.** Under zero congestion and sufficient quota,
   observable behaviour matches `website/content/docs/coinless.md`'s free-by-default
   model; the core-time market is unmodified.
8. **No overclaiming.** Normative text MUST NOT claim guaranteed market
   plurality, core-time allocation, or stronger censorship resistance
   than baseline JAR.
9. **No live meter aliasing.** No two active reservations share a
   `meter_key`; every harvest is refunded to the quota recorded in its
   `ActiveReservations` binding.
10. **OOG continues by resume.** A `kernel:oog` pause is continued only
    by top-up + `CALL_RESUME` (or ended by `DROP_RESUME`); the waiting
    target is never re-`CALL`ed.
11. **No revocation laundering.** A QuotaCap whose grant is revoked or
    expired cannot produce a child that draws: `grant_id`s are
    chain-issued at delegation, and revoking a grant revokes its
    descendants.
12. **Boundary conservation.** A reservation paused across a block
    boundary loses no gas and gains none: pre-harvested residue equals
    the amount reloaded at resume (or refunded and re-reserved).
13. **Top-up authorization.** A paused operation cannot, through
    top-ups, exceed its grant's `per_call_max` ceiling or continue on a
    grant that has been revoked (directly or via an ancestor) or has
    expired since admission.
14. **Issuer removal bites permanently.** After an issuer's removal, no
    draw, delegation, top-up, or cross-block reload referencing any
    grant of a prior generation succeeds; already-loaded gas runs to
    terminal and no more is loaded. Re-acceptance requires re-issuance —
    no old grant revalidates.
15. **No arithmetic wrap.** No quota, reservation, meter, or depth
    arithmetic wraps; `remaining ≤ ceiling` holds on every quota record
    at every step.

---

## Security Considerations

| Threat | Status | Notes |
|--------|--------|-------|
| Balance duplication via `MGMT_COPY` | Mitigated | Balances live in `GasLedger`/`GasMeter`, never in cap values (§2, §3) |
| Forged spending authority from data content | Mitigated | Authority is possession of the embedded `YieldSender` (§3); data carries none |
| Check/debit race on one quota | Mitigated | Reservation at admission inside sequential accumulate (§4) |
| Meter-key collision misrouting gas | Mitigated | Live-unique keys; refunds flow only through the `ActiveReservations` binding (§4) |
| Collective overspend through delegation | Mitigated | Delegation only via the cap's own `delegate` endpoint; clamps only narrow (§3) |
| Coarse revocation via shared `quota:draw` key drop | Partial | Key drop blocks draws from owner edges snapshotted after the drop; pre-drop snapshots may still yield and top-ups bypass the key, so in-flight reservations run to terminal unless an authorization epoch is added; drop both keys together (§3) |
| Pre-admission DoS via deep delegation chains | Partial | `depth` capped at `MAX_DELEGATION_DEPTH`, bounding every ancestry walk, but the bound's value and worst-case cost are deferred; cache is O(1) only on warm, valid hits (§3) |
| Revocation bypass via local delegation | Mitigated | `grant_id`s are chain-issued with recorded ancestry; revocation covers descendants (§3) |
| Top-up bypassing grant limits or revocation | Mitigated | Binding links to the authoritative `GrantRecord`; every top-up re-checks authorization (revocation incl. ancestors, expiry) and the cumulative ceiling (§3–§4) |
| Reservation loss across block boundaries | Mitigated | Pre-harvest into the persistent binding before block end; reload at resume (§4) |
| Exit artifact missing referenced state | Mitigated | `Closure` carries the reachable content; `Manifest` completeness is deferred to resolution and traversal of every listed entry (§8) |
| Issuer accept-list capture | Partial | Two separately controlled yield keys (§5); collusion between the two holders remains possible |
| Removed issuer continuing to draw | Mitigated | Generation-stamped grants; removal bumps the generation, permanently invalidating prior grants across draws, delegations, top-ups, and reloads (§3–§5) |
| Grant resurrection after issuer re-acceptance | Mitigated | Persistent registry retains the generation across absence; checked increment, permanent retirement on overflow; old grants never revalidate (§5) |
| Stranded or minted gas on refund fault | Mitigated | Refund to `ceiling`; excess in immutable per-fault quarantine records (no accumulator to overflow); binding deleted; audit trace (§4) |
| Stale yield after key re-addition | Mitigated | Dropped governance keys are never re-added; recovery rotates to fresh keys and re-issues QuotaCaps holding them (§3) |
| Cached authorization outliving issuer removal | Mitigated | Cache hits independently recheck `expiry` and `issuer_gen` currency, or carry both in the cache key (§3) |
| Arithmetic overflow bypassing limits | Mitigated | Checked arithmetic, refusal before mutation; `remaining ≤ ceiling` invariant (§4) |
| Lineage-as-credential confusion | Mitigated | §5 forbids it explicitly, matching the v3 footgun warning |
| Exit artifact fabrication | Partial | Internal consistency is locally checkable for `Closure` artifacts, conditional on resolving every entry for `Manifest`; provenance needs the OPTIONAL `new_state_root` inclusion proof against a destination-accepted root (§8) |
| Constitutional-reserve spam | Open | Eligibility, rate limits, deduplication deferred |
| Reserve sizing, replenishment, exhaustion | Open | Deferred Work, item 2 |
| Censorship of reserve-funded operations | Open | Inclusion is validator discretion; the §6 inclusion guarantee is an unspecified dependency |

---

## Deferred Work

The following are intentionally out of scope for this RFC and MUST be
addressed in subsequent work:

1. **Ledger record encoding** within the chain's σ, `IssuerId`
   derivation, migration from the per-user `GasLedger` sketch, and the
   selection of `MAX_DELEGATION_DEPTH` with its worst-case
   pre-admission validation cost.
2. **Constitutional reserve design.** Eligibility, sizing, per-Instance
   rate limits, deduplication, replenishment cadence, **funding source
   or authority**, rollover, exhaustion semantics, and the
   protocol-level inclusion guarantee for reserve-funded operations
   under validator-discretion inclusion.
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
| 2026-06-10 | Draft (v0.3) | Recheck fixes: live-unique `meter_key` with `ActiveReservations` binding, OOG continues by top-up + `CALL_RESUME` (never re-`CALL`), delegation via the QuotaCap's own `delegate` endpoint (sender is opaque to holders), import narrowed to re-instantiation under the destination lineage, revocation granularity of the shared `quota:draw` key made explicit with per-grant `grant_id` |
| 2026-06-10 | Draft (v0.4) | Second recheck: delegation chain-mediated (`quota:delegate`) with chain-issued `grant_id`s, ancestry, and descendant revocation; cross-block pauses handled by pre-boundary harvest into the persistent binding + reload at resume; exit artifact carries the reachable content closure or is an explicit manifest; reserve funding source/authority restored to Deferred Work |
| 2026-06-10 | Draft (v0.5) | Third recheck: exit verification split into internal consistency (artifact-local) vs provenance (OPTIONAL `new_state_root` + inclusion proof against a destination-accepted root); `quota:delegate` registration made explicit alongside `quota:draw`; boundary reload resets `residue` to distinguish parked from loaded, and the entry-vs-handle wipe semantics clarified (no re-mint needed) |
| 2026-06-10 | Draft (v0.6) | Fourth recheck: `ActiveReservations` carries the full authorization context (`grant_id`, `authorized` from the draw payload) so OOG top-ups re-check revocation/expiry and the cumulative ceiling; lineage-witness fold restated over already-hashed entries with `acc₀ = h₀` defined explicitly; artifact `content` modelled as `Closure \| Manifest` variants |
| 2026-06-10 | Draft (v0.7) | Fifth recheck: authoritative chain-side `GrantRecord { issuer, quota_id, limits{per_call_max, expiry}, parent, revoked }` keyed by `grant_id` replaces the payload-supplied `authorized` and the revocation set — draws and top-ups both check it; key-drop claim narrowed to future draws (catch-set snapshots; top-ups bypass the key), with an optional authorization epoch for immediate halt; `Manifest` internal consistency made conditional on resolving every entry; stale `closure` field name corrected |
| 2026-06-10 | Draft (v0.8) | Sixth recheck: delegation checks made fully chain-side against the records (fresh `grant_id`, parent exists/authorized, `(issuer, quota_id)` match, child limits within the parent **record**); `GrantRecord` fields immutable except monotonic `revoked: false → true`; ancestry walks bounded by `depth` ≤ `MAX_DELEGATION_DEPTH` with optional generation-counter cache; key-drop boundary stated snapshot-precisely (blocks owner edges snapshotted after the drop; drop both keys together); manifest conditionality propagated to criterion 6 and both security rows |
| 2026-06-10 | Draft (v0.9) | Seventh recheck: generation counter scoped to revocation only — cache hits MUST still check `expiry` against the current block and mismatches fall back to the bounded walk (O(1) on warm, valid hits only); authorization epoch, if adopted, checked at draw/delegation/top-up with bindings recording their admission epoch; `MAX_DELEGATION_DEPTH` selection and worst-case cost deferred (threat re-marked Partial); exit guarantee qualified for `Manifest` artifacts (after resolution and successful traversal) |
| 2026-06-10 | Draft (v0.10) | Eighth recheck: accept-list membership gates issuance, draw, delegation, and top-up — issuer removal stops admissions and top-ups while loaded gas runs to terminal; checked arithmetic required throughout §4 with the `remaining ≤ ceiling` invariant; epoch defined concretely (`auth_epoch` in chain σ, stamped into bindings, equality at top-up, handlers check their current catch set) and renamed to immediate *authorization revocation*; manifest verification requires root traversal with discovered-set equality, and a `Manifest` artifact is a reference export, not self-contained; step 2 binds `g.limits.per_call_max` |
| 2026-06-10 | Draft (v0.11) | Ninth recheck: cross-block reload revalidates the full top-up authorization before loading (refund + `DROP_RESUME` on failure); over-ceiling refund has a defined quarantine outcome (refund to `ceiling`, excess to `QuarantinedGas`, binding deleted, audit trace); issuer **generations** — removal bumps, authorization requires the grant's `issuer_gen` to be current, so removal permanently invalidates grants and re-acceptance requires re-issuance; delegation checklist includes the generation check and §5's citation corrected to §3; dropped governance keys are never re-added (rotation), closing the stale-yield-after-restore edge |
| 2026-06-10 | Draft (v0.12) | Tenth recheck: cache hits recheck `issuer_gen` currency (or carry it in the cache key); quarantine restated as immutable per-fault records — no accumulator to overflow post-harvest; persistent `IssuerRegistry { accepted, generation }` retains generations across absence, with checked increment and permanent retirement on overflow; rotation completed by mandatory QuotaCap re-issuance with fresh senders; all repository paths corrected to `website/content/…` |
