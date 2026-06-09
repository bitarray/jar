# seL4 security properties — side-by-side mapping with v3

## Why this document exists

The v3 design conversations have repeatedly hit the question: *is our
model as secure as seL4?* That question has been re-litigated several
times because we lack a precise referent. This document fixes the
referent: it lists seL4's verified properties explicitly, then maps
each onto v3's design, identifying which properties hold, which hold
in a different form, which require kernel + ChainOrchestrator
together, which we lose, and which don't apply.

The goal is **not** mechanized verification (yet); just a precise
decomposition that ends the doubt loop. Subsequent work — formal
operational semantics, Lean theorems — would build on this list.

This is **Option D** from the methodology discussion. Lighter than
mechanized verification but precise enough to anchor design decisions.

## Important framing: the TCB boundary

In seL4, the trusted computing base is the kernel itself (~10K LoC,
formally verified). Application processes are untrusted; the kernel
prevents them from breaking system invariants regardless of their
behavior.

In v3, the TCB is **{kernel + chain orchestrator bytecode}**. The
kernel handles mechanism (cap-flow, image_hash chain, VM, state-root
hashing). The chain orchestrator's bytecode handles policy (auth
tables, ledger arithmetic, dispatch). Both must be correct for system
invariants to hold.

This is a deliberate architectural choice; see
[../_index.md §0 principle 18](../_index.md). The chain orchestrator
is a small, chain-spec-defined, formally-verifiable artifact — but
it IS in the TCB.

When mapping seL4 properties below, we'll be explicit about whether
each property is enforced by the kernel alone, or by the kernel
together with chain orchestrator bytecode.

## seL4's verified properties

The seL4 verification literature (Klein et al. 2009, 2014; Murray
et al. 2013) establishes a specific decomposition. We use it as
our reference list.

### P1. Functional correctness

The seL4 implementation refines its abstract specification. Every
behavior of the C kernel matches the specification's behavior. This
property says nothing about *what* the spec does — only that the
implementation matches.

### P2. Integrity (authorized writes only)

A subject S can only modify state that S's caps grant write access
to. No write happens "through the back door"; every state mutation
is traceable to a cap that authorized it.

Formally: if subject S writes location L, then S holds (or held) a
cap with write authority over L.

### P3. Confidentiality (authorized reads only)

A subject S can only observe state that S's caps grant read access
to. No information leaks from regions S can't read into S's
observations.

Formally: a non-interference property. If two system states differ
only in regions S can't read, S's observable behavior is the same in
both.

### P4. Cap-flow integrity

Caps appear in a subject's CSpace only via legitimate kernel
operations (Receive on an Endpoint, derived from a Retype, etc.).
Adversary cannot synthesize caps from bytes.

### P5. Authority confinement

Operations only succeed if invoked with appropriate caps. The kernel
enforces "you must hold this cap to do this" at every operation.

### P6. Cap exclusivity (linearity / derivation tree)

The kernel tracks cap derivation: every cap is either an original
(from Retype) or a derivation of a parent cap. Revocation propagates
through the derivation tree. At any moment, there's a definite
ownership / sharing graph.

### P7. Memory protection

Each subject has its own VSpace; the MMU prevents access to memory
not mapped in that VSpace. The kernel manages VSpace mappings via
caps.

### P8. Resource bounded operation

Kernel does not allocate memory during operation. All memory is
allocated explicitly via Retype on Untyped caps. Kernel itself runs
in bounded space.

### P9. Bounded latency

Operations complete in bounded time; no unbounded loops in kernel.
Real-time properties (interrupt response, scheduling latency).

## Mapping to v3

For each seL4 property, we ask:

- Does v3 have an analog?
- If yes, how is it enforced (kernel? kernel+orch?)?
- If no, what do we have instead?
- What are the residual gaps?

### P1 → V1. Functional correctness

**v3 status**: not-yet-verified.

**v3 analog**: v3 spec is currently informal markdown. A Rust V1
implementation exists under `the Rust workspace` for the PVM2 execution engine,
cap structures, gas charging, and in-flight CALL / YIELD / CALL_RESUME
stack mechanics. It is not a formal refinement target yet, and it does
not yet implement the full state-root / per-block orchestration surface.

**Path forward**: build a Lean operational semantics of v3 (Option
A / B from the methodology discussion), then state the Rust
implementation interface precisely enough to prove refinement. The
existing Rust code is useful evidence and testbed, not a proof.

**Gap**: formalization and implementation-refinement proof. Functional
correctness is a goal, not a current verified property.

---

### P2 → V2. Integrity (authorized writes only)

**v3 status**: holds, with TCB extension to chain orchestrator.

**v3 enforcement**:

- **Kernel-enforced part**: an Instance's state is mutated only by
  running its Image's bytecode (principle 13b: "trusted apply"). No
  ABI op writes content into another Instance's state. This is direct
  analog of seL4's integrity.

- **Chain orchestrator part**: for resource conservation
  (account_balances, storage_quotas, session_balances), the
  authority is the orchestrator's bytecode. A buggy orchestrator
  could write incorrectly to its own ledger. Userspace contracts
  cannot bypass this — they don't hold the orchestrator's caps —
  but the orchestrator's bytecode is in the TCB.

**Difference from seL4**: in seL4, integrity is purely structural
(caps + MMU). In v3, integrity is structural for *Instance state* (no
backdoor writes; principle 13b) but bytecode-mediated for
*ledger arithmetic* (orchestrator's bytecode must be correct).

**TCB scope**:
- Instance-state integrity: kernel only.
- Ledger conservation: kernel + orchestrator.

**Property statement (v3)**:
> If subject S modifies state location L, then either (a) L is in
> S's own cnode tree and S's apply ran (Instance-state integrity); or
> (b) L is in some authority Instance O's cnode tree and O's apply ran
> (bytecode-trusted ledger arithmetic).

The gap from seL4: case (b) trusts O's bytecode. Case (a) is
seL4-level structural.

---

### P3 → V3. Confidentiality (authorized reads only)

**v3 status**: does not apply. σ is public.

**v3 enforcement**: none. σ is content-addressed and replicated
across all validators. There are no secrets in σ.

**Why this differs**:
- seL4 isolates processes that could potentially observe each
  other's secrets via memory or covert channels.
- v3's σ is public by definition (state-root committed; replicated;
  reorg-able). There's nothing to confidentially-isolate.

**What we have instead**: confidentiality is achieved off-σ via
hardware-rooted attestation (§15). Validators sign attestations of
state transitions; private keys live off-σ; signatures verify on-σ.
This is a different security property from non-interference.

**Gap**: v3 makes no confidentiality claims at the σ level. Chain-
spec authors who want confidential state need off-σ mechanisms
(zero-knowledge proofs, hardware enclaves, MPC). v3 supports
these via the AttestationAuthority pattern but doesn't provide
in-σ confidentiality.

**Property statement (v3)**:
> No confidentiality property is claimed for σ. σ is public; all
> validators see all state.

---

### P4 → V4. Cap-flow integrity

**v3 status**: holds, kernel-enforced.

**v3 enforcement**:
- Caps are typed values in slots. Type tagging at the slot level
  prevents bytes-as-caps confusion.
- Caps appear in an Instance's cnode only via:
  - MGMT_MOVE/COPY from another slot the apply has access to.
  - Scratchpad reflection on CALL (caller passes scratchpad; callee
    receives at slot[0]).
  - set_image installation of pinned slots.
  - host_mint_cnode (mints a fresh empty Cap::CNode; no caps inside).
  - host_derive_spawn (mints a fresh Cap::Instance with new image;
    only callable from within self's apply).
- Adversary's bytecode cannot synthesize Cap::Instance from raw bytes
  via MGMT_MOVE from a Cap::Data slot — the runtime distinguishes
  Cap::Data from Cap::Instance by type tagging.

**Difference from seL4**: same property at the kernel-mechanism
level. seL4 tracks caps in CSpace via kernel-managed table; v3
tracks them in cnode slots via type-tagged slot encoding. Both
prevent forgery.

**TCB scope**: kernel only.

**Property statement (v3)**:
> A Cap::Instance, Cap::Image, Cap::Data, or Cap::CNode in any slot
> was placed there via a kernel-mediated operation (MGMT_*,
> scratchpad reflection, set_image, or spawn). Adversary cannot
> create caps from bytes.

---

### P5 → V5. Authority confinement

**v3 status**: holds *partially* at the kernel level; full coverage
requires kernel + orchestrator.

**v3 enforcement**:

For **Instance invocation** (CALL on a Cap::Instance):
- Kernel-enforced. To CALL Instance X, you must hold Cap::Instance[X] in
  your cnode (via cap-flow). Same as seL4 cap-as-authority.

For **resource consumption** (gas, quota, custom tokens):
- Bytecode-mediated. To consume gas, the apply has a `gas_budget`
  parameter on its CALL — kernel internal. A meter is set/topped up by
  emitting the `kernel:set_gas_meter` YieldSender, and minted via
  `kernel:mint_gas`.
- To consume quota, host_mint_data_cap takes a quota_slot arg; the
  kernel reads quota_key from the cap and debits the orchestrator's
  ledger. A quota is set/topped up by emitting the
  `kernel:set_storage_quota` YieldSender, and minted via `kernel:mint_quota`.
  The kernel direct-accesses canonical ledgers (well-known
  image pattern) for hot paths; otherwise CALL into authority.

For **policy decisions** (which user contract can mint, which can
transfer, which can write to certain ledgers):
- Cap-mediated by chain orchestrator. The orchestrator mints
  EndpointRefCap-style caps (§14) — each holding a `YieldSender{yield_key}`
  internally — and grants them to authorized contracts; possession of the
  cap (and thus the right to emit its `yield_key`) is the authorization.
  The orchestrator registers that `yield_key` in its own YieldReceiver to
  catch the request. Per-cap policy (rate limits, arg filters) is either
  baked into cap variants or held in a sidecar table keyed by cap identity
  — not by user. Signature verification routes via AttestationAuthority
  (§15), which emits a `YieldSender{"kernel:attest"}` caught by the kernel
  root receiver, per the same yield-mediated authority pattern.

**Difference from seL4**:

| Concern | seL4 | v3 |
|---|---|---|
| Direct invocation authority | cap-as-authority | cap-as-authority (same) |
| Per-user policy | revocable cap derivation | non-revocable cap grant + per-cap-identity policy sidecar |
| Resource quotas | linear caps with kernel tracking | bytecode + ledger |

**TCB scope**:
- CALL-via-cap authority: kernel.
- Resource and policy authority: kernel + orchestrator.

**Property statement (v3)**:
> An invocation on an Instance succeeds only if the invoker holds an
> appropriate Cap::Instance (kernel-enforced). A resource-consuming
> operation succeeds only if the relevant authority Instance's bytecode
> approves and the corresponding ledger entry has sufficient balance.

---

### P6 → V6. Cap exclusivity (linearity / derivation tree)

**v3 status**: explicitly dropped at the kernel level. Beyond the
snapshot/revert trade-off, **linearity has no structural use case in
v3 that other mechanisms don't already cover** — see analysis below.

**v3 design choice**: all caps are uniformly copyable. There is no
linear cap, no derivation tree, no revocation primitive at the
kernel level.

**What we have instead**: conservation invariants enforced by
authority-Instance bytecode. The chain orchestrator's ledger arithmetic
ensures total balances are preserved; the kernel verifies image_hash
chain to gate access to canonical ledgers.

**Why linearity isn't needed (deeper argument)**:

Earlier discussion framed this as "we trade linearity for
snapshot/revert". A deeper analysis shows linearity is *also* not
load-bearing for any other property, so the trade isn't even
necessary on its own merits. Walk through every plausible use case:

1. **Delegate pattern (cap = resource)**. Linearity in seL4 enables
   `Cap::Untyped{remaining}` to be the canonical resource holder.
   But Delegate **requires** that the cap's invocation can mutate
   the canonical resource directly. In v3, due to principle 13b
   (trusted apply: "no ABI op writes content into another Instance's
   state"), this is not possible regardless of linearity. A
   `Cap::Instance[Counter]` invocation runs Counter's apply, mutates
   Counter's state — but Counter's state is local to the Instance, not
   the canonical resource counter held by ChainOrchestrator. For
   actual conservation effect, Counter's apply must yield up to
   ChainOrch.

   So Delegate, even with kernel-level linearity, **cannot be
   implemented in userspace**. It requires the cap-invocation
   mechanism to be a kernel-mediated operation (a syscall), which is
   exactly what our yield-to-kernel pattern provides functionally:
   `host_yield` of a `kernel:*` YieldSender, caught by the kernel as
   the root receiver. seL4's Delegate is syntactically a method call but
   functionally a syscall; v3's `kernel:*` YieldSender is functionally a
   syscall expressed as yield-to-kernel. Same shape, different
   syntax.

   Therefore: **linearity doesn't enable Delegate uniquely — Delegate
   is already kernel-managed regardless. The "Delegate vs kernel-yield
   syscall" dichotomy was a false one.**

2. **Singleton / identity enforcement**. Recovered in v3 via
   image_hash chain canonical pattern + chain-author discipline.
   Each canonical singleton has a unique image_hash chain;
   reading that image_hash via `host_image_hash_chain` and
   comparing the raw bytes makes the discrimination structurally
   precise (identification only — type identifies, possession
   authorizes).

3. **One-shot tickets**. Recovered in v3 via ledger entry marked
   consumed. First call decrements and marks; subsequent calls
   detect and reject.

4. **Atomic transfer**. Recovered in v3 via MGMT_MOVE: source slot
   empties; receiver gets cap; no double-give.

5. **Linear protocol verification**. Recovered in v3 via bytecode
   step state tracking; rejects out-of-order calls.

6. **Capability secrecy / non-aliasing**. Doesn't apply: σ is
   public regardless of cap kind. Linearity wouldn't help with
   confidentiality.

7. **Affine/relevant resource accounting**. Recovered in v3 via
   bytecode discipline + tooling (linters/checkers can detect
   forgotten cnode entries that should have been consumed).

In every case, an existing v3 mechanism provides the property.
**Linearity is not the unique enabler of any structural property in
our setting.**

**Why this is a genuine simplification, not a hidden cost**:

The conservation we lose is structural (kernel-enforced). The
conservation we recover via ledger arithmetic is bytecode-enforced.
The TCB is therefore extended from "kernel" to "kernel + authority
bytecode". This is a real cost.

But: this cost would exist *even if we added linearity*, because
authority bytecode is also responsible for the actual resource
operation (Delegate doesn't change this, per the analysis above).
Adding linearity to the kernel would add kernel surface (linear-
count maintenance, derivation tree, MGMT_COPY gating, drop endpoint
machinery for refunds) without removing the bytecode TCB extension.

So adding linearity = strict cost increase. Not adding linearity =
the design we have.

**Difference from seL4**: significant in syntax/structure,
functionally equivalent for the relevant properties. v3's
conservation depends on bytecode correctness; seL4's depends on
kernel correctness. But seL4's "kernel correctness" includes
correctness of the cap derivation tree implementation, which is
itself non-trivial.

**TCB scope**: kernel + orchestrator (specifically, the ledger
arithmetic in authority bytecodes).

**Property statement (v3)**:
> Conservation of resource X is enforced by authority-Instance F's
> bytecode such that, across all sequences of operations on F's
> ledger, the total X-balance is preserved (modulo legitimate
> mints/burns per F's policy). The kernel structurally prevents
> bypassing F's bytecode by gating access to F's ledger via cap-flow
> + image_hash chain.

> No cap kind in v3 stores a resource balance directly. All
> resource balances live in authority ledgers. Cloning a cap clones
> a reference to a ledger row, not the row's content; conservation
> arithmetic on the row is preserved regardless of clone count.

---

### P7 → V7. Memory protection

**v3 status**: holds via static memory model + deterministic VM.

**v3 enforcement**:
- Each Instance's address space is statically declared by its Image
  (memory_mappings). Mappings reference cnode slots' DataCaps or
  Ephemeral kernel-allocated regions.
- The bytecode VM rejects access to undeclared addresses; access
  Faults the Instance deterministically.
- Page-faults are not exposed to bytecode *semantically* (an undeclared
  access is a terminal fault, not a resumable page-in). Within the fixed
  declared footprint, the kernel uses host-level faults to materialize
  pages lazily; demand paging is unchanged, but read-only regions have
  their page-in **charged at the CALL** (statically), while writable pages
  are charged via CoW per write at first-write faults. This is
  deterministic and invisible to bytecode semantics — see
  [gas-cost.md §3](../gas-cost.md).
- Access control is specified at the bytecode-VM layer. The current
  Rust implementation has both direct VM/interpreter enforcement and an
  x86 nub that uses host page tables / faults to materialize pages and
  enforce permissions. Those MMU faults are an implementation substrate,
  not bytecode-visible authority or consensus-visible page-fault events.

**Difference from seL4**: seL4 specifies and verifies isolation through
hardware MMU-backed VSpaces. v3 specifies isolation through the
deterministic bytecode VM; an implementation may additionally use an MMU
for efficient materialization and permission checks. Both achieve memory
isolation. v3's semantic model is arguably *stronger* in some ways
(bytecode cannot observe host page-fault timing as an authority channel)
but weaker in others (the consensus property relies on VM / nub
correctness rather than a seL4-style verified MMU kernel).

**TCB scope**: kernel (specifically the VM correctness).

**Property statement (v3)**:
> An Instance's apply can only read/write addresses in its declared
> memory_mappings. Access outside is a deterministic fault.

---

### P8 → V8. Resource bounded operation

**v3 status**: holds, with subtleties.

**v3 enforcement**:
- Kernel maintains internal gas counter; per-basic-block metering,
  pre-reserved at block entry (gas-cost.md §1).
- CALL specifies `gas_budget: u64`; kernel saves parent's counter,
  sets to budget, runs callee, restores.
- OOG → the kernel yields the `kernel:oog` yield_key (caught by the
  chain's YieldReceiver, which registers `kernel:oog` at init); the
  `Gas{meter_key}` payload reflects via slot[0].
- Apply's working memory is bounded (declared by Image's
  memory_mappings; Ephemeral allocation has explicit size).
- Read-only region materialization is **pre-charged at the CALL**
  (statically, from `Image.memory_mappings`) and writable-page CoW is
  charged per write — both deterministic. The fault *sequence* stays
  deterministic because RO faults now charge nothing.
- State-root computation at outermost termination has bounded cost
  (O(modified pages × log num pages)).

**Subtlety**: divergence events (§9 case (b)) trigger hashing
mid-block. The cost is bounded per event (proportional to the diverged
value's size), but the count of events is bounded by the apply's
gas (each MGMT_COPY costs gas).

**Difference from seL4**: seL4 is more aggressive (no kernel
allocation at all). v3 allocates Ephemeral regions per apply (heap,
stack); these have declared sizes. Both are bounded; v3's bound is
larger.

**TCB scope**: kernel.

**Property statement (v3)**:
> Per-block kernel work is bounded by O(gas_budget × constant) for
> per-block-at-entry metering (with static footprint multipliers),
> plus O(actual #3 faults × page-cost) for lazy materialization
> (reserved at entry, charged at fault), plus
> O(modified pages × log(num pages)) for state-root hashing, plus
> O(divergence events) for mid-block hashing. All terms are bounded by
> the block's gas budget.

---

### P9 → V9. Bounded latency

**v3 status**: holds, with the same caveats as P8.

**v3 enforcement**: per-block work is bounded; per-tx work is
bounded by tx gas budget. Kernel internal operations (CALL setup,
yield handling, etc.) are O(1).

**Difference from seL4**: seL4 has formal real-time guarantees
(MCS — Mixed Criticality Scheduling). v3 doesn't claim real-time
properties; only "blocks complete in bounded time."

**TCB scope**: kernel.

**Property statement (v3)**:
> Per-block latency is bounded by the per-block-at-entry cost (#1×#2)
> plus actual materialization (#3, reserved at entry) plus
> setup/teardown costs. No unbounded loops in kernel.

---

## Summary table

| seL4 property | v3 status | TCB scope (v3) | Gap |
|---|---|---|---|
| P1: Functional correctness | Not verified yet | N/A | Entire formalization needed |
| P2: Integrity (writes) | Holds | Kernel + orch | Ledger arithmetic in orch bytecode |
| P3: Confidentiality | Does not apply | N/A | σ is public; off-σ mechanisms for confidential state |
| P4: Cap-flow integrity | Holds | Kernel | None |
| P5: Authority confinement | Holds (split) | Kernel + orch | Resource quotas via bytecode |
| P6: Cap exclusivity / linearity | Dropped | Orch (replaced by ledger) | Structural conservation traded for snapshot/revert |
| P7: Memory protection | Holds | Kernel / nub (VM semantics; MMU may be substrate) | None at the VM layer |
| P8: Resource bounded | Holds | Kernel | Slightly larger than seL4's bound |
| P9: Bounded latency | Holds | Kernel | No real-time MCS-style guarantees |

## Where v3 has more than seL4

These are properties seL4 doesn't have (or doesn't care about):

- **V10. Snapshot/revert as primitive.** MGMT_COPY of any Cap::Instance
  produces a content-shared reference; mutations diverge per §9 case
  (b). Universal across all caps. seL4 has no analog.

- **V11. State-root determinism.** Every block has a canonical
  state-root computed deterministically by the kernel. Validators
  agree on the state-root. seL4 has no state-root concept.

- **V12. Cross-block continuation.** Paused Instances carry
  continuations across blocks. Long-running computation natively
  supported. seL4's IPC is synchronous; no equivalent persistence.

- **V13. Forgery resistance via image_hash chain.** Adversary cannot
  construct a Cap::Instance with canonical image_hash without
  legitimate descent. seL4's analog (cap derivation tree) is also
  forgery-resistant but has different properties.

- **V14. Content-addressed storage.** Instances, Images, Data are
  content-addressed; storage dedups identical content. seL4 doesn't
  do this.

## Where v3 has less than seL4

These are properties seL4 has that v3 lacks (or has weaker):

- **L1. Linear cap exclusivity.** seL4 has it structurally; v3
  doesn't. *However*, per the V6 analysis, linearity isn't actually
  load-bearing for any structural property in v3 — every use case is
  recoverable via other mechanisms (ledger arithmetic, image_hash,
  MGMT_MOVE, bytecode discipline). So while v3 "lacks" this, the
  practical loss is not a missing property but a redistribution of
  enforcement (kernel → authority bytecode + structural mechanisms).

- **L2. Cap revocation primitive.** seL4 has it (revoke propagates
  through derivation tree); v3 doesn't structurally; recovered via
  bytecode (orch invalidates ledger entries). Same pattern as L1:
  the property exists in v3 but enforcement is in bytecode.

- **L3. Pure-mechanism kernel TCB.** seL4's TCB is the kernel
  alone; v3's TCB extends to orch bytecode for conservation. This
  is the genuine architectural difference. Mitigated by orch
  bytecode being chain-spec-defined, small, formally verifiable.

- **L4. Hardware MMU isolation.** seL4's verified model centers MMU
  VSpaces. v3's consensus model centers deterministic VM isolation;
  current x86 code may still use MMU/page faults underneath. Trade-off:
  VM semantics are more deterministic; seL4-style MMU isolation is more
  mature and formally verified.

- **L5. Real-time properties.** seL4 has MCS for real-time; v3 has
  bounded latency but no MCS-style guarantees.

- **L6. In-σ confidentiality.** seL4 has it (process isolation);
  v3 doesn't (σ is public). Different threat model.

The relationship between L1 and L3 is worth noting: **even if we
added linearity (L1) to v3, the TCB extension (L3) would not
shrink**. Authority bytecode is required for the actual resource
operations regardless (per the V6 Delegate analysis), so adding
linearity at the kernel would be strict cost increase, not a way
to recover seL4's pure-kernel-TCB property.

## Where the {kernel + ChainOrchestrator} composition matters

The user observed: v3's security at the {kernel + ChainOrch} level
is comparable to seL4. This is borne out by the analysis:

- **At the kernel level alone**: v3 has P4 (cap-flow), P7 (memory),
  P8 (bounded), and partial P2 (Instance-state integrity), partial P5
  (CALL-via-cap authority).

- **At the kernel + orch level**: v3 additionally has full P2 (with
  ledger arithmetic), full P5 (resource and policy authority), and a
  bytecode analog of P6 (conservation via ledger).

- **Out of scope at any level**: P3 (confidentiality), P1 (functional
  correctness — not yet verified).

The orch's role in this composition is critical. If we think of seL4
as "kernel = mechanism, processes = arbitrary policy," v3 splits
this differently: "kernel = mechanism, orch = canonical policy
(small, chain-spec-defined, in TCB), user contracts = arbitrary
policy."

This is a smaller TCB than "kernel + arbitrary userspace" but a
larger TCB than seL4's kernel alone. It's the right boundary for
blockchain because the chain spec defines a finite, well-known
orchestrator policy.

## Hierarchical orchestration is seL4-style cap-as-authority

v3's authority model is uniformly capability-flow at every layer.
The §14 EndpointRefCap pattern *is* cap-as-authority: orchestrators
mint caps; user contracts hold them; possession = right to invoke.
There is no parallel ACL anywhere — earlier drafts that proposed
"orchestrator auth tables" have been retired.

A hierarchical decomposition:

```
Kernel
  └── ChainRoot
       ├── DomainOrch_DeFi
       │    ├── ProtocolOrch_AMM
       │    └── ProtocolOrch_Lending
       └── DomainOrch_NFT
            └── ...
```

User contracts hold caps minted by the appropriate layer
(ProtocolOrch_AMM mints AMM-endpoint caps holding a `YieldSender{yield_key}`;
DomainOrch_DeFi mints cross-protocol caps; ChainRoot mints cross-domain
caps). Each cap carries a layer-specific `yield_key`, and each layer
registers the keys it controls in its own YieldReceiver, so a yield of that
key routes — via per-CALL owner-edge YieldReceiver snapshots to the nearest
registered owner receiver (single-resumer) —
structurally to the right authority. Same mechanism at every layer.

Compared to seL4: the structural property is the same — invocation
authority is gated by cap-holding, kernel-enforced (here, gated by the
receiver-registration at the dispatching layer, which is structural via the
yield_key routing the kernel performs; forgery resistance of the authority
itself rests on interposition over kernel:mint_yield — a descendant cannot
mint a YieldSender for a key the layer reserves below it). The TCB for
direct invocation is the kernel; the TCB for policy-bearing caps (rate
limits, etc., when baked into cap variants per §14) is the
orchestrator that mints the variant.

**Recommendation for chain-spec authors**: structure orchestrator
hierarchies so each layer mints caps for the operations it controls,
and grants them downward. Avoid sidecar policy tables unless a
specific policy must change dynamically post-grant; even then,
key by cap identity rather than by user.

## Direct line vs intermediate-mediated authority: not a security loss

A natural concern when comparing v3 to seL4: **in seL4, every
process has a direct line to the kernel via syscall; in v3,
invocations from user contracts to kernel cascade through
intermediates (ChainOrchestrator, sub-orchestrators). Each
intermediate could refuse to propagate. Isn't this a security
regression?**

The short answer: **no**. Direct line in seL4 is an architectural
choice, not a verified security property. The properties seL4
verifies (P2-P5) are about what happens *when* an invocation is
honored, not about whether an invocation is structurally
guaranteed to reach the authority.

### What seL4 actually guarantees

seL4's verified properties say:

- **If holder has cap**, kernel honors invocation (P5).
- **If holder doesn't have cap**, no invocation possible (P5).
- **Caps cannot be forged or fabricated** (P4).
- **Authority cannot be exercised without cap-holding** (P2-P3).

None of these say "every process must have direct kernel access".
They say what kernel does *when invoked*, not whether invocation
arrives unobstructed.

### Layering in seL4

When seL4 systems need policy enforcement (rate limiting, audit,
mediation), they add server processes between the user and kernel:

```
User → Cap::ServerEndpoint → server.apply → Cap::KernelOp → kernel
```

The user holds a cap to the server, not to the kernel. Server checks
policy; if approved, server invokes kernel via *its own* cap.
Server can:
- Refuse to forward → user request fails (rate limit kicks in).
- Mutate args before forwarding → user gets different behavior.
- Log all activity → audit trail.

This is standard seL4 design when policy enforcement is needed.
Notice the implication: **users in such systems don't have direct
kernel access either**. They go through the server. The server
becomes a single point of failure for that pathway.

seL4 is fine with this. Verified properties hold: server can't
forge kernel responses (no cap forgery); kernel still mediates the
final operation (authority confinement); no cap leaks through the
server (cap-flow integrity).

### v3's structure is the same shape

v3's CO-in-path is essentially the seL4 server-pattern made
structural. ChainOrchestrator IS the policy server; it sits
between user contracts and kernel. User contracts hold caps that
route through CO; CO can rate-limit, audit, gate.

The only difference: in seL4, you *add* a server when you want
policy. In v3, the orchestrator is *always there*, because chain
specs always want policy enforcement (gas accounting, fairness, per-
user budgets, governance restrictions).

For chains that don't need much policy at a given pathway:
hierarchical orchestration (sub-orchestrators) lets the user contract
hold caps that route directly to a leaf orchestrator with minimal
mediation. This is closer to seL4's direct-line model.

### Practical example: rate limiting

To enforce "user A can mint at most 100 DataCaps per block":

```
Setup: CO has INTERPOSED by registering "kernel:mint_quota" in its own
  YieldReceiver (opt-in mediation; containment is what makes this safe —
  A only holds a YieldSender{"kernel:mint_quota"}, never a Receiver).
A's apply: host_yield(YieldSender{"kernel:mint_quota"})  (args via slot[0])
  The yield routes along A's owner edges, and the nearest registered owner
    receiver — CO — catches it (single-resumer), rather than reaching the
    kernel root.
  CO inspects the request (it registered this key precisely to mediate it).
  CO checks O.users[A].mint_count_this_block.
  If count > 100:
    DROP_RESUME(originating chain)
    A's tx fails with rate-limit error.
  If count ≤ 100:
    CO increments count.
    CO FORWARDS by re-emitting the same key (host_yield + CALL_RESUME
      loop); CO's owner edge for the forwarding call omits its receiver for
      that key, so the forward reaches the kernel root receiver.
    Kernel handles. Resume cascades back. A receives DataCap.
```

(Intermediate layers that don't want to intercept a key simply don't
register it in their YieldReceiver — the yield routes past them
structurally to the next registered receiver, with no passthrough cost.
An interposer that *does* catch but then forwards runs the re-emit loop:
`host_yield(sender) → CALL_RESUME(child, ...)` per iteration. See
principles/yield-passthrough-optimization.md for performance commentary.)

In seL4, achieving the same property would require adding a
rate-limit server between user processes and kernel. The user
holds a cap to the server; the server holds a cap to the kernel;
server enforces. Same shape; v3 just makes this structural.

### What "single point of failure" really means

When we earlier called CO a "single point of failure", we framed
it as a security concern. The reframing:

- **For correctness**: CO can't make wrong things happen. Forgery
  resistance via image_hash ensures responses are authentic.
- **For liveness**: CO can refuse service. This is the policy
  enforcement mechanism in action.
- **For fairness**: CO can prioritize. Same as a server in seL4.

A "buggy or malicious CO" is in the same trust position as a
"buggy or malicious seL4 kernel" or "buggy or malicious seL4
rate-limit server". Trusted infrastructure, in TCB, expected to
be correct. Replacement requires governance (chain upgrade in v3,
firmware update in seL4).

### Conditional authority is the right model for blockchain

In seL4, the authority property is "you hold cap = you can invoke".
Direct line is the mechanism that makes this absolute.

In v3, the authority property is "you hold cap = you can invoke,
subject to policy enforced by the orchestrator hierarchy". Cascade
is the mechanism that makes policy enforceable.

This conditional-authority model is what blockchains actually want:

- **Gas accounting**: every operation must be metered; CO sees
  every yield.
- **Per-user fairness**: CO can dispatch to schedule fairly across
  users in a block.
- **Governance restrictions**: certain operations subject to chain
  policy that may change; CO is the policy enforcement point.
- **Audit logging**: all kernel-bound operations logged at CO for
  off-chain analysis.
- **Rate limits**: per-user, per-domain, per-resource limits
  enforceable at CO.

Trying to achieve these in seL4 would require multi-server layered
designs. v3 makes the layered design native.

### What we're not breaking

- **P2 (integrity)**: holds. Forgery resistance (image_hash chain) +
  cnode ownership prevent unauthorized writes and unauthorized cap
  acquisition.
- **P3 (confidentiality)**: σ is public, but Instance state is opaque
  from outside; a keyed yield (Attest, mint request, etc.) routes — via
  owner-edge routing + single-resumer — straight to the nearest registered
  owner YieldReceiver, so unregistered intermediates never see the payload.
  Confidentiality from intermediates is preserved structurally.
- **P4 (cap-flow)**: holds. Caps can't be synthesized.
- **P5 (authority confinement)**: holds. Holder of cap can invoke
  the operation the cap names; intermediates can rate-limit but
  cannot make the operation succeed without cap-holding.
- **All other Vn properties**: unaffected.

### What we're trading

- **seL4's "absolute authority via cap-holding"** → **v3's
  "conditional authority subject to intermediate policy"**.

This is a feature for blockchain (enables policy enforcement) and a
restriction for general-purpose OS use (would require changing
default behavior to use direct invocation paths).

### Liveness as a separate concern

The remaining "single point of failure" is liveness:
intermediate-driven service degradation if CO is buggy or
malicious. Mitigations:

1. **Hierarchical orchestration**: smaller domains, smaller per-CO
   blast radius.
2. **Bytecode verification**: CO's policy bytecode is
   chain-spec-defined, formally verifiable. Reduces "buggy CO"
   risk.
3. **Governance / chain upgrade**: chain governance can replace CO
   if needed. seL4 analog: firmware update.
4. **Multi-validator consensus**: a single validator running a
   misbehaving CO doesn't break consensus; the chain follows the
   honest majority.

These are blockchain-native mitigations. For seL4 use cases (single
machine, single trusted base), liveness depends entirely on the
kernel + servers being correct. v3 has more layers but also
governance + consensus to repair them.

### Conclusion

Direct line in seL4 is **not a verified security property**. It's
an architectural choice that seL4 happens to make and that v3
happens not to make. v3's intermediate-mediated authority is
**equally secure** for the verified properties (P2-P5) and
**better-suited for blockchain** because it enables policy
enforcement natively.

The "single point of failure" framing was misleading. Better
framing: **CO is the policy enforcement point, by design**.
Properties hold; trust is appropriately placed; layering is
explicit.

## Open questions for further analysis

1. **Formal operational semantics of v3.** Build in Lean. Define
   state, ABI ops, transition relation. Required for any formal
   verification.

2. **Theorem statements for V2-V14.** Translate each property
   statement above into a Lean theorem. Identify which are provable
   from the operational semantics, which require additional
   assumptions (e.g., orch bytecode meets a specification).

3. **Specification of orchestrator policy.** What does it mean for
   "orch bytecode is correct"? Need a way to specify the orch's
   intended ledger invariants and prove the orch maintains them.

4. **Composability of theorems.** If kernel + orch are both
   correct, is the composed system correct? The composition
   theorem.

5. **Confidentiality story.** Even though σ is public, can we
   articulate confidentiality properties for off-σ inputs and
   outputs? AttestationAuthority pattern, hardware enclaves, etc.

6. **Information flow analysis.** Even on public σ, are there
   timing channels or state-pattern channels we should worry about?

7. **Empirical comparison with KeyKOS / EROS / Coyotos.** These
   pre-seL4 capability OSes had explicit handling for snapshots
   (KeyKOS's "checkpoint" mechanism). Do their properties carry
   over?

8. **Verified microkernel size.** seL4 is ~10K LoC. What's a
   reasonable size estimate for a verified v3 kernel + orch?
   Probably 30-50K LoC total (kernel ~20K, orch ~10-30K).

## Conclusion

v3 has **most of seL4's verified properties at the {kernel + chain
orchestrator} level**, with notable exceptions:

- **P3 (confidentiality)** doesn't apply — σ is public by design.
- **P6 (cap exclusivity / linearity)** is explicitly dropped.
  Conservation is recovered via bytecode-arithmetic in canonical
  authority Instances. Per the V6 analysis, linearity has **no
  structural use case in v3 that other mechanisms don't already
  cover** — every plausible use (Delegate, singleton enforcement,
  one-shot tickets, atomic transfer, linear protocol verification,
  etc.) is recovered via existing v3 mechanisms (image_hash chain,
  ledger arithmetic, MGMT_MOVE, bytecode discipline). Adding
  linearity to the kernel would be strict cost increase, not
  enabling any property we don't already have.
- **P1 (functional correctness)** is a goal, not a current
  property. Awaiting formal spec + verification.

v3 has **additional properties not in seL4**:

- Snapshot/revert as a primitive operation.
- State-root determinism for replication.
- Cross-block continuation.
- Forgery resistance via image_hash chain (different from cap
  derivation).
- Content-addressed storage.

The TCB extends from "kernel only" (seL4) to "kernel + orch
bytecode" (v3). This is acceptable because:
- The orch is small, chain-spec-defined, formally verifiable.
- The orch's policy is finite and well-understood (ledger
  arithmetic, auth tables, dispatch logic).
- User contracts remain untrusted (their bugs don't affect chain
  invariants because they don't hold orch caps).

**Hierarchical orchestration** (vs monolithic ChainOrchestrator)
recovers more seL4-style properties by delegating cap authority
through the orchestrator hierarchy. Most operations end up gated by
direct cap-holding (kernel-enforced); orch arbitration is reserved
for cross-cutting concerns.

**Direct line is not a security property.** seL4's direct kernel
access is an architectural choice; its verified properties (P2-P5)
hold equally for layered designs (server-in-path). v3's CO-in-path
is the same shape as seL4 + a server layer, just made structural.
The "single point of failure" of CO is the policy enforcement
point, by design — enabling rate limiting, audit, fairness, and
governance restrictions that blockchain chains need. Authority in
v3 is **conditional on intermediate policy**, not absolute via
cap-holding alone. This is a feature for blockchain, not a
security regression.

The path to seL4-equivalent verification is:

1. Formalize v3's operational semantics in Lean.
2. State each property above as a theorem.
3. Prove or refute against the model.
4. Specify orch policy correctness as an assumption; prove the
   composition.
5. (Eventually) implement and prove implementation refinement.

This document anchors the design discussion. Future "is X
secure?" questions can be checked against this property list.
Properties can be added/refined here; if a question can't be
answered by reference to this list, the list itself is incomplete.
