# Cap revocation — why CDT was rejected

> **Status.** The CDT-rejection reasoning in this doc is current and
> load-bearing. The concrete *mechanism* it originally proposed —
> per-cap `scope` tags validated on use, a `σ.gas_ledger`, and a
> `host_gas_consume` host call — has been **superseded**. v3 realizes
> the same "revocation = scope-end" outcome through the kernel-assisted
> Instance design instead: ephemeral kernel-internal meter tables plus
> YieldReceiver key-drop. For the live mechanism see
> [[kernel-assisted-instances]]. This doc is retained for the rationale,
> not the mechanism.

This doc captures a design move that came out of a long thread on whether
v3 needs Capability Derivation Trees (CDT). The short answer: **no — not
in the seL4 sense.** Once you commit to two postulates we already
implicitly hold (everything is addition-only at the protocol layer, and
the system is by-value), revocation collapses into something much
simpler: **revocation is just scope-end, and scope-end is a structural
consequence of context boundaries — no kernel-tracked derivation graph
is needed.**

## Background — what we were trying to solve

We had a set of use cases that *looked like* they needed CDT-style
atomic revocation:

- **Gas meters.** A Gas cap points at a kernel-maintained meter. Many
  copies exist during execution. At block (or invocation) end, the meter
  is "gone." All outstanding copies should be invalid.
- **UserEndpointCap.** ChainOrchestrator hands out caps to user-contract
  endpoints. If a user contract is removed (or retired), all caps to it
  should become invalid.
- **StorageQuota.** Same shape: a quota meter, possibly many cap copies,
  invalidation needed when the quota is decommissioned.

The natural CDT instinct: kernel maintains back-references from each
revocable entity to every slot holding a cap pointing at it. On revoke,
walk the back-references and zero each slot atomically.

This works in seL4 because seL4 caps are linear and live in known
cnode slots that the kernel tracks. **It does not work in our system.**

## Why CDT is structurally wrong here

Two properties of our system rule out the CDT-with-sidecar approach:

### 1. We are by-value

Caps are self-contained data. Their meaning is determined by the cap's
own content plus content-addressable σ lookups (image_hash →
code_blobs, file_id → data_blobs, etc.). There is *no* kernel-tracked
graph of "Instance A is the parent of Instance B" or "slots S1, S2 hold caps
to entity X."

This invariant matters because it's what makes cross-context
operation work. State can be serialized, transferred to another
kernel context (an L1↔L2 bridge, a re-execution, a light client),
and rehydrated. There are no dangling references because there are
no references — content travels in the cap, σ entries rehydrate by
content hash, and the system runs identically.

CDT with kernel-side back-references breaks this invariant. The moment
you add `prev_instance`, `children`, or `cap_back_refs` as kernel-tracked
fields, you've introduced a graph of mutual references that isn't
self-contained in any single value. Moving an Instance cross-context
would mean either dragging the entire reference graph (recursively
unbounded), or producing an Instance whose back-references no longer
point anywhere meaningful.

### 2. We are addition-only at the protocol layer

Blockchain state only grows. User contracts are not destroyed; once a
piece of state is in σ, it stays in σ (subject to garbage collection
under explicit gas/quota accounting, but never via "the owner
destroyed it" semantics that the rest of the system has to react to).

CDT's central operation is **destruction**. It exists to handle "I
deleted X; propagate the invalidation to everything derived from X."
In a system where you cannot delete X, there's no propagation to
manage. There is no "the user contract was destroyed" event in pure
addition-only — only "the user contract is no longer being called,"
which doesn't need kernel mechanism.

So we were trying to solve a problem the system doesn't actually
have, and importing seL4 intuitions that depend on properties
(linear caps + deletion) we don't share.

## The reframing — dangling arises at context boundaries

The use cases that *looked* like they needed revocation
(Gas, scope-bound resources) are actually about **context lifetimes**,
not about explicit destruction.

A clean way to see this: **every invocation is conceptually its own
kernel.** Call it Kernel_N. Kernel_N has:

- Its own Gas budget, materialized as a meter in the kernel-internal
  meter table.
- Its own ephemeral working state — Instances spawned mid-call, scratch
  CNodes, etc.
- Its own active invocation context: the call stack rooted at this
  invocation.

Kernel_N runs, terminates (HALT, Faulted, or Yield-up-into-caller).
The next invocation conceptually starts Kernel_{N+1}: fresh budget,
fresh ephemeral state, fresh call stack.

In this framing, **a Gas cap minted by Kernel_N is scoped to Kernel_N's
lifetime.** If someone preserved it past Kernel_N's end (e.g., stashed
it in a long-lived Instance's cnode), it's now in a context (Kernel_{N+1})
where its issuing kernel no longer exists. The cap is dangling.

Same for the C-moved-from-B-to-D case. Inside a single invocation
context, the call stack is `Kernel → A → B → C`. C's cnode might
contain caps that referenced B-local state (a sub-Instance B spawned,
a scratch CNode B passed in). If C is moved out of B's cnode and
ends up in `Kernel → D → C`, those B-local references are now in
D's context. They don't resolve. They dangle.

**Dangling is the natural consequence of context boundaries plus
ephemeral state.** It happens whether or not we have an explicit
destroy operation. The system doesn't need to destroy anything
explicitly — the boundary itself is the revocation event.

## How v3 realizes scope-end (the live mechanism)

The insight above — *revocation is scope-end, and scope-end is
structural* — is what v3 implements. It does **not** do so via per-cap
scope tags; it falls out of the kernel-assisted Instance design
([[kernel-assisted-instances]]):

- **Gas / StorageQuota.** A `Gas{meter_key}` / `Quota{quota_key}` cap
  names an entry in the kernel-internal `GasMeter` / `StorageQuota`
  table. Those tables are **ephemeral — the kernel is stateless across
  blocks**, so every meter restarts each block (only `root_meter_key`
  is seeded). A `Gas{meter_key}` cap that outlives its meter names a
  wiped/absent entry and is inert. The "all Gas caps die at the
  boundary" property is the table reset, not a tag check. Persistence,
  where wanted, lives in the chain's own σ (a custom GasLedger Instance),
  lazy-loaded per-tx via the OOG-catch pattern.

- **Authority caps (UserEndpointCap and friends).** Revocation is
  **key drop**: the chain removes the `yield_key` from its
  `YieldReceiver` (its `yield_receiver_slot` catch-list), so outstanding
  authority caps holding a `YieldSender` for that key match no receiver
  and fault on yield. No per-cap tracking, no cascade. (Takes effect for
  subtrees of CALLs made after the change, per the snapshot-at-CALL
  semantics.) See the generic authority pattern in the top-level spec §14.

- **Durable caps (`Cap::Image`, durable `Cap::Instance`).** Content-
  addressed, never revoked. The referenced σ entries are forever
  (addition-only). "Deprecation" is a userspace policy concern (the
  contract's own code refuses calls, or the orchestrator unhooks its
  dispatch entry), not a kernel event.

In every case the kernel needs **no derivation graph, no back-refs, and
no destroy cascade** — exactly the property the CDT analysis below
established was unnecessary.

## What's NOT needed (rejected paths)

| Path | Reason for rejection |
|---|---|
| `Cap::Anchored { authority_id, instance_id }` new cap kind | Solves a problem we don't have (revocation in addition-only is just scope-end). |
| `prev_instance` chain as Instance identity | Imports cross-Instance references that break by-value cross-context portability. |
| `children` index + `cap_back_refs` on Instance | Same — kernel-side reference graph that doesn't survive cross-context transfer. |
| Authority + Instance sub-objects on Instance | Heavier than needed; the kernel-internal meter tables + YieldReceiver key drop already handle every concrete case. |
| Per-cap badging (seL4-style) | Adds cap-copy identity we don't need; meter-table reset and YieldReceiver key-drop are sufficient. |
| Global CDT walker / destroy cascade | No destruction in addition-only; cascade has no event to react to. |

## Cross-context preservation

The by-value invariant is what makes bridging work, and the
revocation-by-scope-end model preserves it:

- **Durable caps** (`Cap::Image`, durable `Cap::Instance`) are
  content-addressable and resolve identically in any context that has
  the referenced σ entries installed. Bridging works.

- **Ephemeral caps** (Gas/Quota handles, invocation-local Instances)
  name kernel-internal state that does not cross the boundary. In a
  different kernel (an L1 importing an L2 Instance state) the named
  meter simply isn't there; the cap is inert. This is **correct
  behavior** — those caps were never meant to leave their context.

A bridge that imports L2 state into L1 ends up with durable caps still
valid (they remain content-addressable) and ephemeral caps naturally
inert (their kernel-internal backing isn't present). The L1
Instance[L2] can reproduce L2's InstanceHash from the imported durable
state, and any ephemeral Gas-style caps in that state just won't
resolve — which is what we'd want, since L1 isn't a continuation of
L2's invocation.

## Relationship to other v3 design docs

- Supersedes the (never-written) `principles/instance-cdt.md` and
  `principles/authorities-and-revocation.md` ideas. CDT and authority
  ledgers are not added.
- The concrete scope-tag mechanism this doc originally proposed is
  itself superseded by [[kernel-assisted-instances]] (ephemeral meter
  tables + YieldReceiver key-drop); only the CDT-rejection rationale here is
  current.
- Confirms and elaborates the kernel/invocation lifecycle described
  in [[kernel-chain-interface]]. Each cycle's setup/teardown is
  where invocation-scoped state lives and dies.
- Orthogonal to [[attestation-authority]]. AA records carry no scope
  beyond the kernel's processing of the apply call; the seen-rule and
  signing machinery are not affected by this doc.
- Confirms what `principles/sel4-mapping.md` already noted in its
  deeper-linearity analysis: many seL4 patterns don't translate to
  v3 because v3's by-value + addition-only properties replace them
  with structurally simpler mechanisms.

## Summary

The CDT excursion was solving the wrong problem. In a by-value,
addition-only system, "revocation" is really "scope-end," and scope-end
is structural — it's the boundary between one invocation and the next,
or one instance activation and the next. Caps that should live across
boundaries (content-addressable, durable) work unchanged; caps that
shouldn't (Gas, ephemeral resources) name kernel-internal state that
the boundary wipes, and fall away on their own. The kernel needs no
derivation graph, no back-refs, and no destroy cascade — and v3
delivers exactly that via the kernel-assisted Instance design
([[kernel-assisted-instances]]).

This keeps the by-value invariant, keeps cross-context bridging
working, and avoids importing a substantial chunk of seL4 machinery
that doesn't fit our world.
