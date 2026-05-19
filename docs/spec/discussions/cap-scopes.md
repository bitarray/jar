# Cap scopes — revocation without CDT

This doc captures a design move that came out of a long thread on whether
v3 needs Capability Derivation Trees (CDT). The short answer: **no — not
in the seL4 sense.** Once you commit to two postulates we already
implicitly hold (everything is addition-only at the protocol layer, and
the system is by-value), revocation collapses into something much
simpler: **caps carry a scope; scope is validated lazily on use;
context boundaries are the natural revocation event.**

This doc records why CDT was rejected, what replaces it, and the small
extensions needed to make scope-bound caps work cleanly.

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

- Its own Gas budget, materialized as a meter in σ tagged with
  Kernel_N's identity.
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

## Cap scopes — the design

The mechanism is small. Each cap that refers to scope-bound state
**carries a scope tag**. On use, the kernel validates the tag against
the current context. Mismatch → fault.

### Scope vocabulary

A handful of scope kinds covers what we need:

| Scope | Lifetime | Examples |
|---|---|---|
| **Chain** (∞) | Forever; durable across all invocations | `Cap::Image` (content-addressed), persistent vault Instances, account state |
| **Block** | One block apply | (rare; useful for block-scoped consensus state) |
| **Invocation** (Kernel_N) | One invocation, from CALL to HALT/Fault/return-of-control | Gas meter, invocation-local ephemeral Instances |
| **Instance** (Instance F's activation) | One Instance's running activation within an invocation | Working CNodes B passes to C, scratch slots, sub-Instances B spawned |

Chain-scoped caps have no scope tag — they're "always valid"
(content-addressable, durable). The other three scopes carry a tag
that identifies the originating context.

### Cap representation

A scope-bound cap looks like:

```
Cap::Foo {
    payload: ...,                  // the cap's actual content
    scope: Scope,                  // tag identifying scope context
}

enum Scope {
    Chain,                         // no tag — always valid
    Block(BlockId),
    Invocation(InvocationId),      // monotonic per invocation
    Instance(InstanceActivationId),      // monotonic per activation
}
```

`InvocationId` and `InstanceActivationId` are kernel-issued monotonic
identifiers, assigned at invocation/activation start. They are
**not** persistent identities of any object — they identify the
*scope*, not the *thing*. Once that invocation or activation ends,
the id is conceptually retired (never reused).

### Validation on use

Each operation that consumes a cap goes through scope validation
against the current context:

```
fn validate_scope(cap_scope: Scope, current_context: Context) -> Result {
    match cap_scope {
        Scope::Chain => Ok,                              // always valid
        Scope::Block(b) => if current_context.block == b { Ok } else { Err },
        Scope::Invocation(i) => if current_context.invocation == i { Ok } else { Err },
        Scope::Instance(f) => if current_context.instance_activation == f { Ok } else { Err },
    }
}
```

The kernel keeps the current `Context` (block, invocation, instance
activation) on the active call stack. Validation is O(1) — a
handful of integer comparisons. No back-refs, no graph walks.

A scope-mismatch fault is **soft**: the consuming operation fails
(returns an error to the caller instance), but the system continues.
This is the same as any other capability-resolution failure (cap
malformed, image hash unknown, etc.). The instance holding the bad
cap can choose to ignore the error, clean its slot, or propagate.

### Lazy slot cleanup

Slots holding stale caps don't need to be eagerly zeroed. They
contribute their 32-ish bytes to state-root, faulting on every
attempted use, until something writes a fresh value to the slot
(or the containing structure is itself dropped). For typical
workloads — Gas caps that live in transient instances that are
themselves discarded at invocation end — this is fine: the slot
goes away with its instance.

For the rare case of a stale cap stuck in a long-lived structure
(an old Gas cap that someone stashed into a vault slot), it stays
as garbage forever. State bloat is bounded by how many such
accidents the design permits, which is small in practice — Gas
caps don't *want* to be stashed cross-invocation; the discipline
is enforced by the fact that doing so produces a useless cap.

## Worked examples

### Gas

Setup at invocation start:

```
Kernel_N starts.
  Mint gas meter entry into σ.gas_ledger at slot M with:
    bytes_remaining: <budget>
    scope_invocation: N
  Mint Cap::Gas { meter: M, scope: Invocation(N) }, place in the
    callee's BareInstance at a known slot.
```

During execution:

```
Anyone holding the Gas cap can MGMT_COPY it to other slots in their
  cnode, or pass it as an argument to a sub-call. The cap content
  is the same everywhere; scope tag is Invocation(N).

To consume gas:
  host_gas_consume(cap_slot, amount)
  Kernel:
    cap = read slot
    validate_scope(cap.scope, current)   // Invocation(N) == N ? yes
    meter = σ.gas_ledger[cap.meter]
    meter.bytes_remaining -= amount      // (or fault on underflow)
```

At invocation end:

```
Kernel_N terminates.
  σ.gas_ledger[M] may stay in σ (lazy cleanup) or be reclaimed
    explicitly by the validator's apply logic. Either way:
  Any leftover Cap::Gas { scope: Invocation(N) } in any slot is now
    naturally invalid — current invocation is N+1, validation fails.

Kernel_{N+1} starts.
  Fresh meter M' minted, scope Invocation(N+1). New caps.
```

The "all Gas caps die at invocation end" property falls out of scope
validation. No cascading destroy. No back-refs. No bookkeeping.

### C moved B → D

Inside one invocation (Kernel_N):

```
A → B → C is the call stack.
B's cnode contains sub-Instance X, scope-tagged Instance(B_activation).
B passes Cap::Instance { X, scope: Instance(B_activation) } as an arg to
  C (placed in C's incoming scratchpad slot).

C returns; B continues; eventually the chain returns to Kernel_N.
```

Later, in a separate invocation (Kernel_{N+5}):

```
D → C is the new call stack. C still has the cap to X in some slot.
D calls into C; C tries to use the cap.
  Kernel reads cap: scope = Instance(B_activation)
  Current instance activation: some new id, ≠ B_activation
  validate_scope → fail. Operation faults.
```

C's "stale" reference to X is detected on use. C can handle the
failure (return error, clean the slot, fall back). No cascading
cleanup needed; the bad slot just doesn't resolve until C is asked
to use it.

If C had instead been passed a chain-scoped cap (`Cap::Image` for some
content-addressed image, say), validation would pass regardless of
which invocation C is currently running in. Chain-scoped caps are
the durable carry-across vehicle; everything else is context-bound.

### UserEndpointCap (and the absence of revocation)

In addition-only:

```
ChainOrchestrator creates a user contract for endpoint X.
  user_contract X lives in σ forever.
  Cap::Instance { X.instance_ref, scope: Chain } can be distributed widely.

Some time later, X becomes "deprecated" — no one wants to use it.
  X is still in σ. Caps to it still resolve successfully.
  But: X's own code might check a flag and refuse calls, or its
    CO-side dispatch entry might be unhooked. The caps remain
    structurally valid; their utility is zero by convention.
```

No kernel revocation needed because no kernel destruction happens.
Deprecation is a userspace concern (CO's policy, X's code), not a
kernel one. Caps "going stale" in this sense is purely about who
will honor them, which is downstream of the cap system entirely.

### StorageQuota

Same pattern as Gas. A quota meter in σ.storage_quotas with a scope
tag (Invocation for per-call quotas, Chain for durable per-actor
quotas). Caps carry the scope. Validation on use. Scope-end is the
natural cleanup event.

## Why this is sufficient

CDT was attractive because it gave us *atomic* revocation: at the
moment of destroy, every outstanding reference is dead. We were
asking what we'd lose by giving that up.

The answer turns out to be: nothing important, because:

1. **The use cases that needed atomic revocation were all
   scope-bound.** Gas, ephemeral Instances, scratch caps — they're
   meant to live for one invocation or activation. Scope validation
   gives atomic revocation at the boundary, for free.

2. **The use cases that aren't scope-bound (durable caps) don't
   need revocation in addition-only.** Caps to user contracts, Cap::Image
   to durable code blobs, account-state references — these are
   forever, and the user contracts they reference are also forever.
   Deprecation is a policy concern, not a kernel one.

3. **The dangling state in practice is tiny.** Real workloads don't
   stash Gas caps cross-invocation (no useful purpose). The accidents
   that produce truly dangling slots are rare; the slot bytes are a
   negligible state-root contribution; lazy cleanup absorbs them.

So we get atomic revocation where we need it (scope end), and the
absence of revocation where we don't need it (durable state). The
small price is the scope tag on each scope-bound cap — a handful of
bytes per cap, an O(1) check per use.

## Cross-context preservation

Scope tags interact with bridging exactly the way we want:

- **Chain-scoped caps** (Cap::Image, durable Cap::Instance) carry no
  tag, are content-addressable, and resolve identically in any
  context that has the referenced σ entries installed. Bridging
  works.

- **Block/Invocation/Instance-scoped caps** carry a tag specific to the
  originating kernel's context. In a different kernel (an L1
  importing an L2 Instance state), the tag doesn't match; the cap
  faults on use. This is **correct behavior** — those caps were
  never meant to leave their context.

A bridge that imports L2 state into L1 will end up with chain-scoped
caps still valid (they were durable; they remain durable) and
scope-bound caps naturally invalid (they were context-local; the
context isn't there). The L1 Instance[L2] can reproduce L2's
InstanceHash from the imported state (chain-scoped content), and any
ephemeral Gas-style caps in that state just won't resolve — which
is what we'd want from the start, since L1 isn't a continuation of
L2's invocation.

## What's new in the spec

This design needs:

1. **`Scope` enum on every scope-bound cap kind.** Cap::Gas,
   Cap::StorageQuota, and any future scope-bound caps carry a
   `scope: Scope` field. Cap::Image stays untagged (implicitly
   Chain).

2. **Invocation and instance-activation ids in the kernel's call context.**
   Monotonic counters, assigned at invocation start and at each Instance
   activation. Accessible via the kernel's current-context state.

3. **`validate_scope` in cap-resolution paths.** Every host call or
   cap-consuming op runs the check before acting. Failure is a soft
   fault (operation returns error; instance continues).

4. **No new cap kind, no Instance field, no σ-side back-ref structure.**
   This is the entire delta. `prev_instance`, `children`, `cap_back_refs`,
   `Cap::Anchored` — all not needed and not added.

## What's NOT needed (rejected paths)

| Path | Reason for rejection |
|---|---|
| `Cap::Anchored { authority_id, instance_id }` new cap kind | Solves problem we don't have (revocation in addition-only is just scope-end). |
| `prev_instance` chain as Instance identity | Imports cross-Instance references that break by-value cross-context portability. |
| `children` index + `cap_back_refs` on Instance | Same — kernel-side reference graph that doesn't survive cross-context transfer. |
| Authority + Instance sub-objects on Instance | Heavier than needed; the σ ledger pattern already handles every concrete case. |
| Per-cap badging (seL4-style) | Adds cap-copy identity we don't need; scope tag is sufficient. |
| Global CDT walker / destroy cascade | No destruction in addition-only; cascade has no event to react to. |

## Open questions

A few details that the implementation should pin down:

1. **What exactly is "an invocation"?** The cleanest cut is "one call from
   the outermost kernel entry point to its return" — i.e., one transact
   dispatch, or one apply_block phase. This matches the Gas budget
   shape. But block-level Gas (block-wide budget shared across many
   tx invocations) would suggest Block scope as the natural cut.
   Probably we want both: invocation-scoped Gas for per-tx accounting,
   block-scoped for chain-level budgets. The vocabulary supports it;
   the question is which apply where.

2. **Instance-activation scope: needed in practice?** Instance scope is the
   finest granularity (one activation of one Instance's call). Most
   ephemeral caps probably want Invocation scope (one full invocation),
   not the activation-level fineness. Instance scope might be unused in
   practice. Worth seeing if the use cases (B passes scratch CNode to
   C, etc.) really need it or if Invocation suffices.

3. **Soft fault semantics.** When scope mismatch happens, what exactly
   does the consuming op return? Probably the same shape as any
   capability-resolution failure (a kernel-defined error variant).
   Worth specifying so userspace can pattern-match on it cleanly.

4. **State-root encoding of scope tags.** Caps with embedded `Scope`
   need a canonical encoding. Easiest: discriminant byte + payload
   (BlockId / InvocationId / InstanceActivationId as u64). Straightforward
   extension to existing cap encoding.

5. **Gas ledger lazy cleanup.** Old gas meter entries in σ.gas_ledger
   contribute to state size. Validator can opt to reclaim them
   explicitly at block end (since they're never useful after their
   invocation ends), or leave them as lazy garbage. Probably we
   want explicit cleanup at block apply end for tidiness — but it's
   a state-management decision, not a correctness one. Reclamation
   is safe: the only caps referencing the entry have a stale scope
   tag and will fault regardless.

## Relationship to other v3 design docs

- Supersedes the (never-written) `discussions/instance-cdt.md` and
  `discussions/authorities-and-revocation.md` ideas. CDT and authority
  ledgers are not added; scope tags replace both.
- Confirms and elaborates the kernel/invocation lifecycle described
  in [[kernel-chain-interface]]. Each cycle's setup/teardown is
  where invocation-scope state lives and dies.
- Orthogonal to [[attestation-authority]]. AA records carry no scope
  beyond the kernel's processing of the apply call; the seen-rule and
  signing machinery are not affected by this doc.
- Confirms what `discussions/sel4-mapping.md` already noted in its
  deeper-linearity analysis: many seL4 patterns don't translate to
  v3 because v3's by-value + addition-only properties replace them
  with structural simpler mechanisms.

## Summary

The CDT excursion was solving the wrong problem. In a by-value,
addition-only system, "revocation" is really "scope-end," and scope-end
is structural — it's the boundary between one invocation and the next,
or one instance activation and the next. Caps that should live across
boundaries (chain-scoped, content-addressable) work unchanged; caps
that shouldn't (Gas, ephemeral resources) carry a scope tag and fail
gracefully when used out-of-scope. The kernel needs nothing more
than O(1) scope validation on cap use, and the userspace pattern
of "if a cap might be stale, just try it and handle the error" is
adequate.

This keeps the by-value invariant, keeps cross-context bridging
working, and avoids importing a substantial chunk of seL4 machinery
that doesn't fit our world.
