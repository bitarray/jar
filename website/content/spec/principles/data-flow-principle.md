# Data flow as the core — and the shared-state trap

This doc captures the architectural insight underlying v3 and the
detours we've considered (and rejected). It exists so we don't have
to re-derive the same argument every time the question comes back.

The central claim, stated as a structural invariant:

> **At any moment, each piece of mutable state has at most one
> in-flight mutator.** This is v3's foundational invariant. v3's
> control-flow primitives (CALL, YIELD, HALT) and state-disciplines
> (Instance isolation, hierarchical call stack, by-value content-
> addressing) are chosen because together they make this invariant
> structural — enforced by the kernel without needing programmer
> discipline.

Everything else — fault isolation, sub-fault recovery, the absence
of rollback infrastructure, the absence of reentrancy bug classes —
follows from this. When the model feels tortured, it's a sign we're
trying to violate the invariant.

## Principle vs mechanism

A common source of confusion in our design discussions has been
conflating the **principle** (the structural invariant we want) with
the **mechanisms** (specific choices that implement it). Let's
separate them explicitly.

**The principle:**

> Single-mutator-per-state-unit at any moment.

This is mechanism-agnostic. It can be enforced in multiple ways.

**v3's mechanisms (all of which together enforce the principle):**

1. **Hierarchical call stack.** The kernel maintains a strict stack
   of in-flight invocations. Exactly one entry is Running at a
   time; all others are Waiting. The stack discipline enforces
   single-activation and provides fault-boundary structure.

2. **By-value content-addressing for caps.** Cap::Instance, Cap::Image,
   Cap::Data, Cap::CNode are content-addressed. MGMT_COPY produces
   sibling values; mutations diverge per §9 case (b). Two cap
   copies don't share mutable state — they share initial content,
   then evolve independently.

3. **Instance isolation via cnode ownership.** Each Instance owns its
   cnode; no other Instance can directly read or write it. Mutations
   happen only via the Instance's own bytecode.

4. **Slot-only-updates-at-termination.** An Instance's mutations to its
   cnode are working state until HALT (commits) or fault
   (discards). Sub-Instances in the cnode are part of the working
   state; their mutations during this invocation are subject to the
   parent's atomicity.

These four mechanisms work together. Each contributes to the
principle in a different way:

- Hierarchy provides the invocation boundary (fault/linearity).
- By-value provides the cross-context portability and snapshot
  universality.
- Instance isolation provides the structural ownership.
- Slot-only-updates provides the atomic commit/discard.

**It's important not to confuse any single mechanism for the
principle.** "By-value caps" is not the principle — it's one
mechanism. "Hierarchical call stack" is not the principle — it's
another mechanism. The principle is single-mutator-per-state-unit;
the mechanisms are how v3 chooses to enforce it.

## The principle, stated precisely

Single-mutator-per-state-unit, in v3 terms, means:

1. **Each Instance is a closed unit of state.** Its cnode is its own;
   no other Instance can directly read or write it. Mutations happen
   only via the Instance's own bytecode running its own image's code.

2. **CALL transfers a value (slot[0]); HALT/yield reflects a value
   back.** Caller hands an input down; callee returns an output up.
   No state is shared in either direction beyond what's explicitly
   passed.

3. **CALL transfers ownership of the callee while it runs.** The callee
   Instance is moved from an owner CNode slot into a KernelFrame. The
   origin slot is physically empty and kernel-reserved until the callee
   HALTs, is resumed to completion, or is discarded. The owner therefore
   cannot re-CALL, copy, move, drop, read, or overwrite that Instance
   while it is in flight.

4. **YIELD flows upward only; CALL flows downward only.** A child's
   YIELD sends data up to a prior instance on the stack. A CALL pushes
   a new instance on top. There is no primitive for a child to
   initiate downward work in the parent (which would create
   multi-activation).

5. **In-flight invocations don't share working state.** When A
   CALLs B, B's working mutations are in B's cnode (or in B's
   working slot[0]); A's working state is paused but untouched.
   Their states are isolated.

6. **Termination commits or discards atomically.** An Instance's HALT
   commits its working state to its persistent cnode atomically. A
   Instance's fault discards its working state entirely. There is no
   partial commit, no nested in-progress state across Instances.

These properties, taken together, are how the
single-mutator-per-state-unit invariant manifests in v3's design.

## The two pillars of complexity

The architectural cost of *not* adopting this principle is determined
by two structural properties that, when combined, force transactional
infrastructure:

### Pillar 1: Shared mutable state

State that can be mutated by more than one in-flight context. The
two contexts can be:

- Multiple in-flight activations of the same Instance (multi-activation),
- Multiple paths into the same shared store (global storage),
- Multiple threads on shared memory (true concurrency).

In each case, mutations by one context are visible (or potentially
visible) to others.

### Pillar 2: Per-context fault

Faults can happen at any nesting depth, and each context's fault is
independently observable. Specifically: a sub-CALL's fault doesn't
necessarily fail the caller — the caller can catch it and recover.

This is what enables `try { sub_call() } catch { recover() }`
patterns. It's essential for nontrivial composition (try path A; if
fails, try path B).

### Together: the trap

When **both** pillars are present, the system must implement:

- **Rollback infrastructure** to selectively undo a faulted context's
  mutations to shared state without disturbing other contexts' work.
- **Visibility rules** to specify which mutations are observable to
  which contexts at which times (commit chains, isolation levels).
- **Fault propagation policy** to define what state survives each
  fault scenario.
- **Reentrancy reasoning** for programmers, since shared state plus
  reentry breaks local-narrative reasoning about their code.

Together this is the entire transactional-memory model. Databases
need it. Multi-server OS architectures need it. Ethereum-style
smart contract VMs need it (per-CALL journal of mutations to global
storage).

It's not impossible to build. It's just expensive — both in kernel
machinery and in programmer mental load. And every system that has it
struggles with its consequences (reentrancy bugs, isolation level
ambiguities, complex fault recovery semantics).

### Either pillar alone is harmless

Disable **shared mutable state**:

- Single-mutator-per-state-unit invariant holds.
- Multiple contexts may exist, but they each operate on their own
  state.
- Faults discard the single context's working state; no other
  context affected.
- No rollback infrastructure needed.

Disable **per-context fault** (whole-tx atomicity):

- Faults always propagate to the outermost transaction.
- Shared mutable state exists but is rolled back wholesale on any
  fault.
- Single transaction-scope working state (one overlay, not nested).
- No per-context rollback; rollback is one bulk operation at tx end.

In either case, the heavy transactional infrastructure is unneeded.
Only the conjunction creates the trap.

## v3's choice: disable shared mutable state

v3 chose to **disable shared mutable state** by adopting Instance isolation:

- Each Instance owns its cnode exclusively.
- Sub-Instances have their own cnodes.
- No state is shared across Instance boundaries during in-flight
  invocations.
- Single activation per Instance at a time.

This gives v3:

- **Sub-fault recovery for free, via structural isolation.** When B
  faults, B's working state is discarded; A's state is untouched
  (A and B don't share state). A's CALL to B returns Faulted; A
  recovers or propagates.
- **No rollback infrastructure.** Fault is simply "discard working
  state of the faulted Instance." No transactional journaling, no
  per-activation diffs, no commit chains.
- **No reentrancy bugs.** Instances can't be reentered while in flight;
  the structural single-activation invariant prevents the entire
  class of "B called me back while I was paused" issues that
  Ethereum-style systems have to mitigate via discipline.
- **Snapshot universality.** Cap::Instance is content-addressed; copy
  is structurally simple; no transactional state to consistently
  capture mid-flight.

The cost v3 pays for this:

- **No intra-Instance reentry.** A single Instance can't have multiple
  activations sharing its cnode. Patterns that would need this
  (a handler that mutates state while main is paused) must be
  rewritten.
- **Upward calls require a structural mechanism.** A child can't
  directly invoke an ancestor (that would create multi-activation
  on the ancestor's state). Instead, the child yields a request up;
  the ancestor handles in its own bytecode flow.

## Hierarchy is the invocation boundary

A central architectural fact about v3 that's worth stating directly:

> **The hierarchical call stack is the invocation boundary that
> simultaneously provides sub-tree atomicity (fault propagation) and
> yield-resume linearity (single-resumer guarantee). These two
> properties are dual aspects of the same structural discipline.
> Reentry protection is a free side effect.**

This is a stronger statement than "hierarchy enforces reentry
protection." Hierarchy is doing three things, and the first two are
the structural reasons we need it.

### Fault atomicity (sub-tree atomicity)

An Instance's HALT commits its working state — including any mutations
made by sub-Instances it called during this invocation. An Instance's
fault discards all of that. The fault propagates up the stack;
each level can catch it (continue with Faulted status) or
propagate.

The cascade is structural: if A faults at any point, A's whole
subtree (B, C, etc.) is unwound. There is no "preserve B and C as
free-floating Paused" alternative — that would break the
single-resumer guarantee for yield-resume (see next subsection).

The cascade only works because hierarchy gives us a clear notion
of "what's in A's subtree": everything pushed onto the stack after
A by A's invocation.

### Yield-resume linearity

When B is in Waiting state (paused, awaiting a response), the
single entity that can resume B is structurally determined by the
owner-edge route that caught B's yield. The kernel represents that
handler as a ReferenceEntry on the physical stack. When that handler
HALTs (or CALL_RESUMEs, or DROP_RESUMEs), B's continuation is resolved
by the same routed suspension.

There's no ambiguity. The kernel doesn't need to consult a registry
or check a cap or look up a target — the stack position tells it
exactly who resumes whom. **The linearity is structural; not a
property we maintain via discipline.**

This is what makes Authority caps (and the YIELD-via-YieldSender
pattern) secure. K registers a yield_key in its YieldReceiver and
hands out a `YieldSender{yield_key}`; the cap-holder's emit is routed
by key along owner edges to K (the nearest owner-edge snapshot
containing the key). Only K can produce the response. Because the
yield routes to whichever owner edge's snapshotted YieldReceiver
catches the key — K's, here — only K's response can resume B. No
party can fake a response from elsewhere.

### Why these two are inseparable

You might wonder: could we have fault atomicity without
yield-linearity, or vice versa?

**No.** They're dual aspects of the same structural property
"stack position uniquely determines the relationship between
entries."

Suppose we tried to keep yield-linearity but allow fault to NOT
cascade — preserve B and C as Paused-persistent when A faults.
Then "who can resume B?" is no longer "the stack entry above B"
(A is gone); it becomes "whoever holds a cap to Paused-B." We've
broken yield-linearity. Authority caps become insecure.

Suppose we tried to keep fault cascade but allow non-hierarchical
yield routing — B could yield to any instance, not just an owner
ancestor. Then "what's in A's subtree?" becomes unclear; we'd need
explicit ownership declarations beyond the call/owner structure. We'd
be back to manually-maintained hierarchy.

The stack structure provides both properties at once because physical
stack entries carry the logical owner edge: **CALL creates ownership by
moving a real cnode-owned Instance into a KernelFrame; ReferenceEntry
reactivates an owner; owner relation determines the resumer relation.**
The callee's origin slot remains empty-reserved while the frame is live,
so the owner cannot accidentally create a second activation by re-CALLing
or copying the same slot.

### Reentry protection: free side effect

The single-activation invariant ("at most one Instance is Running
at any moment, and an Instance can have at most one in-flight
invocation") follows from the stack: only the top entry is Running;
the same Instance can appear multiple times in the stack as references
to its single in-flight invocation. There's never two concurrent
activations.

This is reentry protection. We get it for free as a side effect of
the stack discipline.

If we wanted reentry protection alone, we could enforce it via a
per-Instance mutex without any stack discipline. But that wouldn't
give us fault atomicity or yield-linearity — those would need
separate mechanisms.

**So hierarchy is the parsimonious choice: one mechanism, three
properties.** Drop hierarchy and you'd need to design ownership,
fault propagation, and continuation routing as separate concerns.

### Why the orchestrator pattern is structurally required

A consequential implication of hierarchy + single-activation: **two
user contracts cannot directly call each other in v3 if they need
independent fault isolation.** They must communicate through a
common parent — the chain orchestrator. This is structural, not a
design preference.

Why? Trace the alternative.

Suppose A and B hold caps to each other directly (in a hypothetical
"flat" model). A calls B. Stack: `[..., A, B]`. B wants to call A.
Single-activation says A can have only one in-flight invocation;
A is already in-flight. So B's "call back to A" must be a YIELD —
which pushes a reference to A on top of B. Stack: `[..., A, B, ref(A)]`.
A's bytecode at its post-CALL point runs as the handler.

But yield(A) and A_original are the same instance. They share fate.
If yield(A) faults (e.g., during the callback handler logic), A's
**whole invocation** faults — sub-tree atomicity discards
everything A was doing, including B (which is in A's subtree).

So **B cannot have a fault scope independent of A** in this
arrangement. Whatever A's handler does — including reactions to
B's callback — happens inside A's atomic scope. A bug in A's
handler kills B's work too.

This is unacceptable for inter-contract communication. Two user
contracts deserve isolation: A's bugs shouldn't atomically destroy
B's work, and vice versa.

The resolution: A and B don't directly call each other. They both
sit as siblings under a Chain orchestrator. Cross-contract requests
flow through Chain. Chain's bytecode catches sub-faults explicitly:

```
Chain bytecode handling B's request to call A:
  status = CALL(A_handler, args)
  match status:
    HALT(result) => continue handling B with result
    Faulted     => either propagate or recover; B sees the
                    failure as the result of its request
```

A_handler is invoked freshly from Chain (a separate invocation of
A from Chain's perspective, sequentially after A's original work
HALTed). If A_handler faults, Chain catches; B's invocation isn't
disturbed.

So: **A and B's isolation requires both to be sub-invocations of
Chain.** Chain's bytecode is the explicit fault-catching boundary
that gives A and B independent fault scopes.

### Comparison with Ethereum's model

Ethereum permits direct A→B→A calling chains with per-frame fault
isolation because Ethereum maintains **per-CALL working state on
shared storage**. Each CALL pushes a frame with its own journal of
storage mutations. REVERT rolls back that frame's journal; the
caller continues with the failure result.

This is the per-CALL rollback infrastructure that v3 rejects.
Ethereum pays:
- Per-CALL journaling overhead.
- Reentrancy bug class (DAO-style attacks) requiring discipline
  (ReentrancyGuard, Checks-Effects-Interactions, etc.).
- Complex isolation-level semantics for nested transactions.

v3 doesn't pay these costs. The price v3 pays instead is the
orchestrator-mediated communication pattern: contracts can't
directly call each other for fault-isolated sub-invocations; they
go through Chain.

This isn't a workaround — it's the natural shape of v3's design.
The orchestrator pattern is what v3 *is*, given the principle of
single-mutator + per-context fault isolation without transactional
infrastructure.

### The deep architectural derivation

We can now read v3's design as a chain of necessary consequences
from one principle:

```
Principle: single-mutator-per-state-unit + per-context fault
           isolation (sub-fault recovery available to caller).

  ⇒ No shared mutable state across in-flight invocations.
  
  ⇒ Single-activation per Instance.
  
  ⇒ Hierarchical call stack as the invocation boundary
    (fault atomicity + yield-linearity + reentry protection).
  
  ⇒ Direct A↔B between user contracts cannot provide
    per-contract fault isolation (because yield-as-callback
    shares fate with the original invocation).
  
  ⇒ Inter-contract communication must go through a common
    parent (orchestrator) that catches faults explicitly.
  
  ⇒ Chain orchestrator is structurally required for any
    chain with cross-contract calling.
```

Every step is forced by the previous one given the principle. There
is no architectural slack here: changing any one step would either
violate the principle or require additional mechanism (rollback
infrastructure, multi-activation, etc.) that we've already rejected.

This is why v3's orchestrator pattern feels "obvious" once you
internalize it — and why competing models (direct cap-flow between
user contracts, peer-to-peer contract communication, etc.) feel
attractive but break either the principle or the architecture
elsewhere.

## The yield/resume direction insight

A consequence of the invocation-boundary view: yield/resume is
unavoidable but only in one direction.

**Upward yield (data flowing up the call stack from child to caller)**
is the safe direction. The child's instance is paused; the caller
resumes and processes the data. No new activation is created in
the caller; the caller's existing activation just continues from
where it was paused (its CALL to the child). Single-activation
invariant preserved.

**Downward call (child invoking a method on the caller, while caller
is paused)** is the dangerous direction. It would create a new
activation in the caller while caller's existing activation is
paused. Two activations on the caller's state → shared mutable
state within the Instance → invariant violated.

So:

- A child's "I want something from upstream" must be expressed as
  yield (upward data flow), not as call (downward into upstream).
- The upstream Instance handles by reading the yielded data at its
  own paused-CALL point, doing what's needed, and resuming the
  child.
- The upstream Instance does NOT get re-entered as a new activation.

This is the structural constraint that prevents v3 from sliding
into multi-activation. The "Chain handle" pattern that looks like
a downward call must be implemented as an upward yield (or by the
kernel routing the yield by key to the registered YieldReceiver,
without touching Chain's bytecode flow at all). Either way, no
multi-activation.

## The stack model in detail

v3's kernel maintains a call stack. Each entry is either:

- **InstanceEntry(instance, pc, slot_state, status)** — pushed by CALL.
  Introduces a fresh invocation of an Instance.

- **ReferenceEntry(target_position, status)** — pushed by YIELD.
  Refers to an InstanceEntry at an earlier stack position. Same
  instance, same PC as the target; PC advances together when
  active.

Invariants:

- **Exactly one entry is Running at any time** — the top of the
  stack. All others are Waiting.
- **Same-instance entries share PC.** If A appears multiple times
  on the stack (once as InstanceEntry, once as ReferenceEntry from a
  yield to A), they all reflect A's single PC.
- **Instance state machine** (visible at the σ layer):
  Idle ↔ Paused (multi-block persistent pause via DROP_RESUME).
  All other states (Running, Waiting) are kernel-internal stack
  accounting; not σ-visible.

ABI primitives:

- **CALL(cap, args)** — move target out of the caller/owner CNode slot
  into a KernelFrame, reserve the empty origin slot, push InstanceEntry
  for target; caller's current Running entry becomes Waiting.
- **YIELD(yield_sender, args)** — read the `yield_key` from the
  `YieldSender{yield_key}`; route along owner edges to the nearest
  edge whose snapshotted YieldReceiver contains the key
  (single-resumer); push a ReferenceEntry to that owner frame and its
  bytecode resumes.
- **CALL_RESUME(args)** — pop current Running entry (handler);
  underlying Waiting entry becomes Running with args in slot[0].
- **HALT(payload)** — pop current Running entry; if it is an
  InstanceEntry, fold its working state back into an Instance, clear the
  origin reservation, and restore it to the owner slot. Underlying entry
  becomes Running with payload in slot[0].
- **DROP_RESUME** — bridge from in-flight Waiting to σ-resident
  Paused. Materializes the topmost Waiting sub-Instance's continuation
  as Paused-persistent; returns a cap to it; current instance continues.
- **fault** — like HALT but with Faulted status; cascading discard.

V1 implementation note: before σ-resident Paused materialization lands,
DROP_RESUME and handler-unwind discard the affected frames. They clear
origin reservations owned by surviving frames and leave those origin
slots empty; no `Pending` marker is written into the CNode.

Snapshot semantics:

- **An Instance is snapshottable iff it has zero stack entries.** Idle
  Instances are snapshottable. Instances with active in-flight invocations
  (any InstanceEntry or ReferenceEntry on the stack) are not. Paused-
  persistent Instances are snapshottable (their continuation is
  σ-resident, not on the stack).

## Detours we've rejected (and why)

Over the course of v3's design we've considered several alternatives.
Each was a coherent architectural choice; each was ultimately rejected
because it violated the principle.

### Detour 1: Multi-activation with per-activation rollback

The idea: allow Instances to have multiple in-flight activations sharing
their cnode. Each activation has its own working diff over the cnode.
HALT merges diffs upward; fault discards diffs.

Rejected because: this is full transactional infrastructure inside
the kernel. Per-activation diff overlays, merge-on-commit, discard-
on-fault, visibility tracking. Heavy. And reintroduces the
reentrancy bug class.

The path leads to Ethereum-shape semantics — workable but expensive.
v3 already has sub-fault recovery via Instance isolation; we don't need
the rollback infrastructure to get it.

### Detour 2: Multi-activation with whole-tx atomicity

The idea: allow multi-activation reentry but eliminate per-context
fault. Any fault propagates to the transaction root; the whole tx
reverts. One transaction-scope working state.

Rejected because: blockchains need sub-fault recovery for real
patterns (try-catch, multi-path retries, conditional execution).
Whole-tx-only-atomicity is too restrictive. The patterns that would
use sub-fault recovery would have to be expressed across multiple
transactions or via pre-validation.

Plus: still has reentry complications (programmer must reason about
handler interjections during their own code).

### Detour 3: Immutable cnode (purely functional)

The idea: replace mutable cnode with immutable versioned state.
Each "mutation" produces a new version. Multiple versions coexist;
faults discard the in-progress version.

Rejected because: for single-activation, this is operationally
equivalent to mutable cnode (just different implementation). For
multi-activation, it imports MVCC-style conflict resolution
(database-flavored). Doesn't simplify; just relocates complexity.

### Detour 4: seL4-style fault handlers in same Instance

The idea: a designated fault-handler endpoint runs when the Instance
faults, gets access to fault context, can recover or finalize.

Rejected because: the meaningful capability (recovery) requires
per-context partial commits, which requires rollback infrastructure.
The non-recovery variants (logging, cleanup) have nowhere useful to
put their effects in a transactional system — they get discarded
with the rest. No clean middle ground.

### Detour 5: CDT-style revocation

The idea: import seL4's capability derivation tree for authority
revocation.

Rejected because: CDT requires kernel-side back-references between
caps and the contexts that hold them. This creates a graph of
cross-references that doesn't survive cross-context portability
(bridging, L2 import, etc.). Breaks the by-value invariant that
makes v3 work cross-context.

Replaced by structural mechanisms: image_hash chain for forgery
resistance, YieldReceiver key-drop + ephemeral kernel meter tables for
ephemeral authority/revocation, kernel-maintained ledgers for revocable
budgets (Gas, etc.).

### Detour 6: Per-cap-copy CDT identity

The idea: each cap copy has its own identity; copies can be
revoked independently.

Rejected because: cap copies in v3 are content-addressed; making
them per-copy distinguishable would require kernel-side
identification of each copy, breaking the by-value model.

Replaced by: caps are membership credentials; revocation is at the
budget (ledger entry) level, not at the cap level.

### Detour 7: Instance identity (instance_id)

The idea: assign each Instance a stable unique identifier for use in
revocation, references, etc.

Rejected because: a stable instance_id implies multiple cap copies
share that id; using one cap implies using all copies' equivalent
authority (or requires linearity). Either re-introduces shared
mutable state through the id-lookup channel, or requires linearity
we already rejected.

Replaced by: caps are by-value with image_hash_chain for type
identity; no per-Instance identity at the cap level.

### Common pattern in the rejections

Each detour tried to add expressiveness that the data-flow model
doesn't natively support — reentry, fine-grained revocation, fault
handler recovery, etc. — and each required either:

- Reintroducing shared mutable state somewhere (multi-activation,
  CDT back-refs), or
- Adding transactional infrastructure (rollback, per-context diffs),
  or
- Breaking by-value content-addressing (instance_id, per-cap identity).

In each case, the cost wasn't worth the expressiveness gain. The
patterns chain authors actually need can be expressed via:

- **Cap-flow** (pre-supply caps for everything callee might need).
- **Yield-cascade** (current v3 upward request pattern).
- **Key-routed yield** (authority caps hold a `YieldSender{yield_key}`;
  the kernel routes the yield by key to the registered YieldReceiver
  without involving caller's bytecode).
- **Emit/handle** (asynchronous; callee emits, caller processes
  after callee HALTs).
- **Saga / compensating actions** (explicit cleanup logic by chain
  author, not kernel-mediated rollback).

## The checkable invariant

When designing or reviewing a v3 mechanism, the rule of thumb is:

> **Does this introduce shared mutable state across in-flight
> invocations?**

If yes: the design is on the wrong side of the trap. Look for an
alternative.

Specific things to watch for:

- **Multi-activation of an Instance.** Two activations sharing a cnode
  is shared mutable state in flight.
- **By-reference caps with mutable targets.** Two caps pointing at
  the same mutable thing creates sharing.
- **Cross-Instance state graphs maintained by the kernel.** Back-refs,
  CDTs, sidecar tables tied to specific Instances — these are kernel-
  tracked shared state.
- **Yield/resume in the downward direction.** A child invoking the
  caller is shared activation on caller's state.

Things that are safe (and how v3 makes them safe):

- **Cap::Image / Cap::Data / Cap::CNode copies.** These are content-
  addressed values; "sharing" is at the value level (multiple slots
  hold the same hash) but there's no shared mutator because the
  content itself doesn't mutate — mutating "produces a new value."

- **Cap::Instance copies of the same Instance value.** Same content-
  addressing semantics. Two slots holding "the same Cap::Instance" both
  reference the same hash. But the moment one is invoked and mutates,
  the result is a new hash; the other slot still holds the old hash;
  mutations diverge per §9 case (b).

  So Cap::Instance copies don't share mutable state in the in-flight
  sense — they each address a value that evolves independently.

- **YieldSenders as keyed emit rights.** A `YieldSender{yield_key}`
  carries no mutable target — it names a key the kernel routes by.
  The owner frame it resolves to (the nearest owner-edge snapshot
  containing the key) has only one resumer at any time by stack
  discipline. The key is the routing mechanism; the resumption
  authority is structural.

- **References on the call stack between InstanceEntry and ReferenceEntry
  of the same Instance.** Same PC, same cnode, but they don't run
  concurrently — exactly one entry is Running. The "sharing" is
  notational across stack positions; it's not multi-mutator.

The deep reason this works: **v3 separates "sharing of identity"
from "sharing of mutator capacity."** Multiple things can address
the same value or the same stack entry. But at any moment, only one
mutator is active. The invariant holds.

## Why this is a genuine architectural advantage

Compared to Ethereum-style transactional state sharing, v3's
combination of Instance isolation + hierarchical stack + by-value
content-addressing:

1. **Eliminates the reentrancy bug class structurally.** Bugs like
   the DAO hack rely on a contract being reentered while its state
   is mid-update. v3 single-activation prevents this. Chain authors
   don't need ReentrancyGuard, Checks-Effects-Interactions
   discipline, etc.

2. **No journaling overhead.** Ethereum maintains per-CALL frame
   journals of mutations for revert; v3 maintains nothing comparable.
   Faults are trivial discards.

3. **No isolation-level ambiguity.** Ethereum has to specify when
   mutations become visible to sub-calls; v3 has no such question
   because sub-calls have their own state.

4. **Cross-context portability.** Instance state is self-contained;
   moves cleanly between kernels (L1↔L2 bridging, light-client
   replay). Ethereum-style transactional state has subtle issues
   with concurrent / replay scenarios.

5. **Simpler kernel.** Less code, easier to reason about, easier
   to formally verify.

The cost is real but bounded: no intra-Instance reentry. The patterns
that would use it can be rewritten via cap-flow, emit/handle, or
yield-cascade. Most real blockchain patterns don't actually need
reentry on shared state.

## Why this is robust

We have walked this design space carefully over many discussions:

- Considered CDT (rejected): broke by-value.
- Considered linearity (rejected): no structural use case in by-value
  world.
- Considered multi-activation (rejected): introduces shared mutable
  state, needs rollback.
- Considered immutable functional (rejected): operationally
  equivalent to v3 for single-activation; adds MVCC complexity for
  multi-activation.
- Considered seL4-style fault handlers (rejected): the meaningful
  capability requires rollback.
- Considered whole-tx atomicity (rejected): too restrictive for
  blockchain.
- Considered instance_id (rejected): breaks by-value cap identity.
- Considered per-cap-copy CDT (rejected): breaks by-value
  content-addressing.

Every alternative either reintroduced shared mutable state, broke
by-value semantics, or restricted expressiveness below what
blockchains need. The data-flow + Instance-isolation model is the
fixed point.

When we doubt the model, it's worth re-walking these alternatives
to see if anything has changed. Usually it hasn't, and the same
arguments still rule them out. The model has earned trust through
repeated stress-testing.

## What remains to polish

Most details have been resolved through extended discussion. What
remains genuinely open:

1. **YieldSender representation.** The emit token is a
   `YieldSender{yield_key}` — it carries a yield_key the kernel routes
   by, not a stack-entry-id naming a fixed stack position. (This
   key-routing is what the redesign replaces the legacy stack-position
   yieldref with.) Whether the YieldSender is a distinct cap kind or a
   regular `Cap::Instance` over a `kernel:yieldsender` image is a
   spec-surface choice; behavior is the same either way.

2. **Persistence behavior for YieldSenders.** A `YieldSender{yield_key}`
   is freely persistable: it names a key, not a live stack entry, so it
   never goes stale. What it routes to depends on the per-CALL
   snapshots in flight at emit time — an emit whose key matches no
   snapshotted YieldReceiver simply faults ("unhandled yield_key").
   Whether the kernel should additionally restrict where a privileged
   YieldSender may be MGMT_COPYd (a containment knob) is the open spec
   question; both unrestricted and restricted variants work.

3. **DROP_RESUME's cap delivery.** When DROP_RESUME promotes B to
   Paused-persistent, where does the cap to Paused-B go? Returned
   in caller's slot[0]? Left in a designated slot? Spec choice.

4. **Multi-block pause as an explicit feature.** Whether v3 supports
   Paused-persistent state at all (vs. OOG-as-fault and explicit
   chain-author multi-block state machines). Practical/conceptual
   question; not a structural one.

Things that have been resolved through discussion:

- **Yield is structurally a return** that pushes a reference to a
  prior stack entry. Same primitive family as CALL/HALT; not a
  separate concept.
- **Authority caps work via YIELD on a `YieldSender{yield_key}`.** No
  Request/Response Instance triplet needed; key routing plus structural
  linearity from the stack gives us all the security properties
  (confidentiality from intermediates via owner-edge routing +
  single-resumer, replay safety, single-resumer guarantee).
- **Snapshot universality** is qualified: snapshot iff Instance has
  zero stack entries (Idle or Paused-persistent at σ layer). This
  is honest about what's actually true.
- **Reentry protection is incidental.** The structural reason for
  hierarchy is fault atomicity + yield-linearity. Reentry protection
  is a free side effect.
- **CALL_RESUME's role.** Pop top handler entry; underlying Waiting
  entry becomes Running. Symmetric with HALT (which pops on
  termination). Both are "transfer to whoever's below me."

## Summary

**The principle:**

> Single-mutator-per-state-unit at any moment. At no point in v3
> may two in-flight invocations operate on the same piece of
> mutable state.

**The trap:**

> Shared mutable state + per-context fault. Together they force
> transactional infrastructure (rollback, per-context working state,
> commit chains, visibility rules). v3 avoids this by disabling
> shared mutable state, not by avoiding per-context fault — sub-
> fault recovery still works via Instance isolation.

**The mechanisms (how v3 enforces the principle):**

> - Hierarchical call stack — provides the invocation boundary
>   (fault atomicity + yield-linearity); reentry protection is
>   incidental.
> - By-value content-addressing for caps — provides snapshot
>   universality, cross-context portability, and the structural
>   "mutations diverge per copy" semantics that prevents shared
>   mutable state through cap-flow.
> - Instance isolation via cnode ownership — ensures only an Instance's
>   own bytecode can mutate its cnode.
> - Slot-only-updates-at-termination — gives atomic commit/discard
>   without any rollback infrastructure.

**The checkable invariant when reviewing a design:**

> Does this introduce two simultaneous mutators on the same state
> unit? If yes, the design is on the wrong side of the trap. The
> design space we've explored extensively says there's no clever
> way to opt-in to "just a bit" of shared mutable state without
> paying the full transactional infrastructure cost.

**The reason this is robust:**

> Every alternative we've considered (CDT, multi-activation,
> linearity, fault handlers, instance_id, per-cap-copy identity,
> multi-block yield, whole-tx atomicity, etc.) either violates a v3
> invariant (single-mutator, by-value, by-value-content-addressing,
> snapshot universality, cross-context portability) or requires
> transactional infrastructure that the principle avoids. After
> walking the design space repeatedly, the fixed point holds.

**The takeaway for future design discussions:**

> When something feels tortured, check whether we're trying to add
> shared mutable state or per-context recovery on top of shared
> state. We're not. Either find a way to express the goal without
> shared mutable state, or accept that the goal isn't achievable
> within v3's invariant.
>
> When something feels naturally to require "the same instance" of
> an Instance across multiple positions: check whether the call stack's
> reference-entry mechanism (same instance, different stack positions,
> shared PC) captures it. Usually it does.
>
> When designing authority or routing: check whether the hierarchical
> stack already gives you the structural property you want (single
> resumer, fault atomicity, scope-bound caps). Usually it does, and
> the right answer is "use the stack, don't reinvent it."

If a future design discussion seems to be drifting into
multi-activation, rollback, per-context working state, by-reference
caps in persistent storage, or non-hierarchical fault routing —
this is the doc to re-read. The arguments still rule those out.
