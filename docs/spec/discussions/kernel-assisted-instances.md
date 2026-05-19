# Kernel-assisted Instances

This doc captures a unifying design pattern that emerged from
considering how the kernel manages resources (yield routing, gas
accounting, storage quotas, future kernel-mediated operations).
The pattern is: **kernel resources are exposed via the Instance
abstraction, with kernel short-circuit for performance.**

Four supporting principles, three concrete instances, one minimal
kernel-to-userspace interface.

## The four design patterns

These patterns, taken together, define how kernel resources fit
into v3's uniform Instance-based model.

### Pattern 1: Kernel uses normal Instances for storage-shaped state

When the kernel needs to maintain state that userspace will interact
with, that state lives in an Instance — not a special kernel-only data
structure. The Instance might have a kernel-implemented Image (the
"kernel-assisted Instance" concept below), but it's structurally a
Instance: has a place in the system, has endpoints, can be cap-flowed.

This means there's no parallel "kernel registry" / "kernel table"
data type. Just Instances, consistently.

### Pattern 2: Read access via raw DataCap

When an Instance needs to give read access to its state to other parties,
the standard pattern is to expose a `read() → Cap::Data` endpoint
that serializes the relevant portion of state as a DataCap. Copy is
free (content-addressed), so cheap; readers can iterate offline at
no further kernel cost.

This is the canonical read pattern. It's used by both:
- Kernel-assisted Instances offering read access to their internal state.
- Regular userspace Instances offering read access to their data.

### Pattern 3: Kernel short-circuit for performance

When the kernel itself needs to access the state of a kernel-assisted
Instance (e.g., debit gas per instruction), it does so directly — not
via the Instance's endpoints. The kernel knows the layout (since the
Image is kernel-implemented) and reads/writes the struct directly.

This keeps the Instance abstraction in place at the user-facing level
without imposing endpoint-dispatch cost on the kernel's fast path.
Userspace sees an Instance; kernel internally uses a struct. Same data;
two views.

### Pattern 4: Storage cost via dirty-page tracking

Storage and memory are unified: the cost of state is the cost of
its bytes. Specifically:
- **Copy is free.** Content-addressed values can be referenced from
  multiple places at zero cost.
- **Write costs per page.** Mutating state dirties pages; each dirty
  page is charged to a storage quota.
- **Page size: 4 KiB**, matching the underlying JAVM page size.
- **Dirty-page tracking clears when an Instance leaves the stack
  entirely** (stack-leave reset, not per-CALL push/pop). This
  matches "dirty until commit" intuition: while an Instance remains on
  the stack across nested calls, its dirty set persists; once it
  leaves the stack, the dirty set is finalized and charged.

## The kernel-assisted Instance concept

A **kernel-assisted Instance** is an Instance whose Image lives in a
special `kernel:` namespace (e.g., `kernel:yieldcatcher`,
`kernel:gasmeter`). Properties:

- **Image is kernel-implemented in native code.** No userspace
  bytecode runs; kernel implements the endpoints directly.
- **State layout is a kernel-known struct.** Not a generic cnode of
  arbitrary caps; the kernel reads/writes the struct directly.
- **Kernel can short-circuit access** to the state during execution
  (per Pattern 3).
- **Userspace interacts via standard CALL on endpoints.** No
  special ABI for talking to kernel-assisted Instances.
- **Could in principle be reimplemented in pure JAVM bytecode.** The
  kernel implementation is for performance and simplicity; the
  abstraction is plain Instance.

The kernel namespace prefix is documentation convention; mechanically
kernel-assisted images are just well-known image_hashes baked into
kernel code.

### Creating kernel-assisted Instances

Some kernel-assisted Instances require a kernel-issued capability to
create (e.g., `CreateYieldCatcher`, `MintGas`). Holders of the
factory cap can derive instances via the standard host call (kernel
checks the factory cap is held before allowing the derive).

This makes "having a kernel-managed resource" a capability — gated
by cap-flow, like everything else.

Other kernel-assisted Instances exist only at the kernel level
(GasMeter, StorageQuota) and aren't user-derivable. They're
internal kernel state, accessed only via specific kernel-issued
caps (SetGasMeter, SetStorageQuota).

## Where things live (hierarchical placement)

The three concrete instances split into two categories by where
they live:

### Per-Instance (local) kernel-assisted Instances

These live in user Instances' cnodes; one per user Instance as needed:

- **YieldCatcher** — held in a user Instance's `yield_marker_slot`.
  Each Instance has its own YieldCatcher (or none if it doesn't catch
  yields).

### Kernel-internal kernel-assisted Instances

These live at the kernel level (not in any user Instance's cnode):

- **GasMeter** — the global table of active meter values.
- **StorageQuota** — the global table of active quota values.

User chains never hold `Cap::Instance[GasMeter]` or
`Cap::Instance[StorageQuota]`. These are kernel implementation detail.
Userspace interacts with them only via kernel-issued caps (SetX).

### Per-Instance unit handles (regular Cap::Instances)

These are unit caps that name entries in the kernel-internal Instances:

- **Gas{meter_id}** — names a meter in GasMeter. Held in Instance
  cnodes; declared in `gas_slots`.
- **Quota{quota_id}** — names a quota in StorageQuota. Held in
  Instance cnodes; declared in `quota_slots`.

Gas and Quota are kernel-assisted Instances (kernel-known images), but
their state is just an opaque identifier; conservation lives in the
kernel-internal GasMeter/StorageQuota, not in the unit cap itself.

## The three instances, in detail

### YieldCatcher (per-Instance, kernel-assisted)

```
Image: kernel:yieldcatcher
State (kernel struct):
  markers: Vec<Cap::Instance[YieldMarker]>  -- the set of markers
                                            this Instance catches

Endpoints:
  add(marker: Cap::Instance[YieldMarker]) -> ()
    Add marker to the catch list.
  remove(marker: Cap::Instance[YieldMarker]) -> ()
    Remove marker from the catch list.
  read() -> Cap::Data
    Serialize the marker list as a DataCap for reading.

Creation: requires Cap::Instance[CreateYieldCatcher] (kernel-issued).
Held in user Instance's yield_marker_slot (declared in Image).
Kernel short-circuits access during YIELD routing.
```

A user Instance's Image declares `yield_marker_slot: Option<SlotIdx>`.
That slot, if set, must hold a `Cap::Instance[YieldCatcher]`. When the
kernel walks the call stack to route a yield, it consults each
Instance's YieldCatcher's marker list directly (via short-circuit).

For yield routing details, see §14 in README.

### GasMeter (kernel-internal, kernel-assisted)

```
Image: kernel:gasmeter
State (kernel struct):
  meters: Map<MeterId, RemainingGas>  -- the active set

Endpoints (only callable via SetGasMeter cap):
  set(meter_id: u64, value: u64) -> u64
    Atomically set GasMeter[meter_id] = value; return previous value.
    (Returning previous enables read-while-write for harvest.)
    If no entry exists for meter_id, "previous" is 0 and a fresh
    entry is created at value.

Lifecycle:
  At block start: kernel initializes
    meters = { root_meter_id: <chain-spec block budget> }
  During block: chain populates lazily via SetGasMeter using
    chain-chosen meter_ids (kernel is stateless across blocks, so
    meter_id assignment is necessarily chain-managed).
  At block end: kernel discards GasMeter entirely (kernel is
    stateless across blocks).

Access:
  Read by kernel during execution (short-circuit, debit per instruction).
  Modified by holder of SetGasMeter cap (chain-issued).
  Userspace never reads directly — implicit via SetGasMeter's return
    value or via OOG yield payload.
```

GasMeter is kernel-internal. Chain doesn't hold `Cap::Instance[GasMeter]`.
The only path to GasMeter from userspace is via the `SetGasMeter`
cap, which both writes and returns the previous value (atomic).

### Gas{meter_id} (per-Instance unit handle)

```
Image: kernel:gas
State (kernel struct):
  meter_id: u64  -- the meter this cap names

Endpoints: (none meaningful for users; kernel reads state directly)

Creation: requires Cap::Instance[MintGas] (kernel-issued).
  Caller supplies meter_id (chain-chosen — kernel cannot assign
  uniquely without persistent state). Chain is responsible for
  meter_id uniqueness; collisions silently alias to the same meter.

Held in: user Instance's gas_slots (Image-declared).
Used: when kernel debits gas during execution, it reads meter_id
  from the active gas slot and decrements GasMeter[meter_id].
```

Gas caps are regular Cap::Instance; can be MGMT_COPY'd freely. Copies
all name the same meter_id; debiting from any copy debits the same
meter. **Conservation is preserved by the kernel-internal GasMeter,
not by cap uniqueness.** Hence no narrow linearity is needed.

### StorageQuota and Quota (analogous to GasMeter and Gas)

```
StorageQuota:
  Image: kernel:storagequota
  Kernel-internal; chain doesn't hold Cap::Instance[StorageQuota].
  Endpoints (via SetStorageQuota cap):
    set(quota_id: u64, value: u64) -> u64

  Lifecycle:
    At block start: kernel initializes
      quotas = { root_quota_id: <chain-spec block storage budget> }
    During block: chain populates lazily via SetStorageQuota with
      chain-chosen quota_ids.
    At block end: kernel discards StorageQuota entirely.

Quota:
  Image: kernel:quota
  Per-Instance unit handle naming a chain-chosen quota_id.
  Created via MintQuota cap (caller supplies quota_id).
  Held in user Instance's quota_slots.
```

Same pattern as Gas. Kernel debits the relevant quota when pages are
dirtied per Pattern 4. Userspace allocates via SetStorageQuota and
the OOG-style pattern (with StorageExhaustedMarker) for lazy loading.

## The minimal kernel-to-chain interface

What kernel issues to the top-level chain Instance at chain init:

```
Caps in chain's cnode after init:
  
  Gas / Storage management:
    Cap::Instance[Gas{root_meter_id}]      — initial root gas budget
    Cap::Instance[Quota{root_quota_id}]    — initial root quota
    Cap::Instance[SetGasMeter]             — modify GasMeter
    Cap::Instance[SetStorageQuota]         — modify StorageQuota
    Cap::Instance[MintGas]                 — factory for Gas caps
    Cap::Instance[MintQuota]               — factory for Quota caps
  
  Yield routing:
    Cap::Instance[CreateYieldCatcher]      — factory for per-Instance catchers
  
  (Possibly future: factories for other kernel-assisted Instance types.)

Kernel-issued markers (pre-placed in chain's initial YieldCatcher):
  OOG_marker            — caught when any meter hits 0
  StorageExhausted_marker — caught when any quota hits 0
  (others as needed)
```

That's the entire kernel ABI for chain orchestration. The kernel
internals (GasMeter, StorageQuota) are opaque from userspace; only
the cap-mediated operations are visible.

## The lazy-load OOG-catch pattern

Because the kernel is stateless across blocks, GasMeter starts each
block with only `{ root_meter_id: <budget> }`. All other meter_ids
have no entry (effectively zero).

Rather than chain pre-loading every persistent user's meter value
at block start (which scales linearly with active users), chain uses
**lazy loading via OOG-catch**:

```
Setup at chain init (once):
  chain.GasLedger = (chain's own custom Instance holding 
                     persistent gas balances per user)
  chain.YieldCatcher has OOG_marker
  chain.holds SetGasMeter, MintGas caps

Per-tx execution:
  1. Chain receives a tx for User_X.
  2. Chain reads User_X's persistent balance from GasLedger (chain's σ).
  3. Chain picks meter_id for User_X (chain policy: may reuse the
     same id across blocks, or freshen per block; both work).
     If chain doesn't yet hold Cap::Instance[Gas{meter_id}] for it,
     mint via MintGas(meter_id) and stash in GasLedger.
  4. SetGasMeter(meter_id, balance)        — topup
  5. CALL user_contract with gas_cap in gas_slots.
  6. User runs; kernel debits GasMeter[meter_id].
  7. If meter hits 0: OOG yield. Chain catches via YieldCatcher.
       OOG payload: a single Cap::Instance[Gas{meter_id}] copy
         identifying which meter ran out. No caller context
         (intentional — see "OOG payload" below).
       Chain decides: topup more, or fail tx.
       If topup: SetGasMeter(meter_id, more_balance); CALL_RESUME.
       If fail: DROP_RESUME (or whatever fault propagation).
  8. User HALTs.
  9. remaining = SetGasMeter(meter_id, 0)  — harvest, zero out
  10. chain.GasLedger.update(User_X, remaining)
  11. Tx complete.
```

Properties:

- **No pre-loading.** Chain doesn't iterate over all users at block
  start.
- **Bounded by active set.** Only meter_ids of active users get
  populated in kernel's GasMeter during a block.
- **SetGasMeter is set-with-return-previous.** Chain doesn't need
  separate read access; the atomic set+return is sufficient.
- **OOG handler in chain bytecode controls all gas policy.** Topup,
  rate limit, subsidize, refuse — all chain logic.
- **Conservation enforced structurally.** Total spent ≤ sum of
  SetGasMeter additions; chain bytecode is responsible for ensuring
  additions match user balances.

The same pattern applies to storage quotas via StorageExhausted_marker.

### OOG payload: just the Gas cap, nothing else

The OOG yield payload is **only** a `Cap::Instance[Gas{meter_id}]`
copy. No "which call was running," no caller instance_hash, no stack
context.

This is deliberate. Encoding "which call ran out" would
reintroduce CALLER information into a capability-only system —
which is precisely the property v3 avoids (caps name capabilities,
not call origins). There is also no clean way to encode it: a
Instance is reentrant across copies, and "call context" is not a
first-class cap.

The meter_id alone is sufficient. Chain looks meter_id up in its
GasLedger to find the owning user; that's all the context needed
to decide topup vs fail. The same logic applies to
StorageExhausted_marker: payload is a `Cap::Instance[Quota{quota_id}]`.

## Why no narrow linearity is needed

An earlier design exploration considered making balance-bearing
Instances (Gas, Quota) non-copyable at the kernel level — "narrow
linearity" for kernel resources. This turns out not to be needed.

The reasoning:

> **The balance is in the kernel-internal GasMeter / StorageQuota
> table, not in the Gas/Quota unit cap.**

If a user contract holds `Cap::Instance[Gas{meter_id_5}]` and
MGMT_COPYs it to slot[7], both slots now hold caps to meter_id_5.
Operations on either slot decrement the same `GasMeter[meter_id_5]`.
Total spent is the sum of all operations across all copies, bounded
by the meter's current value.

Cap copies don't duplicate the balance because the balance isn't
in the cap. The cap is just a handle naming a meter. The meter has
one value, kernel-controlled, conservation-preserved.

So Gas and Quota are **fully copyable Cap::Instances**. No special
linearity rule. Conservation via the kernel-internal table.

## Kernel statelessness implications

The kernel maintains no persistent state across blocks. All
persistence is via σ (chain's own Instances). What this means:

1. **GasMeter restarts each block.** Only `root_meter_id` is
   initialized; chain repopulates via SetGasMeter.

2. **StorageQuota restarts each block.** Same pattern. (Wrinkle:
   how does kernel know "how much storage" exists at block start?
   See "Open questions.")

3. **Chain holds all persistent state in its own custom Instances.**
   GasLedger, StorageLedger, contract registry, account state,
   etc. — all standard chain σ.

4. **No kernel-side state-root contributions.** Only chain's σ
   contributes to state-root computation. Kernel-internal Instances
   (GasMeter, StorageQuota) are ephemeral; they don't appear in
   state-root.

5. **Cross-block portability** is preserved because all state lives
   in chain's σ, which is content-addressed and serializable.

## Conservation invariant

Total gas spent in block ≤ initial root_meter_id budget +
chain-issued topups.

Because chain is the only entity holding SetGasMeter, and chain's
bytecode is auditable, conservation is enforceable by inspection of
chain code: chain must ensure SetGasMeter additions match balances
debited from chain.GasLedger.

If chain's code is incorrect (adds more gas than balances justify),
conservation breaks. This is a chain-spec bug, not a kernel bug.
For deterministic blockchain consensus, this is acceptable: the
chain's bytecode is what defines the chain.

## Comparison with earlier design attempts

Several earlier approaches were considered and superseded:

| Approach | Issue | Resolved by |
|---|---|---|
| Per-Instance Gas with value baked in | Conservation requires linearity (cap copies diverge values) | Kernel-internal GasMeter; Gas caps name meters, don't carry value |
| Global GasMeter table accessed via Cap::Instance[GasMeter] | Chain holds kernel internals; conflates layers | Kernel-internal GasMeter; only SetGasMeter cap exposed |
| Pre-load all persistent gas at block start | Scales with active user count; expensive | Lazy load via OOG-catch |
| Image-level non-copyability for Gas (narrow linearity) | Adds linearity exception; complicates cap model | Conservation via kernel-internal table; cap copies share value |
| Cap::Type for authority routing | Cap::Type is identification, not authority | Cap::Instance possession (via AuthorityCap holding marker); see §14 |

The current design uses each kernel-assisted Instance for what it's
naturally good at: yield routing (per-Instance YieldCatcher), gas
accounting (kernel-internal GasMeter), storage accounting (kernel-
internal StorageQuota). The unit handles (Gas, Quota) are regular
Cap::Instances; conservation handled by the kernel-internal tables.

## Naming summary

| Concept | Per-Instance unit | Kernel-internal (if applicable) |
|---|---|---|
| Yield routing | `YieldMarker` (cap unit) | n/a — `YieldCatcher` lives per-Instance |
| Gas accounting | `Gas{meter_id}` (handle) | `GasMeter` (kernel internal) |
| Storage accounting | `Quota{quota_id}` (handle) | `StorageQuota` (kernel internal) |

Kernel-assisted Instances in userspace use: `YieldCatcher`,
`Gas{meter_id}`, `Quota{quota_id}`.

Kernel-internal kernel-assisted Instances (never in chain hands):
`GasMeter`, `StorageQuota`.

## Cap-flow at chain init

A concrete picture of what's in the top-level chain Instance's cnode
right after kernel boot:

```
chain.cnode at chain init:
  [PINNED slots: Image's pinned Cap::Image / Cap::Data]
  
  [Slot for YieldCatcher — Image-declared yield_marker_slot]
  yield_catcher_slot = Cap::Instance[YieldCatcher]
    with markers: { OOG_marker, StorageExhaustedMarker, ... }
  
  [Slots for gas]
  Cap::Instance[Gas{root_meter_id}]
  Cap::Instance[SetGasMeter]
  Cap::Instance[MintGas]
  
  [Slots for storage]
  Cap::Instance[Quota{root_quota_id}]
  Cap::Instance[SetStorageQuota]
  Cap::Instance[MintQuota]
  
  [Slot for YieldCatcher factory]
  Cap::Instance[CreateYieldCatcher]
  
  [chain-specific genesis caps, etc.]
```

From here, chain bytecode does whatever chain spec defines.

## Resolved design decisions

The following points were initially flagged as open and have been
resolved. Captured here so the rationale survives.

1. **Dirty-page tracking lifetime — stack-leave reset.** An Instance's
   dirty set persists while it remains on the kernel call stack
   (across nested CALL/yield/resume), and is finalized + charged
   when the Instance leaves the stack entirely. Matches "dirty until
   commit" intuition; per-CALL reset would lose intra-call write
   coalescing.

2. **Page size — 4 KiB**, matching the underlying JAVM page size.
   Consistent with the VM's native granularity; no separate kernel
   page size to track.

3. **Meter_id / quota_id assignment — chain-chosen.** The kernel
   has no persistent state across blocks, so it cannot maintain a
   monotonic counter or any other unique-id scheme on its own. Id
   assignment is therefore chain's responsibility; MintGas /
   MintQuota take the chain-supplied id as input. Collisions
   silently alias to the same meter/quota — chain is responsible
   for uniqueness within its own policy (this is fine: chain is the
   only entity holding MintGas/MintQuota anyway).

4. **OOG yield payload — only `Cap::Instance[Gas{meter_id}]`.** See
   "OOG payload" section above. Deliberately minimal: no caller
   context, no call-stack info. Encoding "which call ran out"
   would reintroduce CALLER into a cap-only system, which v3
   structurally avoids. The meter_id is sufficient — chain looks
   it up in GasLedger. Same shape for StorageExhausted.

5. **Storage quota at block start — chain-spec constant +
   SetStorageQuota.** Kernel initializes
   `quotas = { root_quota_id: <chain-spec block budget> }` at block
   start; everything else is chain-populated lazily via
   SetStorageQuota, analogous to gas. Same lazy-load + exhaustion-
   catch pattern.

6. **Reuse of meter_ids across blocks — chain's call.** Since
   meter_ids are chain-chosen, this is purely chain policy. A
   chain that wants persistent gas semantics will reuse meter_ids
   across blocks (deterministic mapping from user → meter_id). A
   chain that wants fresh-per-block can do that instead. Kernel
   doesn't care; meter_ids are opaque numbers from kernel's view.

7. **Read access to GasMeter for inspection — deferred.** The
   current design exposes only write access via SetGasMeter
   (which returns the previous value, enabling read-while-write
   for the harvest pattern). Pure read access is not provided.
   If a concrete need arises later (e.g., chain wants to inspect
   without disturbing), add a `host_query_meter` read-only cap
   then. Not adding speculatively.

8. **`set_image` on kernel-assisted Instances — structurally
   impossible.** Kernel-assisted Instances run native kernel code,
   not bytecode. They never execute `set_image` (no bytecode to
   issue the host call). The question is moot: there is no
   execution context that could trigger an image change on a
   kernel-assisted Instance.

## Relationship to other docs

- **README §1** (Image): yield_marker_slot field; Image declares
  gas_slots and quota_slots for kernel debiting.
- **README §3** (Instance state machine + kernel call stack): the
  kernel-internal call stack underlies the yield routing.
- **README §4** (Kernel ABI): the kernel-issued caps (SetGasMeter,
  MintGas, CreateYieldCatcher, etc.) appear here.
- **README §8** (Cap kinds): kernel-assisted Instances are regular
  Cap::Instance; no new cap kind needed.
- **README §14** (Authority via capability flow): yield-marker
  authority pattern uses YieldCatcher.
- **README §15, §16** (AA, MintInstance): instances of the authority
  pattern.
- **userspace/generic-authority-pattern.md**: pattern doc for
  authority caps; uses YieldCatcher mechanism.
- **discussions/data-flow-principle.md**: architectural derivation;
  kernel-assisted Instances live within the data-flow / hierarchical
  invocation discipline.

## Summary

> **Kernel resources are exposed via the Instance abstraction with
> kernel short-circuit. Instance-level uniformity is preserved; kernel
> implementation freedom is preserved. Per-Instance resources
> (YieldCatcher) live in user Instances' cnodes; kernel-internal
> resources (GasMeter, StorageQuota) live at the kernel level and
> are accessed only via kernel-issued caps. Unit handles (Gas,
> Quota) are regular Cap::Instances naming entries in the kernel-
> internal tables. Conservation is structural via the kernel-
> internal tables — no narrow linearity is needed. Persistence is
> entirely in chain σ; kernel is stateless across blocks. Lazy load
> via OOG-catch handles persistent state at scale.**

This pattern unifies what would otherwise be ad-hoc kernel APIs
(yield routing, gas, storage, future kernel resources) into a single
shape. The kernel-to-chain interface stays small (a handful of caps
and markers); chain controls all higher-level policy.
