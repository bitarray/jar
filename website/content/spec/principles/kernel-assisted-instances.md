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

This pattern also subsumes equality/comparison. To compare two
kernel-assisted tokens (e.g. two `Gas{meter_key}` handles, or two
`YieldSender{yield_key}` caps), the token Instance returns a **zero-copy
copy of its key DataCap** (CoW makes the copy O(1)); the **caller** maps
it and compares (memcmp). There is deliberately **no `eq` endpoint** —
comparison logic lives in the caller; the token just exposes its raw key
bytes via `read()`.

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
special `kernel:` namespace (e.g., `kernel:yieldsender`,
`kernel:yieldreceiver`, `kernel:gasmeter`). Properties:

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
kernel code. Note two distinct `kernel:*` namespaces: the IMAGE
namespace (`kernel:yieldsender`, `kernel:gasmeter`, …) names the native
images, while the **yield_key** namespace (`kernel:oog`,
`kernel:set_gas_meter`, …) names yields reserved for the kernel root
receiver.

### Creating kernel-assisted Instances

Kernel-assisted Instances are minted by **yielding to the kernel root
receiver**. The kernel is the implicit ROOT YieldReceiver for every
`kernel:*` yield_key; at top-level invocation it places a CNode in the
scratchpad (slot[0]) mapping descriptive names to YieldSenders. To mint,
the guest places the relevant YieldSender in the yield-scratchpad and
`host_yield`s it:

- `kernel:mint_gas`(meter_key)   → returns the `Gas{meter_key}` unit handle.
- `kernel:mint_quota`(quota_key) → returns the `Quota{quota_key}` unit handle.
- `kernel:mint_yield`(raw yield_key) → returns the PAIR
  `(YieldSender{key}, YieldReceiver{[key]})`. UNRESTRICTED: it can mint
  for ANY key, including `kernel:*` keys (deliberate — it enables full
  interposition / virtualization of kernel syscalls; userspace restricts
  it by INTERPOSING).
- `kernel:merge_yield_receiver`(YieldReceiver A, YieldReceiver B)
  → returns `YieldReceiver{A.keys ∪ B.keys}` (set union). This is how a
  multi-key catch-list is composed: mint single-key receivers via
  `kernel:mint_yield`, then union them.

Possession of the YieldSender is what authorizes the mint — gated by
cap-flow, like everything else. This makes "having a kernel-managed
resource" a capability.

Other kernel-assisted Instances exist only at the kernel level
(GasMeter, StorageQuota) and aren't user-derivable. They're
internal kernel state, accessed only by emitting the kernel-reserved
yield_keys `kernel:set_gas_meter` / `kernel:set_storage_quota`.

## Where things live (hierarchical placement)

The kernel-assisted Instances split into two categories by where
they live:

### Per-Instance (local) kernel-assisted Instances

These live in user Instances' cnodes; one per user Instance as needed:

- **YieldReceiver{Vec<yield_key>}** — held in a user Instance's
  `yield_receiver_slot`. The set of yield_keys this Instance catches.
  Each Instance has its own YieldReceiver (or none — an empty/absent
  slot catches nothing).
- **YieldSender{yield_key}** — the EMIT right for a key. Held in any
  cnode slot; placed in the yield-scratchpad to `host_yield`.

### Kernel-internal kernel-assisted Instances

These live at the kernel level (not in any user Instance's cnode):

- **GasMeter** — the global table of active meter values.
- **StorageQuota** — the global table of active quota values.

User chains never hold `Cap::Instance[GasMeter]` or
`Cap::Instance[StorageQuota]`. These are kernel implementation detail.
Userspace interacts with them only by emitting the kernel-reserved
yield_keys (`kernel:set_gas_meter` / `kernel:set_storage_quota`).

### Per-Instance unit handles (regular Cap::Instances)

These are unit caps that name entries in the kernel-internal Instances:

- **Gas{meter_key}** — names a meter in GasMeter. Held in Instance
  cnodes; declared in `gas_slots`.
- **Quota{quota_key}** — names a quota in StorageQuota. Held in
  Instance cnodes; declared in `quota_slots`.

Gas and Quota are kernel-assisted Instances (kernel-known images), but
their state is just an opaque identifier; conservation lives in the
kernel-internal GasMeter/StorageQuota, not in the unit cap itself.

## The four kernel-assisted Instance variants

Kernel-assisted Instances are regular `Cap::Instance`s whose Image is a
kernel-reserved `kernel:*` image. There are four, all identified by a key:

- **`Gas{meter_key}`** — unit handle naming a meter in the
  kernel-internal GasMeter table. Held in `gas_slots`.
- **`Quota{quota_key}`** — unit handle naming a quota in the
  kernel-internal StorageQuota table. Held in `quota_slots`.
- **`YieldSender{yield_key}`** — the EMIT right: possession authorizes
  emitting a yield tagged `yield_key`.
- **`YieldReceiver{Vec<yield_key>}`** — the CATCH right: the set of
  yield_keys this Instance catches. Held in the Instance's
  `yield_receiver_slot`. Stored as a set for O(1) lookup.

`YieldSender` (emit) and `YieldReceiver` (catch) are SEPARATE rights
over a key — the seL4 endpoint Send/Receive model. `kernel:mint_yield`
returns both; the minter distributes Senders (others may emit, routed
up) and keeps Receivers (only it catches). A holder of only a Sender
cannot catch the key (no Receiver to register), eliminating the "child
given a marker catches its own/parent's yield" conflation.

### YieldSender / YieldReceiver (per-Instance, kernel-assisted)

```
Image: kernel:yieldsender
State (kernel struct):
  yield_key: Key  -- the key this sender emits

Endpoints:
  read() -> Cap::Data
    Zero-copy copy of the yield_key DataCap (for caller-side memcmp).

Minted via: kernel:mint_yield(raw yield_key) -> (YieldSender, YieldReceiver).
Used: placed in the yield-scratchpad and host_yield'd to emit.
```

```
Image: kernel:yieldreceiver
State (kernel struct):
  keys: Set<Key>  -- the yield_keys this Instance catches (set, O(1) lookup)

Endpoints:
  read() -> Cap::Data
    Serialize the catch-set as a DataCap for reading.

Composed via: kernel:mint_yield (mints a single-key receiver) +
              kernel:merge_yield_receiver (union of two receivers).
              There are NO add/remove endpoints — a receiver is rebuilt
              by merging, and a slot is updated by moving a new receiver in.
Held in user Instance's yield_receiver_slot (declared in Image).
Kernel short-circuits access during YIELD routing.
```

A user Instance's Image declares
`yield_receiver_slot: Option<Key>`. That slot, if set, must hold a
`Cap::Instance[YieldReceiver]`. When the kernel walks the call stack to
route a yield, it consults each frame's SNAPSHOTTED YieldReceiver
catch-set directly (via short-circuit; see the per-CALL snapshot below).

For yield routing details, see §4 (host_yield) and §3 (kernel call
stack) in top-level spec; §14 applies it to the authority pattern.

### Yield routing

`host_yield(sender: SlotPath)` where `sender` holds a
`YieldSender{yield_key}`:

1. Read `yield_key` from the YieldSender.
2. Follow owner edges from the logical current InstanceEntry toward the root.
3. The NEAREST owner edge whose SNAPSHOTTED YieldReceiver contains
   `yield_key` catches it (**single-resumer**). The kernel is the
   implicit root receiver for `kernel:*` keys (bottom of the owner chain).
4. No match → the emitter FAULTS ("unhandled yield_key").

The caught frame resumes (push a ReferenceEntry); the yielder
transitions to Waiting; the YieldSender's payload reflects via slot[0].
The captured continuation is `(regs, pc, yield_sender)`; pc lands on a
bb_start (PVM-level, unchanged).

### The per-CALL snapshot

A catch-list is a STATIC owner-edge snapshot, not a live read of
`yield_receiver_slot`. At each CALL the kernel snapshots the logical
owner's CURRENT `yield_receiver_slot` YieldReceiver onto the owner edge
for the callee's subtree.

- **PER-EDGE:** the same Instance can own multiple in-flight callees with
  DIFFERENT snapshots — each CALL takes its own. E.g.
  `A CALL B`, `B yield A`, `[ref A] CALL C`: A's frame-0 snapshot (taken
  at `A CALL B`) and the `A -> C` snapshot (taken at `[ref A] CALL C`)
  can differ if A changed its slot in between.
- **FROZEN for the sub-call:** an Instance can mutate
  `yield_receiver_slot` between its downward CALLs (copy the old
  YieldReceiver out, move a new/smaller one in; an empty slot → catches
  nothing), but the snapshot for an in-flight sub-call is immutable, so
  a frame cannot shrink its catch-set mid-flight to dodge a descendant's
  yield. Changes take effect for subtrees of SUBSEQUENT CALLs.
- Stored as a set/index → O(1) per-frame membership; a yield costs
  O(stack depth).

### Interposition (= virtualization / restriction)

To mediate a descendant's yields of a key, an Instance registers that
key in its OWN YieldReceiver. Descendants' yields of that key then reach
this Instance first (nearest receiver); it validates and FORWARDS by
re-emitting the same key with an owner-edge snapshot that omits its own
receiver for that key, so the forward reaches the next
receiver down (a lower interposer, or the kernel root).

This is how userspace restricts the **unrestricted** `kernel:mint_yield`
(which can mint for ANY key, including `kernel:*` keys — deliberately, to
enable full virtualization of kernel syscalls): hand children a
restricted `YieldSender{"kernel:mint_yield"}` that routes to you,
register `"kernel:mint_yield"` in your own receiver, check the requested
key (e.g. allow only `custom:*`, reject `kernel:*`), and forward to the
real kernel.

The SECURITY MODEL is: **containment is PRIMARY** — don't hand untrusted
code a privileged YieldSender (or `kernel:mint_yield`); grant specific
pre-minted senders for granular authority. Mediation (interposition) is
OPT-IN. `kernel:mint_yield` is god-mode (mint any key) and lives in the
TCB (top-level orchestrator), which interposes-to-restrict before
delegating.

### GasMeter (kernel-internal, kernel-assisted)

> **`meter_key`/`quota_key` are `Key`** — the byte-string key type (the same
> type as a cnode slot key, though semantically unrelated). A `Gas{meter_key}`
> unit handle stores its `meter_key` packed into the handle's registers (≤ 8
> bytes); the kernel reads it at frame entry to index the meter mapping.
>
> **TODO (implementation status).** The minimum-kernel ships an *interim*
> realization: a **static kernel-maintained meter mapping** (`Map<Key, u64>`,
> the `meters`/`quotas` tables below), seeded/observed via the
> `kernel:set_gas_meter`/`kernel:set_storage_quota` yield surface, read at frame
> entry from the Instance's primary usable `gas_slots` → `Gas{meter_key}` handle
> and written back at frame exit. The full `GasMeter`/`StorageQuota`
> Map-Instances described
> here (with their own endpoints) are **deferred**: a later spec change
> reimplements them via the YieldSender/YieldReceiver mechanism (the kernel,
> as root receiver, yields the `kernel:oog` key to the chain to resolve a
> meter), removing the dedicated mint paths. Until then the static
> mapping is normative.

```
Image: kernel:gasmeter
State (kernel struct):
  meters: Map<Key, RemainingGas>  -- the active set

Op (emit the kernel:set_gas_meter yield_key):
  kernel:set_gas_meter(meter_key, value) -> u64
    Atomically set GasMeter[meter_key] = value; return previous value.
    (Returning previous enables read-while-write for harvest.)
    If no entry exists for meter_key, "previous" is 0 and a fresh
    entry is created at value.

Lifecycle:
  At block start: kernel initializes
    meters = { root_meter_key: <chain-spec block budget> }
  During block: chain populates lazily by emitting kernel:set_gas_meter
    using chain-chosen meter_keys (kernel is stateless across blocks, so
    meter_key assignment is necessarily chain-managed).
  At block end: kernel discards GasMeter entirely (kernel is
    stateless across blocks).

Access:
  Read by kernel during execution (short-circuit, debit per instruction).
  Modified by emitting kernel:set_gas_meter (the chain holds that
    scratchpad YieldSender).
  Userspace never reads directly — implicit via kernel:set_gas_meter's
    return value or via the kernel:oog yield payload.
```

GasMeter is kernel-internal. Chain doesn't hold `Cap::Instance[GasMeter]`.
The only path to GasMeter from userspace is by emitting the
`kernel:set_gas_meter` yield_key, which both writes and returns the
previous value (atomic).

### Gas{meter_key} (per-Instance unit handle)

```
Image: kernel:gas
State (kernel struct):
  meter_key: Key  -- the meter this cap names

Endpoints: (none meaningful for users; kernel reads state directly)

Creation: emit kernel:mint_gas (the chain holds that scratchpad YieldSender).
  Caller supplies meter_key (chain-chosen — kernel cannot assign
  uniquely without persistent state). Chain is responsible for
  meter_key uniqueness; collisions silently alias to the same meter.

Held in: user Instance's gas_slots (Image-declared).
Used: when kernel debits gas during execution, it consults Image-declared
  gas_slots in order and decrements the active GasMeter[meter_key].
```

Gas caps are regular Cap::Instance; can be MGMT_COPY'd freely. Copies
all name the same meter_key; debiting from any copy debits the same
meter. **Conservation is preserved by the kernel-internal GasMeter,
not by cap uniqueness.** Hence no narrow linearity is needed.

### StorageQuota and Quota (analogous to GasMeter and Gas)

```
StorageQuota:
  Image: kernel:storagequota
  Kernel-internal; chain doesn't hold Cap::Instance[StorageQuota].
  Op (emit kernel:set_storage_quota):
    kernel:set_storage_quota(quota_key, value) -> u64

  Lifecycle:
    At block start: kernel initializes
      quotas = { root_quota_key: <chain-spec block storage budget> }
    During block: chain populates lazily by emitting kernel:set_storage_quota
      with chain-chosen quota_keys.
    At block end: kernel discards StorageQuota entirely.

Quota:
  Image: kernel:quota
  Per-Instance unit handle naming a chain-chosen quota_key.
  Minted by emitting kernel:mint_quota (caller supplies quota_key).
  Held in user Instance's quota_slots.
```

Same pattern as Gas. Kernel debits the relevant quota when pages are
dirtied per Pattern 4. Userspace allocates by emitting
kernel:set_storage_quota and uses the OOG-style pattern (catching the
`kernel:storage_exhausted` yield_key) for lazy loading.

## The minimal kernel-to-chain interface

All kernel interaction is a yield. The kernel is the implicit ROOT
YieldReceiver for every `kernel:*` yield_key. At top-level invocation it
places a **scratchpad CNode** (slot[0]) mapping descriptive names to
YieldSenders, plus the initial gas/quota handles. To invoke a syscall the
guest places the YieldSender in the yield-scratchpad and `host_yield`s it.

```
Scratchpad CNode (slot[0]) — descriptive name -> YieldSender:

  "kernel:mint_gas"             -> YieldSender{"kernel:mint_gas"}
  "kernel:set_gas_meter"        -> YieldSender{"kernel:set_gas_meter"}
  "kernel:mint_quota"           -> YieldSender{"kernel:mint_quota"}
  "kernel:set_storage_quota"    -> YieldSender{"kernel:set_storage_quota"}
  "kernel:mint_yield"           -> YieldSender{"kernel:mint_yield"}
  "kernel:merge_yield_receiver" -> YieldSender{"kernel:merge_yield_receiver"}
  "kernel:attest"               -> YieldSender{"kernel:attest"}  (top-level spec §15)

Initial unit handles in chain's cnode after init:
    Cap::Instance[Gas{root_meter_key}]      — initial root gas budget
    Cap::Instance[Quota{root_quota_key}]    — initial root quota

Root receiver (the kernel, bottom of the stack) catches kernel:* keys.
The chain registers the exhaustion keys in its OWN YieldReceiver at init:
    "kernel:oog"                — caught when any meter hits 0
    "kernel:storage_exhausted"  — caught when any quota hits 0
    (others as needed)
```

That's the entire kernel ABI for chain orchestration. The kernel
internals (GasMeter, StorageQuota) are opaque from userspace; only
the yield-mediated operations are visible. Note that
`kernel:mint_yield` is UNRESTRICTED — it mints a YieldSender for ANY
key; the chain (TCB) interposes over it to gate which keys descendants
may mint.

## The lazy-load OOG-catch pattern

Because the kernel is stateless across blocks, GasMeter starts each
block with only `{ root_meter_key: <budget> }`. All other meter_keys
have no entry (effectively zero).

Rather than chain pre-loading every persistent user's meter value
at block start (which scales linearly with active users), chain uses
**lazy loading via OOG-catch**:

```
Setup at chain init (once):
  chain.GasLedger = (chain's own custom Instance holding 
                     persistent gas balances per user)
  chain registers "kernel:oog" in its YieldReceiver
  chain holds the kernel:set_gas_meter, kernel:mint_gas scratchpad YieldSenders

Per-tx execution:
  1. Chain receives a tx for User_X.
  2. Chain reads User_X's persistent balance from GasLedger (chain's σ).
  3. Chain picks meter_key for User_X (chain policy: may reuse the
     same id across blocks, or freshen per block; both work).
     If chain doesn't yet hold Cap::Instance[Gas{meter_key}] for it,
     mint by emitting kernel:mint_gas(meter_key) and stash in GasLedger.
  4. emit kernel:set_gas_meter(meter_key, balance)   — topup
  5. CALL user_contract with gas_cap in gas_slots.
  6. User runs; kernel debits GasMeter[meter_key].
  7. If meter hits 0: kernel (root receiver) yields kernel:oog.
       Chain catches it via its YieldReceiver registration.
       kernel:oog payload: a single Cap::Instance[Gas{meter_key}] copy
         identifying which meter ran out. No caller context
         (intentional — see "OOG payload" below).
       Chain decides: topup more, or fail tx.
       If topup: emit kernel:set_gas_meter(meter_key, more); CALL_RESUME.
       If fail: DROP_RESUME (or whatever fault propagation).
  8. User HALTs.
  9. remaining = emit kernel:set_gas_meter(meter_key, 0)  — harvest, zero
  10. chain.GasLedger.update(User_X, remaining)
  11. Tx complete.
```

Properties:

- **No pre-loading.** Chain doesn't iterate over all users at block
  start.
- **Bounded by active set.** Only meter_keys of active users get
  populated in kernel's GasMeter during a block.
- **kernel:set_gas_meter is set-with-return-previous.** Chain doesn't
  need separate read access; the atomic set+return is sufficient.
- **OOG handler in chain bytecode controls all gas policy.** Topup,
  rate limit, subsidize, refuse — all chain logic.
- **Conservation enforced structurally.** Total spent ≤ sum of
  kernel:set_gas_meter additions; chain bytecode is responsible for
  ensuring additions match user balances.

The same pattern applies to storage quotas via the
`kernel:storage_exhausted` yield_key.

### OOG payload: just the Gas cap, nothing else

The kernel:oog yield payload is **only** a `Cap::Instance[Gas{meter_key}]`
copy. No "which call was running," no caller identity, no stack
context.

This is deliberate. Encoding "which call ran out" would
reintroduce CALLER information into a capability-only system —
which is precisely the property v3 avoids (caps name capabilities,
not call origins). There is also no clean way to encode it: a
Instance is reentrant across copies, and "call context" is not a
first-class cap.

The meter_key alone is sufficient. Chain looks meter_key up in its
GasLedger to find the owning user; that's all the context needed
to decide topup vs fail. The same logic applies to
`kernel:storage_exhausted`: payload is a `Cap::Instance[Quota{quota_key}]`.

## Why no narrow linearity is needed

An earlier design exploration considered making balance-bearing
Instances (Gas, Quota) non-copyable at the kernel level — "narrow
linearity" for kernel resources. This turns out not to be needed.

The reasoning:

> **The balance is in the kernel-internal GasMeter / StorageQuota
> table, not in the Gas/Quota unit cap.**

If a user contract holds `Cap::Instance[Gas{meter_key_5}]` and
MGMT_COPYs it to slot[7], both slots now hold caps to meter_key_5.
Operations on either slot decrement the same `GasMeter[meter_key_5]`.
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

1. **GasMeter restarts each block.** Only `root_meter_key` is
   initialized; chain repopulates by emitting kernel:set_gas_meter.

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

Total gas spent in block ≤ initial root_meter_key budget +
chain-issued topups.

Because chain is the only holder of the `kernel:set_gas_meter`
YieldSender (unless it interposes to delegate it), and chain's
bytecode is auditable, conservation is enforceable by inspection of
chain code: chain must ensure kernel:set_gas_meter additions match
balances debited from chain.GasLedger.

If chain's code is incorrect (adds more gas than balances justify),
conservation breaks. This is a chain-spec bug, not a kernel bug.
For deterministic blockchain consensus, this is acceptable: the
chain's bytecode is what defines the chain.

## Comparison with earlier design attempts

Several earlier approaches were considered and superseded:

| Approach | Issue | Resolved by |
|---|---|---|
| Per-Instance Gas with value baked in | Conservation requires linearity (cap copies diverge values) | Kernel-internal GasMeter; Gas caps name meters, don't carry value |
| Global GasMeter table accessed via Cap::Instance[GasMeter] | Chain holds kernel internals; conflates layers | Kernel-internal GasMeter; only the kernel:set_gas_meter yield exposed |
| Pre-load all persistent gas at block start | Scales with active user count; expensive | Lazy load via kernel:oog-catch |
| Image-level non-copyability for Gas (narrow linearity) | Adds linearity exception; complicates cap model | Conservation via kernel-internal table; cap copies share value |
| A distinct cap kind for authority routing keyed on type | Type only identifies, it never authorizes; and type identity needs no cap kind — it is the `image_hash` (read via `host_image_hash_chain`) | Cap::Instance possession (via AuthorityCap holding a YieldSender); see §14 |

The current design uses each kernel-assisted Instance for what it's
naturally good at: yield routing (per-Instance YieldReceiver +
YieldSender), gas accounting (kernel-internal GasMeter), storage
accounting (kernel-internal StorageQuota). The unit handles (Gas, Quota)
are regular Cap::Instances; conservation handled by the kernel-internal
tables.

## Naming summary

| Concept | Per-Instance unit | Kernel-internal (if applicable) |
|---|---|---|
| Yield emit | `YieldSender{yield_key}` (cap unit) | n/a — kernel is implicit root receiver |
| Yield catch | `YieldReceiver{Vec<yield_key>}` (per-Instance) | n/a — lives in `yield_receiver_slot` |
| Gas accounting | `Gas{meter_key}` (handle) | `GasMeter` (kernel internal) |
| Storage accounting | `Quota{quota_key}` (handle) | `StorageQuota` (kernel internal) |

Kernel-assisted Instances in userspace use: `YieldSender{yield_key}`,
`YieldReceiver{Vec<yield_key>}`, `Gas{meter_key}`, `Quota{quota_key}`.

Kernel-internal kernel-assisted Instances (never in chain hands):
`GasMeter`, `StorageQuota`.

## Cap-flow at chain init

A concrete picture of what's in the top-level chain Instance's cnode
right after kernel boot:

```
chain.cnode at chain init:
  [PINNED slots: Image's pinned Cap::Image / Cap::Data]
  
  [Scratchpad CNode in slot[0] — kernel:* YieldSenders]
  Cap::CNode {
    "kernel:mint_gas"             -> YieldSender{"kernel:mint_gas"}
    "kernel:set_gas_meter"        -> YieldSender{"kernel:set_gas_meter"}
    "kernel:mint_quota"           -> YieldSender{"kernel:mint_quota"}
    "kernel:set_storage_quota"    -> YieldSender{"kernel:set_storage_quota"}
    "kernel:mint_yield"           -> YieldSender{"kernel:mint_yield"}
    "kernel:merge_yield_receiver" -> YieldSender{"kernel:merge_yield_receiver"}
    "kernel:attest"               -> YieldSender{"kernel:attest"}
  }
  
  [Slot for YieldReceiver — Image-declared yield_receiver_slot]
  yield_receiver_slot = Cap::Instance[YieldReceiver]
    with keys: { "kernel:oog", "kernel:storage_exhausted", ... }
  
  [Slots for gas]
  Cap::Instance[Gas{root_meter_key}]
  
  [Slots for storage]
  Cap::Instance[Quota{root_quota_key}]
  
  [chain-specific genesis caps, etc.]
```

The kernel (bottom of the stack) is the implicit ROOT YieldReceiver for
every `kernel:*` yield_key; the chain's own YieldReceiver registers the
exhaustion keys so the kernel's OOG/exhaustion yields route to it. From
here, chain bytecode does whatever chain spec defines.

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

3. **Meter_id / quota_key assignment — chain-chosen.** The kernel
   has no persistent state across blocks, so it cannot maintain a
   monotonic counter or any other unique-id scheme on its own. Id
   assignment is therefore chain's responsibility; kernel:mint_gas /
   kernel:mint_quota take the chain-supplied id as input. Collisions
   silently alias to the same meter/quota — chain is responsible
   for uniqueness within its own policy (this is fine: chain is the
   only holder of the kernel:mint_gas/kernel:mint_quota YieldSenders
   anyway).

4. **OOG yield payload — only `Cap::Instance[Gas{meter_key}]`.** See
   "OOG payload" section above. Deliberately minimal: no caller
   context, no call-stack info. Encoding "which call ran out"
   would reintroduce CALLER into a cap-only system, which v3
   structurally avoids. The meter_key is sufficient — chain looks
   it up in GasLedger. Same shape for StorageExhausted.

5. **Storage quota at block start — chain-spec constant +
   kernel:set_storage_quota.** Kernel initializes
   `quotas = { root_quota_key: <chain-spec block budget> }` at block
   start; everything else is chain-populated lazily by emitting
   kernel:set_storage_quota, analogous to gas. Same lazy-load +
   exhaustion-catch pattern.

6. **Reuse of meter_keys across blocks — chain's call.** Since
   meter_keys are chain-chosen, this is purely chain policy. A
   chain that wants persistent gas semantics will reuse meter_keys
   across blocks (deterministic mapping from user → meter_key). A
   chain that wants fresh-per-block can do that instead. Kernel
   doesn't care; meter_keys are opaque numbers from kernel's view.

7. **Read access to GasMeter for inspection — deferred.** The
   current design exposes only write access via kernel:set_gas_meter
   (which returns the previous value, enabling read-while-write
   for the harvest pattern). Pure read access is not provided.
   If a concrete need arises later (e.g., chain wants to inspect
   without disturbing), add a `kernel:query_meter` read-only
   yield_key then. Not adding speculatively.

8. **`set_image` on kernel-assisted Instances — structurally
   impossible.** Kernel-assisted Instances run native kernel code,
   not bytecode. They never execute `set_image` (no bytecode to
   issue the host call). The question is moot: there is no
   execution context that could trigger an image change on a
   kernel-assisted Instance.

## Relationship to other docs

- **top-level spec §1** (Image): yield_receiver_slot field; Image declares
  gas_slots and quota_slots for kernel debiting.
- **top-level spec §3** (Instance state machine + kernel call stack): the
  kernel-internal call stack underlies the yield routing
  (owner-edge snapshot + single-resumer).
- **top-level spec §4** (Kernel ABI): the scratchpad `kernel:*` YieldSenders
  (kernel:set_gas_meter, kernel:mint_gas, kernel:mint_yield, etc.)
  appear here.
- **top-level spec §8** (Cap kinds): kernel-assisted Instances are regular
  Cap::Instance; no new cap kind needed.
- **top-level spec §14** (Authority via capability flow): the authority
  pattern uses a YieldSender held inside the authority cap, caught by
  a registered YieldReceiver.
- **top-level spec §15, §16** (AA, MintInstance): instances of the authority
  pattern.
- **userspace/generic-authority-pattern.md**: pattern doc for
  authority caps; uses the YieldSender/YieldReceiver mechanism.
- **principles/data-flow-principle.md**: architectural derivation;
  kernel-assisted Instances live within the data-flow / hierarchical
  invocation discipline.

## Summary

> **Kernel resources are exposed via the Instance abstraction with
> kernel short-circuit. Instance-level uniformity is preserved; kernel
> implementation freedom is preserved. Per-Instance routing rights
> (YieldSender/YieldReceiver) live in user Instances' cnodes; kernel-
> internal resources (GasMeter, StorageQuota) live at the kernel level
> and are accessed only by emitting kernel-reserved yield_keys. Unit
> handles (Gas, Quota) are regular Cap::Instances naming entries in the
> kernel-internal tables. Conservation is structural via the kernel-
> internal tables — no narrow linearity is needed. Persistence is
> entirely in chain σ; kernel is stateless across blocks. Lazy load
> via kernel:oog-catch handles persistent state at scale.**

This pattern unifies what would otherwise be ad-hoc kernel APIs
(yield routing, gas, storage, future kernel resources) into a single
shape. The kernel-to-chain interface stays small (a scratchpad CNode of
`kernel:*` YieldSenders plus the kernel as implicit root YieldReceiver);
chain controls all higher-level policy.
