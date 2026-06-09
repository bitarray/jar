# Owner-edge yield routing

This note records the routing rule that follows from the data-flow
principle: a child can return control and data to its owner, but it must
not gain control over its owner.

## Core rule

When `A CALL B`, the kernel creates an owner edge `A -> B`.
The edge carries a snapshot of A's current `YieldReceiver`. That
snapshot is the authority A offers to B's subtree for this one call.

The owner edge is backed by a real ownership move. The `Cap::Instance`
for B is removed from A's CNode slot and placed in B's KernelFrame. While
B is live on the kernel stack, the origin slot is empty but
kernel-reserved. A cannot CALL, copy, move, drop, read/type-query, or
overwrite that slot until B returns or is discarded. The reservation is
stack metadata, not a `Pending` CNode value, and is never persisted.

`YIELD` follows owner edges:

1. Start at the logical current InstanceEntry. If the top stack entry is a
   `ReferenceEntry`, first resolve it to the InstanceEntry it references.
2. Inspect the current node's owner-edge snapshot.
3. If the snapshot contains the yielded key, push a `ReferenceEntry` to
   that owner and transfer control there.
4. Otherwise continue to the owner and repeat.
5. If no owner edge catches, the yield is unhandled (or, for `kernel:oog`,
   bubbles to the host/root policy).

There is no "skip the emitter's frames" rule. The physical stack is an
execution device, not the data-flow authority graph.

## Reference entries do not create ownership

Consider:

```
A CALL B
B YIELD to A
A CALL C while B is still waiting
```

The physical kernel stack is:

```
A -> B -> ref[A] -> C
```

The owner edges are:

```
A -> B
A -> C
```

`ref[A]` reactivates A. It does not make B the owner of A, and it does
not make B the owner of C. Therefore:

- C's yield starts from the `A -> C` owner edge.
- A's later yield or OOG starts from A itself.
- B can never catch A's or C's yield merely because B is physically below
  `ref[A]` on the stack.
- B's origin slot in A remains empty-reserved while B is waiting, so A
  cannot re-CALL or copy B by using the old slot; A must `CALL_RESUME`
  the waiting continuation or discard it.

This preserves the data-flow principle: B can return control to A, but B
cannot install itself as a handler for A's future control flow.

## Gas and OOG

OOG is a yield of `kernel:oog`, so it follows the same owner-edge routing
rule after gas sources are exhausted.

For an Image with declared `gas_slots`, the kernel consults slots in
order:

- Empty slots are skipped.
- A present non-Gas slot is a hard fault.
- The first valid non-empty slot is the primary meter.
- Later valid slots are fallback reserves.
- If every declared slot is empty, the declaration hard-faults because
  there is no primary Gas cap to carry in an OOG payload.

When all usable meters are exhausted, the OOG payload is the primary
usable `Gas{meter_key}` handle. On `CALL_RESUME`, execution retries from
that primary meter so a top-up of the payload meter is deterministic.

## Single-stack implementation

The implementation can keep one physical stack. It only needs to record
the owner edge explicitly on entries:

```
StackEntry {
  target: InstanceEntryIndex,       // what this entry runs
  owner: Option<InstanceEntryIndex>,
  origin: Option<(owner, SlotPath)>,
  owner.pending_origins: Set<SlotPath>,
  owner_catch_set: Set<Key>,        // snapshot for owner -> this
  gas_scope: ordered usable meters,
}
```

On CALL from a `ReferenceEntry`, the logical owner is the reference's
`target`, not the reference entry itself. That is what gives
`A -> B -> ref[A] -> C` the correct owner graph: `A -> B` and `A -> C`.
