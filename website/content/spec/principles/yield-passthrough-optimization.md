# Yield passthrough — performance optimization options

In v3, a yield is routed by `yield_key` along owner edges to the nearest
snapshotted `YieldReceiver` whose catch-list contains that key. An
Instance that did NOT register the key in the owner-edge snapshot for a
child is bypassed automatically, so containment is automatic — an
unregistered intermediate never sees the yield and has NOTHING to
propagate. The explicit passthrough loop is therefore only needed when an
intermediate DELIBERATELY interposed (registered the `yield_key` in its
own YieldReceiver for that child CALL) and, after validating, wants to
FORWARD by re-emitting the same YieldSender. The canonical pattern for
that opt-in mediation is a bytecode loop. This doc discusses the
optimization options for that loop. **None of these are in the main
spec; this is a forward-looking note.**

## The canonical passthrough pattern

An interposing Instance layer — one that registered a `yield_key` in
its YieldReceiver to mediate a descendant's yields of that key, but
wants to forward most of them on — writes the following loop after a
CALL:

```
-- self.slot[0] holds the scratchpad for outbound CALL (the args
-- the layer wants to send to child)

ret = CALL(child_slot, endpoint, gas_budget)
loop {
  match ret.status:
    HALT(value) =>
      -- self.slot[0] now holds child's reflected output
      return value
    Paused(yield_key) =>
      -- we only get here for keys we registered in our YieldReceiver;
      -- unregistered keys followed owner edges to the next receiver
      -- and never paused us.
      if we want to mediate this yield_key locally:
        handle the yield_key ...
      else:
        -- self.slot[0] holds child's request (reflected from yield).
        -- forward by re-emitting the same YieldSender; routing starts
        -- from our owner edge and reaches the next receiver down.
        host_yield(yield_sender_for[yield_key])
        -- on resume, self.slot[0] holds the response from the receiver.
        -- forward to child.
        ret = CALL_RESUME(child_slot, gas_budget)
    Faulted =>
      -- self.slot[0] holds whatever child had at fault
      handle fault
}
```

This works using only the existing kernel ABI (CALL, host_yield,
CALL_RESUME). No new primitives required. slot[0] threads the
scratchpad through each interposition level automatically (yield
reflects up to the registered receiver; CALL_RESUME moves down). Per
interposing layer cost: roughly 100ns (a few bytecode instructions per
iteration). For K=5 interposing layers: ~500ns total — well within
block-apply budget.

## When passthrough might become a bottleneck

This loop runs ONLY at the layers that deliberately interposed on the
key — registered it in their YieldReceiver and chose to forward it.
Layers that did not register the key are emitter-excluded and cost
nothing; the kernel jumps straight past them to the nearest receiver.
So K is the number of INTERPOSING layers for a given key, typically far
fewer than the stack depth. If chains routinely stack many interposers
that re-emit (e.g. layered virtualization of the same syscall key), the
cumulative cost could become measurable. Rough scaling:

- Per yield: K × 100ns where K is the number of interposing layers that
  forward the key (NOT the stack depth).
- Per block: (yields per tx) × (txs per block) × K × 100ns.

For typical chain workloads (hundreds of yields per block, K~3-5
interposing layers), this is well under 1ms — not a bottleneck.

If we find a workload where it is (deeply-nested orchestration that
stacks many forwarding interposers on a hot key), an optimization is
available.

## Optimization option: `call_passthrough` opcode

Note this opcode is only relevant to the interposition case — a layer
that registered a key purely to forward it. Containment (not registering
the key) already costs nothing, so there is nothing to optimize there.
Even for an interposer, the predicate cannot be a kernel-chosen
`reason`: the loop must decide per yield_key whether to forward, and the
set of keys this frame can forward is exactly the frame's registered
YieldReceiver. So the opcode's predicate is the frame's registered
`yield_key` set — the keys it locally mediates (and thus does NOT
forward) — and the kernel forwards the rest by re-emitting the matching
scratchpad YieldSender:

```
call_passthrough(child_slot, endpoint, gas_budget,
                 local_yield_keys) → ret

  Kernel internal:
    let ret = CALL(child_slot, endpoint, gas_budget)
    loop:
      match ret.status:
        HALT, Faulted => return ret
        Paused(yield_key):
          if yield_key ∈ local_yield_keys:
            return ret  -- bytecode wants to mediate this one
          host_yield(yield_sender_for[yield_key])
          ret = CALL_RESUME(child_slot, gas_budget)
```

Bytecode using it:

```
ret = call_passthrough(child, ep, gas, local_keys=MY_KEYS)
match ret:
  HALT(v) => use v
  Paused(yield_key) => mediate (must be in MY_KEYS)
  Faulted => handle fault
```

The kernel runs the loop without invoking bytecode. Cost per
interposing layer: ~10ns (state transition only).

For K=5 interposing layers: ~50ns total. ~10× faster than bytecode loop.

## Why not in the spec now

This is a peephole optimization. The bytecode loop works correctly
and is performant enough for any realistic workload. Adding the
opcode is straightforward if/when profiling shows a need.

- **No correctness benefit.** Same semantics either way.
- **Negligible practical cost.** Bytecode loop adds ~500ns to typical
  interposition chains. Block budgets are seconds; this rounds to zero.
- **ABI minimalism.** One more opcode is small, but every opcode
  added is one more thing to verify, document, and maintain.
- **Adoption discipline.** If we add the opcode, chains must opt in
  per CALL site. They might forget; performance varies based on
  bytecode discipline. With bytecode loop, the cost is uniform and
  predictable.

## Alternative considered: Image-flag `auto_forward`

An earlier draft considered an Image-level declaration:

```
Image {
  ...
  auto_forward: Set<yield_key>   // keys this Image auto-forwards
}
```

For these keys the kernel re-emits without invoking bytecode; the
forward is kernel-fast.

Trade-offs:

- **Declarative**: per-Image policy stated once.
- **But static**: the same Image can't mediate key K for some sub-calls
  while forwarding it for others.
- **Image author burden**: every Image needs to think about which keys
  it forwards.

We chose against this in favor of per-CALL granularity (either via
bytecode loop or via `call_passthrough` opcode). The bytecode pattern
gives the Image author full runtime flexibility; the kernel doesn't
need an Image-level field. The per-CALL YieldReceiver snapshot already
makes the forward-vs-mediate split a runtime decision — a static
Image-level set would be strictly less expressive.

## When to revisit

Add `call_passthrough` opcode when:

- Profiling shows interposition-forwarding overhead is a measurable
  fraction of block apply time.
- Chain authors are routinely writing the same forwarding-loop
  boilerplate and errors arise from getting it wrong.
- A common chain pattern (e.g., deep interposer hierarchies that stack
  forwarders on one key) emerges and we want to make it fast by default.

Until then: bytecode loop is the canonical pattern. Document it in
the userspace coding guide when we write one.
