# Yield passthrough — performance optimization options

In v3, when an Instance in the middle of a CALL stack receives a yield
from below that it doesn't want to handle, it must propagate the
yield upward. The canonical pattern is a bytecode loop. This doc
discusses the optimization options for that loop. **None of these
are in the main spec; this is a forward-looking note.**

## The canonical passthrough pattern

An Instance layer that wants to propagate yields it doesn't handle
writes the following loop after a CALL:

```
-- self.slot[0] holds the scratchpad for outbound CALL (the args
-- the layer wants to send to child)

ret = CALL(child_slot, endpoint, gas_budget)
loop {
  match ret.status:
    HALT(value) =>
      -- self.slot[0] now holds child's reflected output
      return value
    Paused(reason) =>
      if reason ∈ MY_HANDLED_REASONS:
        handle the reason ...
      else:
        -- self.slot[0] holds child's request (reflected from yield).
        -- yield, propagating slot[0] up to our caller.
        host_yield(reason)
        -- on resume, self.slot[0] holds the response from our caller.
        -- forward to child.
        ret = CALL_RESUME(child_slot, gas_budget)
    Faulted =>
      -- self.slot[0] holds whatever child had at fault
      handle fault
}
```

This works using only the existing kernel ABI (CALL, host_yield,
CALL_RESUME). No new primitives required. slot[0] threads the
scratchpad through each cascade level automatically (yield reflects
up; CALL_RESUME moves down). Per cascade layer cost: roughly 100ns
(a few bytecode instructions per iteration). For K=5 cascade depth:
~500ns total — well within block-apply budget.

## When passthrough might become a bottleneck

This loop runs at every layer between yield originator and handler.
If chains routinely have deep call stacks with many yields per CALL,
the cumulative cost could become measurable. Rough scaling:

- Per yield: K × 100ns where K is cascade depth.
- Per block: (yields per tx) × (txs per block) × K × 100ns.

For typical chain workloads (hundreds of yields per block, K~3-5),
this is well under 1ms — not a bottleneck.

If we find a workload where it is (deeply-nested orchestration with
high yield frequency), an optimization is available.

## Optimization option: `call_passthrough` opcode

A single new opcode that does the loop in kernel-internal code,
skipping bytecode execution:

```
call_passthrough(child_slot, endpoint, gas_budget,
                 handled_reasons_bitmap) → ret

  Kernel internal:
    let ret = CALL(child_slot, endpoint, gas_budget)
    loop:
      match ret.status:
        HALT, Faulted => return ret
        Paused(reason):
          if reason ∈ handled_reasons_bitmap:
            return ret  -- bytecode wants to handle this one
          host_yield(reason)
          ret = CALL_RESUME(child_slot, gas_budget)
```

Bytecode using it:

```
ret = call_passthrough(child, ep, gas, handled_reasons=MY_REASONS)
match ret:
  HALT(v) => use v
  Paused(reason) => handle (must be in MY_REASONS)
  Faulted => handle fault
```

The kernel runs the loop without invoking bytecode. Cost per layer:
~10ns (state transition only).

For K=5 cascade: ~50ns total. ~10× faster than bytecode loop.

## Why not in the spec now

This is a peephole optimization. The bytecode loop works correctly
and is performant enough for any realistic workload. Adding the
opcode is straightforward if/when profiling shows a need.

- **No correctness benefit.** Same semantics either way.
- **Negligible practical cost.** Bytecode loop adds ~500ns to typical
  cascades. Block budgets are seconds; this rounds to zero.
- **ABI minimalism.** One more opcode is small, but every opcode
  added is one more thing to verify, document, and maintain.
- **Adoption discipline.** If we add the opcode, chains must opt in
  per CALL site. They might forget; performance varies based on
  bytecode discipline. With bytecode loop, the cost is uniform and
  predictable.

## Alternative considered: Image-flag `auto_propagate`

An earlier draft considered an Image-level declaration:

```
Image {
  ...
  auto_propagate: BitSet<reason_id>   // reasons this Image auto-propagates
}
```

Kernel skips bytecode for these reasons; cascade is kernel-fast.

Trade-offs:

- **Declarative**: per-Image policy stated once.
- **But static**: same Image can't intercept reason R for some sub-calls
  while propagating it for others.
- **Image author burden**: every Image needs to think about which
  reasons it passes through.

We chose against this in favor of per-CALL granularity (either via
bytecode loop or via `call_passthrough` opcode). The bytecode pattern
gives the Image author full runtime flexibility; the kernel doesn't
need an Image-level field.

## When to revisit

Add `call_passthrough` opcode when:

- Profiling shows cascade overhead is a measurable fraction of block
  apply time.
- Chain authors are routinely writing the same loop boilerplate and
  errors arise from getting it wrong.
- A common chain pattern (e.g., deep orchestrator hierarchies)
  emerges and we want to make it fast by default.

Until then: bytecode loop is the canonical pattern. Document it in
the userspace coding guide when we write one.
