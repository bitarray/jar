# Call-stack memory bounds via cap nesting depth

How the in-kernel call stack is bounded — and why the bound belongs on the
**cap graph's nesting depth, enforced at move-time**, not on a runtime
eviction cap or a call-time depth check.

This doc covers the recompiler's per-frame memory anatomy, the
"fault-is-permanent → enforce at extension, not at use" principle, and the
target design (composable cap depth). It is the source of truth for *why*
`RUNTIME_CACHE_CAP` / runtime eviction was removed and what replaces it.

Companion: [kvm-microkernel.md](kvm-microkernel.md) (the microkernel itself),
[../gas-cost.md](../gas-cost.md) (category-#3 materialization, which the
per-frame `mat_state` tracks).

## Background: what a call-stack frame costs

The in-kernel CALL/HALT loop (`nub-arch-x86::call_loop`) drives sub-VM
recursion: a frame `derive_spawn`s a child instance into a cnode slot and
`host_call`s it; the parent is **suspended** (its state pushed on an in-memory
`Vec<KernelFrame>`) until the child HALTs. Each live stack level is one
`KernelFrame`. A frame's memory splits into two very different halves:

| half | what it is | size | grows with |
|------|------------|------|------------|
| **`FrameRuntime`** | the ring-3 **page table** (PML4 + the PML4[0] demand-paging intermediates) | ~24 KiB (typical small guest) | the guest's touched 2 MiB regions |
| **`KernelFrame` residue** | `mem` overlay (CoW dirty pages) + `mat_state` (category-#3 per-page **CoW** write state) + cnode + regs/hashes | ~0.5–4.5 KiB today; O(working set) in general | pages written |

The page table is the only **trivially reconstructable** per-frame resource: a
*suspended* frame doesn't need its ring-3 page table at all (only the running
frame's CR3 is live), and rebuilding it on resume is cheap (zero-setup demand
paging rebuilds it fault-by-fault). The residue is the frame's actual working
state and is *not* reconstructable.

**Realized (page-table cache across CALLs).** Because the page table is
reconstructable it is also safely *cacheable*: rather than dropping it at a
child's HALT, the kernel parks the `FrameRuntime` with the resident `Owned`
sub-VM (in the parent frame, keyed by cnode slot, paired with the cap whose
overlay it maps) and a re-CALL of the same instance reuses the whole table
instead of rebuilding it fault-by-fault. Determinism is preserved by re-arming
at HALT — clearing the *writable* bit on each CoW'd leaf so the next CALL's
first write re-faults and re-charges exactly one `cow_cost` per page, identical
to a fresh frame (the W-bit re-arm of
[cache determinism](../principles/cache-determinism-and-eager-call-charge.md)).
A re-CALL into a warm instance then allocates nothing but the small
`KernelFrame` residue. (The suspend/resume rebuild above still applies when a
runtime is *reclaimed* under memory pressure — a different axis from the
same-frame parent↔child CALL round trip.)

(The read-only page-in cost is **not** part of the residue: it is computed on
the fly at the CALL from the static Image — `Image.code` length plus the
pinned/RO `memory_mappings`, clustered per 2 MiB unit — and charged to the
caller. There is no stored per-frame RO-charge state; `mat_state` tracks only
CoW per-page write residency.)

### How this compares to an OS task

A resident frame (~24–30 KiB) is squarely in OS-task territory: roughly a Linux
thread's kernel stack + `task_struct` (~25 KiB), or a minimal process's page
tables (~16–40 KiB). The structural point is less comfortable, though: we pay a
**process-like cost (its own page table) per *call-stack frame*** — because PVM
addresses are native VAs (`DATA_BASE`/`CODE_BASE` fixed, baseless `[reg]`
access), two frames running different images cannot share an address space;
each needs its own CR3 mapping `DATA_BASE` → its own pages. So an N-deep
synchronous recursion is closer to **N forked processes than N function calls**.
A Linux thread shares one address space — N-deep *function* recursion costs only
stack frames (tens–hundreds of bytes each), zero extra page tables.

That asymmetry is the entire reason a depth bound is load-bearing: the
expensive axis is *synchronous-call nesting* (page tables), and it must be kept
small.

## The eviction cap was bounding the wrong (and minor) half

`RUNTIME_CACHE_CAP` (256, later 512) bounded the number of *resident*
`FrameRuntime`s, evicting a paused frame's page table once it fell outside the
window and rebuilding it on resume. The implicit assumption — true only for the
benches — is that the page table dominates per-frame memory. It does for a small
guest (residue ~0.5–4.5 KiB vs a 24 KiB table). But:

- The cap bounds the page tables (the *reconstructable, fixed-size* half) and
  leaves the **residue uncapped** (the overlay working set + dense `mat_state`,
  which is what actually scales with depth × instance size).
- `FrameRuntime` is **capped** (≤ N resident, flat); `KernelFrame` is
  **uncapped** (one per live level, up to `MAX_DEPTH`). With 64× more frames than
  resident runtimes at max depth, the aggregate residue overtakes the capped
  page-table pool — at *shallow* depth for a large instance (a 256 MiB instance's
  dense `mat_state` alone is 64 KiB/frame, > the 24 KiB table, and uncapped).

So eviction solved a narrow case (deep recursion of *small* instances) and added
real machinery — a recharge-correctness hazard in particular. Evicting +
rebuilding a frame resets its category-#3 materialization state, so a resumed
frame would **re-charge** CoW gas for pages it already wrote, forking the
never-evicting interpreter. (RO page-in is no longer fault-charged — it is
accounted at the CALL — so there is no RO re-charge hazard.) That was fixed
(gas state moved to the
eviction-surviving `KernelFrame` + `reestablish_after_rebuild` re-maps on rebuild
charging nothing), but the fix only exists *because* eviction exists. Remove
eviction and the whole class of hazard + machinery goes with it.

## The real bound: cnode nesting depth, enforced at move-time

The clean model has **two populations** with **two structural limits**, both
checked at the point of structural extension:

| population | cost each | limit | bounded resource |
|------------|-----------|-------|------------------|
| **synchronous `host_call` nesting** | ~24 KiB (page table) | **small** (~10²) — the cnode recursion depth | resident page tables |
| **yield/resume continuations** | ~200 B (a reference to a prior item) | **large** — its own chain limit | cheap reference memory |

Synchronous `host_call` can only descend the cnode/CSpace (the data-flow
principle: effects follow explicit capability data flow). If the cnode graph's
nesting depth is bounded, the synchronous call stack is bounded with it — so the
page-table-bearing population is structurally small and **no eviction is
needed**: keep the few hundred page tables resident, period. Unbounded "logical"
recursion is expressed as yield/resume continuations — references to existing
items, not fresh MMU contexts — bounded separately and cheaply.

### Enforce at the MOVE, never at the CALL — because faults are permanent

In this model a PVM fault is **terminal** (no recovery, no unwinding). That
dictates *where* the limit is enforced:

> **Every limit must be enforced at the point of structural extension
> (move / mint / push), never at the use site (call / resume) — so that use is
> total.**

A limit checked at **use** is a non-local, dynamic landmine: a `host_call`'s
depth depends on how its caller was reached, which the callee cannot see, so it
cannot defend against it — the limit surfaces as an unpredictable *permanent
fault*. It also breaks the contract *"if you hold a valid instance in a slot,
calling it works."*

A limit checked at the **move** is a local, structural property of the operand
in hand, and it lands on an operation that **already has a failure surface**
(move/`derive_spawn` already rejects e.g. a pinned-slot write — the recompiler
traps on that today). "Recursion depth exceeded" extends that existing error
mode rather than minting a new one; `host_call` keeps its clean
always-succeeds-on-a-held-cap contract because the structure was validated when
it was built.

### Caps must carry a composable depth

For the move-time check to be correct it cannot be a simple `+1`. Moving a
cnode/instance subtree of depth `K` into a slot at nesting depth `D` yields depth
`D + K`. So **every cap carries its own recursion depth as a tracked field,
composed at construction**, and the move rule is:

```
parent_depth + moved_subtree_depth ≤ CNODE_DEPTH_LIMIT
```

This makes the depth bound a **data-structure invariant** (the cnode analogue of
a height-balanced tree, and very seL4: the guard/radix layout *is* a structural
cap on addressing depth, enforced at cap-op time, never at invoke). Two
properties make it well-defined:

- **Composability.** `derive_spawn` of a fresh child is `parent_depth + 1`;
  moving an arbitrary subtree composes `D + K`. Depth is computed once at
  construction and read at each move.
- **Acyclicity is free.** Depth is only well-defined on a DAG — and a
  content-addressed cap cannot contain itself (you would need its hash before
  computing it), so the cnode graph is acyclic by construction. No cycle
  detection is needed.

### The "up to spec" gap this depends on

The current recompiler shape does *not* yet give the bound: `derive_spawn`
stores the child inline (`CapHashOrRef::Owned`) and `dispatch_host_call`
inherits the parent's cnode as a **flat copy** (it doesn't nest), so recursion
nests synchronous frames on a flat cnode with no structural ceiling — only the
crude global `MAX_DEPTH` stands between it and OOM. The target requires:

1. `derive_spawn` becomes a real **nesting move**: it modifies a cnode slot,
   building a sub-cnode/sub-instance one level deeper, and the subsequent
   `host_call` descends into it.
2. Caps gain the **composable depth** field, set at construction.
3. The **move** path (`set_key` / `derive_spawn`) checks
   `parent_depth + moved_depth ≤ CNODE_DEPTH_LIMIT` and rejects past it — next to
   the existing pinned-slot rejection.
4. Yield/resume gets its own (large) continuation-chain limit, enforced at the
   push, by the same principle.

`CNODE_DEPTH_LIMIT` is then *the* synchronous depth bound, sized from the
page-table budget (e.g. a few hundred → a few MiB of always-resident page
tables). It supersedes the global `MAX_DEPTH` for the synchronous axis.

## Interim state (after removing eviction, before the cnode-depth limit)

Eviction / `RUNTIME_CACHE_CAP` is **removed now**; the cnode-depth limit is
future work. In between:

- A `FrameRuntime` is built once per frame (lazily, on first entry) and reused
  across re-entries (parent resume after a child HALT) — the original caching;
  only the *eviction* (dropping it under depth pressure) is gone. No rebuild ⇒
  `reestablish_after_rebuild` is dead and removed.
- The only depth backstop is the global `MAX_DEPTH` (32768), and — bluntly — it
  **does not actually engage as a graceful cap.** Without eviction, `32768 ×
  ~24 KiB ≈ 768 MiB` of page tables ≫ the 256 MiB heap, so a deep recursion
  exhausts talc inside `build_runtime → PageTable::new()` and **talc OOM panics
  (a guest-wide abort), long before `stack.len() ≥ MAX_DEPTH` is ever reached.**
  So the interim behaviour is "works to ~9000 deep, then aborts," not "returns
  `ERR_DEPTH_LIMIT` at 32768." The `~9000` figure is below the `256 MiB /
  24 KiB ≈ 10900` pure-page-table ceiling because the `KernelFrame` residue
  (overlay, `mat_state`, cnode) plus the never-evicting JIT cache + `MEM_CACHE`
  compete for the same heap. This is acceptable as an interim only because **no
  current workload approaches even depth 1000** — but it *is* a real narrowing
  of the failure envelope versus the eviction era (which capped page tables at
  ~12 MiB and ran fine to 32768). The proper fix is exactly this doc's design:
  the **move-time cnode-depth limit rejects gracefully at construction** (faults
  are permanent, so a use-time abort is the wrong shape); it supersedes
  `MAX_DEPTH`. (Aside: `PageTable::new()?` already maps an allocation failure to
  `ERR_JIT_FAILED`, so if talc returned `None` instead of panicking, even the
  interim OOM would surface as a clean error rather than an abort.)
- **`mat_state` stays on `KernelFrame`** (not moved back onto
  `FrameRuntime`), even though nothing evicts today. It is the category-#3 **CoW**
  write *history* — path-dependent, not reconstructable, and must outlive any
  future reclamation of the runtime. (The RO page-in cost is not stored at all —
  it is recomputed at each CALL from the static Image — so it has no per-frame
  home to defend.) Keeping `mat_state` on the non-reclaimable `KernelFrame`
  is the swap-aligned home (below); moving it back would be undone by the swap
  work.

## Forward: the cap-swap end-state subsumes all of this

The ultimate direction (not implemented) is host-backed **swap**: DataCap pages,
CNode slots, JIT artifacts, and page tables are all reclaimable under memory
pressure — flush/merkle/persist-to-host and refetch-on-fault — even for a
*running* instance. Under that model:

- Runtime-eviction is just a degenerate special case of swap (reclaim a
  reconstructable resource, recreate on access). `reestablish_after_rebuild` was
  exactly its primitive: *reclaim the resource, keep the gas history, re-map
  without re-charging on next touch.* That pattern is the **swap refetch
  primitive** — recorded here so it is not lost when the dead-now code is
  removed.
- The only **irreducibly non-swappable** per-suspended-frame state is then (a)
  the stack-spine scalars (regs, pc, a few hashes — ~200 B) and (b) the
  category-#3 **CoW** write history (`mat_state`). (RO page-in is not per-frame
  state at all — it is computed at the CALL from the Image — so it never enters
  this swap budget.) (b) is the design constraint:
  it cannot be dropped (dropping it re-introduces the recharge fork) and is
  currently **dense** (`O(extent)`). It is fine today (current guests have small,
  contiguous extents → tens of bytes), but the swap design wants it **sparse**
  (`O(pages touched)`), so per-frame irreducible state scales with the true
  working set rather than the declared extent.

So the memory limit ultimately wants to be `depth × (spine + sparse mat_state)`,
with everything else swappable — and the cnode-depth limit (synchronous) +
continuation limit (yield) are the two structural ceilings that keep `depth`
itself bounded. Every one of those limits is enforced at structural extension,
never at use.

## TODO checklist

- [ ] `derive_spawn` becomes a nesting move (modify cnode slot → `host_call`).
- [ ] Composable `depth` field on caps (cnode/instance), set at construction.
- [ ] Move-time `parent_depth + moved_depth ≤ CNODE_DEPTH_LIMIT` check (next to
      the pinned-slot rejection).
- [ ] Size `CNODE_DEPTH_LIMIT` from the page-table budget; retire `MAX_DEPTH` for
      the synchronous axis.
- [ ] Yield/resume continuation-chain limit, enforced at the push.
- [ ] Sparse `mat_state` (`O(pages touched)`), prerequisite for the
      swap budget to close.
- [ ] (Swap, later) generalize the `reestablish` primitive to refetch-on-fault.
