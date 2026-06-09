---
title: Cache determinism and the eager-at-CALL charge
linkTitle: Cache determinism
weight: 7
---

# Cache determinism and the eager-at-CALL charge

Why category-#3 charges read-only page-in (and JIT compile) **eagerly, at the
CALL**, while the implementation stays **fully lazy / demand-paged** — and why
that split is forced, not a convenience. This is the design record behind
[gas-cost.md §3](../gas-cost.md); read that for the normative rules.

## The one principle: gas is a function of committed state, never of cache

A node may cache anything that is a pure function of inputs: the **compiled
code** for an Image, the **page table** for a frame, the **resident pages** of
a DataCap. These caches are *node-local* — two honest nodes can hold different
subsets at any instant (different histories, different eviction, a node that
just restarted). So a consensus gas charge **cannot read cache state**, in
either direction:

- it cannot *charge* for a cache miss (a node that missed would charge more
  than one that hit — a fork), and
- it cannot *discount* for a cache hit (same fork, mirrored).

The only quantity every node agrees on is the **committed-state delta** the
operation produces. So gas is defined on that:

| operation | committed-state delta | charge |
|---|---|---|
| read (load) | none — σ unchanged | **0** |
| JIT compile of a callee | none — a pure function of the Image | a fixed function of the **Image** (charged every CALL) |
| read-only page-in | none — the region is immutable | a fixed function of the **Image** (charged at the CALL) |
| copy-on-write (first write) | a new dirty page → a new content-addressed page at the periodic state root | per page, **depth-aware** |

A read being free is therefore not a concession — it is **forced and sound**:
a read changes nothing committed, and the fetch cost is node-local and
non-deterministic, so zero is the only deterministic charge consistent with a
node-local cache. The whole of the eager-at-CALL design falls out of taking
this principle seriously for the *write* and *compile* sides too.

## Why read-only page-in cannot stay a lazy fault charge

The previous model charged read-only page-in lazily, at the first-touch fault.
That is incompatible with the thing we actually want: **caching the page table
with the instance** so a re-CALL into a warm instance is fast.

The mechanism for a lazy page-in charge *is* the not-present fault — the fault
is the charge signal. But a warm cached page table has the present bits
**already set**, so a read does not fault, so there is **no signal to charge
on**. To restore the signal you would have to clear the present bits every
frame — which re-faults every read and **destroys the read cache you just
built**. Concretely:

> Lazy fault-driven read-only page-in and a persistent page-table cache are
> mutually exclusive.

If you want the page-table cache, the read-side charge has to move off the
fault to a point that is *independent of whether the fault fires* — and the
only such point that is still a deterministic function of the Image is the
**CALL** (or an `MGMT_MOVE` that maps a fresh cap). Hence: eager, static,
at the CALL.

## The read/write asymmetry is principled, not arbitrary

Writes stay lazy (CoW at the fault) but reads move to the CALL. The reason is
the cache mechanics, not taste:

- **Clearing the *writable* bit re-arms a write without disturbing the read
  cache.** The page stays present + read-only, reads keep hitting cache, only
  the next *write* re-faults. Cheap (`O(pages-written)`) and surgical — and it
  is exactly how the per-frame CoW charge is re-armed at HALT.
- **There is no equivalent for reads.** Re-arming a read means clearing
  *present*, which re-faults *everything* and kills the cache.

So writes can be metered per-frame at the fault (re-arm the W bit, recharge the
CoW), while reads must be metered once, up front, at the CALL. The two halves
of #3 land in different places because the hardware lets you cheaply re-arm one
and not the other.

(Aside — is the eager re-charge expensive? No: read-only page-in clusters per
**2 MiB unit**, and `page_in_cost` prices the *map event*, not the bytes. An
8 MiB read-only footprint is 4 units, not 2048 pages, so re-charging the
declared units on every CALL is small. The "overcharge" of charging declared
rather than touched units is the deterministic price of the up-front charge.)

## Finding A — the CoW charge must be merkle-depth-aware (the "merkle bomb")

A CoW write's real cost is not the 4 KiB copy — it is the **re-hash** of the
dirtied page into the periodic state root, which is `O(merkle_depth)` of the
page's DataCap (recompute the leaf and every node up to the root). A flat
per-page `cow_cost` undercharges a write to a **deep** DataCap by ~the depth:

> Build a maximally-deep DataCap and scatter one-byte writes across distinct
> pages. Each write costs `O(1)` to charge but `O(depth)` to re-hash — an
> undercharge of ~20–32× (the depth).

Fix: `cow_cost(depth) = cow_cost_base · merkle_depth_multiplier`, with
`depth = ceil(log2(page_count))`. The depth is **statically bounded** by the
slot's `memory_mappings` size (a cap mapped into a slot satisfies
`cap.size ≤ mapping.size`), so it is a per-slot constant resolved at frame
setup and the worst-case reserve stays a static per-block constant.

## Finding B — kernel writes bypass the #PF and must be charged at the ecall

The contrapositive of the committed-state principle: **every** delta must be
charged once, by whatever mechanism produces it. The guest write-protect `#PF`
catches only *ring-3 guest* writes. The kernel writes guest memory through its
**own** mapping, with no write-protection and no fault:

- a host `ecalli` that writes its **output** into guest memory (e.g. a
  content-read host call) dirties N pages with no `#PF`;
- an `MGMT_MOVE` that maps a fresh DataCap into a slot makes new pages visible.

Those are real committed-state deltas, so their cost (per page, depth-aware,
like a CoW) must be charged **at the `ecalli` / MGMT op**, dynamically, in its
own gas block. The fault path cannot be the only #3 detector — a kernel-authored
write is invisible to it.

## The cold-fetch amplification, and why eager-at-CALL closes it

Dropping the read-side charge entirely (not moving it — *removing* it) would be
consensus-sound (reads have no delta) but opens a **node-liveness** hole that
consensus gas otherwise can't touch. The category-#2 footprint multiplier
prices *resident* cache-hierarchy latency (×1–4, capped at DRAM); it is blind
to a **cold fetch from storage** (~1000× a DRAM access, and growing ~`log(DB
size)` with LSM read-amplification). Without a read-admission meter:

> Pre-build a working set of distinct caps exceeding node RAM (one-time #4
> storage-quota cost ≈ RAM-sized). Then each block `MGMT_MOVE` a different cap
> into a slot and read it — repeated cold fetches at ~zero gas, converting a
> one-time quota into perpetual free cold-fetch I/O.

The `page_in_cost` per declared 2 MiB unit is precisely the lever that prices
"pull a region into the working set" by volume. Charging it at the CALL **and
at `MGMT_MOVE`** (per the new cap's declared units) is what shuts this down: a
move-then-read of a large cold cap now costs gas proportional to its read-only
units. (This is also why finding B's `MGMT_MOVE` charge matters: without it the
amplification re-opens through the move even with eager-at-CALL.)

The remaining tail — `page_in_cost` is a constant calibrated for a target DB
size, while real fetch cost drifts up ~`log(DB)` as state bloats — is systemic,
not attacker-targeted, and is addressed by **#4 storage quota** (price
being-in-state → bound DB growth) plus periodic re-calibration, never by
dropping the per-unit charge (which would make the same drift *unbounded*
instead of logarithmic).

## Dependency: this soundness assumes no per-block witness

Free reads are sound **because** the chain commits a state root only
periodically (e.g. per minute), so a read enters no per-block commitment: it
neither dirties the tree nor adds to a witness. If a future variant required
**stateless validation** (a per-block witness proving every read value), each
distinct page read would cost `O(depth)` witness nodes — a real, deterministic
per-read cost that *would* need charging, and the free-read design would have to
be revisited. The eager-at-CALL read charge is coupled to the periodic-root
(fatdb) model; that coupling is deliberate and should be re-examined if the
commitment cadence changes.

## Summary

- Gas = f(committed-state delta), cache-independent. Reads are free (forced,
  sound); CoW is the delta; compile + read-only page-in are fixed functions of
  the Image.
- Read-only page-in moves to the CALL because a persistent page-table cache
  suppresses the read fault — you cannot keep both lazy-RO-charge and the cache.
- The read/write split (eager RO at CALL, lazy CoW at faults) is forced by what
  the hardware lets you cheaply re-arm (the W bit, not the present bit).
- A (depth-aware CoW) and B (kernel-write charging at the ecall) close the two
  large undercharges; the per-unit page-in charge at CALL **and** `MGMT_MOVE`
  closes the cold-fetch amplification.
