---
title: Gas and resource cost model
linkTitle: Gas cost
weight: 6
---

# Gas and resource cost model

A JAR invocation is metered along **four cost categories**, settled by
**two budgets**:

| # | category | real resource bounded | budget | charged when | specified in |
|---|----------|-----------------------|--------|--------------|--------------|
| 1 | **Execution** | CPU compute time | **gas** | per basic block, at block entry | [pvm2/gas-cost.md](pvm2/gas-cost.md) |
| 2 | **Memory-access latency** | cache-hierarchy pressure | **gas** | per basic block (a static multiplier folded into #1) | this doc |
| 3 | **Memory materialization** | copy-on-write / call-frame work | **gas** | per first-touch **write** (CoW, per page); read-only page-in + compile charged **eagerly at the CALL** | this doc |
| 4 | **State storage** | persistent σ growth | **storage quota** | at HALT (finalized when the Instance leaves the call stack) | this doc + [§2 of the spec](_index.md) |

Gas (#1–#3) bounds **block execution time** (the DoS / validator-payment
meter). Storage quota (#4) bounds **persistent state growth** (the
state-bloat / economic meter). They are independent budgets; a single
memory write may touch both (gas for the work, quota for the persistent
page) — that is not double-counting, because it pays for two different
real resources.

This document is normative for #2, #3, and the **charging discipline**
that ties all four together. #1 is specified by
[gas-cost.md](pvm2/gas-cost.md) (the single-pass
pipeline model + per-instruction cost table). #4 is summarized here and
detailed under "Storage cost via dirty-page tracking" in
[the spec §2](_index.md).

## 1. Charging discipline — per block, pre-reserved at entry

Gas is charged **per basic block, once, at block entry** — never
per-instruction, never mid-block. This is the property that lets the
recompiler emit one gas check per block instead of a check per
instruction, and it is the reason **a pause point is always a basic-block
start** (`Paused.pc ∈ bb_starts`; see [§3 "Paused.pc constraint"](_index.md)).

The block-entry check is a **pre-reservation**, not a charge:

```
at block entry B:
    let need = gas_cost(B)              # = #1 execution × #2 footprint multiplier
    let reserve = worst_case_3(B)       # = the block's maximum possible #3 (see §3)
    if  gas < need + reserve:
        OUT-OF-GAS yield                # gas UNCHANGED; B is NOT entered; continuation = start of B
    else:
        gas -= need                     # charge instruction cost only; `reserve` is a gate, not a charge
        execute B
        on each first-touch fault: gas -= actual_3   # guaranteed ≥ 0 (see invariant below)
```

**Invariant: gas never goes negative.** The entry gate guarantees
`gas ≥ need + worst_case_3 ≥ need + actual_3`, so the actual #3 debits
taken during the block can never drive gas below zero. There is no debt,
no signed-underflow, no mid-block out-of-gas.

**Out-of-gas is a recoverable yield, and it does not charge.** OOG fires
**only** at a block-entry gate, *before* any instruction of the block
runs. Because the block was not entered, **no gas is charged for it** —
its instructions were not executed. The captured continuation is the
start of the un-entered block; the kernel yields the `kernel:oog`
yield_key (caught by the chain's `YieldReceiver`, the `Gas{meter_key}`
payload reflecting via slot[0]), the chain typically tops up the meter by
emitting `kernel:set_gas_meter` and `CALL_RESUME`s, and the block is
re-attempted from its start (see [§4 OOG](_index.md)). The
gas already consumed by *prior, completed* blocks is what was debited;
the OOG block itself is free.

**A `reserve` is not a `charge`.** The block enters only if its
worst-case #3 *could* be afforded, but the meter is decremented only by
the instruction cost plus the #3 the block *actually* incurs. The unused
reserve is never consumed — it is purely the entry gate. (Consequence: a
near-limit program may OOG-yield "early" at a memory-heavy block whose
worst case it cannot cover even though it would have faulted few pages.
This is recoverable — a normal OOG top-up — and is a *provisioning*
matter, not an over-charge: provision the meter to cover the heaviest
block on the path and no such yield occurs.)

**Program faults are permanent and may occur mid-block.** A *hard fault*
(access to an undeclared address, wrong permission, write to a pinned
region — see §3) makes the Instance `Faulted`, dropped, never resumed
([§5](_index.md)). Because a faulted Instance is never re-entered, a hard
fault has no continuation and is therefore **not** subject to the
"pause only at a bb_start" rule — it may occur at any instruction. Only
*recoverable yields* (OOG, voluntary `host_yield`) must land on a
bb_start, because only they resume. This split — **faults mid-block,
yields at bb_start** — is what makes the discipline consistent.

**Two kinds of gas block.** The static pre-reservation above is the
discipline for *ordinary* blocks, whose cost is fully known at predecode.
`ecall`/`ecalli` are the exception — their cost is unknowable at compile
time (a CALL's callee, a host op's length) — so each forms its **own** gas
block with **no** static preamble, and the kernel charges it
**dynamically**. The discipline is identical (check before charge, OOG
before any work, gas never negative); only the cost is computed at runtime
rather than baked into a preamble. See "ecall/ecalli blocks" in §3.

## 2. Memory-access latency — a static footprint multiplier

Every load/store carries a base latency (`mem_cycles`, default 25; see
the LOAD/STORE rows of PVM2 gas-cost table). Larger
working sets cause more cache misses, so that latency is **scaled by a
footprint tier** chosen from the Instance's total accessible memory:

| accessible pages | memory | multiplier | `mem_cycles` | basis |
|------------------|--------|------------|--------------|-------|
| ≤ 2048 | ≤ 8 MiB | ×1 | 25 | fits L2/L3 |
| ≤ 8192 | ≤ 32 MiB | ×2 | 50 | L3 edge (≈2.2× measured) |
| ≤ 65536 | ≤ 256 MiB | ×3 | 75 | DRAM (≈3.3× measured) |
| > 65536 | > 256 MiB | ×4 | 100 | DRAM + headroom |

**Counting rule (must be bit-identical across engines).** "Accessible
pages" is the count of **distinct consensus 4 KiB pages** in the
Instance's declared address space: the union of every declared
`memory_mapping`'s page range — Persistent *and* Ephemeral, pinned-RO
included, and counting zero-padded tail pages of an under-sized source
DataCap (`N < S`). It is a **count of pages, not bytes**; the tier
comparison is on that integer (the MiB column is derived,
`2048 × 4 KiB = 8 MiB`, etc.), so no byte/page rounding can diverge.
Overlapping mappings (if any) are counted once (distinct pages). The count
is taken once, from `Image.memory_mappings`, at predecode; tier boundaries
are **inclusive** (`≤`). Both engines compute it from the same Image, so
the resulting `mem_cycles` is identical.

Empirical basis: internal memory-gas measurements (`mem_seq`/`mem_rand`
benchmarks, 4 KiB→3 GiB), which descends from the same sources as Gray
Paper [#508](https://github.com/gavofyork/graypaper/pull/508) and the PVM
working-set proposal ([#531](https://github.com/gavofyork/graypaper/pull/531)).

**The multiplier is entirely static — zero runtime cost.** v3 memory is
**declared by the Image and fixed for the Instance's lifetime** (no
`grow_heap`; OOM is a fault — [§2 principle 5](_index.md)). The accessible
page count is therefore a constant, the tier is resolved once at compile
time, and it is **baked into each block's `gas_cost(B)`** at predecode.
At runtime the block-entry check subtracts a single precomputed
constant — there is no per-access probe, no working-set state, no LRU.
This is the deliberate divergence from Gray Paper #531's dynamic
working-set: #531 prices *actual access locality* (an LRU with a runtime
per-miss penalty); we price the *declared footprint* (a static
conservative upper bound). We trade locality-accuracy for a memory model
with no runtime metering cost, which a fast recompiler needs.

The multiplier is locality-blind (a tight hot loop in a large declared
mapping still pays its tier on every access). #3 below supplies the
locality-aware component (you pay materialization only for pages you
actually touch). In practice large state lives in the content-addressed
storage tier accessed by host calls, not in a large *mapped* region, so
the mapped footprint — and thus the multiplier — stays small.

Both engines derive the tier from the same declared footprint, so it is
deterministic.

## 3. Memory materialization — eager RO charge at the CALL, lazy CoW at faults

### What is charged where (a split between read and write)

Memory materialization is metered in **two places**, by what each
actually costs the committed state:

- **Read-only page-in + JIT compile → at the CALL** (eager, static). The
  cost of bringing a callee's read-only regions (its code and pinned
  DataCaps) into the working set, and of compiling its code, is a function
  of the callee **Image** alone — it changes nothing in committed state —
  so it is computed **statically from `Image.memory_mappings` + code size**
  and charged once, **at the CALL** that maps the callee (`call_frame_cost`,
  below). A read **at a fault charges nothing**.
- **Copy-on-write → at the fault** (lazy, per page). The first **write**
  to a writable page copies-on-write and is the **sole fault-driven #3
  charge**. It is the one materialization event that changes committed
  state (a new dirty page → a new content-addressed page at the periodic
  state root), so it is metered where it happens, per 4 KiB page.

### Lazy mapping (the *mechanism* is unchanged; only the gas attribution moved)

Mapped DataCap regions are still materialized **lazily, on first touch**,
not eagerly at apply start. At entry the region's pages are left
**not-present**; the first access faults into the kernel, which resolves
the page (reads: map the content-addressed page read-only; first writes:
copy-on-write the page read-write), then retries the instruction. This
demand-paging mechanism is unchanged — what changed is *gas attribution*:
the read-side page-in no longer debits at the fault (it was pre-charged at
the CALL), and only the CoW write debits there. The hardware page table's
**writable** bit is the first-write tracking, so the recompiler charges the
CoW at the fault with **no separate dirty bitmap**; the **present** bit's
first-read transition is recorded but free.

Architecturally this is "eager compile + eager RO-map charge at the CALL"
while execution stays fully lazy. The two need not agree on *timing* because
gas is defined on the **committed-state delta**, not on cache residency: a
read produces no delta (free, deterministically — see [§5](#5-determinism-and-consensus)),
a CALL's compile/RO-map is a fixed function of the Image (charged once,
regardless of whether a node's compile/page-table cache is warm), and a CoW
is the delta (charged per page). See
[principles/cache-determinism-and-eager-call-charge.md](principles/cache-determinism-and-eager-call-charge.md)
for why a node-local cache (compiled code, page tables, resident pages)
must never change the charge.

This stays within "no lazy paging" in the seL4 sense and preserves the
[lazy-validation discipline](pvm2/rv64e-xjar-eei.md#validation-model-structure-eager-semantics-lazy)
(structure validated eagerly at deblob, semantics validated lazily at
execution; code source: [`rust/javm-cap/src/cap/image.rs`](https://github.com/jarchain/jar/blob/master/rust/javm-cap/src/cap/image.rs)):
the faults materialize pages of an **already-declared** address space (an
access *outside* the declared `memory_mappings` is a hard fault, not a
lazy allocation), and both engines agree on exactly which accesses fault.
We materialize a fixed address space lazily; we never grow one — so
materialization adds no admission-time screening and leaves code lazily
validated.

### The two #3 events

- **First write to a writable page** → *copy-on-write*, charged **per 4 KiB
  page**: an unpinned / ephemeral page is paged in read-only on its first
  read (free — see below), and the first **write** allocates a working page,
  copies, and maps it read-write — one copy per page. CoW dirties the page
  (→ #4 at HALT). Writable pages are **not** clustered: a write does genuine
  per-page work. The CoW charge is **merkle-depth-aware** — see "Depth-aware
  CoW" below.
- **`ecall`/`ecalli` kernel work** → *call-frame / host-op
  materialization*: a CALL allocates a new call-stack frame and **materializes
  the callee** — JIT-compile its code, eagerly account its read-only page-in,
  set up its address space, push the frame; a host call may copy, mint, move,
  or **write output into guest memory**. This #3 is **unbounded at compile
  time** and is **not** part of any neighboring block's static reserve — it is
  charged **dynamically**, in the `ecall`'s own gas block, when the `ecall`
  executes. See "ecall/ecalli blocks" below.

**Dropped event — read-only page-in at the fault.** Pinned DataCaps and the
code region are no longer metered per fault. They are pinned (immutable) and
their page-in changes no committed state, so the cost is **pre-charged at the
CALL** that maps them, computed statically from the callee Image (one
`page_in_cost` per declared 2 MiB read-only unit, folded into
`call_frame_cost`). The pages are still demand-paged — the recompiler
fault-arounds a whole read-only unit on first touch (one map event per
`cap ∩ 2 MiB cluster`) — but that fault debits **zero gas**. A guest *data*
read of its own code bytes (a PIC `ld`/`lw` from the code region) is likewise
free at the fault; the code region's page-in is part of its `call_frame_cost`.
The single-pass pipeline (#1) prices instruction execution; there is no
per-fetch code-page charge.

### Read-only units — counted at the CALL, mapped gas-free at the fault

`page_in` prices the **map event** — bringing a read-only region into the
working set — **not** the bytes (that per-byte latency is category #1's
`mem_cycles`). Read-only memory is accounted in **units**, where a unit is
**one DataCap intersected with one 2 MiB cluster** (`cluster = ⌊addr /
2 MiB⌋`, named `unit_base = max(cluster_lo, cap_start)`). Two things use the
unit, and they are now separated:

- **At the CALL — the charge.** `call_frame_cost` counts the callee's
  **declared** read-only units (its code region plus each pinned mapping,
  each clustered per 2 MiB) and charges one `page_in_cost` per unit. This is
  a static function of the Image — a conservative footprint upper bound (it
  charges every declared unit, touched or not), the price of making the
  charge cache-independent and computable up front.
- **At the fault — the mapping, free.** The recompiler still fault-arounds a
  whole unit on first touch (mapping all its read-only pages in one event, so
  a large read-only input materializes for one fault per 2 MiB, not one per
  4 KiB page), but that fault debits **zero gas**. The unit is **clamped to a
  single DataCap** (a map event touches exactly one cap; two caps sharing a
  cluster are two units), so the fault-around never over-reaches — but this
  is now a pure fault-reduction optimization, not a charge.

2 MiB is the common large-page size across targets (x86-64 PDE, AArch64 L2
block, RISC-V megapage), so the cluster model is architecture-portable: a
unit that is a fully-cap-backed, 2 MiB-aligned cluster can in principle be
mapped with a single large-page PTE. The choice of 2 MiB and the per-event
`page_in_cost` / `compile_cost` are subject to calibration (§6).

Because read-only page-in no longer fires at a fault, it **contributes
nothing to the per-block worst-case reserve** — only a store's CoW does (next
subsections).

### Depth-aware CoW (the merkle cost of a write)

A CoW write's true cost is not the 4 KiB copy — it is the **re-hash** of the
dirtied page into the periodic state root, which is `O(merkle_depth)` of the
page's DataCap (recomputing the leaf and every node up to the root). A flat
per-page `cow_cost` therefore **under-charges a write to a deep DataCap** by
~the depth: an attacker who builds a maximally-deep cap and scatters one-byte
writes pays `O(1)` per page for `O(depth)` of re-hash work (the "merkle
bomb"). So `cow_cost` is **depth-aware**:
`cow_cost(depth) = cow_cost_base · merkle_depth_multiplier`, with
`depth = ceil(log2(page_count))`. The depth is **statically bounded** by the
slot's `memory_mappings` size (a DataCap mapped into a slot must satisfy
`cap.size ≤ mapping.size`), so it is a per-slot constant resolved at frame
setup, and the worst-case reserve below stays a static per-block constant.
(`merkle_depth_multiplier` is a calibration placeholder — §6.)

### Atomic per access

The unit of #3 charging and faulting is **the memory access, not the
page**. A single access may straddle two pages; whichever page's fault
the hardware raises first, the handler reconstructs the *entire* access
range from the faulting instruction and resolves all its pages together,
in this fixed order:

1. **Accessibility check over all pages first.** For each page: is it in
   a declared `memory_mapping`, with a non-empty source slot, and the
   right permission (R for load; RW for store — a store to a pinned/RO
   region fails here)? If **any** page fails → **hard fault** (permanent),
   atomically: nothing mapped, nothing charged.
2. **Materialize all not-yet-resident pages and charge their #3.**
   Read-only pages are fault-arounded per unit and charge **nothing** (their
   page-in was pre-charged at the CALL); writable pages are mapped read-only
   on first read (free) and, on a first **write**, copied-on-write and
   charged `cow_cost(depth)` per page. This cannot out-of-gas: the block-entry
   reserve (below) already guaranteed the gas was present.
3. **Retry the instruction**, which now hits all-present pages and
   completes. (No second fault — the handler mapped every page the access
   touches.)

Precedence is **hard-fault > materialize**, all-or-nothing over the whole
access. Consequences: the arch-dependent order of the two page faults is
unobservable (one fault resolves the whole access; the page set and total
#3 are order-independent); a straddle touching one valid and one invalid
page hard-faults charging nothing (a read charges nothing anyway; a write's
CoW is all-or-nothing); and #3 can never out-of-gas mid-access (see the
reserve). OOG is decoupled entirely — it lives only at the block-entry gate.

**Two fault levels — host-level retry vs PVM2-level terminal.** The
materialization step (2) is a **host-level** page fault: the kernel maps
the resolved page(s) and re-executes one native instruction. It is
transparent to the PVM2 model and is *not* a PVM2-level resume — exactly
the carve-out the ISA spec permits
(PVM2 "Faults must stay terminal", the
parenthetical on host-level copy-on-write `#PF`). The accessibility
failure in step (1) is a **PVM2-level** fault: it makes the Instance
`Faulted` and is **terminal — never resumed** (the same doc requires this,
because a PVM2-level page-fault resume would land mid-block and break both
`pc ∈ bb_starts` and the per-block precharge). So a #3 retry never creates
a resumable mid-block pc; only the block-entry OOG yield does, and it is at
a bb_start by construction.

### The worst-case reserve (gating #3 without negative gas)

Because #3 is charged mid-block at faults, it must not be able to
out-of-gas mid-block (that would force a mid-block yield, which has no
bb_start to resume at). The block-entry gate prevents this: the block is
entered only if gas covers its **worst-case #3** in addition to its
instruction cost:

```
worst_case_3(B) = Σ over B's memory ops:
                    load  → 0          (read-only page-in pre-charged at the CALL)
                    store → cow_cost(depth) × MAX_PAGES_PER_ACCESS
```

This covers **only the block's own stores** — the one remaining mid-block #3
source. **Loads contribute nothing**: read-only page-in is pre-charged at the
CALL that brought the region into the frame, and a read at a fault debits
zero, so a load can never drive the meter mid-block. It is a **static
per-block constant** (the recompiler counts B's stores at predecode, with
`cow_cost(depth)` a per-slot constant from the slot's `memory_mappings` size,
exactly as it sums #1), so it is baked into the block-entry check alongside
`gas_cost(B)` and costs one comparison at runtime. `reserve ≠ charge`: only
the #3 actually incurred is debited.

An `ecall`'s kernel-side #3 (call-frame, host-op work) is deliberately
**not** in this reserve: it is unbounded at compile time, so it is charged
dynamically in its own `ecall` block (next subsection), not reserved at a
neighboring block's head. This is the split that keeps `worst_case_3`
finite and exact: **bounded #3 here, unbounded #3 at the ecall.**

`MAX_PAGES_PER_ACCESS = 2`, because the widest PVM2 memory access is a
**single 8-byte scalar** (`ld`/`sd`), and `8 < 4096`, so even a misaligned
access (permitted via `Zicclsm` — see PVM2)
spans at most `ceil(8 / 4096) + 1 = 2` consensus pages — so a single store
can CoW at most 2 pages. **Invariant:** this constant holds only while no
extension adds a memory access wider than one page minus one byte. PVM2
today excludes the A/F/D/Q/V extensions and cache-block ops, so it holds;
adding a wider access (e.g. vector load/store) **must** revisit
`MAX_PAGES_PER_ACCESS` or the reserve under-counts and #3 could exceed it.

`cow_cost` (the fault-time write charge) and `page_in_cost` / `compile_cost`
(the CALL-time read-only-page-in and per-code-page compile charges, folded
into `call_frame_cost`) are per-event constants calibrated empirically
alongside #1's `mem_cycles` (same benchmark lineage); their normative source
of truth is the kernel page-fault / call-setup handler (`nub-arch-*`, §6).
They are not yet pinned to final numbers — until they are, this section is the
placeholder of record and must be updated in lockstep with the handler.

### ecall/ecalli blocks — dynamic self-charging

`ecall.jar` (every MGMT op — `MOVE`/`COPY`/`DROP`/`CALL`/`CALL_RESUME`/
`DROP_RESUME`, distinguished by a register operand) and `ecalli` (host
calls) are the one instruction category whose #3 the recompiler **cannot
bound at compile time**: a CALL's cost depends on the slot-resolved callee
Image (compile + eager read-only page-in + frame), a host op's on a runtime
length or value size. So they are **not** charged by a static preamble. Instead,
**each `ecall`/`ecalli` is its own gas block**, and the kernel handler
charges it **dynamically**, against the actual cost:

```
ecall block (no static preamble):
    actual = cost(op, runtime args)        # frame size / callee Image / host-op length
    if gas < actual:
        OUT-OF-GAS yield                   # gas UNCHANGED; continuation = THIS ecall's pc
    else:
        gas -= actual                      # charge the real cost
        do the work                        # → continuation = next pc (on complete or yield)
```

**Why its own block — the resume-pc forces it.** An `ecall` has three
outcomes with two different continuations: it *completes* or *yields*
(`host_yield`, or a CALL that pauses) → resume at the **next** instruction;
it *out-of-gases* → resume at the **current** instruction, to re-attempt
the whole op after a top-up. The next pc is already a bb_start (an `ecall`
is a terminator). For the OOG case to be representable, the `ecall`'s
**own** pc must also be a bb_start — so an `ecall`/`ecalli` is a **forced
block start**, a boundary on *both* sides (a singleton block). Both pause
points are then bb_starts, so `Paused.pc ∈ bb_starts` still holds.

The headline invariant survives unchanged: the check is before the charge
(gas never goes negative), and OOG does no work and charges nothing (the
re-attempt is clean). The only difference from an ordinary block is that
the cost is computed at runtime by the kernel rather than baked into a
preamble — the recompiler emits the VM-exit and **no** `cmp/sub` gate.

**Not the terminal kernel exits.** `Trap`, `Reserved`, and a standard
`ecall`/`ebreak` also leave to the kernel, but they are **terminal faults**
(Instance dropped, no continuation), so they have no resume-at-self case
and need no own-block. Only `ecall.jar`/`ecalli` are recoverable. And
loads/stores — the other instructions with a runtime-dependent #3 — are
statically *bounded* (≤ 2 pages, reserved at the block head per the
previous subsection) and resolved by a host-level retry, never an OOG, so
they stay mid-block. The rule is exactly: **bounded #3 → static reserve at
the block head; unbounded #3 → its own `ecall` block, dynamic charge.**

**`call_frame_cost` (the CALL case).** A CALL's dynamic charge materializes
the sub-invocation,
`call_frame_cost(code_len, ro_units) = frame_base + ceil(code_len/4 KiB)·compile_cost + ro_units·page_in_cost`:

- the **JIT compile** — `O(code)`: `ceil(code_len / 4 KiB)` code pages ×
  `compile_cost`. **Always charged in full**, even though the compiled image
  is **memoized by `image_hash`** — the memoization skips the *work*, never
  the *charge* (a second CALL into a warm Image runs faster but pays the same;
  gas must not depend on a node-local cache — see "Determinism" below and the
  cache-determinism discussion),
- the **eager read-only page-in** — `ro_units · page_in_cost`, where
  `ro_units` is the count of the callee's **declared** 2 MiB read-only units
  (its code region plus each pinned mapping), statically computed from the
  Image; this is the read-side cost that no longer fires at a fault,
- **page-table setup** for the callee's declared address space (not-present
  PTEs over the footprint; the *data* pages stay lazy — they materialize on
  first touch as the callee runs, the CoW charged to the callee), the
  **JitContext + dense dispatch-table** allocation, and the **call-stack
  frame** push — together the `frame_base`.

**Kernel writes into guest memory are charged here, not at a fault.** A host
`ecalli` that writes its output into the callee's memory (e.g. a
content-read host call), and an `MGMT_MOVE` that maps a fresh DataCap into a
slot, write through the **kernel's** mapping — they bypass the guest's
write-protect `#PF`, so the per-page CoW fault never fires. Those dirtied
pages are real committed-state deltas, so their cost (per page, depth-aware,
like a CoW) is charged **at the `ecalli`/MGMT op**, dynamically, as part of
its own gas block. The fault path is not the only #3 detector; a
kernel-authored write must be metered where the kernel makes it.

It is charged to the **caller's** meter (the CALL is the caller's
instruction); the callee then runs on its own meter. The compile component
is O(code), bounded by `MAX_CODE_SIZE` — large but finite. Charging it
*dynamically at the CALL* (rather than reserving the worst case at a
preceding block's head) is precisely what keeps that bound from forcing
every caller to hold `MAX_CODE_SIZE`-worth of gas just to enter; it ties to
the "code size is the natural bound" argument below. `call_frame_cost`'s
normative source of truth is the kernel call-setup handler (`nub-arch-*`,
§6), pending final calibration.

### Eviction is by slot mutation, not LRU

A `memory_mapping` binds a region to a **cnode slot**. Pages are evicted
**deterministically, by cap-table events**, never by cache pressure:

- A **pinned** slot's cap cannot change → its pages stay mapped, never
  evicted. A pinned cap is the read-only kind whose page-in is charged once,
  **at the CALL** that mapped it (per declared 2 MiB unit), not at any fault.
- `MGMT_MOVE`/`MGMT_DROP` on an **unpinned** mapped slot evicts the old
  DataCap's pages. Mapping a **new** read-only cap into a slot re-incurs its
  read-only page-in — charged at the `MGMT_MOVE` (per its declared units),
  the same dynamic #3 as a CALL's eager RO charge (and the spot that prices
  "pull a fresh cap in and read it" — the kernel-write charging in
  "ecall/ecalli blocks" above). A subsequently written page CoWs fresh,
  charged per page at the write.

This gives the re-materialization behavior of an LRU (a region can be
charged #3 more than once) without LRU's nondeterministic victim
selection: eviction is a function of the deterministic `MGMT_*` stream,
which is already part of execution.

Because `MGMT_MOVE`/`MGMT_DROP` are `ecalli`s — **block terminators** — no
eviction (and hence no re-CoW of an evicted page) can happen *within* a
single straight-line block. Each in-block store therefore CoWs its pages
**at most once**, which is exactly why `worst_case_3(B)` can count each store
once with no re-charge term and still bound the block's actual #3. This is the
other half of the "no `N_max` needed" argument below: the reserve is finite
and exact per block precisely because the only events that could re-dirty a
page are themselves block boundaries.

### No basic-block-size cap is needed

Because gas never goes negative (the entry gate pre-reserves the
worst case) and OOG never charges, an arbitrarily long straight-line
block is **not** an attack: it either pre-reserves its full worst-case #3
to enter (and then pays only its actual #3), or it OOG-yields at entry
having done **zero** work. There is no mid-block credit to bound, so no
synthetic `N_max` gas-block split is required. The Image's code size is
the natural bound on a block's instruction cost and its `worst_case_3`.

## 4. State storage cost (summary)

Storage quota — not gas — bounds persistent σ growth. It is charged for:

- **Committed, newly-diverged dirty pages.** A page that is read-only, or
  written-then-discarded, or in a faulted apply, costs no storage. Only a
  page whose new content **persists** at HALT becomes a new
  content-addressed page and is charged one page of quota. CoW +
  content-addressing make this **the delta, not the copy**: copying a
  large DataCap and writing one page costs one page of quota; the
  unchanged pages remain shared by hash.
- **Minted caps** (`host_mint_*`).

The dirty set persists across yield/resume and nested CALLs while the
Instance is on the call stack; it is finalized and charged when the
Instance **leaves the stack** (HALT commits; fault discards — but #3 work
already gas-charged is not refunded, STM-exempt). The per-dirty-page rule,
"copy is free / write costs per page," and merkleization are specified
under "Storage cost via dirty-page tracking" and "Page-merkleized DataCap"
in [§2](_index.md).

**Quota is a separate budget and does not enter the per-block gas gate.**
Quota exhaustion surfaces as the recoverable `kernel:storage_exhausted`
yield (§2 of the spec), distinct from gas OOG: the kernel yields
`kernel:storage_exhausted` (caught by the chain's `YieldReceiver`, the
`Quota{quota_key}` payload reflecting via slot[0]), and the chain tops up
by emitting `kernel:set_storage_quota` and `CALL_RESUME`s. The two events
that grow σ are a cap mint (`host_mint_data_cap`, an `ecalli` — a bb_start)
and the dirty-page commit at HALT (a termination); neither is a mid-block
instruction, so the `kernel:storage_exhausted` yield lands at a bb_start
exactly like every other
recoverable yield — the "yields only at a bb_start" rule holds for quota
too, even though quota is not part of the gas reserve. A first-write CoW
*dirties* a page (it pays #3 gas there) but does not settle that page's #4
quota mid-block; the quota charge is deferred to commit. The precise
pre-reserve-vs-deferred accounting for dirty pages is detailed under
"Storage cost via dirty-page tracking" in [§2](_index.md); it is out of
scope for this gas document.

## 5. Determinism and consensus

Every charge above must be **bit-identical across nodes and across
x86-64 / AArch64 / RISC-V**, and identical between the interpreter and the
recompiler. The load-bearing rules:

- **Gas is a function of the committed-state delta, never of cache
  residency.** A read produces no committed-state delta, so it charges
  **zero** — deterministically, regardless of whether a node had the page (or
  the compiled image, or the page table) cached. A CALL's compile + read-only
  page-in is a fixed function of the callee **Image** (charged in full every
  CALL; memoization skips work, not gas). A CoW is the delta (charged per
  page). This is what lets every node-local cache — compiled code, page
  tables, resident pages — be a pure performance optimization the charge never
  observes; see
  [principles/cache-determinism-and-eager-call-charge.md](principles/cache-determinism-and-eager-call-charge.md).
- **Use present/writable (permission) faults, never the hardware
  Accessed/Dirty bits.** A/D bits are set speculatively / with
  microarchitecture- and ISA-specific timing (x86 speculative A-bit,
  ARM `FEAT_HAFDBS`, RISC-V `Svadu` vs. fault-based). Permission and
  translation faults are precise and architectural — delivered only for
  retired accesses, in program order — so the fault sequence equals the
  architectural first-touch/first-write sequence on all three ISAs.
- **Read vs. write is taken from the fault, not inferred**: x86
  page-fault error-code W/R bit; AArch64 `ESR_EL1.WnR`; RISC-V cause 13
  (load) vs. 15 (store) page fault.
- **Charge per consensus page (4 KiB), independent of host page size.**
  The guest page table uses the consensus 4 KiB granule on every node
  regardless of the host's hardware page size (Apple's 16 KiB host runs a
  4 KiB guest — the host granule is a different translation level), so
  fault granularity is deterministic.
- **Charge per page** (order-independent within a straddling access).
- **Engine parity.** The interpreter detects first-write with an explicit
  software check; the recompiler uses the MMU write-protect fault. Both run
  the same per-access ordering (accessibility-all → materialize-all): a read
  charges nothing on either (so the read-side fault only needs to agree on
  *mapping*, not on a charge), and a first write charges the same
  `cow_cost(depth)` on both. The CALL's `call_frame_cost(code_len, ro_units)`
  is computed from the same Image on both, so they agree there too.
- **Block boundaries match.** Both engines derive `bb_starts`,
  `gas_cost(B)`, and `worst_case_3(B)` from the same `Image.code` — and both
  treat `ecall.jar`/`ecalli` as **forced block starts** (their own singleton
  blocks) — so the set of gas-block entry checks, the dynamic `ecall`
  charge points, and thus where OOG can fire are identical.

## 6. Source of truth

#1's source of truth is
[`rust/javm-exec/src/gas_cost.rs`](https://github.com/jarchain/jar/blob/master/rust/javm-exec/src/gas_cost.rs)
plus [gas-cost.md](pvm2/gas-cost.md). #2's tiers
trace to internal memory-gas measurements and live in
[`rust/javm-exec/src/gas_const.rs`](https://github.com/jarchain/jar/blob/master/rust/javm-exec/src/gas_const.rs).
#3's per-page state machine + page-set rule is the shared
[`rust/javm-exec/src/mat.rs`](https://github.com/jarchain/jar/blob/master/rust/javm-exec/src/mat.rs)
(`charge_for` returns `0` for a read, `cow_cost` for a write), driven
identically by **both** engines: the interpreter's software first-touch
(`CopyingMemory::touch_read`/`touch_write`) and the recompiler's hardware
page-fault materializer (`nub-arch-x86`'s `try_materialize` over a
not-present data extent). The CALL-time charge is
[`gas_const::call_frame_cost`](https://github.com/jarchain/jar/blob/master/rust/javm-exec/src/gas_const.rs)
(compile + eager read-only page-in + frame base), applied by the recompiler's
in-kernel CALL dispatch (`nub-arch-x86`'s `call_loop.rs`, OP_HOST_CALL).
#4 (storage quota) is realized at HALT
finalization and **has not yet landed** — out of scope of the current
cost-model work; this document is its normative description until it does.
The #3 constants in `gas_const.rs` are calibration placeholders
(`TODO(gas-calibration)`). Any change to a cost or to the charging
discipline must update this doc and the corresponding source together.
