# v3 implementation architecture

A plan for how the v3 spec (this directory's README) maps onto a Rust
workspace. Captures crate boundaries, layering, the few architectural
choices that are load-bearing for the split, and a recommended path
from the current `~/jar/rust` codebase to the target shape.

This is a *living* design doc — it gets edited as implementation
surfaces things the spec didn't anticipate. The spec is the source of
truth for what the system *is*; this doc is the source of truth for
how the code *is organized*.

## Goals

- **Cap system as the foundational layer.** The cap system (Cap kinds,
  CNode, BMT, image_hash chain, MGMT_* semantics) sits at the bottom
  of the dep graph. It has no knowledge of execution, hardware,
  block apply, or chain orchestration.

- **Execution engine separable from caps.** The pure execution part
  of JAVM (interpreter, recompiler, memory pages, gas metering,
  registers, ecall opcode dispatch) is a standalone crate. No cap
  awareness.

- **Full JAVM = caps + execution + call stack.** The call stack is
  the natural place where execution meets caps (an InstanceEntry
  holds both a Cap::Instance reference and PC/regs). It belongs
  one layer up, in the integration crate that combines the two.

- **Backend trait for storage.** CNodes can be large (up to 2^k slots
  for any k); the storage backing must be abstracted via a trait so
  we can swap in-memory for merkle-tree-backed implementations later
  without touching upstream code.

- **Incremental migration.** The current `javm`-and-`jar-kernel` split
  has the right shape conceptually but not the right factoring. We
  refactor in stages, each stage compile-clean.

## Non-goals

- No premature optimization. Initial implementation uses simple
  hashing (flat blake2b-256) where the spec calls for BMT; the BMT
  primitive lands when state-root computation cost actually matters.
- No backwards compatibility with v1/v2 designs. The kernel branch
  ahead of `master` is the migration target; old kernel shapes are
  not preserved.
- No new tooling crates this round. Bench / transpiler / build crates
  stay as-is.

## Crate dependency graph

```
                    jar (binary; testnet driver)
                            ▲
                    jar-harness (genesis, multi-node integration)
                            ▲
                    jar-kernel (σ, block apply, host calls,
                                kernel-assisted Image defs,
                                JAR-specific Images)
                            ▲
                          javm  (call stack, MainFrame/BareFrame,
                                 MGMT ecall dispatch, host-call
                                 coordination, InvocationKernel)
                       ▲           ▲
                       │           │
              ┌────────┘           └────────┐
              │                             │
        javm-exec                       jar-cap
        (interpreter,                   (Cap, CNode + backend trait,
         recompiler, memory,             Image, BMT, image_hash chain,
         gas, registers,                 MGMT_* pure semantics, hash)
         ecall dispatch trait)
```

Five new/refactored crates:

| Crate | Role | Depends on |
|---|---|---|
| `jar-cap` | Foundational cap system | (nothing in workspace; just `scale`, `blake2b`, etc.) |
| `javm-exec` | Pure execution engine | (nothing in workspace) |
| `javm` | Full JAVM (caps + execution + call stack) | `jar-cap`, `javm-exec` |
| `jar-kernel` | Chain kernel | `javm` |
| `jar-harness` | Genesis + integration | `jar-kernel` |

Note: `javm` keeps its current name. The execution-only split is
`javm-exec`; the cap layer is `jar-cap`. The integration crate `javm`
is what callers (jar-kernel) reach for; its API is roughly today's
`InvocationKernel`.

## Layer 1: `jar-cap`

The foundational cap system. No execution, no I/O, no kernel concepts.
Just the structural primitives that the spec defines.

### Responsibilities

- **Cap kinds.** Exactly the five v3 cap kinds per spec README §8 —
  a non-parameterized enum:
  - `Cap::Instance(InstanceCap)` — Frame-bound stateful unit.
  - `Cap::Image(ImageCap)`
  - `Cap::Data(DataCap)`
  - `Cap::CNode(CNodeCap)`
  - `Cap::Type(TypeCap)`

  No generic `<P>` parameter; no `Cap::Protocol` variant. The v2
  ProtocolCap mechanism does not exist in v3. JAR-specific things
  (vaults, files, quotas, kernel-assisted resources) are encoded
  as `Cap::Instance` values with particular Images (in the
  `kernel:` namespace for kernel-assisted), not as a separate
  cap variant.

- **CNode.** Variable-size cap table (2^k slots). Holds `Option<Cap>`
  per slot. Pinned-slot machinery (per Image declaration). Slot path
  addressing for nested cnodes.

- **CNode backend trait.** Storage abstraction. See "CNode backend"
  section below.

- **Image content + image_hash chain.** Image structure
  (code, endpoints, memory_mappings, gas_slots, quota_slots,
  pinned_slots, yield_marker_slot). Hash chain math:
  `genesis = hash(image)`, `set_image extends = hash(prev || hash(new))`,
  `derive_spawn = hash(spawner_chain || hash(new))`.

- **BMT (balanced merkle tree).** Generic merkle primitive used by:
  - State-root computation (over σ — handled at jar-kernel level
    but using this primitive)
  - Page-merkleized DataCaps (large data values; modify-by-page)
  - Large CNode merkleization (future; initial impl flat-hashes)
  
  Initial impl: a simple "compute root from leaves" function. No
  persistent tree structure. Defer the lazy / incremental BMT to
  when it's the bottleneck.

- **MGMT_* semantics as pure functions.** `mgmt_copy(table, src, dst)`,
  `mgmt_move`, `mgmt_drop`, `mgmt_cnode_swap`. Operate on cap tables;
  no execution context required. javm-side ecall dispatch calls these.

- **Hash trait.** `Hash<H>` with a default `Blake2b256` impl. Allows
  swapping for testing (mock hash) or future hash agility.

### Module layout

```
jar-cap/
  src/
    lib.rs
    cap.rs          -- Cap enum, InstanceCap, ImageCap, DataCap,
                       CNodeCap, TypeCap
    cnode.rs        -- CNode + CNodeBackend trait + default in-mem impl
    image.rs        -- Image struct, image_hash chain math
    slot.rs         -- SlotPath, SlotIdx; pinned-slot whitelist
    bmt.rs          -- balanced merkle tree primitive
    hash.rs         -- Hash trait + blake2b default
    ops.rs          -- mgmt_copy / mgmt_move / mgmt_drop / mgmt_cnode_swap
                       as pure functions over &mut CNode
    error.rs        -- CapError, OpError
```

### What jar-cap deliberately doesn't have

- No knowledge of registers / PC / gas — those are execution concerns.
- No "active VM" or "running instance" — those are call-stack concerns.
- No host calls — those are integration concerns at the javm layer.
- No σ / block / state-root — those are jar-kernel concerns.

This means `jar-cap` can be tested as a pure value-typed system:
build a CNode, do operations, verify hashes. Property tests over
cnode operations belong here.

## Layer 2: `javm-exec`

The execution engine. PVM interpretation + native recompilation. No
cap awareness.

### Responsibilities

- **Interpreter.** PVM instruction set; register state (13 GPRs +
  internal); memory pages; gas counter; trap handling.

- **Recompiler.** JIT to native (Linux x86-64 only initially).
  Same execution semantics as interpreter; differs in throughput.

- **Memory model.** Page-based (4 KiB pages); read / write / COW
  semantics; explicit mapping table per "address space" (one per
  active execution context). The current javm `MemoryMap` shape.

- **Gas metering.** Per-instruction counter, decremented as code
  runs. Out-of-gas is an exit reason; not a fault here (the layer
  above translates OOG to a yield with the kernel-issued OOGMarker).

- **ExitReason.** The terminal status from an execution batch:
  `Halt`, `Trap`, `Panic`, `OutOfGas`, `PageFault`, `Ecall`, `HostCall`.

- **Ecall dispatch as a trait.** `trait EcallHandler { fn dispatch(
  &mut self, op: u32, regs: &mut Regs, mem: &mut Mem) -> EcallResult; }`
  The execution engine knows there are ecalls; it doesn't know what
  they mean. The caller (`javm` integration crate) supplies the
  EcallHandler that interprets ecalli numbers as MGMT operations,
  host-call selectors, etc.

### Module layout

```
javm-exec/
  src/
    lib.rs
    interp.rs       -- interpreter loop
    recompiler/     -- existing recompiler subtree
    mem.rs          -- pages, mapping table
    regs.rs         -- register state
    gas.rs          -- gas counter
    exit.rs         -- ExitReason enum
    ecall.rs        -- EcallHandler trait
```

### What javm-exec deliberately doesn't have

- No `Cap`, `CNode`, `Image`. The execution engine knows it has 4 KiB
  pages and registers; it doesn't know that some pages came from a
  DataCap.

- No call stack. A single `execute()` call runs until ExitReason.
  The caller decides what to do next.

- No InvocationKernel. That's the integration crate's job.

This split means `javm-exec` can be benchmarked / fuzzed against
PolkaVM independently of the cap system.

## Layer 3: `javm` (integration)

Combines `jar-cap` and `javm-exec`. Owns the call stack, the
kernel-known cap-bearing Frame structures (MainFrame, BareFrame),
the MGMT-ecall handler, and the host-call coordination boundary.

### Responsibilities

- **Call stack.** The kernel-internal stack of `InstanceEntry` and
  `ReferenceEntry`. Exactly one entry Running at a time. Pushes on
  CALL, pops on HALT/fault. ReferenceEntry pushed by yield routing.
  See README §3 and discussions/data-flow-principle.md "The stack
  model in detail."

- **Frame structures.** `MainFrame` (the cnode of the currently-Running
  Instance) and `BareFrame` (kernel-injected pinned slots — kernel-
  issued caps like SetGasMeter, OOGMarker, etc.).

- **MGMT ecall dispatch.** Translates ecalli numbers (MGMT_COPY,
  MGMT_MOVE, MGMT_DROP, MGMT_CNODE_MINT, MGMT_CNODE_SWAP, etc.) into
  calls on `jar-cap`'s pure ops. Updates registers per the ABI.

- **Yield routing.** Walks the call stack matching markers against
  each Instance's YieldCatcher. The YieldCatcher's state is read via
  kernel short-circuit (not endpoint dispatch); javm has direct
  access to the kernel-assisted Frame's struct.

- **Per-instruction gas debit.** The execution engine reports gas
  consumed; javm debits the meter named by the active Instance's
  gas slot. On hit-zero: triggers OOG yield (with kernel-issued
  OOGMarker payload).

- **InvocationKernel-equivalent API.** A `Vm` surface (renamed from
  v2's `InvocationKernel<P>` — non-generic in v3) implementing the
  v3 spec (set_image, host_derive_spawn, host_yield-with-marker,
  etc.). This is what `jar-kernel` calls into.

### Module layout

```
javm/
  src/
    lib.rs
    callstack.rs    -- InstanceEntry, ReferenceEntry, stack invariants
    frame.rs        -- MainFrame, BareFrame
    vm.rs           -- Vm (call-stack-aware VM driver; no <P> parameter)
    ecall.rs        -- MGMT + host-call dispatch (impls EcallHandler
                       from javm-exec)
    yield_route.rs  -- yield-marker routing
    gas_debit.rs    -- per-instruction gas debit, OOG yield trigger
```

No `ProtocolCap` / `ProtocolCapHost` traits — v2's generic
protocol-payload mechanism is gone in v3. Kernel-assisted Images
(YieldCatcher, GasMeter, etc.) are recognized by image_hash
match against a fixed registry the kernel knows; no generic
plug-in trait needed.

### Key design decision: call stack lives here

The call stack is the meeting point of execution + caps:
- Each `InstanceEntry` references a `Cap::Instance` (from `jar-cap`)
- Each entry carries execution state (PC, regs — from `javm-exec`)
- The stack drives both ecall-dispatch (execution side) and
  yield-routing (cap side)

Therefore call stack belongs in the integration crate (`javm`), not
in either underlying crate. Neither `jar-cap` nor `javm-exec` should
need to know about it; they're each consumed by `javm` which weaves
them together.

## Layer 4: `jar-kernel`

The chain kernel. Owns σ state; runs block apply; provides host
calls; defines the well-known Images for kernel-assisted Instances.

### Responsibilities

- **Kernel-assisted Image definitions.** Native-code Images for
  YieldCatcher, GasMeter, StorageQuota, Gas{meter_id},
  Quota{quota_id}, and the factory caps (SetGasMeter,
  SetStorageQuota, MintGas, MintQuota, CreateYieldCatcher) — all
  recognized by their image_hash in the `kernel:` namespace. The
  v3 spec encodes these as `Cap::Instance` values with kernel-known
  Images; the kernel short-circuits their state access. There is
  no separate "protocol cap" mechanism.

- **JAR-specific Images.** Per-chain Images that the JAR chain uses
  (vault, file, resource, ...) — also just regular Images. What
  v2 called `RegCap::VaultRef` etc. become `Cap::Instance` values
  with these Images.

- **σ state.** Vaults, images, data_blobs, code_blobs, storage_quotas,
  transact_endpoints, dispatch_endpoints, validators, IdCounters.

- **State root.** Merkleization of σ. Uses jar-cap's BMT primitive
  but composes over the σ shape (registries-of-entries). State-root
  scheme described in README §3 and §12.

- **Block apply.** The `apply_block` / transact / dispatch phases.
  Drives javm per event. Catches yields per marker. Implements the
  lazy-load OOG-catch pattern (catch OOG → SetGasMeter topup →
  CALL_RESUME).

- **Kernel-assisted Frames.** Native implementations of GasMeter,
  StorageQuota, YieldCatcher. Kernel short-circuits these (no
  bytecode dispatch).

- **Host calls.** set_image, host_derive_spawn, host_open, host_save,
  host_yield, host_mint_cnode, host_mint_data_cap, host_read_data_cap,
  host_same_type, host_same_type_as, host_type_of, host_subtype,
  host_type_eq, host_make_image (see "Cap::Image construction" below).

- **PoA / consensus** (existing) — validator scheduling, block hash,
  proposer rotation.

### Module layout (refactor of current crate)

Greenfield: jar-kernel-v3 is built from scratch using jar-cap + javm
as building blocks; the v2 `jar-kernel` crate stays untouched until
retirement. Major shape:
- `cap/` module is gone — there are no JAR-specific cap kinds; just
  Images that produce `Cap::Instance` values.
- `vm/` module shrinks — call stack + ecall dispatch + invocation
  kernel move to `javm`.
- `state/` mostly unchanged.
- New: `kernel_assisted/` module for native impls of YieldCatcher,
  GasMeter, StorageQuota.

## CNode backend (the trait)

Cnodes vary widely in size:
- **Root cnode (RootCNode)**: fixed 256 slots, ~8 KiB if naive
  `[Option<Cap>; 256]`.
- **Cap::CNode** (variable): 2^k slots for any k. Large k (e.g., 16
  = 64K slots, 20 = 1M slots) is plausible for chain registries.

A 1M-slot cnode held naively as `Vec<Option<Cap>>` is ~32 MB per
instance. Many such cnodes in flight is untenable. Hence the trait.

```rust
pub trait CNodeBackend {
    fn size_log(&self) -> u8;            // 2^k
    fn get(&self, idx: u32) -> Option<&Cap>;
    fn set(&mut self, idx: u32, cap: Option<Cap>);
    fn hash(&self) -> Hash;              // content hash; cached/lazy ok
    fn snapshot(&self) -> Self where Self: Sized;
                                         // COW snapshot for working state
}
```

Two initial implementations:

1. **`MemoryCNode`** (default). Simple `Vec<Option<Cap>>`, allocated
   to size. Hash computed from full content. Snapshot = clone. Fast
   for small cnodes; uses too much memory for large.

2. **`MerkleCNode`** (lazy, for large). A balanced merkle tree where
   subtrees can be:
   - **Hash-only** (not materialized — just the BMT hash)
   - **Materialized** (a leaf array of slots, possibly with their
     own substructure)
   
   `set()` materializes the path to the modified leaf; `hash()`
   recomputes only the modified branches. `snapshot()` is O(1) —
   shares all immutable subtrees.

For v0, only `MemoryCNode` is implemented. The trait exists so we
can drop in `MerkleCNode` later without touching anything upstream.

## BMT (balanced merkle tree)

The primitive: a balanced binary merkle tree over a sequence of
leaves. Used at three places in the spec:

1. **State-root.** σ is hashed canonically; chain header carries
   `state_root = root_hash(σ)`. See README §12.

2. **Page-merkleized DataCaps.** Large data values stored as a BMT
   of 4 KiB pages so that modifying one page is O(log num_pages)
   to recompute the hash. See README §2 "Page-merkleized DataCap."

3. **MerkleCNode** (above; future).

Initial implementation:

```rust
pub struct Bmt;

impl Bmt {
    /// Compute the merkle root over a slice of leaf hashes.
    pub fn root<H: Hash>(leaves: &[H::Out]) -> H::Out;

    /// Generate a proof for leaf at index i; verify via `verify_proof`.
    pub fn proof<H: Hash>(leaves: &[H::Out], i: usize) -> MerkleProof<H>;

    pub fn verify_proof<H: Hash>(
        root: H::Out, leaf: H::Out, i: usize, proof: &MerkleProof<H>
    ) -> bool;
}
```

Domain separation: leaf hashes prepend `0x00`, internal nodes prepend
`0x01` (standard practice).

For v0, just `root()` is implemented; proofs are added if/when a
host-call needs them.

## Hash function

`Blake2b256` is the default `Hash` impl. Matches existing JAR / spec
conventions. The trait is generic so we can swap for testing or
future agility, but the spec is currently written assuming
blake2b-256.

## Implementation path (greenfield)

The v3 implementation is built from scratch as new crates alongside
v2; v2 crates stay untouched as a reference/cherry-pick source until
v3 is feature-complete. Each stage ends compile- and lint-clean.

### Stage 1 — create `jar-cap`

- New `rust/jar-cap/` crate.
- Write (not "move") the v3 cap system:
  - `Cap` enum (non-generic; five v3 kinds).
  - `CNode` + `CNodeBackend` trait + `InMemoryCNode` default impl.
  - `Image` + image_hash chain math.
  - `Hash` trait + `Blake2b256` default.
  - `Bmt::root()` primitive.
  - Pure-function `mgmt_copy/move/drop/cnode_swap/cnode_mint` ops.
- Cherry-pick the blake2b wrapper from v2; everything else is new.

### Stage 2 — create `javm-exec`

- New `rust/javm-exec/` crate.
- Pure execution: interpreter, recompiler, memory pages, gas counter,
  registers, ExitReason, `EcallHandler` trait.
- Cherry-pick from v2's `javm/src/{interpreter,memory,recompiler/...}`
  but strip all cap-awareness — execution engine knows nothing about
  caps; ecalls go through `EcallHandler` trait.

### Stage 3 — create `javm` (integration crate)

- New `rust/javm/` crate (will collide with the v2 name; rename v2
  to `javm-legacy` at that stage, or use a distinct name like
  `jar-vm`).
- Compose jar-cap + javm-exec via the call stack:
  - `Vm` driver (renamed from v2's `InvocationKernel`; non-generic).
  - InstanceEntry / ReferenceEntry call stack.
  - MainFrame / BareFrame.
  - MGMT ecall dispatch + host-call coordination.
  - Yield-marker routing.
  - Per-instruction gas debit against active Instance's gas slot.

### Stage 4 — kernel-assisted Instances in jar-kernel-v3

- Add `jar-kernel/src/kernel_assisted/`:
  - `yield_catcher.rs` — kernel-implemented YieldCatcher image.
  - `gas_meter.rs` — kernel-internal GasMeter table.
  - `storage_quota.rs` — kernel-internal StorageQuota table.
  - `gas.rs` — Gas{meter_id} unit-handle image.
  - `quota.rs` — Quota{quota_id} unit-handle image.
- Add factory caps: SetGasMeter, SetStorageQuota, MintGas, MintQuota,
  CreateYieldCatcher.
- Add kernel-issued markers: OOGMarker, StorageExhaustedMarker.
- Inject all of these into chain Instance's cnode at genesis (per
  README §12 "Chain init: kernel-issued caps").

### Stage 5 — wire up the lazy-load OOG-catch pattern

- jar-kernel's apply_block catches OOG yields, calls SetGasMeter to
  top up, CALL_RESUMEs.
- Reference: discussions/kernel-assisted-instances.md "The lazy-load
  OOG-catch pattern."

### Stage 6 — state-root via BMT

- jar-kernel's state-root computation uses `jar-cap::Bmt`.
- Per-registry: BMT over sorted (id → entry) pairs.
- Composed: a fixed-shape parent BMT over the per-registry roots.
- Hash chain header carries the composed root.

### Stage 7 — page-merkleized DataCap

- DataCap of size > one page stored as BMT of 4 KiB chunks.
- HALT: recompute only modified chunk hashes + their paths.
- Initial impl: just compute the root each time (O(N) on HALT). The
  incremental version is a later optimization.

After stage 7, we have the v3 spec end-to-end. Subsequent work is
optimization (MerkleCNode, incremental BMT updates, JIT-recompiler
support for new ops, etc.).

## Big undecided spec issues (and recommended resolutions)

These are spec-level questions still in the spec's §18 "Open
questions" or implicit in the discussion docs. Each gets a
recommended resolution that I'll use unless the user redirects —
fill-in-the-gap defaults.

### 1. Cap::Image construction

**Question:** How are Cap::Image values constructed at runtime?

**Recommendation:** A host call.

```
host_make_image(code, endpoints, mappings, gas_slots, quota_slots,
                pinned_slots, yield_marker_slot, dst: SlotPath) → ()
  Validates the input (bytecode parseable; slot indices in range;
  no pinned-slot collisions with declared gas/quota/yield slots).
  Constructs an Image; computes hash(image); places Cap::Image at dst.
```

Cost: bytecode validation work; debited from active gas meter.
Storage cost: debited from active quota.

Alternative considered: pre-image-construction at genesis only.
Rejected because chains need to construct new Images during apply
(e.g., when minting new subject types).

### 2. Yieldref cap representation

**Question:** Is the yield-marker cap a distinct kind (Cap::YieldRef)
or just a Cap::Instance with a specific image_hash chain?

**Recommendation:** Just a Cap::Instance. No new cap kind.

The marker is a Frame derived via `host_derive_spawn(MarkerImage)`;
its `instance_hash` is the routing key. The kernel does no special
validation beyond `instance_hash` equality. There's no per-marker
behavior — markers are pure routing keys. So no need for a distinct
cap kind; Cap::Instance suffices.

### 3. CNode size constraints on host_derive_spawn

**Question:** Must the cnode argument to host_derive_spawn be exactly
256 slots? Or auto-pad smaller? Or accept variable size?

**Recommendation:** Exactly 256 slots (matching RootCNode). Caller is
responsible. host_derive_spawn returns an error if size mismatches.

Auto-padding is convenient but ambiguous (which slots are pinned?).
Variable-size root cnodes complicate the address-space-mapping
machinery. Exact size is simplest and not onerous (caller just
host_mint_cnode's a 256-slot cnode).

### 4. Recursion depth limit

**Question:** Maximum kernel call-stack depth?

**Recommendation:** Chain-spec constant. Default 256.

Why 256: matches root cnode size (mnemonic), bounds memory per
in-flight invocation (256 × ~few KB stack-entry-size ≈ ~MB worst
case), well above any plausible legitimate depth. Going deeper is a
fault.

### 5. Pinned-slot collision policy on set_image

**Question:** When set_image's new pinned slots collide with
non-pinned content the caller has put in those slots, the current
spec says FAIL. Should there be a "force" variant?

**Recommendation:** No force variant. Caller MGMT_DROPs the colliding
slot first if intentional. Spec semantics unchanged.

A force variant would silently lose user data; a chain author who
needs the slot can just drop it explicitly.

### 6. MGMT_CNODE_SWAP cross-cnode semantics

**Question:** Can MGMT_CNODE_SWAP swap a slot in the root cnode with
a slot in a nested Cap::CNode? Across two different nested cnodes?

**Recommendation:** Both ends of swap must be in the same cnode
(either root or the same nested cnode). Cross-cnode swap is rejected.

Rationale: cross-cnode swap means the two endpoints have different
hash dependencies (modifying one updates the parent cnode hash; the
other updates a different parent cnode hash). Atomic two-cnode swap
requires updating two hashes; messier semantics. Same-cnode is the
common case and is structurally simple.

### 7. State-root scheme

**Question:** Concrete merkle structure for σ?

**Recommendation:** BMT over each registry's sorted key-value pairs;
flat fixed-shape parent over the registry roots. Specifically:

```
state_root = bmt_root([
  bmt_root(vaults, sorted by VaultId),
  bmt_root(images, sorted by ImageId),
  bmt_root(data_blobs, sorted by FileId),
  bmt_root(code_blobs, sorted by CodeId),
  bmt_root(storage_quotas, sorted by QuotaId),
  bmt_root(transact_endpoints, indexed),
  bmt_root(dispatch_endpoints, indexed),
  bmt_root(validators, indexed),
  hash(chain_index || ...miscellaneous fields...),
])
```

Order is canonical; never reordered. Adding new registries appends
to the parent shape — chain spec versioning.

### 8. Paused-persistent vs Waiting

**Question:** When does a yielded Instance stay Waiting on the call
stack (in-flight only) vs become σ-resident Paused?

**Recommendation:** All yields stay Waiting by default. Only an
explicit `DROP_RESUME` host call promotes Waiting → Paused-persistent
and detaches the continuation as a σ-resident cap.

Block-end: any still-Waiting stack entries fault their corresponding
Instances (block-end is a hard boundary). Chain that wants multi-
block continuation explicitly DROP_RESUMEs.

### 9. Cap::Type vs Cap::Image canonical form

**Question:** Both reference image_hash chains. What's the difference?

**Recommendation:** They stay distinct.

- `Cap::Image` carries the full Image spec (code, endpoints,
  mappings, pinned_slots, etc.) — content-addressed by its content
  hash.
- `Cap::Type` carries just an image_hash chain — opaque identifier
  for "the type produced by deriving image X1 ∘ ... ∘ Xn from
  genesis."

You can compute Cap::Type from any Cap::Instance (via
host_type_of) or from another Cap::Type extended by Images (via
host_subtype). You can never go the other way — a Cap::Type doesn't
let you recover the Images.

Tests for type equality use `host_type_eq` (image_hash equality).
Authority uses Cap::Instance possession + yield-marker pattern (per
README §14), not Cap::Type.

## Smaller fill-in-the-gap decisions

These are sub-spec details where I'll just make a defensible call
unless the user redirects.

- **Page size: 4 KiB.** Matches the underlying JAVM page size; no
  reason to introduce a different kernel-level page size.

- **Hash: blake2b-256.** Matches existing JAR conventions.

- **CodeId: blake2b-256 of code blob.** Content-addressed; auto-dedup.
  (Already in the current implementation.)

- **FileId / QuotaId / VaultId / ImageId: monotonic u64.**
  Chain-state-resident counters in IdCounters. Already current.

- **Meter_id / quota_id: chain-chosen u64.** Per resolved decisions
  in [discussions/kernel-assisted-instances.md](../discussions/kernel-assisted-instances.md).

- **Dirty-page tracking lifetime: stack-leave reset.** Per resolved
  decisions in kernel-assisted-instances.md.

- **OOG payload: just the Gas{meter_id} cap.** No caller context.
  Per resolved decisions.

- **Genesis chain Instance: derived from a `genesis_image` Cap::Image
  the validator binary bakes in.** Spec calls it "Kernel" but the
  name is just convention; what matters is that genesis is a single
  fixed Image that the chain spec defines.

- **Block apply gas budget: chain-spec constant.** Kernel initializes
  `root_meter_id` to this value at block start.

- **Block apply quota budget: chain-spec constant.** Same.

- **Validator binary holds the genesis_image hash; the chain Instance
  is materialized by deriving from genesis_image.**

## Open implementation questions

Smaller things I haven't decided but probably don't need to before
starting Stage 1:

1. **Async vs sync hardware trait.** Current `Hardware` trait in
   jar-kernel is sync. Block store / persistence might want async
   eventually. Defer.

2. **Recompiler support for new ops.** MGMT_CNODE_SWAP, set_image,
   host_derive_spawn, etc. are new ops the recompiler needs to
   handle. Initially they can be interpreted (recompiler falls back
   to interp for unrecognized opcodes). Recompile-all later.

3. **Cap::CNode hashing.** Recursive — a cnode's hash depends on
   slot caps' hashes (including nested cnodes' hashes). The
   recursion bottoms out at content-addressed Cap::Image / Cap::Data
   and at Cap::Instance whose hash is its content hash. Decision:
   computed lazily, cached per-CNode.

4. **Slot identity in cnode hashing.** Should empty slots be encoded
   explicitly, or compressed via a bitmap? Current impl encodes
   `Option<Cap>` per slot. Decision: encode explicitly for v0
   (simple); optimize later if it matters.

5. **Validator-binary version vs chain-spec version separation.**
   Validator binary baked-in constants (genesis_image, block budgets,
   etc.) vs chain-state-dependent constants. Probably both, but the
   exact split should be drawn explicitly. Defer.

## Sanity check: does this match the spec?

Map the spec sections to crate placement:

| Spec section | Implementation lives in |
|---|---|
| §0 Foundational principles | (philosophy; no code) |
| §1 Instance and Image | `jar-cap` (Image, image_hash); `javm` (MainFrame) |
| §2 Memory model | `javm-exec` (pages, mapping); `jar-cap` (DataCap structure); `jar-kernel` (Pattern 4 dirty-page tracking) |
| §3 Status state machine + call stack | `javm` (call stack); `jar-kernel` (status as σ state) |
| §4 Kernel ABI | `javm` (CALL/CALL_RESUME/host_yield/MGMT dispatch); `jar-kernel` (host_open/host_save/etc., kernel-issued cap endpoints) |
| §5 Apply terminations | `javm` (HALT/yield/fault transitions); `jar-kernel` (status propagation) |
| §6 Operation patterns | (usage patterns; no specific code) |
| §7 Pure-function apply | (structural invariant; enforced by the layering) |
| §8 Cap kinds | `jar-cap` (Cap enum, the five kinds) |
| §9 By-value semantics | `jar-cap` (cnode hashing, hash divergence); `javm` (working-memory cap-table updates) |
| §10 Sub-tree atomicity | `javm` (call-stack discipline; fault unwinds) |
| §11 Sync CALL + emits + saga | `jar-kernel` (emit handling, saga compensation) |
| §12 Per-block kernel + chain Instance | `jar-kernel` (apply_block, chain init kernel-issued caps) |
| §13 Off-chain Dispatch | `jar-kernel` (off-chain dispatch path) |
| §14 Authority via capability flow | (chain bytecode pattern; no kernel code) |
| §15 Attestation | `jar-kernel` (AA kernel-assisted Instance; per-attest yield handler) |
| §16 MintInstance | (chain bytecode pattern; same authority mechanism) |
| §17 Footgun reduction | (structural; enforced by the layering) |
| §22 Kernel-assisted Instances | `jar-kernel/kernel_assisted/` |

Every spec mechanism has a home in exactly one crate. No spec
section is split across more than two crates. Crate boundaries are
informed by the spec, not arbitrary.

## Summary

```
jar-cap     — foundational cap system (Cap, CNode + backend trait,
              Image, BMT, image_hash chain, MGMT pure semantics)
javm-exec   — pure execution (interpreter, recompiler, memory, gas)
javm        — call stack + cap-aware Frame structures + MGMT dispatch
              + yield routing + gas debit
jar-kernel  — σ state, block apply, kernel-assisted Image
              definitions, host calls, state-root, consensus
jar-harness — genesis + multi-node integration (unchanged)
jar         — testnet binary (unchanged)
```

Implementation path (greenfield, v2 stays as cherry-pick reference):
create jar-cap → create javm-exec → create javm (integration) → add
kernel-assisted Instances to jar-kernel-v3 → wire OOG-catch →
state-root via BMT → page-merkleized DataCap. Each stage compile-
clean.

The architectural choices that are *load-bearing* for this split:

1. **Call stack lives in `javm` integration crate.** It's the meeting
   point of execution + caps; belongs at the integration layer.

2. **CNode backend is a trait.** Allows in-memory default + future
   merkle-backed impl for large cnodes without upstream churn.

3. **BMT is a `jar-cap`-level primitive.** Shared by state-root,
   page-merkleized DataCap, and (future) MerkleCNode.

4. **Cap enum is non-generic.** No `<P>` parameter, no
   `Cap::Protocol` variant. JAR-specific things are encoded as
   `Cap::Instance` values with particular Images; kernel-assisted
   things by image_hash match against the kernel's registry. The
   v2 ProtocolCap mechanism is retired.

For the spec-level questions still open in README §18, the
recommended resolutions above are defensible defaults; the user
can redirect any individual one.
