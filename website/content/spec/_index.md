---
title: Specification
linkTitle: Specification
weight: 5
---

# Minimum kernel v3 — top-level spec

A redesign of the JAR kernel as a content-addressed, by-value, capability-
threaded VM kernel. The discipline: **state is content-addressed values,
caps are typed forgery-resistant references, conservation is bytecode
arithmetic in canonical authorities, and snapshot/revert is universal
via MGMT_COPY.**

This document promotes the v3 design from discussion to top-level spec.
The discussion-level exploration with linearity remains at
[../minimum/discussions/minimal-kernel-v3.md](../minimum/discussions/minimal-kernel-v3.md)
for reference if we want to revisit linearity later.

## The shape, in one paragraph

An Instance holds an Image (its current spec) and a 256-slot cnode (its
mutable state). Image is a structured cap kind (`Cap::Image`)
containing code, endpoints, memory mappings, and pinned ro caps.
Instances evolve their Image via **`set_image`** — atomically swapping
pinned slots and extending the cumulative `image_hash` chain. The
canonical formula: at genesis `image_hash = hash(initial_image)`;
after `set_image(new)`, `image_hash = hash(image_hash_before ||
hash(new))`. All five cap kinds (Instance, Image, Data, CNode, Type) are
**uniformly copyable** (content-addressed; MGMT_COPY shares content
hash; mutations diverge). Conservation of resources lives in
**authority bytecode** (ChainOrchestrator's ledgers); structural
forgery resistance comes from the **image_hash chain rooted at the
genesis Kernel Instance** plus cap-flow + cap-runtime integrity. New
Instances are produced via **`MGMT_COPY`** of an existing Cap::Instance
(same-type sibling; image_hash preserved) or **`host_derive_spawn`**
(new image; image_hash chain extends; sub-type creation).
Snapshot/revert is universal:
MGMT_COPY of any Instance produces a content-shared reference;
mutations diverge per §9 case (b).

## Key design properties

- **No kernel-level linearity.** All caps are copyable. Conservation
  is bytecode-enforced in authority Instances; forgery resistance is
  structural via image_hash chain. Linearity is not just dropped
  for snapshot/revert convenience — it has no structural use case in
  v3 that other mechanisms (ledger arithmetic, image_hash, MGMT_MOVE,
  bytecode discipline) don't already cover. See §8 "Why no
  linearity".
- **Cap::Instance is uniformly copyable.** No `image.copyable` field.
  Snapshot/revert works on any Instance.
- **No KernelInstance category — kernel-assisted Instances instead.**
  Instances whose image is well-known to the kernel (YieldCatcher,
  GasMeter, StorageQuota, Gas{meter_id}, Quota{quota_id},
  AttestationAuthority) are still Cap::Instance; the kernel may
  direct-access their state for hot-path metering, but they share
  the cap kind with everything else. See §22 and
  [discussions/kernel-assisted-instances.md](discussions/kernel-assisted-instances.md).
- **By-value with content-addressed slot references.** Slots only
  update at apply termination. Sub-tree atomicity is structural:
  faulted apply leaves no observable side effect outside its working
  memory.
- **Forgery resistance via image_hash chain.** Adversary cannot
  construct Cap::Instance with canonical image_hash without legitimate
  derive_spawn / set_image descent from genesis.
- **Pure-function apply.** `(input, state, scratchpad) → outputs |
  yield | fault`. No side effects during execution; effects encoded
  as outputs.
- **Instance creation:** `MGMT_COPY` of a Cap::Instance for same-type
  siblings (image_hash preserved; content-shared with mutations
  diverging per §9 case (b)); `host_derive_spawn(image, cnode)` for
  sub-types (image_hash chain extends).
- **Instance copy is universal.** MGMT_COPY of any Cap::Instance produces
  a content-shared copy. For copies that need different initial state
  than the source, the Image declares a setup endpoint the caller
  CALLs into after MGMT_COPY.
- **Image's pinned slots accept Cap::Data and Cap::Image.** Both are
  content-addressed copyable kinds suitable for "ro spec content".
- **Resource caps are not separate kinds.** Gas and StorageQuota
  are kernel-assisted Cap::Instances (§22): per-Instance unit handles
  (`Cap::Instance[Gas{meter_id}]` in `gas_slots`,
  `Cap::Instance[Quota{quota_id}]` in `quota_slots`) into kernel-
  internal `GasMeter` / `StorageQuota` tables. Chain accesses the
  tables only via kernel-issued `SetGasMeter` / `SetStorageQuota`
  caps. Custom resources are typed handles into authority ledgers.
- **Authority is conveyed by capabilities.** Cap possession is the
  right to invoke. Unforgeability via image_hash chain; unappropriability
  via cnode ownership. No per-user ACL tables; no bearer tokens (in
  the secrecy sense); no σ-resident signing keys; no Cap::Authority
  kind. See §14 for the EndpointRefCap pattern and
  [userspace/generic-authority-pattern.md](userspace/generic-authority-pattern.md)
  for the broader authority cap spec.

## 0. Foundational principles

```
1.  Data flow direction is structural.
    Forward data flow defines scope; faults propagate against it.

2.  Instance is the unit of state.
    Always Image-bound. Persistent state = cnode contents.
    Image (Cap::Image) is the spec; cnode contents are the state.

3.  Caps are values; cnode is a table of values.
    Slots reference Instance values by hash. Slots only update at apply
    termination.

4.  Caps are uniformly copyable.
    All five cap kinds (Instance, Image, Data, CNode, Type) are
    content-addressed copyable. No kernel-level linearity. Conservation
    of resources lives in authority bytecode; structural forgery
    resistance comes from image_hash chain.

5.  Memory is static, declared by Image.
    Two purposes: ro reference data (Image-baked or pinned cnode
    DataCaps) and rw working/persistent areas (mapped via cnode
    DataCap slots). No dynamic mapping; no lazy paging.

6.  Apply is a pure function.
    apply : (input, state, scratchpad) → (new_state, reply, emits)
            | yield(slot, reason)
            | fault.
    No side effects during execution. Effects are encoded as outputs.

7.  Sub-tree atomicity is structural.
    A's HALT commits everything A did including changes to sub-Instances
    A owns. A's fault discards all of it. By-value with slot-only-
    updates-at-termination.

8.  CALL is the only invocation primitive.
    CALL_RESUME and DROP_PAUSED handle Paused Instances. No CALL_TO.

9.  slot[0] is the universal scratchpad channel.
    All inbound/outbound payload between instances flows through slot[0].
    CALL/CALL_RESUME move caller's slot[0] into target's slot[0]
    (down). HALT/yield/fault reflect target's slot[0] back to caller's
    slot[0] (up). host_yield takes only a marker reference (a
    Cap::Instance whose instance_hash is the routing key — see §14); the
    marker's payload reflects via slot[0]. Apply discipline: keep
    slot[0] in a safe-to-reflect state at all times (OOG can yield
    at any instruction; mid-mutation states would expose partial
    data).

10. OOG is just kernel-triggered host_yield with the kernel-issued
    OOGMarker (§4). Captures continuation; reflects a
    Cap::Instance[Gas{meter_id}] payload to caller; caller typically
    SetGasMeter's a topup and CALL_RESUMEs.

11. Saga is for peer coordination only.
    Sub-Instance ownership is structurally atomic. Saga (emit +
    on_failure) covers the case where A doesn't own B.

12. Gas accounting is STM-exempt.
    Debited at every termination (HALT, yield, fault) regardless.
    Validators are paid for compute they performed.

13. Encapsulation = data-flow isolation + trusted apply.
    Two related properties; they apply at different levels.

    (a) Data-flow isolation. An Instance can only access caps that have
        flowed to it via legitimate cap-flow. Siblings, parents, and
        unrelated Instances are structurally unreachable.

    (b) Trusted apply. An Instance's state changes only via running its
        Image's bytecode. Kernel-enforced; no ABI op writes content
        into another Instance's state. Load-bearing at levels where
        state encodes authorization (orchestrators).

    INTEGRITY, not confidentiality (σ is public). What makes
    sandbox, replay, trustless composition, and the orchestrator-
    mediated authority pattern (§14) work.

14. Image is mutated as a unit; set_image is a "push".
    The only on-self spec-changing primitive is
    set_image(new_image: Cap::Image). Each set_image:
      - swaps pinned slots (from old image's to new image's),
      - installs new_image as current,
      - updates image_hash = hash(self.image_hash || hash(new_image)).
    Lineage chain extends; it does not contract.
    No host_set_code / host_set_endpoints / etc. — those would let
    userspace mutate spec piecewise, breaking atomicity.
    Sub-type Instance creation uses host_derive_spawn (spawning a fresh
    Instance with chosen image), which extends the chain on the *spawned*
    Instance, not self. Same-type Instance creation uses MGMT_COPY (preserves
    image_hash; content-shared copy).

15. Pinned slots are per-Image, not per-Instance.
    Image.pinned_slots declares which cnode slots hold pinned ro caps
    (Cap::Data or Cap::Image — content-addressed copyable kinds).
    They're part of the program's spec: LLVM jump tables, baked-in
    constants, Cap::Image references for derive_spawn, etc.
    set_image swaps pinned slots atomically with the rest of the spec.

16. image_hash captures lineage as a cumulative chain hash.
    Canonical formulae:
      genesis:                  image_hash = hash(initial_image)
      after set_image(new):     image_hash = hash(image_hash_before
                                                   || hash(new))
      via derive_spawn(new):    spawned.image_hash =
                                  hash(spawner.image_hash || hash(new))
      via MGMT_COPY:            copy.image_hash = source.image_hash
                                  (preserved, not extended)
    Forgery resistance: post-extension hashes are recursive and never
    equal hash(any single Image). Only genesis Instances have image_hash
    of the form hash(Image). Cap-flow on the genesis Kernel Instance +
    cap-runtime integrity prevent adversary from producing Instances with
    canonical image_hash chains.

17. Type query is semantic, not raw; types are identification, not
    authorization.
    Userspace cannot read raw image_hash. Two type-query host calls:
      host_same_type(a, b)
                  — image_hash equality between two caps the caller
                    holds.
      host_same_type_as(comparer, comparee, [images])
                  — relative-chain comparison: returns true iff
                    comparer's image_hash equals the hash chain
                    extension of comparee's image_hash through the
                    given Cap::Image derivation steps.
    Plus the Cap::Type primitives (host_type_of, host_subtype,
    host_type_eq) for working with types as caps. See §8.
    
    **Type queries identify; possession authorizes.** Two Instances
    being "the same type" doesn't grant authority. Authority requires
    possession of Cap::Instance (the actual instance) used per the
    yield-marker pattern (§14, userspace/generic-authority-pattern.md).
    Raw image_hash and full lineage walking are not exposed; if
    needed, chains track
    ancestors in their own state.

18. Authority within σ is conveyed by capabilities.
    σ is public, but caps in v3 are not bearer tokens whose security
    depends on secrecy — their unforgeability is structural via
    image_hash chain (§16 principle) plus cnode ownership discipline
    (§13). Authority is expressed by minting EndpointRefCap-style
    caps and granting them via cap-flow (§14). Possession = right
    to invoke; intermediates can route but cannot inspect endpoints
    that gate on caller-witness image_hash. No σ-resident signing
    keys; no per-user ACL tables.

19. Instance creation is via MGMT_COPY (for siblings) and host_derive_spawn
    (for sub-types).
    Cap::Instance is uniformly copyable; new Instances are produced by:
      - MGMT_COPY of a Cap::Instance:   content-shared copy with the
                                     same image_hash. Mutations to
                                     either ref diverge per §9 case
                                     (b). For "same type with fresh
                                     state", caller follows MGMT_COPY
                                     with a CALL into an image-defined
                                     setup endpoint.
      - host_derive_spawn(image, cnode):
                                     new image; image_hash chain
                                     extends from self. For sub-type
                                     creation (user contract
                                     instantiation, authority chains,
                                     etc.). Only callable from within
                                     self's apply; consumes the cnode
                                     arg.

20. Instance's root cnode is fixed at 256 slots.
    Variable-size storage uses Cap::CNode (size = 2^k slots; minted
    via host_mint_cnode). Cap::CNode is uniformly copyable; copying a
    populated Cap::CNode produces a content-addressed share.

21. Authority + Subject pattern for issued resources.
    Authority Instances (Kernel, MintInstances, chain-defined issuers) are
    held by the chain orchestrator. They mint Subject Instances via
    host_derive_spawn or by issuing typed handles. Subjects can be
    cloned via MGMT_COPY (content-shared) where applicable; for
    resource splitting, the operation routes to the authority's
    bytecode (or kernel, for kernel-assisted resources) which
    allocates a new ledger entry and constructs the new handle.
    Conservation is enforced by the authority's bytecode + ledger
    (or by kernel-internal tables for kernel-assisted resources, per
    principle 22).

22. Kernel resources are exposed via the kernel-assisted Instance
    pattern.
    Where the kernel needs to maintain state that userspace interacts
    with (yield routing, gas accounting, storage accounting, future
    kernel-mediated operations), that state lives in an Instance whose
    Image is in a kernel-reserved namespace (e.g.,
    `kernel:yieldcatcher`, `kernel:gasmeter`). Properties:
      - Userspace sees a regular Cap::Instance; cap-flow works uniformly.
      - The Image is kernel-implemented in native code (no userspace
        bytecode runs); the state layout is a kernel-known struct.
      - The kernel may short-circuit access to the state during the
        fast path (e.g., per-instruction gas debit) — but the
        abstraction at the user-facing level is plain Instance.
      - Some kernel-assisted Instances live in user Instances' cnodes
        (e.g., YieldCatcher held in an Instance's `yield_marker_slot`);
        others are kernel-internal and never appear in chain hands
        (e.g., GasMeter, StorageQuota — accessed only via kernel-
        issued caps like SetGasMeter).
      - Unit handles into kernel-internal tables (Gas{meter_id},
        Quota{quota_id}) are regular Cap::Instance; conservation lives
        in the kernel-internal table, so cap copies don't multiply
        balance.
    See [discussions/kernel-assisted-instances.md](discussions/kernel-assisted-instances.md)
    for the full design and rationale.
```

## 1. Instance and Image

```
Instance {
  image_id:    ImageHash      -- hash of current Image
  cnode:       RootCNode      -- fixed 256 slots; caps as values;
                              --   persistent state (pinned slots are
                              --   populated from Image.pinned_slots;
                              --   non-pinned slots are mutable state)
  status:      Idle
             | Paused {
                 regs:           ...
                 pc:             u64
                 yield_marker:   Cap::Instance  -- the marker yielded with
               }
             | Faulted { fault_info }

  -- derived (kernel-attested):
  image_hash:    Hash         -- canonical formulae:
                              --   genesis: hash(initial_image)
                              --   after set_image(new):
                              --     hash(image_hash_before || hash(new))
                              --   via derive_spawn(new, cnode):
                              --     spawned.image_hash =
                              --       hash(spawner.image_hash || hash(new))
                              --   via MGMT_COPY of Cap::Instance:
                              --     copy.image_hash = source.image_hash
                              --       (preserved; not a chain extension)
}

RootCNode {                   -- the Instance's root cnode (fixed 256 slots).
  slots:         [Option<Cap>; 256]
}

CNode {                       -- variable size in Cap::CNode (2^k slots).
  slots:         [Option<Cap>; SIZE]
}

Image {                        -- content-addressed; Cap::Image kind
                               -- the smallest unit of program specification
  code:            Bytes            -- bytecode embedded directly
                                    -- (validated at Image construction:
                                    --  parseable; no malformed instructions)
  memory_mappings: [MemoryMapping]
  endpoints:       [Option<EndpointDef>; 256]
  gas_slots:       [SlotIdx]        -- slots that hold Cap::Instance[Gas{meter_id}]
                                    -- (kernel-assisted Instances; see §22).
                                    -- Kernel debits the meter named by the
                                    -- active gas slot while this Instance runs.
                                    -- Convention: gas_slots[0] = primary
                                    --  meter; subsequent entries are
                                    --  fallback reserves (chain-spec policy).
  quota_slots:     [SlotIdx]        -- slots that hold Cap::Instance[Quota{quota_id}]
                                    -- (kernel-assisted Instances; see §22).
                                    -- Kernel debits the named quota when
                                    -- pages are dirtied by this Instance.
                                    -- Convention same as gas_slots: [0] is
                                    --  primary; rest are fallback reserves.
  pinned_slots:    Map<SlotIdx, ContentAddressedCap>
                                    -- pinned ro caps that the program
                                    -- needs. ContentAddressedCap ∈
                                    -- { Cap::Data, Cap::Image }:
                                    --   Cap::Data: LLVM jump tables,
                                    --     baked-in constants, etc.
                                    --   Cap::Image: derive_spawn target
                                    --     images for authority Instances.
                                    -- All slot indices in [0, 256).
  yield_marker_slot: Option<SlotIdx>
                                    -- The slot in the Instance's cnode that
                                    -- holds Cap::Instance[YieldCatcher] — a
                                    -- kernel-assisted Instance (see §22)
                                    -- whose state is the list of markers
                                    -- this Instance catches. On YIELD, kernel
                                    -- walks the call stack and consults each
                                    -- Instance's YieldCatcher via short-circuit
                                    -- (no endpoint dispatch), matching by
                                    -- instance_hash equality.
                                    -- See §4 (host_yield) and §14 (yield-
                                    -- marker authority pattern).
                                    -- None = this Instance catches no yields.
}

MemoryMapping {
  start:   u64                  -- virtual address; MUST be 4 KiB-aligned
  size:    u64                  -- bytes; MUST be a multiple of 4 KiB
  source:  Persistent(SlotPath) -- cnode-DataCap-backed; mutations COW'd
        |  Ephemeral            -- kernel-allocated per-apply; not in cnode;
                                --   captured into Paused on yield
}

-- Page-alignment rationale: DataCap content is page-multiple by
-- construction (see §2). Page-aligning mappings lets the kernel map
-- DataCap pages directly into ring-3 page tables without copying
-- bytes through an intermediate per-call buffer. Pinned-RO mappings
-- of the same DataCap across multiple Instances share physical pages.

EndpointDef {
  entry_pc:          u64
  initial_registers: ...
  arg_registers:     ...
  arg_cnode_size:    u8
}
```

Notes:

- **No `rw_bytes` field.** Persistent rw memory lives as DataCaps in
  cnode, loaded into the address space via memory_mappings at apply
  start.
- **No `volatile` mode.** Stack/scratch live in Ephemeral mappings
  (kernel-allocated, captured into Paused on yield).
- **No `host_set_*` for spec.** Image is mutated as a unit via
  `set_image` (§4).
- **No `image.copyable` field.** All Cap::Instance is copyable at the
  kernel level. MGMT_COPY produces content-shared copy; for
  initialization with different state, the Image declares a setup
  endpoint the caller CALLs into after MGMT_COPY.
- **No `linear_count`.** No linearity, no copy gating.
- **No prev_instance field.** Lineage is captured as a cumulative chain
  hash in `image_hash`.
- **`image_id` is the hash of the current Image.** Different from
  `image_hash` (the lineage-derived chain hash).
- **Pinned slots are determined by Image, not Instance.** Different
  Images have different pinned slot configurations. set_image swaps
  them atomically (§4).

### All Instances are Image-bound

Every Instance is bound to an Image. There are no Image-free Instances.
The Image is referenced by `image_id` (the hash of the current
Cap::Image).

### Cap::Image is a structured cap kind

Cap::Image is a copyable, content-addressed value. Its content is
the Image structure (code, endpoints, mappings, pinned_slots). The
kernel parses Cap::Image at apply boundary to set up working memory
and endpoint dispatch.

Cap::Image instances can be passed via cap-flow, stored in cnode
slots, or constructed by chains as needed for `set_image` /
`host_derive_spawn` calls.

### `set_image` is the only on-self spec-mutation primitive

`set_image` swaps an Instance's Image atomically, including pinned slots:

```
set_image(new_image: Cap::Image) → ()
  Pre: caller is running an apply on self.

  Kernel:
    1. Pinned-slot diff:
       old_pinned = self.image.pinned_slots.keys()
       new_pinned = new_image.pinned_slots.keys()

    2. Clear old pinned slots:
       For each idx in old_pinned:
         self.cnode[idx] = (empty)

    3. Install new pinned slots:
       For each (idx, ro_cap) in new_image.pinned_slots:
         if self.cnode[idx] is non-empty:
           FAIL — collision (caller has non-pinned content where
                  new image needs pinned).
         else:
           self.cnode[idx] = ro_cap
           (kernel may optimize as content-shared reference)

    4. Update image:
       self.image_id = hash(new_image)

    5. Update image_hash chain:
       self.image_hash = hash(self.image_hash_before || hash(new_image))
       (kernel-attested; chain extends)

    6. New image's spec takes effect at next CALL.
```

Each `set_image` is a "push" — image_hash chain extends. Pinned
content is swapped (old image's pinned data goes; new image's pinned
data comes in). Cap-flow on the new image determines who can call
set_image with what; cap-runtime integrity prevents synthesis.

The collision check at step 3 keeps userspace honest: if a caller
has populated a non-pinned slot at an index that the new image needs
pinned, set_image fails.

### Genesis-seeded Instance

At genesis, the chain spec seeds a single root Instance: `Kernel`. Its
image_hash is the hash of its initial Image:

```
Kernel: image_id = hash(KernelImage), image_hash = hash(KernelImage)
```

All other Instances (authority Instances, user contracts, resource Instances)
are derived from `Kernel` via `host_derive_spawn`, which extends the
image_hash chain. The chain spec doesn't seed a roster of templates;
just `Kernel`, plus the Cap::Image references (in `Kernel`'s pinned
slots or initial cnode) for the authorities the chain wants to
derive.

### Forgery resistance

The unforgeability argument is structural:

```
Property A: image_hash = hash(Image_X) for some Image X
  ⟺ this is THE genesis Instance for Image X
    (or a MGMT_COPY descendant that preserved hash(Image_X)).

Property B: image_hash = hash(some_image_hash || hash(Image_X))
  ⟺ this Instance was produced via set_image(Image_X) on an Instance with
    image_hash = some_image_hash, OR via host_derive_spawn(Image_X, ...)
    by a spawner with image_hash = some_image_hash, OR is a MGMT_COPY
    descendant of either.

Property C: image_hash chain rooted at hash(KernelImage)
  ⟺ at some point, this Instance's lineage traced through the genesis
    Kernel Instance.
```

Adversary cannot:

- Synthesize Cap::Instance with target image_hash (cap-runtime integrity).
- Apply Kernel (cap-flow gates; only the kernel/orchestrator has the cap).
- Produce image_hash = hash(KernelImage) via set_image or derive_spawn
  (post-extension image_hash is recursive, not equal to hash(any single
  Image) modulo cryptographic collisions).
- Derive-spawn from canonical Instances without holding a Cap::Instance to
  one (host_derive_spawn is only callable from within self's apply,
  which requires having self as a cap to CALL into).
- MGMT_COPY from a canonical Instance without holding a Cap::Instance to it
  in some accessible slot (cap-flow gates).

Forgery resistance comes from:

1. **Cap-runtime integrity**: caps not synthesizable from bytes.
2. **Cap-flow on the genesis Kernel Instance**: Kernel's Cap::Instance is
   exclusive to the chain orchestrator; authority Instances derived from
   it are similarly held by the orchestrator.
3. **Kernel-attested image_hash formula**: kernel computes the chain
   hash on every set_image / derive_spawn; MGMT_COPY preserves it;
   userspace cannot influence.

### Type queries

Userspace cannot read raw image_hash. Two type-query host calls:

```
host_same_type(a: SlotPath, b: SlotPath) → bool
  Returns true iff a.image_hash == b.image_hash.

host_same_type_as(
    comparer: SlotPath,
    comparee: SlotPath,
    images:   [SlotPath of Cap::Image]
) → bool
  Returns true iff:
    comparer.image_hash == fold_left(
      images, comparee.image_hash,
      (acc, img) -> hash(acc || hash(img))
    )
  i.e., comparer is what you'd get by deriving comparee through the
  given Image steps. Relative-chain comparison; comparee must be a
  Cap::Instance (anchor relative to known reference); absolute Cap::Image
  anchors are deliberately not supported.
```

For "is this a canonical Gas Instance?": chain pins a reference Gas
template; compare via `host_same_type`. For "is this Instance of a
specific subtype?": use `host_same_type_as`. **For authority
routing, do NOT use type queries — use possession of Cap::Instance
combined with the yield-marker mechanism (§14). Type matching is
identification, not authorization.** Lineage walking and raw hash
inspection are not exposed.

## 2. Memory model

### Static layout, declared by Image

`memory_mappings` is a list of regions; each maps one cnode slot's
DataCap into the address space:

```
Image declares:
  memory_mappings: [
    {start: 0x10000, size: 64KB,  source: MainCnode[3]}    -- pinned (ro)
    {start: 0x20000, size: 1MB,   source: Persistent(MainCnode[5])}  -- unpinned (rw)
    {start: 0x120000,size: 16MB,  source: Persistent(Scratchpad[5])} -- caller-provided
    {start: 0x800000,size: 8MB,   source: Ephemeral}                 -- stack/scratch
  ]
  cnode initial state (at construction):
    [3] = Cap::Data(BAKED_RO_BYTES)           -- baked-in ro data
    [5] = Cap::Data(EMPTY)                     -- mutable working area
    ...
  pinned_slots = {3: Cap::Data(...), ...}
```

At apply start: for Persistent mappings, kernel reads each source
slot's DataCap and lays its bytes at the declared start..start+size
in the apply's address space. Pinned source slots → mapped
read-only. Unpinned → mapped read-write with copy-on-write per page.
Ephemeral mappings are kernel-allocated zeroed at apply start.

### DataCap shape: page-multiple content, no separate size

```
DataCap {
  content: Bytes              -- length is always a multiple of 4 KiB
}

hash(DataCap) = hash_tree_root(content)
```

`DataCap.content.len()` is the only authoritative size — there is no
separate `size` field. The kernel does NOT canonicalize content by
stripping trailing zeros. `DataCap("Hello\0\0...\0")` (4 KiB) and
`DataCap("Hello\0...\0")` (8 KiB) are distinct caps with distinct
hashes; they coexist in the cache without dedup.

Rationale: the previous "trailing-zero-stripped canonical form" rule
existed to deduplicate logically-identical short caps. In practice
nothing produces caps in both stripped and padded shapes for the same
logical content — caps come from `host_mint_data_cap` (caller-supplied
bytes, padded up to a page boundary at mint) or from HALT auto-mint
(page-aligned dirty-page content). Both paths produce page-multiple
caps. Removing the strip rule simplifies the kernel without losing
any observable dedup.

### Size handling at map time

```
DataCap.content.len() = N      (both 4 KiB-multiples)
region.size           = S      (both 4 KiB-multiples)

if N == S:  direct page-by-page mapping.
if N <  S:  map the N bytes of the DataCap; map the remaining S − N
            bytes from the shared global zero page (RO).
if N >  S:  CALL faults. Caller is responsible for sizing.
```

Variable-length payloads (e.g., caller args via slot[0]) flow through
a DataCap whose content's logical meaning is interpreted by the
receiver — either via a length-prefix encoding inside the bytes or by
zero-terminator scanning. The kernel does not carry a logical-length
hint.

### Persistence of mapped regions at HALT

For each rw mapping (source slot is unpinned):

```
At HALT:
  If apply explicitly replaced the source slot via cap-table ops:
    Use the replaced cap. Discard memory modifications from this region.
  Else if any pages in the region are dirty:
    Mint a new DataCap whose content is the modified pages verbatim
      (page-multiple, no trailing-zero stripping). Place at source slot.
  Else:
    Source slot unchanged.
```

Apply has full control: explicit slot replacement wins over auto-mint.

### Volatile-style memory: a userspace pattern

The kernel does not provide a "volatile" memory mode. Programs that
want a memory region zeroed at every CALL implement it themselves:

```
Apply:
  ... uses scratch region during execution ...

  -- Before HALT:
  reset(VOLATILE_SLOT, empty_DataCap)
  HALT
```

At HALT: source slot now holds the empty DataCap. At next CALL:
kernel maps empty DataCap → zero-pad → apply sees a zeroed region.

### Page-merkleized DataCap

DataCaps used as backing for mapped regions are stored as
balanced-merkle trees of page-sized chunks. At HALT:

- Modified pages get new chunk hashes.
- Unchanged pages reuse existing chunk hashes.
- Merkle paths from modified leaves to root are recomputed.
- Cost: O(modified_pages × log num_pages), not O(total size).

**Page size: 4 KiB**, matching the underlying JAVM page size.

### Storage cost via dirty-page tracking

Mutation of mapped DataCaps dirties pages; kernel charges each
dirty page to the StorageQuota referenced by the Instance's active
quota_slot (the quota_id named there; see §22). Properties:

- **Copy is free.** Content-addressed values can be referenced from
  multiple slots / mappings at zero cost.
- **Write costs per page.** Each dirty page = one page-cost unit
  charged to the active quota.
- **Stack-leave reset.** An Instance's dirty set persists while it
  remains on the kernel call stack (across nested CALL / yield /
  resume), and is finalized + charged when the Instance leaves the
  stack entirely. This matches "dirty until commit" intuition: a
  Instance that yields and resumes is still mid-invocation, so its
  dirty set is not yet finalized.

If the active quota is exhausted mid-mutation, the kernel yields
with the chain-issued `StorageExhaustedMarker` (per §4); the chain
typically tops up via SetStorageQuota and CALL_RESUMEs.

### Memory and caps are mostly decoupled

Cnode holds caps as values. Most caps (Instance, Image, CNode) are
never mapped into the address space. The single exception: DataCaps
in source slots of memory mappings have their content laid into
memory at apply start.

For ad-hoc data flow:

```
host_read_data_cap(cap, dst_offset, len) → actual_len
  -- copy bytes from a DataCap into a writable mapped region.

host_mint_data_cap(src_offset, len) → DataCap
  -- read bytes from any region; strip trailing zeros; mint a fresh
  -- DataCap; debit StorageQuota ledger entry of self's quota slot.
```

### Rust heap

The Rust heap is a regular Ephemeral mapped region:

```
Apply:
  At apply start: HEAP region zeroed.
  Allocator operates over the region.
  At HALT/fault: heap discarded.
  At yield: heap captured into Paused.volatile_bytes.
```

For programs that want the heap to persist across CALLs, use a
Persistent mapping with a cnode DataCap. OOM is a fault; for
graceful OOM handling, programs use try-* allocator APIs or yield
via a chain-defined `NeedHeapSpace` marker.

## 3. The Instance status state machine and kernel call stack

### Instance states (σ-resident)

```
            spawn          CALL @ endpoint        HALT
   ────────────────► Idle ─────────────────► [apply runs] ──► Idle (new value)
                        ▲    ▲                   │  (target.slot[0]
                        │    │                   │   reflects to caller)
                        │    │                   │
                        │    │                   │ host_yield(marker)
                        │    │                   │   OR kernel OOG (= yield
                        │    │                   │   to OOG-marker)
                        │    │                   │ (target.slot[0] reflects
                        │    │                   │   to caller-handler; per
                        │    │                   │   discipline, slot[0]
                        │    │                   │   is in a safe state)
                        │    └───────────────────┤
                        │   CALL_RESUME(target): │  capture continuation
                        │   caller's slot[0]     │  (regs, pc, marker)
                        │   moves into target's  │
                        │   slot[0]              │
                        │                        ┴
                        │                     Paused
                        │                        │
                        │                        │ panic / illegal access /
                        │                        │ memory fault / etc.
                        │                        │ (target.slot[0] reflects
                        │                        │  to caller; then target
                        │                        │  dropped)
                        │                        ▼
                        │                   Faulted (dead)
                        │                        │
                        │                        │ MGMT_DROP
                        ▼                        ▼
                     [N/A]                    [removed]
```

- **Idle**: ready to be invoked at any Image endpoint.
- **Paused**: continuation captured (regs, pc, marker). Resumable via
  CALL_RESUME (caller's slot[0] becomes target's new slot[0]).
- **Faulted**: dead from a hard fault. Cannot be invoked further.

### Kernel call stack (kernel-internal)

While the kernel is executing apply, it maintains an ordered call
stack. The stack drives control transfer (CALL/YIELD/HALT) and
provides the structural invocation boundary that gives v3 its fault
atomicity and yield-resume linearity.

Stack entries are one of:

- **InstanceEntry(instance, pc, slot_state, status)** — pushed by
  CALL. Introduces a fresh invocation of an Instance.
- **ReferenceEntry(target_position, status)** — pushed by YIELD.
  Refers to an InstanceEntry at an earlier stack position. Same Instance
  instance, same PC as the target; PC advances together when active.

Invariants:

- **Exactly one entry is Running at any moment** — the top of the
  stack. All others are Waiting.
- **Same-instance entries share PC.** If A appears multiple times on
  the stack (once as InstanceEntry from CALL, once as ReferenceEntry
  from a yield routed to A), they all reflect A's single PC.
- **Instance state machine is σ-visible only.** Running and Waiting are
  kernel-internal call-stack accounting, not Instance states. From
  outside the kernel, an Instance in flight just shows as "not Idle yet."
- **An Instance is snapshottable iff it has zero entries on the call
  stack.** Idle Instances are snapshottable; Instances mid-invocation are
  not. (Paused Instances are snapshottable because their continuation
  lives in σ, not on the stack.)

### Pause and the call stack

When an Instance yields voluntarily, it transitions to Paused state (its
continuation captured in σ-resident Paused state) — OR — its
continuation stays on the call stack as a ReferenceEntry waiting for
resumption from below, depending on whether the yield is "persistent"
(stays across blocks) or "in-flight" (stays in the call stack until
resolved this block).

In practice, all routine yields stay in the kernel call stack
(ReferenceEntry). Paused-persistent is the special case when DROP_RESUME
is invoked or the chain explicitly preserves an in-flight invocation
across blocks.

### Why hierarchy is the invocation boundary

The hierarchical call stack provides three structural properties at
one mechanism cost:

1. **Sub-tree atomicity (§10).** An Instance's HALT/fault commits/discards
   everything in its subtree atomically. Sub-Instances called during
   this invocation are part of the parent's atomic scope.
2. **Yield-resume linearity (§14).** A instance in Waiting has a
   structurally unique resumer — whatever's directly above it on the
   stack. Cap-authority routing relies on this.
3. **Reentry protection (free side effect).** Same Instance can't have
   two concurrent activations because the stack is sequential.

See [discussions/data-flow-principle.md](discussions/data-flow-principle.md)
for the architectural derivation: single-mutator-per-state-unit forces
single-activation; per-context fault isolation + single-activation
forces hierarchical structure; hierarchical structure forces orchestrator
mediation for cross-contract calls. The chain orchestrator pattern is
structurally required, not just a convention.

**OOG = kernel-triggered yield, not a fault.** Same continuation
mechanism as voluntary yield (reflects slot[0]; marker = kernel's
canonical OOG marker).

**Hard faults are deterministic and permanent.** Same Instance + same
input → same fault.

**Pause is opaque.** Verbs are CALL_RESUME (sends caller's slot[0] as
the new target slot[0]) and DROP_PAUSED.

**slot[0] discipline.** Apply must keep slot[0] in a "safe to reflect"
state at all times: empty, the input scratchpad, or a complete output
Cap::CNode atomically MGMT_MOVE'd in. Never leave slot[0] mid-mutation,
because OOG yield (or fault) can reflect at any instruction boundary.
The canonical pattern: at apply entry, MGMT_MOVE slot[0] (input) into
a working slot; do work in working slots; just before HALT/yield,
atomically MGMT_MOVE the output Cap::CNode into slot[0].

## 4. The kernel ABI

### CALL — invoke an Idle Instance at an endpoint

```
CALL(target: SlotPath, endpoint_idx: u8) → result
  Pre: target Instance is Idle.
  Effect:
    Caller's slot[0] moves into target's slot[0] (the scratchpad).
    Kernel pushes an InstanceEntry for target on the call stack.
    Kernel materializes mapped regions from cnode DataCaps.
    Apply runs; per-instruction gas debit comes from the meter
      named by target's active gas slot (see §22 and "Gas
      accounting" below).
  On HALT:    target ← Idle (new value); target's slot[0] reflects
              to caller's slot[0].
  On yield:   target enters Waiting on the call stack (or Paused if
              the yield is preserved across blocks); target's
              slot[0] reflects to caller's slot[0]; phi[7] holds the
              yield payload reference (typically a marker / unit
              cap copy).
  On fault:   target ← Faulted, then dropped; target's slot[0]
              reflects to caller's slot[0]; phi[7] = fault info.
  Return: phi[7] = (return value | yield payload ref | fault info);
          phi[8] = status.
```

CALL takes no gas_budget. Gas is metered against the meter named by
the target Instance's active gas slot (Image-declared `gas_slots[0]`).
The caller controls the available gas by ensuring the target's gas
slot points to a meter with sufficient balance — typically by
populating the target's gas slot before CALL (cap-flow or
host_derive_spawn-time initialization).

### CALL_RESUME — resume a Paused or Waiting Instance

```
CALL_RESUME(target: SlotPath) → result
  Pre: target Instance is Paused, or target is at the top of a Waiting
       chain on the call stack expecting resumption.
  Effect:
    Caller's slot[0] moves into target's slot[0] (same as CALL).
    Continuation restored; apply resumes from saved pc.
    Apply reads the response (caller's prepared scratchpad) from slot[0].
  Termination semantics same as CALL.
```

### DROP_PAUSED — give up on a Paused Instance

```
DROP_PAUSED(target: SlotPath)
  Pre: target Instance is Paused.
  target slot becomes empty (Instance and its cnode discarded).
  Caller's slot[0] unchanged (no reflection).
```

### host_yield — voluntary yield with marker routing

```
host_yield(marker: SlotPath)   -- does not return to apply
  Pre: marker holds a Cap::Instance (the yield marker; see §14).
  Effect:
    Read marker; compute marker.instance_hash.
    Walk kernel call stack from top (yielder) toward bottom (root).
    For each InstanceEntry F encountered:
      If F.image.yield_marker_slot is set, F's cnode at that slot
      holds a Cap::Instance[YieldCatcher] (a kernel-assisted Instance;
      §22). Kernel short-circuits into the YieldCatcher's state —
      its marker list — and tests each entry:
        If entry is Cap::Instance and entry.instance_hash == marker.instance_hash:
          Match. Push ReferenceEntry pointing to F. F resumes at its
          post-CALL continuation with the marker payload reflected
          into slot[0].
          Return; control transfers to F.
    No match found: fault yielder with "unhandled marker."

    Per slot[0] discipline: the yielder's slot[0] should be in a safe
    state before calling host_yield, since on resume it will hold the
    handler's response.

  Capture continuation (regs, pc) for the yielder.
  Yielder transitions to Waiting on the kernel stack.
  Gas debited for the yielder (STM-exempt; debited from the meter
    named by yielder's active gas slot).

  On CALL_RESUME from the handler:
    Caller-handler's slot[0] reflects to yielder's slot[0].
    Yielder's apply resumes from saved pc.
    Returns: phi[7..] = registered args; phi[8] = status.

Kernel-issued markers (placed in chain's initial YieldCatcher at
boot; see §12):
  OOGMarker             -- kernel-injected on gas exhaustion. Payload:
                           a Cap::Instance[Gas{meter_id}] copy naming
                           the meter that ran out. Nothing else (no
                           caller context — see "OOG payload" below).
  StorageExhaustedMarker
                        -- kernel-injected on quota exhaustion.
                           Payload: Cap::Instance[Quota{quota_id}] copy.

Chain-defined markers: per chain spec; minted by chain orchestrator
via host_derive_spawn and distributed via cap-flow.
```

The yield marker mechanism replaces the old "yield reason code." A
yield is routed to a specific handler in the call stack based on the
marker's `instance_hash`. The handler must have a matching marker in its
YieldCatcher's marker list.

**OOG payload — just the Gas cap, nothing else.** The OOG yield
payload is *only* the `Cap::Instance[Gas{meter_id}]` copy. No "which
call was running," no caller instance_hash, no stack context.
Encoding "which call ran out" would reintroduce CALLER information
into a capability-only system — which is precisely what v3 avoids.
The meter_id alone is sufficient: chain looks meter_id up in its
own ledger to find the owning user; that's all the context needed
to decide topup vs fail. Same shape for StorageExhausted.

See §14 for the canonical authority pattern that uses this mechanism.

### host_read_data_cap / host_mint_data_cap

```
host_read_data_cap(cap: SlotPath, dst_offset: u64, len: u64) → actual_len
  Copy bytes from the DataCap at `cap` into a writable region at
  dst_offset. Returns actual bytes copied (may be less than len if
  cap.size is smaller).

host_mint_data_cap(src_offset: u64, len: u64, quota_slot: SlotPath,
                   dst: SlotPath) → ()
  Read len bytes from any region starting at src_offset.
  Strip trailing zeros to get canonical content.
  Read quota_slot (holds Cap::Instance[Quota{quota_id}]); debit
    kernel-internal StorageQuota[quota_id] by stripped size.
  Mint a fresh Cap::Data; place at dst.
```

### Image / spawn / type-related host calls

```
set_image(new_image: SlotPath) → ()
  Pre: caller is running self's apply.
       new_image at SlotPath holds a Cap::Image.
  Atomically swaps Image; updates image_hash chain (see §1).

host_derive_spawn(image: SlotPath, cnode: SlotPath, dst: SlotPath) → ()
  Pre: caller is running self's apply.
       image holds a Cap::Image.
       cnode holds a Cap::CNode of size 256.
       dst is empty.
  Effect:
    Constructs a fresh Instance:
      image:       (the Cap::Image at `image`)
      image_hash:  hash(self.image_hash || hash(image))   (chain extends)
      cnode:       initialized from input cnode's slots, with the
                   spawned image's pinned slots overlaid.
      status:      Idle
    Consumes the input Cap::CNode (Cap::Image is content-addressed
    copyable; reading it doesn't consume).
    Places Cap::Instance at dst.

host_same_type(a: SlotPath, b: SlotPath) → bool
  Returns true iff a.image_hash == b.image_hash.
  
  USE FOR IDENTIFICATION ONLY. Two Instances being "the same type" does
  not grant authority — possession of a Cap::Instance is what grants
  authority. See §14 for the proper authority pattern.

host_same_type_as(
    comparer: SlotPath,
    comparee: SlotPath,
    images:   [SlotPath of Cap::Image]
) → bool
  Returns true iff comparer.image_hash equals the chain extension
  of comparee.image_hash through the given Image derivation steps.
  
  USE FOR IDENTIFICATION ONLY. Same caveat as host_same_type: type
  matching is not an authority proof. Use Cap::Instance possession for
  authority.

-- Cap::Type ops (see §8 for Cap::Type definition):

host_type_of(instance: SlotPath, dst: SlotPath) → ()
  Pre: instance holds a Cap::Instance; dst is empty.
  Effect: extract the Instance's image_hash; place Cap::Type{image_hash}
  at dst.
  
  USE FOR IDENTIFICATION ONLY. Possession of Cap::Type does not grant
  authority equivalent to possession of Cap::Instance. See §8 and §14.

host_subtype(
    base: SlotPath,
    images: [SlotPath of Cap::Image],
    dst: SlotPath
) → ()
  Pre: base holds a Cap::Type; dst is empty; images are Cap::Images.
  Effect: compute the chain-extended image_hash:
    result_hash = fold(base.image_hash, hashes(images),
                       (acc, h) -> hash(acc || h))
  Place Cap::Type{result_hash} at dst.
  
  Pure computation. No Instance derivation. No authority granted.

host_type_eq(a: SlotPath, b: SlotPath) → bool
  Pre: a, b hold Cap::Type.
  Returns true iff a.image_hash == b.image_hash.
```

For **same-type Instance creation** (siblings of self's type), use
`MGMT_COPY` on a Cap::Instance whose image_hash matches the target type.
Content-shared copy; mutations diverge per §9 case (b). If the
sibling needs a different state than self at construction, the
Image declares a setup endpoint that the caller CALLs into after
MGMT_COPY to initialize it.

For **sub-type Instance creation** (different image, new image_hash
chain), use `host_derive_spawn`. The image_hash chain extends from
self; this is how authority Instances create their subjects.

There is **no** `host_set_code` / `host_set_endpoints` /
`host_set_memory_mappings` — Image is mutated as a unit.

There is **no** `host_set_pinned` — pinning is determined by
`Image.pinned_slots`.

There is **no** `host_is_template_of` — lineage walking is off-chain
or userspace.

There is **no** raw image_hash exposure — the only type query is
`host_same_type`.

### Cap-table operations

```
MGMT_COPY(src: SlotPath, dst: SlotPath) → Result
  Clone source cap into dst slot. All cap kinds are copyable.
  Rejects if source slot is `pinned`.
  Cost: O(1) (content-addressed; both slots reference the same hash).

MGMT_MOVE(src: SlotPath, dst: SlotPath) → Result
  Move source cap to dst slot. Rejects if source slot is `pinned`.

MGMT_DROP(src: SlotPath) → Result
  Remove cap from slot. Rejects if `pinned`.

host_mint_cnode(slot: SlotPath, cnode_size_log: u8, quota_slot: SlotPath)
  -- Mints a fresh empty Cap::CNode of size 2^cnode_size_log slots.
  -- Places at the given slot in self's cnode (slot must be empty).
  -- Debits StorageQuota[quota_slot's quota_id] by metadata size.

MGMT_CNODE_SWAP(a: SlotPath, b: SlotPath)
  -- Swap contents of two slots. Both slots must be either both in
  -- self's root cnode, or both in the same Cap::CNode reachable from
  -- self. Useful for atomic batch operations.
```

### Calling convention

Endpoint invocation is **process spawn + IPC**, not a SysV-style
function call. Caller and target have separate register files; the
kernel mediates the boundary. Target's bootstrap state comes from
two sources merged in order:

1. **Snapshot** (callee-declared): `endpoint.initial_regs` from the
   target's Image table — typically `phi[1] = stack_top` and any
   other constants the program wants at entry. All unset GPRs are 0.
   PC is set to `endpoint.entry_pc`.
2. **Args overlay** (caller-supplied): `phi[7..10]` are written last
   from the four u64 arg slots in the CALL site.

The kernel does *not* write the endpoint selector or the target slot
into any callee register. The endpoint is fully encoded by PC (each
endpoint has its own `entry_pc` in the Image table — there is no
in-bytecode dispatcher reading a selector). The target slot is the
caller's private namespace and isn't meaningful inside the target.
An Image author that wants either value can declare it in
`initial_regs` for the specific endpoint.

```
On CALL entry (target's apply starts at endpoint.entry_pc):
  phi[i]      = endpoint.initial_regs[i]  for each i (snapshot)
  phi[7..10]  = register args (4 u64 args supplied by caller; overlay)
  all other phi = 0
  slot[0]     = scratchpad (moved from caller's slot[0])

On CALL_RESUME entry (target's apply resumes from saved pc):
  slot[0]     = scratchpad (moved from caller's slot[0]; the response)
  -- no register args: target's registers are restored from the saved
     continuation (regs, pc captured at host_yield).

On apply termination, return registers (kernel writes into CALLER):
  caller's phi[7]  = on HALT:    u64 return value
                     on Paused:  yield payload reference
                     on Faulted: fault info pointer
  caller's phi[8]  = system status (Ok | Paused | Faulted)
  caller's slot[0] = reflected from target's slot[0]
```

Caller's other registers are untouched across the CALL boundary —
they're preserved by the kernel in the caller's continuation while
the target runs, not by any callee-side discipline.

### Gas accounting (STM-exempt)

Gas is accounted via the kernel-assisted GasMeter pattern (§22):

```
GasMeter (kernel-internal, kernel-assisted Instance):
  Image: kernel:gasmeter
  State: meters: Map<MeterId, RemainingGas>
  Lifecycle: kernel initializes at block start with
    { root_meter_id: <chain-spec block budget> }; all other meters
    are populated lazily by chain via SetGasMeter; kernel discards
    GasMeter at block end (kernel is stateless across blocks).

Gas{meter_id} (per-Instance unit handle, kernel-assisted Instance):
  Image: kernel:gas
  State: meter_id: u64
  Created via Cap::Instance[MintGas].mint(meter_id) — caller supplies
    the meter_id (chain-chosen; kernel cannot assign uniquely
    without persistent state).
  Conservation lives in GasMeter, not in the cap — cap copies all
    name the same meter; debiting any copy debits the same meter.
```

During execution of an Instance:
- Kernel reads the meter_id from the Instance's active gas slot
  (`gas_slots[0]`).
- Per-instruction metering decrements `GasMeter[meter_id]` directly
  via kernel short-circuit (no endpoint dispatch).
- When the meter reaches 0 mid-execution, kernel triggers a yield
  with the well-known `OOGMarker` (kernel-issued at chain init;
  placed in chain's initial YieldCatcher). Payload: a
  `Cap::Instance[Gas{meter_id}]` copy.

Per-instruction metering is invisible to userspace; debits don't
go through the CALL/yield mechanism. STM-exempt: gas already
consumed by a faulted apply is not refunded.

### Kernel-issued caps for resource management

The kernel injects a small set of caps into the top-level chain
Instance at chain init. These are how userspace interacts with
kernel-internal kernel-assisted Instances (GasMeter, StorageQuota)
and how userspace creates per-Instance YieldCatchers.

Each is a regular Cap::Instance (kernel-assisted); userspace invokes
its endpoints via CALL.

```
Cap::Instance[SetGasMeter] (kernel-internal access):
  endpoint set(meter_id: u64, value: u64) → u64
    Atomically GasMeter[meter_id] := value; return previous value.
    If no entry exists, "previous" is 0 and the entry is created.
    The atomic set+read enables the "harvest remaining" idiom.

Cap::Instance[SetStorageQuota] (kernel-internal access):
  endpoint set(quota_id: u64, value: u64) → u64
    Same semantics as SetGasMeter for StorageQuota.

Cap::Instance[MintGas] (factory):
  endpoint mint(meter_id: u64) → Cap::Instance[Gas{meter_id}]
    Constructs a fresh Gas unit handle naming the given meter_id.
    Chain is responsible for meter_id uniqueness (collisions
    silently alias).

Cap::Instance[MintQuota] (factory):
  endpoint mint(quota_id: u64) → Cap::Instance[Quota{quota_id}]
    Symmetric.

Cap::Instance[CreateYieldCatcher] (factory):
  endpoint create() → Cap::Instance[YieldCatcher]
    Constructs a fresh empty YieldCatcher (no markers).

Cap::Instance[YieldCatcher] (per-Instance, kernel-assisted):
  endpoint add(marker: Cap::Instance) → ()
    Add a marker template to the catch list.
  endpoint remove(marker: Cap::Instance) → ()
    Remove a marker template.
  endpoint read() → Cap::Data
    Serialize the marker list as a DataCap for inspection.
```

For the full design and rationale (lazy-load OOG-catch, why no
narrow linearity, etc.), see
[discussions/kernel-assisted-instances.md](discussions/kernel-assisted-instances.md).

## 5. Apply terminations

```
HALT(phi[7] = return_value)
  → Instance becomes Idle with new value.
  → Target's slot[0] reflects to caller's slot[0] (apply's chosen
    output, atomically placed via MGMT_MOVE just before HALT).
  → Emits returned for orchestrator processing.
  → Caller: phi[8] = Ok.
  → Gas debited.

host_yield(marker)              -- includes kernel-triggered OOG
  → Instance becomes Waiting on the call stack (or Paused if the yield
    is preserved across blocks).
  → Target's slot[0] reflects to caller's slot[0] (carrying the
    marker's payload — typically a unit cap copy like
    Cap::Instance[Gas{meter_id}] for OOG, per §4).
  → Emits returned for orchestrator processing.
  → Caller: phi[8] = Paused; phi[7] = yield payload reference.
  → Caller may CALL_RESUME (with new scratchpad in caller's slot[0])
    or DROP_PAUSED.
  → Gas debited (from the active gas meter).

panic / illegal access / memory fault / write to pinned region / ...
  → Instance becomes Faulted.
  → Target's slot[0] reflects to caller's slot[0]
    (whatever was there at fault; per discipline, safe-to-reflect).
  → Target then dropped (cnode discarded except for the reflected slot[0]).
  → Emits discarded.
  → Caller: phi[8] = Faulted.
  → Instance cannot be invoked further.
  → Gas debited.
```

| Outcome | Instance.status after | Re-CALL OK? | Caller's slot[0] |
|---|---|---|---|
| HALT  | Idle    | Yes (new state) | reflected from target |
| Paused (yield/OOG) | Waiting on call stack (or Paused if preserved) | No (must RESUME) | reflected from target (marker payload) |
| Fault | Faulted, then dropped | No | reflected from target at fault point |

## 6. Operation patterns

### Pattern A — state-apply loop

Orchestrator (chain Instance's apply) processes events:

```
for event in block_body:
  -- prepare scratchpad in self.slot[0]
  build event-specific Cap::CNode into self.slot[0]
  -- ensure target's gas_slots[0] names a meter with enough balance
  -- (typically chain has already done SetGasMeter for this user's
  -- meter_id; see §22 lazy-load OOG-catch pattern).
  match CALL(target_slot, endpoint):
    Ok:
      target updated; self.slot[0] now has target's reply.
      proceed.
    Paused via OOGMarker:
      -- payload (slot[0]) holds Cap::Instance[Gas{meter_id}].
      -- Chain looks meter_id up in its GasLedger.
      record / decide topup-or-fail; if topup:
        SetGasMeter(meter_id, more); CALL_RESUME.
      else DROP_PAUSED (fault propagation).
    Paused via StorageExhaustedMarker:
      -- payload holds Cap::Instance[Quota{quota_id}].
      analogous; SetStorageQuota then CALL_RESUME, or fail.
    Paused via chain-defined marker:
      marker-specific handling per chain spec.
      (self.slot[0] has the marker's payload from yield.)
    Faulted:
      drop target; chain-spec policy decides (log, governance, etc.).
      (self.slot[0] has whatever target had at fault.)
```

### Pattern B — state-read (explicit copy + CALL)

For queries that shouldn't mutate target's persistent state:

```
MGMT_COPY(T_slot, T_copy_slot)
  -- content-shared copy; same image_hash; mutations to T_copy or T
  -- will diverge per §9 case (b).
build query args into self.slot[0]
match CALL(T_copy_slot, query_endpoint):
  Ok:    self.slot[0] has reply; use it; MGMT_DROP T_copy.
  ...:   handle; MGMT_DROP T_copy.
```

Available universally because Cap::Instance is copyable. The original
T is unaffected — query runs against the divergent copy.

### Pattern C — snapshot/revert

```
let backup = MGMT_COPY(target_slot)   -- O(1); content-shared
do_risky_work_on_target()
if bad_outcome:
  MGMT_COPY(backup, target_slot)      -- restore
else:
  MGMT_DROP(backup)                    -- discard backup
```

Available universally because all caps are copyable.

## 7. Pure-function apply

apply is `(input, state, scratchpad) → outputs | yield | fault`. No
side effects. Effects are encoded as outputs:

- **Instance state mutations** (cnode, mapped DataCap content) — committed
  on HALT.
- **Emits** — `Emit{target, args, arg_caps, on_failure}` returned for
  the orchestrator.
- **Intent records in well-known-Image Instances** — for things like
  attestation, publishing, scheduling: apply mutates state in a known
  userspace Instance (e.g., AttestationAuthority); the kernel post-HALT
  reads that state and performs hardware ops.

Anything that "looks like" a side effect — sign, verify, publish,
attest, log, BLS aggregate — is encoded as a record in such a
well-known Instance, not as in-apply mutation. The kernel handles
crypto and hardware post-HALT (§15).

## 8. Cap kinds

```
Cap::Instance   — Instance value reference. Content-addressed copyable.
               MGMT_COPY produces a content-shared reference;
               mutations diverge per §9 case (b).
               AUTHORITY-BEARING. Possession is structural proof of
               authority. Use this for authority routing.
Cap::Image   — Image (spec, including bytecode) reference.
               Content-addressed copyable.
Cap::Data    — Bytes (trailing-zero-stripped). Content-addressed
               copyable.
Cap::CNode   — Variable-size cnode (size = 2^k slots).
               Content-addressed copyable.
Cap::Type    — Cumulative image_hash chain identifier.
               Content-addressed copyable. Opaque to bytecode reads;
               equality-comparable via host calls; composable via
               host_subtype.
               IDENTIFICATION-ONLY. NOT an authority credential.
               See "Cap::Type vs Cap::Instance" below.
```

Five cap kinds. All uniformly copyable. No conditional linearity.
No `linear_count`. No drop endpoints.

### Why these five

- **Cap::Instance**: the unit of state. Copyable; MGMT_COPY produces a
  content-shared reference. Mutations via CALL into the Instance's
  apply produce a divergent value (per §9 case (b)). **Possession of
  Cap::Instance is the authority-bearing primitive.**
- **Cap::Image**: the unit of program specification. Content-
  addressed; copyable. Image embeds bytecode directly. Multiple
  Instances can share an Image via the content-addressed hash.
- **Cap::Data**: arbitrary bytes. The general data carrier.
- **Cap::CNode**: variable-size cnode (size = 2^k slots). Used by
  Instances that need more than 256 slots, for nested storage, and as
  the **constructor argument** for `host_derive_spawn`.
- **Cap::Type**: a type identifier — a Cap holding a single
  `image_hash` value (the cumulative chain hash). Used for runtime
  type-checking and type-based dispatch. **Never used standalone for
  authority.**

### Cap::Type vs Cap::Instance — identification vs authorization

This distinction is load-bearing and must be understood clearly:

> **Cap::Type identifies an Instance's type.**
> **Cap::Instance authorizes invocation of a specific Instance.**
>
> These are NOT interchangeable. Cap::Type is derivable from any
> Cap::Instance whose chain is a prefix (via host_type_of + host_subtype);
> Cap::Instance can only be obtained via legitimate cap-flow originating
> from an Instance's actual derivation.

**Forgery resistance for Cap::Instance:** An Instance with image_hash X can
only be produced by derivation through the kernel-mediated
`host_derive_spawn`, which extends the deriver's chain. Adversary
cannot fabricate a Cap::Instance with a chain that doesn't include
their own derivation history. The image_hash chain is forgery-
resistant.

**Cap::Type is NOT forgery-resistant in the same sense.** Anyone
holding a Cap::Instance whose chain prefix is X can compute
Cap::Type{X} via host_type_of. They can further compute
Cap::Type{X + derive_steps} via host_subtype. The Cap::Type
"identifies the type" but doesn't prove the holder has the
corresponding Cap::Instance.

**Authority must use Cap::Instance, not Cap::Type.** A pattern like
"if I hold Cap::Type{X}, I have authority X" is WRONG. The correct
pattern is "if I hold Cap::Instance whose type is X, I have authority X"
— and this is what §14 (yield-marker authority pattern) uses.

**When to use Cap::Type:**
- Runtime type-checking (e.g., "is this Instance of type X?").
- Type-based dispatch in bytecode logic.
- Composing types abstractly without materializing Instances.

**When NOT to use Cap::Type:**
- As a routing key for authority operations (use Cap::Instance).
- As a stand-in for an actual Instance.
- As proof of identity (it's only proof of *knowing the type*).

### Resource caps as kernel-assisted Instances or userspace patterns

Earlier drafts had Cap::Gas, Cap::StorageQuota as separate cap kinds.
In v3, these are NOT cap kinds. They split into two families:

**Kernel-assisted resources (kernel-mediated, see §22):**

- **Gas**: tracked in a kernel-internal `GasMeter` (kernel-assisted
  Instance, never in chain hands). Each Instance holds
  `Cap::Instance[Gas{meter_id}]` in its `gas_slots`; per-instruction
  metering decrements `GasMeter[meter_id]` directly via kernel
  short-circuit. Conservation lives in GasMeter, not in the Gas
  cap, so copies all name the same meter (no narrow linearity
  needed). OOG triggers a yield with `OOGMarker`.
- **StorageQuota**: symmetric — kernel-internal `StorageQuota`
  table, `Cap::Instance[Quota{quota_id}]` unit handles held in
  `quota_slots`, dirty-page tracking debits per Pattern 4 (§2).
  Exhaustion triggers a yield with `StorageExhaustedMarker`.

Chain interacts with kernel-internal tables via the kernel-issued
caps `SetGasMeter` / `SetStorageQuota` (set+return-previous);
mints unit handles via `MintGas` / `MintQuota` (chain-chosen ids).
See §4 for the cap endpoints.

**Userspace resources (chain-bytecode-managed):**

- **Persistent fee balance (tokens)**: ledger entries in chain
  orchestrator's σ (`O.account_balances[user]` as Cap::Data
  integers).
- **Custom resources (tokens, NFTs, etc.)**: typed handles
  (Cap::Instance[ResourceImage]) into authority-managed ledgers. The
  Instance's state names the ledger entry (e.g., session_id); the
  balance lives in O.

Conservation in the userspace case is bytecode-arithmetic in
authorities. Forgery resistance via image_hash chain.

### MGMT_COPY uniformly succeeds

```
MGMT_COPY(src, dst):
  cap = read(src)
  copy share into dst (content-addressed; both refs point to same hash)
```

No copyability checks. No linear_count. No conditional gating.

For Instance cloning: MGMT_COPY produces a content-shared reference;
mutations diverge per §9 case (b). The result has the same
image_hash as the source (same type).

If the resulting clone should have a *different state* from the
source (e.g., resetting some slots, populating new values), the
caller follows MGMT_COPY with a CALL into an image-defined setup
endpoint:

```
A.apply:
  MGMT_COPY(template_slot, clone_slot)
  build init_args Cap::CNode into self.slot[0]
  CALL(clone_slot, setup_endpoint)
  -- clone is now mutated per the image's setup logic
```

The image author decides what the setup endpoint does (reset slots,
write new state, etc.). MGMT_COPY plus image-defined initialization
gives full flexibility without requiring a special kernel primitive.

### Why no linearity

Earlier drafts considered making certain caps (or all Cap::Instance)
linear at the kernel level, with kernel-tracked exclusivity. v3
explicitly rejects this. The argument:

**Linearity is needed only for the "Delegate" pattern.** Delegate
means: the cap **contains** a resource (e.g., `Untyped{remaining:
100}`); operations on the cap mutate its internal balance and
produce sub-resources; conservation requires no aliasing.

In v3's by-value, copyable-cap model, Delegate cannot work. With
copies of a balance-bearing cap, each clone tracks its own copy of
the balance; mutating one doesn't affect the other; total spend
across clones can exceed initial balance. Conservation breaks.

The seL4 mitigation is structural linearity (kernel rejects
MGMT_COPY of linear caps). But this introduces a kernel privilege
that goes beyond "running mechanism" — the kernel becomes an
enforcer of structural exclusivity, asymmetric with what userspace
can do.

**More importantly, even with linearity, userspace can't implement
Delegate.** If ChainOrchestrator gives a user contract a linear
`Cap::Instance[Counter{count: 100}]`, the user contract's invocation
of `counter.consume(50)` mutates the *local* Counter Instance's count
to 50. But CO's *canonical* counter (in CO's σ-state) is unchanged
— there's no structural way for Counter's apply to mutate CO's
state from inside Counter's own apply (principle 13b: trusted
apply). So the actual conservation effect can only happen when
Counter yields up to CO, CO's apply runs, CO mutates its state.
That's not Delegate; that's managed cap with yield-to-issuer.

So Delegate, in seL4 itself, is "managed cap accessed via syscall"
— not actually different from our managed cap pattern in functional
terms. seL4's syntactic veneer (`untyped.retype(...)` looking like
a method call) hides the syscall. The kernel does the work; the cap
is the authority handle.

**Linearity has no other structural use case in v3** that other
mechanisms don't already cover:

| Use case for linearity | v3 alternative |
|---|---|
| Delegate (cap = resource) | Managed cap (cap = handle into ledger) + ledger arithmetic in issuer |
| Singleton/identity enforcement | image_hash chain canonical pattern + chain-author discipline |
| One-shot tickets | Ledger entry marked consumed; bytecode rejects re-use |
| Atomic transfer | MGMT_MOVE empties source; receiver gets cap |
| Linear protocol verification | Bytecode tracks step state; rejects out-of-order calls |
| Capability secrecy / non-aliasing | Doesn't apply: σ is public regardless |
| Affine/relevant resource accounting | Bytecode discipline + tooling |

Each row has a v3 mechanism that achieves the same property without
requiring kernel linearity tracking. The kernel stays minimal
(running mechanism only); conservation invariants live in authority
bytecode (small, chain-spec-defined, formally verifiable).

So **linearity earns no place in v3**. Cap::Instance, Cap::Image,
Cap::Data, Cap::CNode are uniformly copyable. Conservation is
ledger arithmetic. Identity is image_hash chain. Atomic transfer
is MGMT_MOVE. There is no kernel privilege beyond running the VM,
computing image_hash, and direct-accessing canonical-image state.

### Why no σ-resident signing primitive

The kernel does **not** provide an in-σ signing primitive, and it
does not provide an in-apply verification cap either. Both signing
and verification happen **kernel-side, post-HALT**, against an
AttestationAuthority Instance the apply produces (§15).

- **σ is public.** Any "secret" in σ is exposed to all validators.
- **Hardware-rooted per-validator signing breaks determinism in
  apply.** Each validator's hardware would produce different
  signatures.
- **Kernel post-HALT is the right boundary.** Apply records intent;
  kernel does the crypto.

### Pinned cnode slots

Pinning is determined by the Instance's current `Image.pinned_slots` —
a Map<SlotIdx, ContentAddressedCap> declaring which slots hold
pinned ro caps. ContentAddressedCap ∈ { Cap::Data, Cap::Image }.

A pinned slot:

- Cannot be MGMT_MOVE'd out.
- Cannot be MGMT_COPY'd out (rejected — pinned status doesn't
  propagate).
- Cannot be MGMT_DROP'd.
- Cannot be replaced by writing a different cap.
- For Cap::Data: memory mappings sourcing from the slot are
  implicitly ro (writes to the mapped address range fault).

`set_image` swaps the pinned set atomically with the rest of the
Image (§4).

Use cases:
- **Cap::Data**: ro reference data baked into the program.
- **Cap::Image**: target images for `host_derive_spawn` calls.
  Authority Instances pin the Cap::Image references for the subject
  types they mint.

## 9. By-value semantics with content-addressed slot references

```
Slot's cap = reference (by hash) to a specific Instance or Data value.

Apply runs:
  Kernel materializes Instance value into apply's working memory.
  Apply mutates working memory (with COW per page for mapped DataCaps).
  Slot is NOT updated yet.

At termination:
  HALT  → kernel computes hash of new Instance value (with new mapped
          DataCaps); slot updates to that hash.
  yield → kernel computes hash of Paused Instance value (with continuation);
          slot updates.
  fault → slot was never updated; outer's view of pre-call value is
          preserved structurally.

No explicit STM buffer; no merge-or-discard ceremony. Atomicity comes
from "slots only update at termination."
```

### The two-condition hashing property

The kernel only needs to compute new hashes ("persist the value")
in exactly two situations:

**(a) At the *outermost* apply's termination** (HALT, yield, or
fault). At that boundary the kernel computes hashes for everything
that was modified (the whole sub-tree). Modified mapped DataCaps
get hashed incrementally via page-merkle.

**Sub-applies within the outermost invocation do NOT trigger
hashing.** When A's apply CALLs B, B's apply runs to HALT, and A
continues — the new B value lives in A's working memory; A's cnode
reference to B is updated in working memory; no hash is computed.

**(b) When an apply explicitly creates a second reference to a
value whose hash isn't yet materialized.** This is the divergence
moment: a singleton in working memory is being duplicated, and the
two references must remain stable independently from this point on.

- MGMT_COPY of a cap whose value lives in working memory.
- An Image's `copy` endpoint producing a Cap::Instance for an Instance
  value that's currently being mutated.

For caps whose hashes are already known (loaded from cnode at apply
start, etc.), MGMT_COPY is free — just duplicates the (hash, size)
tuple.

### Cost model

```
Per-block hashing = O(modified pages × log(num pages))
                      [paid at outermost termination, once per block]
                  + Σ O(divergence event sizes)
                      [paid per explicit copy of a working-memory
                       singleton, mid-block]
```

The crucial property: **sub-CALL chains within a block don't pay
per-level hashing.**

## 10. Sub-tree atomicity

When A.apply CALLs sub-Instances it owns:

```
A → B → C, all sync CALLs:

If C HALTs and B HALTs and A HALTs: all changes commit to σ.
If C HALTs but B faults: B's working state (including the new C
   value) discarded. A sees pre-call B and pre-call C.
If A faults: no changes commit; σ unchanged.

Automatic transactional rollback for sync CALL chains. Each apply's
cap-reference updates live in working memory until that apply HALTs.
Failures unwind everything below.
```

For peer coordination (A doesn't own B), use the saga pattern (§11).

## 11. Sync CALL + emits + saga

### Sync CALL — direct invocation of owned sub-Instances

A CALLs B from A's cnode. B's apply mutates B's working state in
A's working cnode. Sub-tree atomicity is automatic.

### emit — cross-Instance canonical mutation via orchestrator

When A doesn't own B:

```
A.apply HALTs with emit{target=B, args, on_failure=A.refund}.
  → A's new state committed to orchestrator's cnode.

Orchestrator processes emit (sync CALL to B):
  B HALTs   → both A and B committed.
  B Paused  → orchestrator handles per reason.
  B faults  → orchestrator invokes A's refund (compensating action).
```

### Why both

Sync CALL atomicity is structural for owned sub-trees. Saga is for
peer coordination where A's apply terminates before B's CALL begins.

## 12. Per-block kernel + chain Instance

The chain Instance's value IS the chain state.

```
Hardware → Kernel: (parent chain Instance value, block_body)
Kernel:
  Materialize chain Instance from parent state.
  Initialize per-block kernel-assisted Instances (§22):
    GasMeter      := { root_meter_id: <chain-spec block budget> }
    StorageQuota  := { root_quota_id: <chain-spec block budget> }
  Place block_body Cap::CNode into kernel's slot[0].
  CALL(chain_Frame, process_endpoint).
  Apply runs; processes events; sub-CALLs and emits chain.
  HALT.
  state_root = hash(new chain Instance value); commit in block header.
  Discard per-block kernel state (GasMeter, StorageQuota); kernel
    is stateless across blocks.
```

If chain Instance's apply HALTs: block commits; new state-root.
If chain Instance faults: block rejected; no σ change.
If chain Instance yields: chain Instance is now Paused; resumable next
  block.

### Chain init: kernel-issued caps

At first block (genesis) — or at every block, depending on chain
spec — the kernel injects these caps into the top-level chain
Instance's cnode (see §4 for endpoint specs):

```
Gas / storage management:
  Cap::Instance[Gas{root_meter_id}]      -- initial root gas budget
  Cap::Instance[Quota{root_quota_id}]    -- initial root storage budget
  Cap::Instance[SetGasMeter]             -- modify GasMeter (returns prev)
  Cap::Instance[SetStorageQuota]         -- modify StorageQuota
  Cap::Instance[MintGas]                 -- factory for Gas unit handles
  Cap::Instance[MintQuota]               -- factory for Quota unit handles

Yield routing:
  Cap::Instance[CreateYieldCatcher]      -- factory for per-Instance catchers
  
  Pre-placed in chain's initial YieldCatcher
  (chain.cnode[yield_marker_slot]):
    OOGMarker                         -- caught when any meter hits 0
    StorageExhaustedMarker            -- caught when any quota hits 0
    (others as chain spec requires)
```

This is the entire kernel ABI for chain orchestration. Kernel
internals (GasMeter, StorageQuota) are opaque from userspace; only
the cap-mediated operations are visible. Persistence of gas/quota
balances across blocks (e.g., per-user budgets) lives in chain σ,
not in kernel state; chain repopulates kernel tables lazily via
`SetGasMeter` / `SetStorageQuota` in response to OOG /
StorageExhausted yields. See
[discussions/kernel-assisted-instances.md](discussions/kernel-assisted-instances.md)
for the lazy-load OOG-catch pattern.

## 13. Off-chain Dispatch — ephemeral per block

Off-chain Dispatch Instances are fresh per block:

```
Block N: spawn fresh Dispatch Instance; first message is
  aggregate_{N-1}; produce aggregate_N; sign; submit; destroy.
```

The aggregate carries state across blocks. No off-chain storage.

## 14. Authority via capability flow

σ is public. Earlier drafts of this design treated that as an obstacle
to capability-based authority and fell back on per-user ACLs ("auth
tables") maintained by orchestrators. **That was a mistake.** Public
σ does not preclude capability authority — it only precludes
*secrecy-based* authority (signatures, bearer tokens). Capability
authority depends on **unforgeability**, which v3 provides
structurally via image_hash chain plus cnode ownership discipline.
With both in place, possession of a cap *is* the authorization. No
parallel ACL is needed.

### The properties that make caps work in public σ

- **Visibility of a cap in σ does not grant access to it.** Anyone
  can read σ and see that A holds Cap::Instance[X]; nothing follows.
- **Fabrication is structurally prevented.** An Instance whose
  `image_hash` chain doesn't show legitimate derivation from the
  expected parent is rejected on use; the chain extension is kernel-
  mediated and cannot be synthesized in userspace.
- **Cap transfer is gated by ownership.** B cannot reach into A's
  cnode to take a cap; moves require the source's cooperation.
  Mutation of A's cnode is bytecode-mediated by A's apply alone
  (Encapsulation, §0 principle 13).

So a cap held in σ is forgery-resistant *and* unappropriable. That is
exactly the unforgeability seL4 caps provide via kernel mediation;
v3 reproduces it via image_hash chain plus ownership discipline.

### The kernel yield-marker mechanism

Authority caps are implemented via the kernel's yield-marker
mechanism: a instance catches yields routed to it by holding matching
marker Instances in its **YieldCatcher** (a kernel-assisted Instance
referenced from the catcher's `yield_marker_slot`; see §22).
Yielding bytecode places a marker Instance in a scratchpad slot; the
kernel walks the call stack from top down, consulting each instance's
YieldCatcher via kernel short-circuit, and routes the yield to the
first matching instance.

```
Yield routing:
  yielder.bytecode places Cap::Instance[marker_M] in scratchpad
  yielder.bytecode invokes host_yield(scratchpad_slot)
  Kernel:
    target_hash := marker_M.instance_hash
    for each InstanceEntry F on stack from top down:
      if F.image.yield_marker_slot is set:
        let YC = F.cnode[F.yield_marker_slot]
                 (a Cap::Instance[YieldCatcher])
        for each marker template in YC.state.markers:
          if marker.instance_hash == target_hash:
            push ReferenceEntry(F); transfer control to F.
            return.
    fault yielder with "unhandled marker"
```

The marker Instance's `instance_hash` (which incorporates its full
image_hash chain via §1) is the routing key. Adversaries cannot
fabricate matching markers because the chain extension is kernel-
mediated.

A YieldCatcher's marker list is mutated via the catcher's
`add(marker)` / `remove(marker)` endpoints (see §4). To revoke an
authority, the holder removes the marker template — outstanding
authority caps holding that marker fail to match on yield.

### The pattern

A chain Orchestrator `O` mints **authority caps** for the operations
it's willing to expose, and grants them to user contracts that should
be able to invoke them. Each authority cap holds a marker Instance
internally; the marker is opaque from outside the authority cap.
Only the cap's own bytecode (defined by its Image) can extract the
marker to yield with it.

```
Setup phase (Chain init):

  -- Chain mints a marker for each authority type:
  marker_invoke = host_derive_spawn(InvokeMarkerImage, init={})
  
  -- Chain adds the marker to its YieldCatcher
  -- (chain.cnode[yield_marker_slot] holds Cap::Instance[YieldCatcher],
  --  pre-populated at chain init per §12 with OOGMarker etc.):
  CALL(chain.cnode[yield_marker_slot], add, marker=Cap::Instance[marker_invoke])

Image EndpointRefCap (well-known image):
  state:
    marker:         Cap::Instance[marker_invoke]    -- in self.cnode slot
    target_address: ContractId                   -- which contract
    endpoint_idx:   u8                           -- which endpoint
  endpoints:
    invoke(args)
      -- 1. Compose payload from self.state + args:
      --     payload = { target_address, endpoint_idx, args }
      -- 2. Place payload in arg slot (slot for handler to read).
      -- 3. Place self.cnode[marker_slot] (Cap::Instance[marker_invoke])
      --    into yield-scratchpad slot.
      -- 4. host_yield(yield-scratchpad).
      -- 5. On resume, slot[0] holds the handler's response. HALT.

Chain mints these:

O.endpoint grant_endpoint_access(target, endpoint_idx) → Cap::Instance[EndpointRefCap]:
  cap = host_derive_spawn(EndpointRefCapImage,
                          init = { marker: Cap::Instance[marker_invoke],
                                   target_address: target,
                                   endpoint_idx: endpoint_idx })
  return cap
```

A user contract `A` that holds the cap invokes it directly:

```
A.endpoint do_something():
  ref_cap = self.slot[7]   -- holds Cap::Instance[EndpointRefCap(B, 5)]
  slot[0] := args
  CALL(ref_cap, "invoke")
  -- ref_cap's invoke endpoint runs; yields with marker; kernel
  --   routes to Chain; Chain dispatches to B; response returns.
  result = slot[0]
  ...
```

### Why this works

**1. Forgery resistance is structural.** Marker instances are derived
via `host_derive_spawn` from Chain's bytecode; their `instance_hash`
includes Chain's image_hash chain. An adversary cannot fabricate a
matching marker (would require Chain's chain in the derivation
history, which kernel-mediation prevents).

**2. Authorization is possession of the AuthorityCap, not the
marker.** The marker is opaque inside AuthorityCap's state (only
AuthorityCap's bytecode reads it). User contracts hold
`Cap::Instance[EndpointRefCap]`, not the marker directly. They invoke
EndpointRefCap; EndpointRefCap's bytecode yields with the marker on
their behalf.

**3. Cap::Type vs Cap::Instance distinction matters.** Holding a
Cap::Type that *identifies* the marker's type does NOT grant the
ability to yield with the marker. Only holding an actual
`Cap::Instance[marker]` (i.e., the marker Instance) does. The
yield-marker routing uses instance_hash equality on real Cap::Instance
values, never Cap::Type. See §8.

**4. Delegation is automatic.** A can MGMT_COPY the EndpointRefCap
and pass to another contract. Whoever ends up holding it can invoke.
Non-delegable authority would require additional discipline at the
AuthorityCap Image level.

**5. Public σ is fine.** Anyone can read that A holds the cap.
Nothing follows from reading. Only A can move the cap out of A's
cnode; only the cap holder can invoke through it; the marker stays
opaque inside AuthorityCap.

**6. No per-user table at O.** O's state is the contracts themselves
plus O's own facets and YieldCatcher marker list. Per-user
authorization lives in *which caps A holds*, which is A's own cnode
contents.

**7. Revocation via marker rotation.** Chain can remove the marker
from its YieldCatcher via `YieldCatcher.remove(marker)` (or replace
it with a new marker by minting a fresh one and adding it). All
outstanding AuthorityCaps holding the old marker fail to match.
Mint new AuthorityCaps with the new marker if needed. Structural
revocation without per-cap tracking.

### Where policy attaches

Some operations need policy beyond "permitted to invoke" — rate
limits, arg filters, quota deductions per call. Two patterns:

**(a) Bake policy into cap variants.** Mint different EndpointRefCaps
for different policies. A "rate-limited" variant carries its own
limit; an "unlimited" variant doesn't. The cap encodes the policy.
Self-contained; preferred default.

**(b) Sidecar policy table keyed by cap identity.** O maintains a
small map keyed by cap-identity (e.g., a monotonic mint-id captured
in the cap's state at grant time) → policy. On dispatch, O looks up.
This is *not* an auth_table — it's not keyed by user, it doesn't
gate "who can invoke," it only refines "how each cap behaves." Use
when policy must be dynamically adjusted post-grant.

The choice depends on whether the policy is fixed at grant or
dynamic afterwards. Both are capability-pure; neither re-introduces
the ACL anti-pattern.

### Hierarchical orchestration

ChainOrchestrator can decompose:

```
Kernel
  └── ChainRoot (handles chain-wide policy)
       ├── DomainOrch_DeFi
       │    ├── ProtocolOrch_AMM
       │    │    └── ...
       │    └── ProtocolOrch_Lending
       │         └── ...
       ├── DomainOrch_NFT
       │    └── ...
       └── DomainOrch_Identity
```

User contracts that interact with the AMM hold EndpointRefCaps
minted by ProtocolOrch_AMM (delegated through their parent domain
orchestrator). They invoke endpoints directly via cap-flow — same
mechanism at every layer. Possession of the cap is the authority.

For operations spanning domains, the user contract holds an
EndpointRefCap minted by the higher-level orchestrator (e.g., a
ChainRoot-minted cap that targets a cross-domain coordination
endpoint). The cascade reaches the appropriate level structurally;
each cap embeds the level that minted it via image_hash chain.
Capability flow at every layer; no ACLs at any layer.

## 15. Attestation as a yield-mediated authority

Attestation — verifying signatures on inputs and producing
signatures on outputs — is exposed as an **AttestationAuthority (AA)
cap**. AA is a userspace Instance minted by the kernel and granted to
chain code; possession is the authority to request attestations.
The actual crypto runs kernel-side via per-attest yield, with mode
(verify vs sign) determined by whether the block carries
attestation_traces. AA follows the generic authority pattern
documented in [userspace/generic-authority-pattern.md](userspace/generic-authority-pattern.md).

### The shape

```
Image AttestationAuthority (well-known image; minted by kernel):
  state:
    marker: Cap::Instance[attest_marker]    -- in self.cnode
  endpoints:
    attest(key, blob) → AttestStatus
      -- 1. Compose payload: { key, blob }, place in arg slot.
      -- 2. Place Cap::Instance[attest_marker] in yield-scratchpad.
      -- 3. host_yield(yield-scratchpad).
      -- 4. On resume, slot[0] holds the kernel's response (status).
      -- 5. HALT returning status to caller.

Setup (kernel/chain init):
  attest_marker = host_derive_spawn(AttestMarkerImage, init={})
  -- Add to the kernel handler instance's YieldCatcher
  -- (kernel's handler is a kernel-internal instance whose
  --  yield_marker_slot points to its own YieldCatcher):
  CALL(kernel_handler.YieldCatcher, add,
       marker=Cap::Instance[attest_marker])
  -- Now kernel catches yields with this marker.

  -- AA caps are minted with marker in their state:
  aa_cap = host_derive_spawn(AAImage, init={ marker: Cap::Instance[attest_marker] })
  -- Distribute aa_cap to chain code that needs to attest.

enum AttestStatus {
  Recorded,         -- request was recorded; kernel will sign at
                    -- termination (sign mode) or has verified
                    -- (verify mode). Userspace sees the same value.
  InvalidKey,
  MalformedBlob,
  QuotaExceeded,
  ... (mode-invariant failure modes)
}
```

The mechanism follows the canonical authority pattern (§14, §17):
attest_marker's image_hash chain is rooted in the kernel; user code
holding Cap::Instance[AA] can invoke AA which yields with the marker;
kernel catches via yield_marker_slot match; kernel processes mode-
aware and returns mode-invariant status. The marker is opaque inside
AA — only AA's bytecode reads it.

Userspace never sees a signature. The return value of `AA.attest` is
a status enum, identical in produce and verify modes for the same
input. This is the consensus-safety guarantee: there is nothing
userspace can observe that depends on mode.

### Why a status enum (not the signature)

If `AA.attest` returned a signature:

- **In sign mode**, the kernel would have to produce a signature
  visible to userspace. Userspace could then branch on its bytes,
  leak it, or compose it into σ in ways the kernel can't constrain.
- **In verify mode**, there is no live signing key. The kernel
  would have to fabricate something; userspace could distinguish
  fabricated from real and diverge from sign-mode behavior.
  Consensus breaks.

Returning only a status enum makes userspace's observable behavior
**identical** in both modes. The actual signature exists only at the
block level (in attestation_traces), where consensus mediates it.

### Tx / block flow

```
Block carries an optional sidecar attestation_traces:
  None         → sign mode (this validator is the proposer).
  Some(sigs)   → verify mode (this validator is a verifier).

Kernel injects a Cap::Instance[AA] at apply start, in scratchpad of
the top-level apply. AA's image_hash_chain extends from the kernel-
bridge image, structurally proving "minted by this kernel."

Apply (or downstream Instances receiving AA via cap-flow) calls
AA.attest(key, blob) at every signature obligation.

Per-attest yield handling:
  - AA's bytecode yields with attest_marker; kernel walks the call
    stack and consults each InstanceEntry's YieldCatcher (via short-
    circuit). Match found at kernel handler instance.
  - Intermediates don't catch (their YieldCatcher's marker list
    doesn't contain attest_marker). They have no access to the
    yielded payload — it never lands in their slot[0].
  - The kernel reads the payload (key, blob) from the yield's arg
    slot — these are part of AA's payload composition, not part of
    AA's identity.
  - The kernel performs the mode-appropriate work:
      Verify mode: hw_verify(key, blob, traces[next_slot]).
                   Status = Recorded on success; else mode-invariant
                   failure or block-fault (see attestation-authority.md).
      Sign mode:   if validator has authority to sign with key,
                     hw_sign(key, blob) → sig; append to outgoing
                     attestation_traces; Status = Recorded.
                   else: mode-invariant failure (consensus safe
                     because failure conditions are deterministic
                     functions of apply-visible state).
  - The kernel places status in slot[0]; CALL_RESUME returns control
    to AA's bytecode.

Apply HALTs. At HALT, kernel knows:
  Verify mode: did every required position in traces get consumed?
               If not, block invalid (apply produced fewer attestations
               than the block claims).
  Sign mode:   are all hw_sign calls done? Block is finalized with
               the attestation_traces sidecar.
```

### Why this obviates a σ-resident sig primitive

- **No signing key in σ.** The signing key is per-node hardware
  state, never on-chain.
- **No Cap::SigVerify needed.** Verification is kernel-side, per-
  attest, against block-supplied traces.
- **No SigningCap as a userspace cap.** Authority to sign with a
  given key is per-node config; userspace gets only the AA cap, which
  grants "request attestations" not "see signatures."
- **Determinism preserved.** Userspace observes only mode-invariant
  status. The signature itself lives at the block layer.

### AA presence and chain integrity

Kernel verifies on receipt of every Attest yield that the request's
`image_hash_chain` extends from a kernel-minted AA. A fabricated
Attest from userspace would have a chain that doesn't match; rejected
structurally. This is what forgery resistance buys; no presence-check
machinery beyond chain validation is required.

The chain orchestrator's bytecode is responsible for ensuring AA
flows through cap-flow to the Instances that need to attest. If the
orchestrator's bytecode is incorrect (drops AA), the relevant
attestations don't happen, and the block fails consensus. Strong
incentive to author correctly.

### BLS aggregation

A separate AA endpoint follows the same yield-mediated pattern:

```
AA.aggregate(group_key, partial_sig) → AggregateStatus
  -- builds an Aggregate request Instance (state: { group_key, partial_sig });
  -- yields up; kernel collects partials per group;
  -- at block finalization, kernel BLS-aggregates and appends final
  -- sig to block sidecar.
  -- Returns mode-invariant status.
```

### Cross-chain proofs

External-chain attestations use the same AA cap. The verifier on
this chain calls `AA.attest(external_chain_pubkey, header_hash)`.
The block carries the external sig in attestation_traces; kernel
verifies per-yield. No new mechanism.

## 16. MintInstance as a capability-mediated pattern

MintInstance (issuance authority for typed values) is owned by the
chain Orchestrator. User contracts that should be able to mint hold
**MintRefCap** — a capability minted by O that, on invocation, yields
a Mint request up the cascade to O. Same yield-mediated authority
pattern as AA; same forgery resistance via image_hash chain. No
auth_table lookup; no user-keyed ACL.

```
Image MintInstance (owned by O, well-known image):
  state:
    issued:  Map<MintHandle, Issuance>,
    policy:  ...
  endpoints:
    mint(domain, content) → Issuance       -- only callable from O.apply
    burn(handle)                           -- only callable from O.apply
    transfer(handle, from, to)             -- only callable from O.apply

Image MintRefCap (granted by O to user contracts that may mint):
  state:
    domain: DomainId                       -- which mint domain this cap is for
    marker: Cap::Instance[mint_marker]        -- in self.cnode
    -- possibly: policy fields (rate limits, etc.) baked in per §14
  endpoints:
    mint(content) → MintStatus
      -- Per the canonical authority pattern (§14, §17):
      -- 1. Compose payload from { domain, content } + args.
      -- 2. Place Cap::Instance[mint_marker] in yield-scratchpad.
      -- 3. host_yield(yield-scratchpad).
      -- 4. Kernel routes to O (which has mint_marker in its
      --    yield_marker_slot). O invokes MintInstance.mint internally
      --    and returns status via CALL_RESUME.
      -- 5. On resume, slot[0] holds status (and any new Issuance cap).
      -- 6. HALT to caller.
    burn(handle) → BurnStatus    -- symmetric pattern
    transfer(...) → TransferStatus
```

Setup: O derives mint_marker via `host_derive_spawn(MintMarkerImage)`
and adds it to its YieldCatcher via
`CALL(O.YieldCatcher, add, marker=Cap::Instance[mint_marker])`. Then
mints MintRefCaps with the marker embedded. See
`userspace/generic-authority-pattern.md` for the full pattern.

### Flow

```
Alice's tx (off-chain, signed):
  "Alice transfers 10 to Bob."

Chain Orchestrator's apply:
  1. Record Alice's signature into AttestationAuthority:
       AA.attest(alice_pubkey, tx_payload_hash).
  2. Look up Alice's user contract A (just a contract registry
     lookup — no auth_table).
  3. Update Alice's account state (decrement) and Bob's (increment).
  4. If a typed stamp is needed, O calls MintInstance.mint directly
     (O holds the cap to MintInstance, intra-O cap-flow).

Cross-contract case (A invokes an operation that mints):
  1. A holds Cap::Instance[MintRefCap(domain_X)] in its cnode (granted
     by O earlier via O's grant endpoint).
  2. A.apply calls MintRefCap.mint(content).
  3. MintRefCap's bytecode yields with mint_marker; kernel walks
     the call stack; finds O's YieldCatcher contains a matching
     marker template; routes to O.
  4. O's bytecode reads payload (domain_X, content), invokes
     MintInstance.mint(domain_X, content) → Issuance.
  5. O places result in slot[0]; CALL_RESUME. MintRefCap resumes,
     HALTs with status to A.

Forgery resistance: a malicious A cannot yield with mint_marker
without holding a real MintRefCap (the marker is in MintRefCap's
state, opaque from outside). And A can't fabricate a MintRefCap
because Chain's chain prefix can't be replicated.
```

## 17. Footgun reduction

Structurally eliminated:

- **Reentrancy attacks** — by-value snapshots; nested calls operate
  on separate instances.
- **Mid-update state observation** — apply runs on its own working
  state; only termination publishes to outer.
- **Cap-as-value confusion** — caps are content-addressed copyable;
  MGMT_COPY produces explicit shared references; mutations diverge
  per §9 case (b).
- **Bytecode validation at Image construction** — kernel validates
  Image's embedded bytecode for parseability when the Image is
  constructed. Malformed bytecode rejected at construction.
- **Memory exhaustion mid-apply** — static memory; allocation only
  via the heap-region pattern with bounded size.
- **Page-fault nondeterminism** — no page faults; access to undeclared
  addresses Faults the Instance deterministically.
- **Lazy paging consensus footguns** — no lazy paging.
- **Lost continuation** — yield captures continuation in Instance value.
- **Pinned data corruption** — kernel rejects writes to pinned regions
  and modifications to pinned cnode entries.
- **Surprise gas refunds on fault** — gas STM-exempt; debited regardless.
- **Bearer-token forgery in public σ** — there are no bearer tokens
  in the secrecy sense. Caps in σ are visible but unforgeable
  (image_hash chain) and unappropriable (cnode ownership). Authority
  flows via capability grant (§14); off-chain → on-chain authority
  uses AttestationAuthority verified kernel-side via per-attest yield
  against block-supplied traces (§15).
- **`caller()`-style identity introspection** — not exposed. Instances
  identify their callers structurally (orchestrator's own dispatch
  loop tracking which child it just CALLed).
- **Spec-mutation forgery (image_hash collision via spec replication)** —
  prevented structurally. image_hash is a kernel-attested chain;
  genesis Instances have image_hash = hash(initial_image); post-set_image
  / post-derive_spawn image_hashes are recursive.
- **Raw image_hash inspection footguns** — userspace cannot read raw
  image_hash. The only type queries are semantic (`host_same_type`,
  `host_same_type_as`).
- **Piecewise spec mutation inconsistency** — Image is mutated as a
  unit via `set_image`. No `host_set_code` / `host_set_endpoints`.
- **Conservation violations via cap copying** — conservation lives
  either in kernel-internal tables (for kernel-assisted resources
  like Gas/Quota: copies of `Cap::Instance[Gas{meter_id}]` all name
  the same meter; debiting any copy debits the same row) or in
  authority bytecode (for userspace resources: typed handle copies
  reference the same ledger row). Either way, copying doesn't
  multiply balance — no kernel-level linearity required.

## 18. Open questions

1. **Chain-defined yield markers**: canonical patterns for chain-
   defined markers (CooperativeCheckpoint, NeedHeapSpace, etc.)
   and how chains extend the kernel-issued set (OOGMarker,
   StorageExhaustedMarker).

2. **EndpointRefCap variants and dispatch-side policy**: which
   policy fields (rate limit, arg filter, etc.) bake into the cap
   itself vs. live in a sidecar policy table keyed by cap identity
   at the dispatcher (§14, "Where policy attaches").

3. **Cap::Image construction**: how chain authors construct
   Cap::Image values. Probably via a `host_make_image(code: Bytes,
   endpoints: ..., mappings: ..., pinned_slots: ...) → Cap::Image`
   host call. Bytecode validation at construction.

4. **gas_slots / quota_slots fallback policies**: standard
   combinations chain authors should know — single primary meter
   vs. primary + caller-reserve fallback vs. multi-reserve. Likely
   chain-spec-specific.

5. **State-root computation**: chain-spec choice of merkle scheme;
   canonical serialization for hashing.

6. **Per-block kernel ABI**: exact inputs/outputs at the
   (parent state, block_body) → (new state, header) boundary.

7. **Recursion depth limit**: sync CALL has bounded stack; what's
   the limit?

8. **Long-running computation patterns**: best practices for chain
   authors using the yield/Paused mechanism for compile, ZK proof
   generation, etc.

9. **Genesis seed**: what initial cnode contents does Kernel hold?
   Chains likely pin Cap::Image references for the authorities the
   chain wants to derive at bootstrap, plus the kernel-issued caps
   listed in §12.

10. **Pinned-slot collision policy**: when `set_image` finds a
    target pinned slot is already occupied by non-pinned content,
    we currently FAIL. Should there be a "force" variant?

11. **MGMT_CNODE_SWAP semantics**: pinned-slot rules, cross-cnode
    behavior.

12. **set_image / derive_spawn validation timing for memory_mappings
    against slot types**: at the spawn/transition moment, or at next
    CALL?

13. **`image_id`-equal but `image_hash`-different Instances**: same code,
    different lineage — `host_same_type` returns false. Document so
    chain authors don't conflate "same Image content" with "same
    type".

14. **Off-chain Dispatch Instance's image_hash**: derived per the
    canonical formula, or absent (ephemeral, never hashed)?

15. **Cap::CNode size constraints for spawn**: host_derive_spawn
    requires a Cap::CNode of size 256. Should kernel auto-pad
    smaller Cap::CNodes, or require exact-size?

16. **Hierarchical orchestrator patterns**: when does decomposition
    pay off? What's the minimal canonical set of orchestrators per
    chain?

Resolved decisions on the kernel-assisted Instance design (gas / quota
/ yield routing — page size, dirty-page tracking lifetime, id
assignment policy, OOG payload shape, etc.) are captured in
[discussions/kernel-assisted-instances.md](discussions/kernel-assisted-instances.md).

## 19. Summary

```
Instance (always Image-bound):
  image_id:     ImageHash
  cnode:        256 slots; pinned slots per Image; non-pinned mutable
  status:       Idle | Paused {...} | Faulted
  image_hash:   derived; kernel-attested chain hash:
                  genesis:                  hash(initial_image)
                  after set_image(new):     hash(image_hash_before
                                                  || hash(new))
                  via derive_spawn(new):    hash(spawner.image_hash
                                                  || hash(new))
                  via MGMT_COPY:            preserved

Cap::Image (content-addressed, copyable):
  - code:            Bytes  (bytecode embedded; validated at construction)
  - memory_mappings: [{start, size, source}]
  - endpoints:       [Option<EndpointDef>; 256]
  - gas_slots:       [SlotIdx]    -- slots holding Cap::Instance[Gas{meter_id}]
  - quota_slots:     [SlotIdx]    -- slots holding Cap::Instance[Quota{quota_id}]
  - pinned_slots:    Map<SlotIdx, ContentAddressedCap>
                       (ContentAddressedCap ∈ { Cap::Data, Cap::Image })
  - yield_marker_slot: Option<SlotIdx>
                       -- slot holding Cap::Instance[YieldCatcher]

Cap::CNode (uniformly copyable; mintable):
  - size: 2^k slots
  - slots: [Option<Cap>; size]
  - Used for storage exceeding 256-slot Instance root cnode, for
    state-snapshot/revert patterns, and as the cnode argument to
    host_derive_spawn.

Memory model:
  - Static layout per Image; no dynamic mapping; no lazy paging.
  - Persistent mapping = backed by cnode DataCap; mutations COW'd.
  - Ephemeral mapping = kernel-allocated; per-apply.
  - DataCap canonical form: trailing-zero-stripped.
  - Size-mismatch: small DataCap zero-padded; large DataCap faults.

Apply terminations (all reflect target.slot[0] to caller.slot[0]):
  HALT  → Idle (new value)
  yield → Waiting on call stack (Paused if preserved across blocks);
          continuation is regs+pc; yield payload (typically a marker
          / unit cap) reflects to caller via slot[0].
          (kernel OOG = host_yield with kernel-issued OOGMarker;
           payload is Cap::Instance[Gas{meter_id}].)
  fault → Faulted, then dropped
  Gas debited STM-exempt: from the meter named by the active Instance's
    gas slot; debits are per-instruction; no per-CALL budget.
  Apply discipline: keep slot[0] in a safe-to-reflect state at all
    times (input scratchpad, empty, or complete output Cap::CNode
    atomically MGMT_MOVE'd in). OOG and fault can happen at any
    instruction; partial slot[0] would expose mid-mutation state.

Kernel ABI:
  Invocation:           CALL, CALL_RESUME, DROP_PAUSED
                        (no gas_budget — gas via gas_slots)
  Yield:                host_yield (YieldCatcher-routed marker)
  Data:                 host_read_data_cap, host_mint_data_cap
  Cap-table:            MGMT_COPY/MOVE/DROP/CNODE_SWAP
  Image / spawn:        set_image, host_derive_spawn
  Type-query:           host_same_type, host_same_type_as,
                        host_type_of, host_subtype, host_type_eq
  CNode:                host_mint_cnode

Kernel-issued caps at chain init (see §4, §12):
  Gas/storage:          SetGasMeter, SetStorageQuota, MintGas,
                        MintQuota, root Gas/Quota unit handles.
  Yield routing:        CreateYieldCatcher; chain's initial
                        YieldCatcher pre-populated with OOGMarker,
                        StorageExhaustedMarker.

Cap kinds (five; all copyable):
  Cap::Instance   — Instance value reference. AUTHORITY-BEARING.
                 Includes kernel-assisted Instances (§22): YieldCatcher,
                 Gas{meter_id}, Quota{quota_id}, etc.
  Cap::Image   — spec including embedded bytecode.
  Cap::Data    — arbitrary bytes.
  Cap::CNode   — variable-size cnode (mintable).
  Cap::Type    — image_hash chain identifier. IDENTIFICATION-ONLY;
                 NOT for authority routing (see §8).

  Resource caps (Gas, StorageQuota) are NOT separate cap kinds —
  they are kernel-assisted Cap::Instances:
    Gas{meter_id}   — per-Instance unit handle naming a meter in the
                      kernel-internal GasMeter table. Conservation
                      lives in the table; cap copies all name the
                      same meter; no narrow linearity needed.
    Quota{quota_id} — symmetric for StorageQuota.
  Chain accesses kernel-internal GasMeter/StorageQuota only via
  the kernel-issued SetGasMeter/SetStorageQuota caps.
  Custom (non-kernel-assisted) resources are typed handles into
  authority ledgers.

  No σ-resident signing primitive. Signing/verification happen
  kernel-side post-HALT against AttestationAuthority records (§15).

Image mutation:
  set_image(new_image: Cap::Image) is the only on-self spec-changing
  primitive.

Instance creation:
  MGMT_COPY of Cap::Instance:
    content-shared copy; same image_hash. Mutations diverge per §9
    case (b). For "same type with fresh state": follow MGMT_COPY
    with CALL into image-defined setup endpoint.
  host_derive_spawn(image, cnode):
    new image; image_hash = hash(self.image_hash || hash(image));
    consumes cnode. For sub-type creation (authority Instances creating
    subjects, etc.). Only callable from within self's apply.

Authority + Subject pattern:
  Authority Instances: held by chain orchestrator (Kernel, MintInstances,
    chain-defined issuers). They mint Subject Instances via
    host_derive_spawn or issue typed handles.
  Subject Instances: e.g., user contracts, custom token handles.
  Conservation enforced by authority bytecode (ledger arithmetic)
    for userspace resources, or by the kernel-internal table for
    kernel-assisted resources (Gas/Quota, §22).
  Forgery resistance via image_hash chain.

Type query:
  host_same_type(a, b)  → image_hash equality
  host_same_type_as(comparer, comparee, [images])
                        → comparer is comparee derived through images
  Lineage walking and raw image_hash are not exposed.

Forgery resistance (structural):
  Genesis Kernel Instance has image_hash = hash(KernelImage).
  Post-set_image / post-derive_spawn image_hashes are recursive;
    never equal hash(any single Image).
  Cap-flow on the genesis Kernel Instance gates entry.
  Cap-runtime integrity: caps not synthesizable from bytes.

By-value with content-addressed slot references:
  Slots only update at apply termination.
  Sub-tree atomicity structural.
  No STM buffer required.

Snapshot/revert universal:
  MGMT_COPY of any Cap::Instance produces a content-shared reference.
  Mutations diverge per §9 case (b).
  Always available; always works.

Pinned cnode slots: kernel-locked, declared by current Image's
  `pinned_slots`. Holds Cap::Data (baked-in ro bytes) or Cap::Image
  (derive_spawn targets).

Pure-function apply; effects as outputs.
Saga pattern for peer coordination via emit + on_failure.
Per-block kernel as top orchestrator.
Off-chain Dispatch ephemeral per block.

Authority model:
  In-σ authority is conveyed by capabilities; possession = right to
  invoke. Caps are unforgeable (image_hash chain) and unappropriable
  (cnode ownership); secrecy of σ is unnecessary. Orchestrators mint
  EndpointRefCap-style caps and grant them via cap-flow; no per-user
  ACL tables. No σ-resident signing keys; no Cap::Authority cap kind.
  Off-chain → on-chain authority via AttestationAuthority cap (status-
  only return; per-attest yield mediated by kernel against block-
  supplied traces). Hierarchical orchestrators compose by minting and
  granting caps at each layer.
```

This is the consolidated v3 design without linearity.

For a side-by-side comparison with seL4's verified security
properties, see [discussions/sel4-mapping.md](discussions/sel4-mapping.md).

For the discussion-level exploration that includes the linearity
alternative, see
[../minimum/discussions/minimal-kernel-v3.md](../minimum/discussions/minimal-kernel-v3.md).
