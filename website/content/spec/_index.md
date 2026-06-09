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

This is the decided v3 kernel specification. Exploratory drafts and
superseded alternatives are intentionally not published here.

## The shape, in one paragraph

An Instance holds an Image (its current spec) and a Key-addressed root
cnode (its mutable state). Image is a structured cap kind (`Cap::Image`)
containing code, endpoints, memory mappings, and pinned ro caps.
Instances evolve their Image via **`set_image`** — atomically swapping
pinned slots and extending the cumulative `image_hash` chain. The
canonical formula: at genesis `image_hash = hash(initial_image)`;
after `set_image(new)`, `image_hash = hash(image_hash_before ||
hash(new))`. All four cap kinds (Instance, Image, Data, CNode) are
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
  The four kernel-assisted variants (Gas{meter_key}, Quota{quota_key},
  YieldSender{yield_key}, YieldReceiver{Vec<yield_key>}), plus the
  AttestationAuthority cap, are still Cap::Instance; the kernel may
  direct-access their state for hot-path metering, but they share
  the cap kind with everything else. (The kernel-internal GasMeter /
  StorageQuota tables they index are not caps.) See principle 22 and
  [principles/kernel-assisted-instances.md](principles/kernel-assisted-instances.md).
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
  (`Cap::Instance[Gas{meter_key}]` in `gas_slots`,
  `Cap::Instance[Quota{quota_key}]` in `quota_slots`) into kernel-
  internal `GasMeter` / `StorageQuota` tables. Chain accesses the
  tables by yielding the `kernel:set_gas_meter` /
  `kernel:set_storage_quota` YieldSenders (from the scratchpad CNode).
  Custom resources are typed handles into authority ledgers.
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
    All four cap kinds (Instance, Image, Data, CNode) are
    content-addressed copyable. No kernel-level linearity. Conservation
    of resources lives in authority bytecode; structural forgery
    resistance comes from image_hash chain.

5.  Memory is static, declared by Image.
    Two purposes: ro reference data (Image-baked or pinned cnode
    DataCaps) and rw working/persistent areas (mapped via cnode
    DataCap slots). The declared footprint is fixed for the
    Instance's lifetime (no dynamic growth). Within that fixed
    footprint, demand paging is unchanged — pages still materialize
    lazily on first touch — but the gas attribution differs by region:
    ro regions (pinned DataCaps, code) are materialized lazily yet their
    page-in is **charged eagerly at the CALL** (computed statically from
    `Image.memory_mappings`), while writable pages materialize and charge
    **copy-on-write on first write** — see [gas-cost.md §3](gas-cost.md).
    This is a metering mechanism, not dynamic allocation: an access
    outside the declared mappings is a hard fault, never a lazy allocation.

6.  Apply is a pure function.
    apply : (input, state, scratchpad) → (new_state, reply, emits)
            | yield(yield_sender)
            | fault.
    No side effects during execution. Effects are encoded as outputs.

7.  Sub-tree atomicity is structural.
    A's HALT commits everything A did including changes to sub-Instances
    A owns. A's fault discards all of it. By-value with slot-only-
    updates-at-termination.

8.  CALL is the only invocation primitive.
    CALL_RESUME and DROP_RESUME handle Paused / Waiting continuations.
    No CALL_TO.

9.  slot[0] is the universal scratchpad channel.
    All inbound/outbound payload between instances flows through slot[0].
    CALL/CALL_RESUME move caller's slot[0] into target's slot[0]
    (down). HALT/yield/fault reflect target's slot[0] back to caller's
    slot[0] (up). host_yield takes only a YieldSender reference (a
    Cap::Instance whose yield_key is the routing key — see §14); the
    YieldSender's payload reflects via slot[0]. Apply discipline: keep
    slot[0] in a safe-to-reflect state at all times (a hard fault can
    reflect at any instruction — OOG and voluntary yields only at a
    basic-block start; mid-mutation states would expose partial data).

10. OOG is just the kernel yielding the `kernel:oog` yield_key (§4),
    routed by the same owner-edge rule as voluntary yield. Captures
    continuation; reflects a Cap::Instance[Gas{meter_key}] payload to the
    owner-side handler; the handler typically tops up via the
    `kernel:set_gas_meter` YieldSender and CALL_RESUMEs.

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

17. Type identity is the image_hash; types are identification, not
    authorization.
    An Instance's type is its kernel-attested image_hash (the cumulative
    chain hash), read as raw bytes via one host call:
      host_image_hash_chain(slot, dst)
                  — place a Cap::Data holding the cap's image_hash bytes
                    at dst.
    Same-type = memcmp two such results; subtype = fold the chain
    extension (hash(acc || hash(image))) yourself. See §8.

    **Type identifies; possession authorizes.** Two Instances being "the
    same type" doesn't grant authority. Authority requires possession of
    Cap::Instance (the actual instance) used per the
    YieldSender/YieldReceiver authority pattern (§14,
    userspace/generic-authority-pattern.md). The image_hash *value* is
    freely readable and freely computable (neither secret nor an
    authority credential), so there is no separate Cap::Type kind. Full
    lineage *walking* (enumerating ancestors) is not exposed; if needed,
    chains track ancestors in their own state.

18. Authority within σ is conveyed by capabilities.
    σ is public, but caps in v3 are not bearer tokens whose security
    depends on secrecy — their unforgeability is structural via
    image_hash chain (§16 principle) plus cnode ownership discipline
    (§13). Authority is expressed by minting EndpointRefCap-style
    caps and granting them via cap-flow (§14). Possession = right
    to invoke; intermediates can route a keyed yield but never see its
    payload — owner-edge routing + single-resumer reflect it only via the
    nearest registered owner receiver's slot[0]. No σ-resident signing
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

20. Instance's root cnode is Key-addressed, not a fixed 256-slot table.
    The root cnode and Cap::CNode share the same sparse Key-addressed map
    shape: `Key -> Cap`. There is no declared `2^k` capacity: a CNode grows
    on demand, bounded by storage quota. Leaf values are always caps
    (`CapHashOrRef`), never raw data — so a CNode can model
    `address -> Cap::Instance` for native contracts. Minted via
    host_mint_cnode; any old size argument is legacy and has no semantic
    meaning. Cap::CNode is uniformly copyable; copying a populated Cap::CNode
    produces a content-addressed share.

    Commitment layout is not the runtime access model. A state-root/proof
    implementation may derive a structurally-compressed binary radix Merkle
    view by placing each logical key at `hash(key)` (EIP-7864-style minimal
    InternalNodes, no 256-value stem subtree), but ordinary kernel execution
    reads, writes, CALLs, MOVEs, and DROPs by direct Key lookup. The kernel
    should not hash CNode keys at runtime except when it is actually computing
    a CNode commitment/root/proof.

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
    `kernel:yieldreceiver`, `kernel:gasmeter`). The four kernel-assisted
    variants are `Gas{meter_key}`, `Quota{quota_key}`,
    `YieldSender{yield_key}` (the EMIT right), and
    `YieldReceiver{Vec<yield_key>}` (the CATCH right). Properties:
      - Userspace sees a regular Cap::Instance; cap-flow works uniformly.
      - The Image is kernel-implemented in native code (no userspace
        bytecode runs); the state layout is a kernel-known struct.
      - The kernel may short-circuit access to the state during the
        fast path (e.g., the per-block gas reserve at block entry) —
        but the abstraction at the user-facing level is plain Instance.
      - Some kernel-assisted Instances live in user Instances' cnodes
        (e.g., a YieldReceiver held in an Instance's `yield_receiver_slot`);
        others are kernel-internal and never appear in chain hands
        (e.g., GasMeter, StorageQuota — accessed by yielding the
        `kernel:*` YieldSenders from the scratchpad CNode).
      - Unit handles into kernel-internal tables (Gas{meter_key},
        Quota{quota_key}) are regular Cap::Instance; conservation lives
        in the kernel-internal table, so cap copies don't multiply
        balance.
    See [principles/kernel-assisted-instances.md](principles/kernel-assisted-instances.md)
    for the full design and rationale.
```

## 1. Instance and Image

```
Instance {
  image_id:    ImageHash      -- hash of current Image
  cnode:       RootCNode      -- Key-addressed sparse cnode; caps as values;
                              --   persistent state (pinned slots are
                              --   populated from Image.pinned_slots;
                              --   non-pinned slots are mutable state)
  status:      Idle
             | Paused {
                 regs:           ...
                 pc:             u64           -- MUST be a basic-block start
                                               --   (see "Paused.pc constraint" below)
                 yield_sender:   Cap::Instance  -- the captured YieldSender
                                               --   (carrying its yield_key)
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

RootCNode {                   -- the Instance's root cnode.
  slots:         Map<Key, Cap>       -- sparse, Key-addressed; no fixed
                                     -- 256-slot table.
}

CNode {                       -- sparse Key-addressed kv-map in Cap::CNode.
  slots:         Map<Key, Cap>       -- commitment/proof code may derive a
                                     -- hash(key)-keyed Merkle view when needed.
}

Image {                        -- content-addressed; Cap::Image kind
                               -- the smallest unit of program specification
  code:            Bytes            -- bytecode embedded directly
                                    -- (instruction semantics are lazy:
                                    --  illegal/reserved encodings panic only
                                    --  when reached)
  memory_mappings: [MemoryMapping]
  endpoints:       Map<Key, EndpointDef>
                                    -- sparse, Key-keyed; no fixed 256 capacity.
  gas_slots:       [Key]        -- slots that hold Cap::Instance[Gas{meter_key}]
                                    -- (kernel-assisted Instances; see §22).
                                    -- Kernel consults slots in order while
                                    -- this Instance runs. Empty slots are
                                    -- skipped; present non-Gas slots fault.
                                    -- The first valid non-empty slot is the
                                    -- primary meter used in OOG payloads;
                                    -- subsequent valid slots are fallback
                                    -- reserves.
  quota_slots:     [Key]        -- slots that hold Cap::Instance[Quota{quota_key}]
                                    -- (kernel-assisted Instances; see §22).
                                    -- Kernel debits the named quota when
                                    -- pages are dirtied by this Instance.
                                    -- Convention same as gas_slots: [0] is
                                    --  primary; rest are fallback reserves.
  pinned_slots:    Map<Key, ContentAddressedCap>
                                    -- pinned ro caps that the program
                                    -- needs. ContentAddressedCap ∈
                                    -- { Cap::Data, Cap::Image }:
                                    --   Cap::Data: LLVM jump tables,
                                    --     baked-in constants, etc.
                                    --   Cap::Image: derive_spawn target
                                    --     images for authority Instances.
                                    -- Slot keys are Keys; compact byte keys
                                    -- are conventional for ABI well-known
                                    -- slots such as slot[0].
  yield_receiver_slot: Option<Key>
                                    -- The slot in the Instance's cnode that
                                    -- holds Cap::Instance[YieldReceiver] — a
                                    -- kernel-assisted Instance (see §22)
                                    -- whose state is the set of yield_keys
                                    -- this Instance offers to children it
                                    -- owns. On CALL, the kernel snapshots the
                                    -- caller's current YieldReceiver onto the
                                    -- owner edge. On YIELD/OOG, routing walks
                                    -- owner edges and the nearest edge snapshot
                                    -- containing the key catches it
                                    -- (single-resumer). Routing is by yield_key
                                    -- membership, not by an instance_hash list.
                                    -- See §4 (host_yield) and §14
                                    -- (YieldSender/YieldReceiver authority
                                    -- pattern).
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

- **Instance rw memory is a `mem: DataCap`.** The Instance carries its
  read-write data image as a single dense `Cap::Data` covering the extent
  `[DATA_BASE, DATA_BASE + mem.size)` — the **immutable Backing** half of the
  Backing+View mutability model. It is built at construction by folding every
  memory_mapping's source content (pinned and initial) at its offset; pinned VA
  ranges are re-laid read-only at seed time, so the pinned-RO gas tier is
  preserved without keeping pinned bytes separate. A running engine writes
  dirtied pages straight into the **same `DataCap`'s** copy-on-write overlay
  (`DataCap = { backing: Arc<PageSlab>, overlay }` — Backing and overlay are one
  unified `Cap::Data`; there is no separate `Cap::DataView` type and no HALT
  auto-mint, so the cap itself is the source of truth for its dirty pages).
  Content-addressing flushes the overlay into a fresh backing first (`flush()`),
  so a settled `mem` always has an empty overlay. (This replaces the earlier
  `rw_overlays` byte-range list — same inline-content model, canonicalised into
  one content-addressed dense DataCap.)
- **DataCap is dense, page-multiple, and page-aligned.** A `Cap::Data`
  is page-aligned content whose byte length is the authoritative size and
  is always a multiple of 4 KiB. There is no separate `size` field and no
  trailing-zero stripping: `DataCap("Hello" padded to 4 KiB)` and
  `DataCap("Hello" padded to 8 KiB)` are distinct. No sliding window /
  `set_offset` — programs roam large state by mapping/unmapping bounded
  dense DataCaps; the mutable working form is the same `DataCap` carrying
  a non-empty overlay.
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

### Type identity

An Instance's type is its kernel-attested `image_hash` (the cumulative
chain hash). Userspace reads it directly:

```
host_image_hash_chain(slot: SlotPath, dst: SlotPath) → ()
  Pre: slot holds a Cap::Instance (or Cap::Image); dst is empty.
  Effect: place a Cap::Data holding the raw bytes of the cap's
    image_hash (the cumulative chain hash) at dst.
```

For "is this a canonical Gas Instance?": chain pins a reference Gas
template; `memcmp` the two `host_image_hash_chain` results. For "is this
Instance a specific subtype?": fold the chain extension yourself
(`hash(acc || hash(image))`) over the reference's bytes and compare.
**For authority routing, do NOT use type matching — use possession of
Cap::Instance combined with the YieldSender/YieldReceiver mechanism
(§14). Type identifies; possession authorizes.** Full lineage walking
(enumerating ancestors) is not exposed; only the single cumulative
image_hash value is.

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

At apply start: the kernel declares the address-space regions named by
the Image's memory_mappings, but does **not** eagerly lay their bytes.
Pages materialize **lazily, on first touch** (read → page-in the
content-addressed page; first write → copy-on-write a working page),
which is how the kernel meters memory materialization (#3) — see
[gas-cost.md §3](gas-cost.md). Pinned source slots → mapped read-only
(a write hard-faults); their page-in is materialized lazily but **charged
eagerly at the CALL** that maps the callee (computed statically from the
Image's `memory_mappings`), so the RO fault itself debits no gas. Unpinned →
read-write via copy-on-write per page (writable pages are not clustered);
the first write to a writable page charges CoW per page (depth-aware — see
"Depth-aware CoW" in [gas-cost.md §3](gas-cost.md)). Ephemeral mappings are
kernel-allocated zeroed regions (also materialized on first touch, per
page).

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

Rationale: the previous strip-canonicalization rule existed to deduplicate
logically-identical short caps. In practice
nothing produces caps in both stripped and padded shapes for the same
logical content — caps come from `host_mint_data_cap` (caller-supplied
bytes, padded up to a page boundary at mint) or from flushing a running
`DataCap`'s overlay into a fresh backing (page-aligned dirty-page content).
Both paths produce page-multiple caps. Removing the strip rule simplifies
the kernel without losing any observable dedup.

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
    The region's `DataCap` overlay already holds the modified pages (the
      engine CoW'd them in during the run — the cap is the source of truth,
      no separate mint). Flush the overlay into a fresh backing
      (page-multiple, no trailing-zero stripping) and place at source slot.
  Else:
    Source slot unchanged.
```

Apply has full control: explicit slot replacement wins over the
dirtied-region flush-and-persist.

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
quota_slot (the quota_key named there; see §22). Properties:

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
the `kernel:storage_exhausted` yield_key (per §4), caught by the
chain's YieldReceiver; the chain typically tops up via the
`kernel:set_storage_quota` YieldSender and CALL_RESUMEs.

### Memory and caps are mostly decoupled

Cnode holds caps as values. Most caps (Instance, Image, CNode) are
never mapped into the address space. The single exception: DataCaps
in source slots of memory mappings back address-space regions, whose
pages are lazily materialized into memory on first touch (page-in /
copy-on-write — see [gas-cost.md §3](gas-cost.md)), not laid in eagerly
at apply start.

For ad-hoc data flow:

```
host_read_data_cap(cap, dst_offset, len) → actual_len
  -- copy bytes from a DataCap into a writable mapped region.

host_mint_data_cap(src_offset, len) → DataCap
  -- read len bytes from any region; page-round / zero-pad to a fresh
  -- page-aligned DataCap; debit StorageQuota ledger entry of self's
  -- quota slot by the minted page-multiple size.
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
a chain-defined `NeedHeapSpace` yield_key (minted via
`kernel:mint_yield`).

## 3. The Instance status state machine and kernel call stack

### Instance states (σ-resident)

```
            spawn          CALL @ endpoint        HALT
   ────────────────► Idle ─────────────────► [apply runs] ──► Idle (new value)
                        ▲    ▲                   │  (target.slot[0]
                        │    │                   │   reflects to caller)
                        │    │                   │
                        │    │                   │ host_yield(YieldSender)
                        │    │                   │   OR kernel OOG (= yield
                        │    │                   │   of kernel:oog)
                        │    │                   │ (target.slot[0] reflects
                        │    │                   │   to caller-handler; per
                        │    │                   │   discipline, slot[0]
                        │    │                   │   is in a safe state)
                        │    └───────────────────┤
                        │   CALL_RESUME(target): │  capture continuation
                        │   caller's slot[0]     │  (regs, pc, yield_sender)
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
- **Paused**: continuation captured (regs, pc, yield_sender). Resumable via
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

**Origin-slot reservation.** An InstanceEntry owns the live Instance
state while it is on the stack. The Instance was moved out of an owner
CNode slot at CALL time; that origin slot is empty in the CNode but
reserved in kernel stack metadata. The metadata records the owner frame
and SlotPath. It is not a `Pending` cap, is not visible to hashing, and
is never persisted. Because the slot is reserved, the owner cannot
re-CALL, copy, move, drop, read/type-query, or overwrite the same
Instance while the child is running or waiting. On normal HALT/REPLY the
updated Instance is restored to the origin slot and the reservation is
cleared. On V1 discard paths (`DROP_RESUME`, handler unwind, hard fault
of the subtree), the reservation is cleared and the origin slot remains
empty.

**Per-CALL owner-edge snapshot of the catch-list.** At each CALL the kernel
creates an owner edge from the logical current Instance to the callee and
snapshots the owner's CURRENT `yield_receiver_slot` YieldReceiver onto that
edge. The catch-list is a STATIC edge snapshot, not a live read of
`yield_receiver_slot`:

- **Per owner edge.** The same Instance can own multiple in-flight callees with
  different snapshots. E.g. `A CALL B`, `B yield A`, `[ref A] CALL C`: the
  physical stack is `A -> B -> ref[A] -> C`, but owner edges are `A -> B` and
  `A -> C`. The snapshot on `A -> B` and the snapshot on `A -> C` can differ if
  A changed its slot in between.
- **Frozen for the sub-call.** An Instance can mutate `yield_receiver_slot`
  between its downward CALLs (copy the old YieldReceiver out, move a
  new/smaller one in; an empty slot catches nothing), but the snapshot for an
  in-flight owner edge is immutable — a frame cannot shrink its catch-set
  mid-flight to dodge a descendant's yield. Changes take effect for subtrees
  of SUBSEQUENT CALLs.
- **O(1) membership.** Stored as a set/index on the owner edge, so membership is
  O(1); a yield costs O(owner depth).

Invariants:

- **Exactly one entry is Running at any moment** — the top of the
  stack. All others are Waiting.
- **Same-instance entries share PC.** If A appears multiple times on
  the stack (once as InstanceEntry from CALL, once as ReferenceEntry
  from a yield routed to A), they all reflect A's single PC.
- **ReferenceEntry is control, not ownership.** A ReferenceEntry reactivates an
  earlier owner frame. It does not make the waiting yielder an owner of the
  reactivated frame. Thus in `A -> B -> ref[A] -> C`, B can never catch A's or
  C's later yields unless B is on the owner path of the yielder.
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
2. **Yield-resume linearity (§14).** An Instance in Waiting has a
   structurally unique resumer — the owner-side handler ReferenceEntry
   created by owner-edge routing. Cap-authority routing relies on this.
3. **Reentry protection (free side effect).** Same Instance can't have
   two concurrent activations because the stack is sequential.

See [principles/data-flow-principle.md](principles/data-flow-principle.md)
for the architectural derivation: single-mutator-per-state-unit forces
single-activation; per-context fault isolation + single-activation
forces hierarchical structure; hierarchical structure forces orchestrator
mediation for cross-contract calls. The chain orchestrator pattern is
structurally required, not just a convention. See also
[principles/owner-edge-yield-routing.md](principles/owner-edge-yield-routing.md)
for the precise CALL/YIELD/OOG owner-edge rule.

**OOG = kernel-triggered yield, not a fault.** Same continuation
mechanism as voluntary yield (reflects slot[0]; routing key =
`kernel:oog`).

**Hard faults are deterministic and permanent.** Same Instance + same
input → same fault.

**Pause is opaque.** Verbs are CALL_RESUME (sends caller's slot[0] as
the new target slot[0]) and DROP_RESUME.

#### Paused.pc constraint

`Paused.pc` MUST be a basic-block start (a member of `bb_starts(code)`
as defined by the Instance's `image_id`). Implementations validate
this on entry to CALL_RESUME — a Paused state whose `pc` is not a
bb_start is rejected as invalid (treated as a kernel-invariant
violation, not a soft failure).

This holds naturally for every pause source. Note that `ecall.jar` and
`ecalli` are **forced block starts** — each is its own singleton gas block,
a boundary on *both* sides — so an `ecall`'s own PC is always a bb_start
(see [gas-cost.md §3 "ecall/ecalli blocks"](gas-cost.md)). The pause
sources:

- **Voluntary yield** (ecalli to a yielding host op) yields on the
  instruction *following* the ecalli. `ecalli` is a terminator, so its
  successor PC is in `bb_starts` by definition.
- **OOG at an ordinary block** fires from the per-block gas check the JIT
  emits at every bb_start *before* any instruction of the block executes.
  The check is a **pre-reservation** (`gas ≥ gas_cost(B) + worst_case_3(B)`),
  not a charge-then-test: when it fails, the block is **not entered** and
  **no gas is charged**, and the captured pc is that block's bb_start.
- **OOG at an `ecall`/`ecalli`** fires from the kernel's **dynamic** charge
  (the ecall's cost — a CALL frame, a host op's work — is unknowable at
  compile time, so it has no static preamble). If gas is insufficient the
  kernel yields **before doing the work**, and the captured pc is the
  `ecall`'s **own** PC — a bb_start, because the ecall is a forced block
  start — so the op is cleanly re-attempted after a top-up.

In every case gas never goes negative and there is no mid-block instruction
at which OOG can land. See [gas-cost.md §1 and §3](gas-cost.md).

`bb_starts` is not part of the wire format; it is JIT-derived from
`Image.code` per the PVM2 ISA spec
([pvm2/rv64e-xjar-eei.md](pvm2/rv64e-xjar-eei.md)).
The linker is required to guarantee that every PC at which the
program can possibly pause is a bb_start; the constraint above is
the kernel-side check that the guarantee held.

**Pause-state portability.** PVM2 has no `br_table` and no
`Image.jump_table`; indirect dispatch is plain `jalr` (custom-0
funct3=011 is reserved). The values `jalr` computes are **PVM2 PCs**
— offsets into `Image.code` — never native code addresses: the target
it jumps to, and the return address it writes into `rd`/`ra`, are both
Image-relative. Every indirect jump validates its target lands on a
`bb_start` and re-translates that PVM2 PC through the recompiler's dense
dispatch table (keyed by PVM2 PC, rebuilt per recompilation). This makes
`Paused { pc, regs }` portable across JIT recompilations of the same
Image: `pc` and any register-held return addresses are Image-relative
PVM2 PCs, so a paused state rebinds to the new native layout through the
freshly-built dispatch table — the same PVM2 PC resolves to the same
logical instruction regardless of the underlying native code layout.

**slot[0] discipline.** Apply must keep slot[0] in a "safe to reflect"
state at all times: empty, the input scratchpad, or a complete output
Cap::CNode atomically MGMT_MOVE'd in. Never leave slot[0] mid-mutation,
because a **hard fault can reflect at any instruction boundary** (an OOG
or voluntary yield can only land at a basic-block start, but a fault
cannot be deferred — so the safe-to-reflect rule must hold at every
instruction).
The canonical pattern: at apply entry, MGMT_MOVE slot[0] (input) into
a working slot; do work in working slots; just before HALT/yield,
atomically MGMT_MOVE the output Cap::CNode into slot[0].

## 4. The kernel ABI

### CALL — invoke an Idle Instance at an endpoint

```
CALL(target: SlotPath, endpoint: Key) → result
  Pre: target slot holds an Idle Cap::Instance and is not pinned or
       empty-reserved by an in-flight child.
  Effect:
    Kernel moves the target Instance out of its origin slot and into a
      KernelFrame. The origin slot becomes physically empty, but
      kernel-reserved/pinned by stack metadata until the callee returns
      or is discarded.
    Caller's slot[0] moves into target's slot[0] (the scratchpad).
    Kernel pushes an InstanceEntry for target on the call stack and
      creates the owner edge from the logical current Instance to target.
    Kernel declares mapped regions from cnode DataCaps (pages
      materialize lazily on first touch — see gas-cost.md §3).
    Apply runs; gas is charged per basic block at block entry,
      against the active meter chosen from target's ordered gas slots
      or loaned owner gas scope (see §22 and "Gas accounting" below,
      and gas-cost.md §1).
  On HALT:    target ← Idle (new value); target's slot[0] reflects
              to caller's slot[0]; the owner reservation is cleared
              and the updated Instance is written back to the origin
              slot.
  On yield:   target enters Waiting on the call stack (or Paused if
              the yield is preserved across blocks); target's
              slot[0] reflects to caller's slot[0]; phi[7] holds the
              yield payload reference (typically a YieldSender / unit
              cap copy). The origin slot remains empty-reserved.
  On fault:   target ← Faulted, then dropped; target's slot[0]
              reflects to caller's slot[0]; phi[7] = fault info. The
              reservation is cleared and the origin slot remains empty.
  Return: phi[7] = (return value | yield payload ref | fault info);
          phi[8] = status.
```

CALL takes no gas_budget. Gas is metered against the target Instance's
ordered Image-declared `gas_slots`. Empty declared slots are skipped;
present non-Gas slots hard-fault the target. The first valid non-empty
slot is primary, later valid slots are fallback reserves, and an Image
with no declared gas slots loans its owner's gas scope. The caller
controls available gas by ensuring the target's gas slots point to
meters with sufficient balance — typically by populating those slots
before CALL (cap-flow or host_derive_spawn-time initialization).

While a callee is on the kernel call stack, its origin slot is empty but
reserved. The reservation is not a CNode value and is never persisted.
Any guest operation that tries to CALL, MGMT_COPY, MGMT_MOVE, MGMT_DROP,
read/type-query, or write into that SlotPath faults like pinned-slot
misuse. `CALL_RESUME` resumes the stack continuation directly; it does
not look up the origin slot and therefore does not require the origin cap
to be present.

### CALL_RESUME — resume a Paused or Waiting Instance

```
CALL_RESUME(target: SlotPath) → result
  Pre: target Instance is Paused, or target is at the top of a Waiting
       chain on the call stack expecting resumption.
       If Paused: Paused.pc ∈ bb_starts(target.image.code).
  Effect:
    If target is Waiting on the kernel call stack, resume the recorded
      continuation directly; do not read the target's origin slot.
    Caller's slot[0] moves into target's slot[0] (same as CALL).
    Continuation restored; apply resumes from saved pc.
    Apply reads the response (caller's prepared scratchpad) from slot[0].
  Termination semantics same as CALL.
```

### DROP_RESUME — detach an in-flight continuation

```
DROP_RESUME(target: SlotPath)
  Pre: target is Paused, or target is at the top of a Waiting chain on
       the kernel call stack expecting resumption.
  Effect:
    If target is Waiting: pop the corresponding resumption frame from the
      kernel call stack and materialize the target continuation as a
      σ-resident Paused Instance.
    If target is already Paused: leave the Paused continuation detached.
    The current handler continues running; caller's slot[0] is unchanged
      unless the chain's chosen cap-delivery convention explicitly writes a
      Paused cap there.
```

V1 implementation note: until σ-resident Paused materialization is
implemented, `DROP_RESUME` and handler-unwind discard the affected
in-flight frames. Any origin-slot reservations owned by surviving frames
are cleared, and the origin slots remain empty. No `Pending` cap is
written to the CNode.

### host_yield — yield_key routing

```
host_yield(sender: SlotPath)   -- does not return to apply
  Pre: sender holds a Cap::Instance[YieldSender{yield_key}] (see §14).
  Effect:
    Read yield_key from the YieldSender.
    Let E be the logical current InstanceEntry (following a ReferenceEntry
      to its target if needed).
    Walk owner edges from E toward the root. For each edge child -> owner
      (nearest first):
      child.owner_catch_set is the YieldReceiver snapshot taken from owner
        at the CALL that created child (§3).
      If the snapshot's set contains yield_key:
        Match (single-resumer). Push ReferenceEntry pointing to owner. The
        owner resumes at its post-CALL continuation with the YieldSender's
        payload reflected into slot[0].
        Return; control transfers to owner.
    The kernel is the implicit ROOT YieldReceiver for kernel:* keys
      (bottom of the stack).
    No match found: fault the emitter with "unhandled yield_key."

    Per slot[0] discipline: the yielder's slot[0] should be in a safe
    state before calling host_yield, since on resume it will hold the
    handler's response.

  Capture continuation (regs, pc, yield_sender) for the yielder.
  Yielder transitions to Waiting on the kernel stack.
  Gas debited for the yielder (STM-exempt; debited from the active meter
    chosen from the yielder's ordered gas slots / loaned owner gas scope).

  On CALL_RESUME from the handler:
    Caller-handler's slot[0] reflects to yielder's slot[0].
    Yielder's apply resumes from saved pc.
    Returns: phi[7..] = registered args; phi[8] = status.

Kernel:* yields caught by the kernel-as-root-receiver (the chain
registers these in its YieldReceiver at init; see §12):
  kernel:oog            -- kernel-injected on gas exhaustion. Payload:
                           a Cap::Instance[Gas{meter_key}] copy naming
                           the meter that ran out. Nothing else (no
                           caller context — see "OOG payload" below).
  kernel:storage_exhausted
                        -- kernel-injected on quota exhaustion.
                           Payload: Cap::Instance[Quota{quota_key}] copy.

Chain-defined yield_keys: per chain spec; minted via kernel:mint_yield
(returns a YieldSender/YieldReceiver pair) and distributed via cap-flow.
```

The yield_key mechanism replaces the old "yield reason code." A
yield is routed to a specific owner-side handler by its `yield_key`:
the kernel walks owner edges, and the nearest edge whose snapshotted
YieldReceiver contains the key catches it. Physical stack frames that
are not on the owner path are invisible to routing.

**OOG payload — just the Gas cap, nothing else.** The OOG yield
payload is *only* the primary usable `Cap::Instance[Gas{meter_key}]`
copy. Before emitting OOG, the kernel exhaustively consults every
usable gas slot in order. No "which call was running," no caller
identity, no stack context.
Encoding "which call ran out" would reintroduce CALLER information
into a capability-only system — which is precisely what v3 avoids.
The meter_key alone is sufficient: chain looks meter_key up in its
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
  Page-round / zero-pad to get page-multiple, page-aligned content.
  Read quota_slot (holds Cap::Instance[Quota{quota_key}]); debit
    kernel-internal StorageQuota[quota_key] by minted page-multiple size.
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
       cnode holds a Key-addressed Cap::CNode.
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

host_image_hash_chain(slot: SlotPath, dst: SlotPath) → ()
  Pre: slot holds a Cap::Instance (or Cap::Image); dst is empty.
  Effect: place a Cap::Data holding the raw bytes of the cap's
    image_hash (the cumulative chain hash) at dst.

  USE FOR IDENTIFICATION ONLY. Two Instances being "the same type"
  (equal image_hash) does not grant authority — possession of a
  Cap::Instance is what grants authority. Same-type = memcmp the two
  hashes; subtype = fold hash(acc || hash(image)) over a reference's
  bytes yourself. See §14 for the proper authority pattern.
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

The image_hash *value* is readable via `host_image_hash_chain`
(identification only); full lineage *walking* is not exposed.

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
  -- Debits StorageQuota[quota_slot's quota_key] by metadata size.

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
  State: meters: Map<Key, RemainingGas>
  Lifecycle: kernel initializes at block start with
    { root_meter_key: <chain-spec block budget> }; all other meters
    are populated lazily by chain via kernel:set_gas_meter; kernel
    discards GasMeter at block end (kernel is stateless across blocks).

Gas{meter_key} (per-Instance unit handle, kernel-assisted Instance):
  Image: kernel:gas
  State: meter_key: Key
  Created by emitting kernel:mint_gas(meter_key) — caller supplies
    the meter_key (chain-chosen; kernel cannot assign uniquely
    without persistent state).
  Conservation lives in GasMeter, not in the cap — cap copies all
    name the same meter; debiting any copy debits the same meter.
```

During execution of an Instance:
- Kernel resolves the Instance's ordered `gas_slots`. Empty slots are skipped;
  present non-Gas slots hard-fault. The first valid non-empty slot is primary;
  later valid slots are fallback reserves. If no gas slots are declared, the
  Instance loans its owner's gas scope.
- Metering is **per basic block, at block entry** (not per-instruction).
  At each bb_start the kernel/JIT pre-reserves the block's cost against
  the active GasMeter via kernel short-circuit (no endpoint dispatch): if
  `gas < gas_cost(B) + worst_case_3(B)`, the block is **not entered**. The
  kernel then tries the next usable gas slot, if any; only after all usable
  slots are exhausted does it trigger a yield of the well-known `kernel:oog`
  key — charging **nothing** for the un-entered block. Otherwise the block's
  instruction cost is debited at entry and the **copy-on-write** share of memory
  materialization (#3) is debited as write-faults occur; gas never goes
  negative. The remaining #3 cost — the CALL frame (JIT compile + eager
  read-only page-in) — is **not** fault-driven: it is charged dynamically at the
  CALL, to the caller (see the ecall note below), and host-call `ecalli`s that
  write guest memory are charged at the `ecalli` itself (finding B), since those
  writes bypass the guest #PF.
  See [gas-cost.md §1](gas-cost.md).
- **`ecall.jar`/`ecalli` are the exception**: each is its **own** gas block
  (a forced block start) with **no** static preamble, because its cost — a
  CALL frame, a host op's work — is unknowable at compile time. The kernel
  charges it **dynamically** when the ecall executes: if `gas < actual`, it
  OOG-yields **before** doing the work and captures the ecall's **own** PC
  (re-attempt cleanly after top-up); otherwise it debits `actual` and
  proceeds. Same check-before-charge discipline; gas still never goes
  negative. See [gas-cost.md §3 "ecall/ecalli blocks"](gas-cost.md).
- The `kernel:oog` key is registered in the chain's YieldReceiver at chain
  init (the kernel is its root receiver); its payload is the primary usable
  `Cap::Instance[Gas{meter_key}]` copy. The captured continuation is the
  un-entered block's bb_start (or, for an ecall, the ecall's own PC). On
  CALL_RESUME after OOG, execution retries from the primary meter so a top-up of
  the payload meter is deterministic.

Per-block metering is invisible to userspace; debits don't
go through the CALL/yield mechanism. STM-exempt: gas already
consumed by a faulted apply is not refunded.

### Scratchpad CNode of kernel YieldSenders

All kernel interaction is a yield. The kernel is the implicit ROOT
YieldReceiver for every `kernel:*` yield_key. At top-level invocation the
kernel places a CNode in the scratchpad (slot[0]) mapping descriptive
names -> YieldSenders. These are how userspace interacts with kernel-
internal kernel-assisted Instances (GasMeter, StorageQuota) and how
userspace composes per-Instance YieldReceivers.

To invoke a syscall the guest places the named YieldSender in the
yield-scratchpad and `host_yield`s it (payload via slot[0]); the kernel
(root receiver) catches the `kernel:*` key and performs the op.

```
kernel:mint_gas (YieldSender):
  emit kernel:mint_gas(meter_key) → Cap::Instance[Gas{meter_key}]
    Returns a fresh Gas unit handle naming the given meter_key.
    Chain is responsible for meter_key uniqueness (collisions
    silently alias).

kernel:set_gas_meter (YieldSender, kernel-internal access):
  emit kernel:set_gas_meter(meter_key, value: u64) → u64
    Atomically GasMeter[meter_key] := value; return previous value.
    If no entry exists, "previous" is 0 and the entry is created.
    The atomic set+read enables the "harvest remaining" idiom.

kernel:mint_quota (YieldSender):
  emit kernel:mint_quota(quota_key) → Cap::Instance[Quota{quota_key}]
    Symmetric to kernel:mint_gas over StorageQuota.

kernel:set_storage_quota (YieldSender, kernel-internal access):
  emit kernel:set_storage_quota(quota_key, value: u64) → u64
    Same semantics as kernel:set_gas_meter for StorageQuota.

kernel:mint_yield (YieldSender):
  emit kernel:mint_yield(raw yield_key)
       → (YieldSender{key}, YieldReceiver{[key]})
    Returns the PAIR. UNRESTRICTED: it can mint for ANY key, including
    kernel:* keys — this enables full interposition / virtualization of
    kernel syscalls. Userspace restricts it by INTERPOSING (§14).

kernel:merge_yield_receiver (YieldSender):
  emit kernel:merge_yield_receiver(YieldReceiver A, YieldReceiver B)
       → YieldReceiver{A.keys ∪ B.keys}
    Composes two catch-sets; the result is placed in yield_receiver_slot.

kernel:attest (YieldSender):
  emit kernel:attest(key, blob) → AttestStatus
    Attestation request (§15). Caught by the kernel as implicit ROOT
    YieldReceiver for kernel:* keys; the AA cap holds this YieldSender.
```

A YieldReceiver is a SET of yield_keys (held in the Instance's
`yield_receiver_slot`). It is composed via `kernel:mint_yield` +
`kernel:merge_yield_receiver` — there are NO add/remove/read endpoints.

For the full design and rationale (lazy-load OOG-catch, why no
narrow linearity, etc.), see
[principles/kernel-assisted-instances.md](principles/kernel-assisted-instances.md).

## 5. Apply terminations

```
HALT(phi[7] = return_value)
  → Instance becomes Idle with new value.
  → Target's slot[0] reflects to caller's slot[0] (apply's chosen
    output, atomically placed via MGMT_MOVE just before HALT).
  → Emits returned for orchestrator processing.
  → Caller: phi[8] = Ok.
  → Gas debited.

host_yield(YieldSender)         -- includes kernel-triggered OOG
  → Instance becomes Waiting on the call stack (or Paused if the yield
    is preserved across blocks).
  → Target's slot[0] reflects to caller's slot[0] (carrying the
    YieldSender's payload — typically a unit cap copy like
    Cap::Instance[Gas{meter_key}] for OOG, per §4).
  → Emits returned for orchestrator processing.
  → Caller: phi[8] = Paused; phi[7] = yield payload reference.
  → Caller may CALL_RESUME (with new scratchpad in caller's slot[0])
    or DROP_RESUME.
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
| Paused (yield/OOG) | Waiting on call stack (or Paused if preserved) | No (must RESUME) | reflected from target (YieldSender payload) |
| Fault | Faulted, then dropped | No | reflected from target at fault point |

## 6. Operation patterns

### Pattern A — state-apply loop

Orchestrator (chain Instance's apply) processes events:

```
for event in block_body:
  -- prepare scratchpad in self.slot[0]
  build event-specific Cap::CNode into self.slot[0]
  -- ensure target's ordered gas_slots name meters with enough balance
  -- (typically chain has already emitted kernel:set_gas_meter for this
  -- user's meter_key; see §22 lazy-load OOG-catch pattern).
  match CALL(target_slot, endpoint):
    Ok:
      target updated; self.slot[0] now has target's reply.
      proceed.
    Paused via kernel:oog:
      -- payload (slot[0]) holds Cap::Instance[Gas{meter_key}].
      -- Chain looks meter_key up in its GasLedger.
      record / decide topup-or-fail; if topup:
        emit kernel:set_gas_meter(meter_key, more); CALL_RESUME.
      else DROP_RESUME (fault propagation / persistent pause handoff).
    Paused via kernel:storage_exhausted:
      -- payload holds Cap::Instance[Quota{quota_key}].
      analogous; emit kernel:set_storage_quota then CALL_RESUME, or fail.
    Paused via chain-defined yield_key:
      key-specific handling per chain spec.
      (self.slot[0] has the YieldSender's payload from yield.)
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
Cap::Data    — page-multiple, page-aligned Bytes. Content-addressed
               copyable. Trailing zeros are state.
Cap::CNode   — Sparse Key-addressed cap map (no fixed capacity).
               Content-addressed copyable.
```

Four cap kinds. All uniformly copyable. No conditional linearity.
No `linear_count`. No drop endpoints.

### Why these four

- **Cap::Instance**: the unit of state. Copyable; MGMT_COPY produces a
  content-shared reference. Mutations via CALL into the Instance's
  apply produce a divergent value (per §9 case (b)). **Possession of
  Cap::Instance is the authority-bearing primitive.**
- **Cap::Image**: the unit of program specification. Content-
  addressed; copyable. Image embeds bytecode directly. Multiple
  Instances can share an Image via the content-addressed hash.
- **Cap::Data**: arbitrary bytes. The general data carrier.
- **Cap::CNode**: sparse Key-addressed cap map (`Key -> Cap`; no fixed
  capacity). Used for root cnodes, nested storage, state snapshots, and as
  the **constructor argument** for `host_derive_spawn`. Content hashing and
  proof generation may derive a hash-keyed Merkle/radix commitment view, but
  that view is not the runtime storage model.

A type identifier is not a separate cap kind: an Instance's type *is*
its kernel-attested `image_hash`, read as raw bytes via
`host_image_hash_chain` (§4) and compared in userspace. **Type
identifies; possession of a `Cap::Instance` authorizes.**

### Type vs Instance — identification vs authorization

This distinction is load-bearing and must be understood clearly:

> **An image_hash identifies an Instance's type.**
> **A Cap::Instance authorizes invocation of a specific Instance.**
>
> These are NOT interchangeable. An image_hash value is freely readable
> (via `host_image_hash_chain`) and freely computable (fold the chain
> extension yourself); a Cap::Instance can only be obtained via
> legitimate cap-flow originating from an Instance's actual derivation.

**Forgery resistance for Cap::Instance:** An Instance with image_hash X can
only be produced by derivation through the kernel-mediated
`host_derive_spawn`, which extends the deriver's chain. An adversary
cannot fabricate a Cap::Instance with a chain that doesn't include
their own derivation history. The image_hash chain is forgery-
resistant.

**An image_hash *value* is NOT forgery-resistant in the same sense — and
that is exactly why exposing it is safe.** Anyone can read X's image_hash
and compute any `X + derive_steps` extension; the value is neither secret
(σ is public) nor an authority credential. A type identifier carries no
authority to protect, so there is nothing to hide — which is why
`Cap::Type` (an opaque wrapper around this freely-computable value) is
not a separate cap kind.

**Authority must use Cap::Instance possession, not type matching.** A
pattern like "if a cap's image_hash == X, it has authority X" is WRONG.
The correct pattern is "if I hold a Cap::Instance and route via the
yield mechanism, I exercise authority" — and this is what §14
(YieldSender/YieldReceiver authority pattern) uses.

**When to read image_hash:** runtime type-checking ("is this Instance of
type X?"), type-based dispatch, composing type identifiers abstractly
without materializing Instances. **When NOT to:** as a routing key or
proof of authority — use Cap::Instance possession + the yield pattern.

### Resource caps as kernel-assisted Instances or userspace patterns

Earlier drafts had Cap::Gas, Cap::StorageQuota as separate cap kinds.
In v3, these are NOT cap kinds. They split into two families:

**Kernel-assisted resources (kernel-mediated, see §22):**

- **Gas**: tracked in a kernel-internal `GasMeter` (kernel-assisted
  Instance, never in chain hands). Each Instance holds
  `Cap::Instance[Gas{meter_key}]` in its `gas_slots`; per-basic-block
  metering reserves the block cost against `GasMeter[meter_key]` at
  block entry via kernel short-circuit (gas-cost.md §1). Conservation
  lives in GasMeter, not in the Gas cap, so copies all name the same
  meter (no narrow linearity needed). OOG (an entry-gate failure that
  charges nothing) triggers a yield of `kernel:oog`.
- **StorageQuota**: symmetric — kernel-internal `StorageQuota`
  table, `Cap::Instance[Quota{quota_key}]` unit handles held in
  `quota_slots`, dirty-page tracking debits per Pattern 4 (§2).
  Exhaustion triggers a yield of `kernel:storage_exhausted`.

Chain interacts with kernel-internal tables by yielding the scratchpad
YieldSenders `kernel:set_gas_meter` / `kernel:set_storage_quota`
(set+return-previous); mints unit handles via `kernel:mint_gas` /
`kernel:mint_quota` (chain-chosen ids). See §4 for the yield ops.

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
a Map<Key, ContentAddressedCap> declaring which slots hold
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

### Empty-reserved origin slots

When CALL moves an Instance into a KernelFrame, its origin SlotPath is
empty in the owner's CNode and reserved by kernel stack metadata. It is
not a cap value and must not be serialized, hashed, copied, or persisted.

An empty-reserved origin slot has the same guest-visible protection as a
pinned slot for operations against that SlotPath:

- CALL faults.
- MGMT_COPY / MGMT_MOVE / MGMT_DROP faults.
- read/type-query operations such as `host_image_hash_chain` fault.
- Writes, mints, swaps, or moves into the slot fault.

The private kernel restore path is the only operation that may write the
updated Instance back into the slot; it first clears the reservation. V1
discard paths clear the reservation and leave the slot empty.

## 9. By-value semantics with content-addressed slot references

```
Slot's cap = reference (by hash) to a specific Instance or Data value.

Apply runs:
  Kernel moves the Instance value out of its origin slot into a
    KernelFrame; the origin slot is empty-reserved.
  Apply mutates working memory (with COW per page for mapped DataCaps).
  Origin slot is NOT updated yet and cannot be reused.

At termination:
  HALT  → kernel computes hash of new Instance value (with new mapped
          DataCaps); reservation clears; slot updates to the new value.
  yield → kernel computes hash of Paused Instance value (with continuation);
          slot updates only if/when the continuation is materialized as
          σ-resident Paused. While Waiting on the call stack, the origin
          slot remains empty-reserved.
  fault/discard → reservation clears; origin slot remains empty.

No explicit STM buffer; no merge-or-discard ceremony. Atomicity comes
from "running Instances are owned by frames; origin slots restore only at
termination."
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
    GasMeter      := { root_meter_key: <chain-spec block budget> }
    StorageQuota  := { root_quota_key: <chain-spec block budget> }
  Kernel is the implicit ROOT YieldReceiver for all kernel:* keys.
  Place a scratchpad CNode of named kernel:* YieldSenders (§4) plus the
    block_body Cap::CNode into kernel's slot[0].
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

### Chain init: scratchpad YieldSenders + chain YieldReceiver

At first block (genesis) — or at every block, depending on chain
spec — the kernel injects the root unit handles into the top-level
chain Instance's cnode and places the scratchpad CNode of named
kernel:* YieldSenders (see §4 for the yield ops):

```
Gas / storage management:
  Cap::Instance[Gas{root_meter_key}]      -- initial root gas budget
  Cap::Instance[Quota{root_quota_key}]    -- initial root storage budget
  Scratchpad CNode (slot[0]) of named YieldSenders:
    kernel:set_gas_meter        -- modify GasMeter (returns prev)
    kernel:set_storage_quota    -- modify StorageQuota
    kernel:mint_gas             -- mint Gas unit handles
    kernel:mint_quota           -- mint Quota unit handles
    kernel:mint_yield           -- mint a YieldSender/YieldReceiver pair
    kernel:merge_yield_receiver -- union two YieldReceiver catch-sets
    kernel:attest               -- attestation request (§15)

Yield routing:
  Kernel is the implicit ROOT YieldReceiver for all kernel:* keys.

  Registered in chain's YieldReceiver
  (chain.cnode[yield_receiver_slot]):
    kernel:oog                        -- caught when any meter hits 0
    kernel:storage_exhausted          -- caught when any quota hits 0
    (others as chain spec requires)
```

This is the entire kernel ABI for chain orchestration. Kernel
internals (GasMeter, StorageQuota) are opaque from userspace; only
the yield-mediated operations are visible. Persistence of gas/quota
balances across blocks (e.g., per-user budgets) lives in chain σ,
not in kernel state; chain repopulates kernel tables lazily by
emitting `kernel:set_gas_meter` / `kernel:set_storage_quota` in
response to OOG / StorageExhausted yields. See
[principles/kernel-assisted-instances.md](principles/kernel-assisted-instances.md)
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

### The kernel YieldSender/YieldReceiver mechanism

Authority caps are implemented via the kernel's YieldSender/YieldReceiver
mechanism. `YieldSender{yield_key}` is the EMIT right; `YieldReceiver`
is the CATCH right — the set of yield_keys an Instance catches, held in
its **YieldReceiver** (a kernel-assisted Instance referenced from
`yield_receiver_slot`; see §22). These are SEPARATE rights over a key,
the seL4 endpoint Send/Receive model: a holder of only a Sender can emit
(routed up) but cannot catch the key. Yielding bytecode places a
YieldSender in a scratchpad slot; the kernel reads its yield_key and
routes the yield along owner edges to the nearest per-CALL owner-edge
snapshot (§3) whose YieldReceiver contains the key (single-resumer).

```
Yield routing:
  yielder.bytecode places Cap::Instance[YieldSender{K}] in scratchpad
  yielder.bytecode invokes host_yield(scratchpad_slot)
  Kernel:
    key := YieldSender.yield_key
    node := logical current InstanceEntry
    for each owner edge node -> owner from node toward root:
      if node.owner_catch_set contains key:
        push ReferenceEntry(owner); transfer control to owner.
        return.
      node := owner
    -- kernel is the implicit root receiver for kernel:* keys
    fault yielder with "unhandled yield_key"
```

The `yield_key` is the routing key; `kernel:*` keys are reserved for the
kernel. A YieldSender is forgery-resistant because minting one for a
restricted key requires `kernel:mint_yield`, which the top-level
orchestrator INTERPOSES over (§14 forgery resistance) to gate which keys
are mintable below it.

A YieldReceiver's catch-set is composed via `kernel:mint_yield` (mints a
Sender/Receiver pair for a key) and `kernel:merge_yield_receiver` (unions
two catch-sets), then moved into `yield_receiver_slot` — there are no
add/remove endpoints. To revoke an authority, drop the key from the
receiver's catch-list (or re-mint under a fresh key and re-issue caps);
outstanding Senders for the old key then match no receiver and fault.
Snapshot caveat: revocation takes effect for subtrees of CALLs made
AFTER the change (§3).

### The pattern

A chain Orchestrator `O` mints **authority caps** for the operations
it's willing to expose, and grants them to user contracts that should
be able to invoke them. Each authority cap holds a YieldSender
internally; the YieldSender is opaque from outside the authority cap.
Only the cap's own bytecode (defined by its Image) can extract the
YieldSender to yield with it.

```
Setup phase (Chain init):

  -- Chain mints a Sender/Receiver pair for each authority key
  -- (kernel:mint_yield returns the pair; O keeps the Receiver, hands
  --  out Senders):
  (sender_invoke, receiver_invoke) = kernel:mint_yield("invoke")

  -- Chain registers the key in its own YieldReceiver by merging it in
  -- (chain.cnode[yield_receiver_slot] holds Cap::Instance[YieldReceiver],
  --  pre-populated at chain init per §12 with kernel:oog etc.):
  merged = kernel:merge_yield_receiver(chain.yield_receiver, receiver_invoke)
  -- move `merged` into chain.cnode[yield_receiver_slot]

Image EndpointRefCap (well-known image):
  state:
    sender:         Cap::Instance[YieldSender{"invoke"}]  -- in self.cnode
    target_address: ContractId                   -- which contract
    endpoint:       Key                          -- which endpoint
  endpoints:
    invoke(args)
      -- 1. Compose payload from self.state + args:
      --     payload = { target_address, endpoint, args }
      -- 2. Place payload in arg slot (slot for handler to read).
      -- 3. Place self.cnode[sender_slot] (Cap::Instance[YieldSender])
      --    into yield-scratchpad slot.
      -- 4. host_yield(yield-scratchpad).
      -- 5. On resume, slot[0] holds the handler's response. HALT.

Chain mints these:

O.endpoint grant_endpoint_access(target, endpoint: Key) → Cap::Instance[EndpointRefCap]:
  cap = host_derive_spawn(EndpointRefCapImage,
                          init = { sender: Cap::Instance[YieldSender{"invoke"}],
                                   target_address: target,
                                   endpoint: endpoint })
  return cap
```

A user contract `A` that holds the cap invokes it directly:

```
A.endpoint do_something():
  ref_cap = self.slot[7]   -- holds Cap::Instance[EndpointRefCap(B, "process")]
  slot[0] := args
  CALL(ref_cap, "invoke")
  -- ref_cap's invoke endpoint runs; yields with YieldSender; kernel
  --   routes to Chain; Chain dispatches to B; response returns.
  result = slot[0]
  ...
```

### Why this works

**1. Forgery resistance is structural.** An adversary cannot mint a
YieldSender for a restricted key because `kernel:mint_yield` is
INTERPOSED over by the top-level orchestrator, which gates (via
key-namespace) which keys are mintable below it. A forged Sender for an
unregistered key matches no receiver and faults.

**2. Authorization is possession of the AuthorityCap, not the
YieldSender.** The YieldSender is opaque inside AuthorityCap's state (only
AuthorityCap's bytecode reads it). User contracts hold
`Cap::Instance[EndpointRefCap]`, not the YieldSender directly. They invoke
EndpointRefCap; EndpointRefCap's bytecode yields with the YieldSender on
their behalf.

**3. Identifying a type is not holding the cap.** Reading a YieldSender's
image_hash (its type) does NOT grant the ability to yield with it. Only
holding an actual `Cap::Instance[YieldSender{key}]` does. Routing uses
yield_key membership in snapshotted YieldReceivers on real Cap::Instance
values, never a type identifier. See §8.

**4. Delegation is automatic.** A can MGMT_COPY the EndpointRefCap
and pass to another contract. Whoever ends up holding it can invoke.
Non-delegable authority would require additional discipline at the
AuthorityCap Image level.

**5. Public σ is fine.** Anyone can read that A holds the cap.
Nothing follows from reading. Only A can move the cap out of A's
cnode; only the cap holder can invoke through it; the YieldSender stays
opaque inside AuthorityCap. Confidentiality from intermediates is
structural via owner-edge routing + single-resumer: a keyed yield goes
straight to the nearest registered owner receiver, so unregistered
intermediates never see the payload.

**6. No per-user table at O.** O's state is the contracts themselves
plus O's own facets and YieldReceiver catch-set. Per-user
authorization lives in *which caps A holds*, which is A's own cnode
contents.

**7. Revocation via key rotation.** Chain can drop the key from its
YieldReceiver catch-set (re-merge a receiver that omits it), or re-mint
under a fresh key via `kernel:mint_yield` and re-issue caps. All
outstanding AuthorityCaps holding a YieldSender for the old key then
match no receiver and fault (snapshot caveat: takes effect for subtrees
of CALLs made AFTER the change). Mint new AuthorityCaps with the new key
if needed. Structural revocation without per-cap tracking.

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
    sender: Cap::Instance[YieldSender{"kernel:attest"}]   -- in self.cnode
  endpoints:
    attest(key, blob) → AttestStatus
      -- 1. Compose payload: { key, blob }, place in arg slot.
      -- 2. Place Cap::Instance[YieldSender{"kernel:attest"}] in
      --    yield-scratchpad.
      -- 3. host_yield(yield-scratchpad).
      -- 4. On resume, slot[0] holds the kernel's response (status).
      -- 5. HALT returning status to caller.

Setup (kernel/chain init):
  -- "kernel:attest" is a reserved kernel:* key; the kernel is its
  --  implicit ROOT YieldReceiver, so no add ceremony is needed.
  --  The kernel:attest YieldSender lives in the top-level scratchpad
  --  CNode (§4).

  -- AA caps are minted with the YieldSender in their state:
  aa_cap = host_derive_spawn(AAImage,
                  init={ sender: Cap::Instance[YieldSender{"kernel:attest"}] })
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

The mechanism follows the canonical authority pattern (§14, principle 17):
`kernel:attest` is a reserved kernel:* key with the kernel as root
receiver; user code holding Cap::Instance[AA] can invoke AA which yields
with the YieldSender; the kernel root receiver catches it; the kernel
processes mode-aware and returns mode-invariant status. The YieldSender
is opaque inside AA — only AA's bytecode reads it.

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
  - AA's bytecode yields with YieldSender{"kernel:attest"}; the kernel
    walks AA's owner edges toward the root. The kernel is the root receiver
    for kernel:* keys, so it catches.
  - Intermediates don't catch (their snapshotted YieldReceiver lacks
    "kernel:attest"). They have no access to the yielded payload — it
    never lands in their slot[0] (single-resumer + owner-edge routing).
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

An adversary cannot emit a `kernel:attest` yield because it cannot
obtain `YieldSender{"kernel:attest"}` — the top-level orchestrator
interposes over the unrestricted `kernel:mint_yield` and gates the
`kernel:*` yield_key namespace below it. An emitter without that Sender
matches no `kernel:attest` receiver and faults. This is what forgery
resistance buys; no presence-check machinery beyond key-namespace
gating is required.

The chain orchestrator's bytecode is responsible for ensuring AA
flows through cap-flow to the Instances that need to attest. If the
orchestrator's bytecode is incorrect (drops AA), the relevant
attestations don't happen, and the block fails consensus. Strong
incentive to author correctly.

### BLS aggregation

A separate AA endpoint follows the same yield-mediated pattern:

```
AA.aggregate(group_key, partial_sig) → AggregateStatus
  -- composes { group_key, partial_sig } into slot[0]; yields the attest
  --   YieldSender; the kernel root receiver collects partials per group;
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
pattern as AA; same forgery resistance via interposition over
`kernel:mint_yield` (a user cannot mint `YieldSender{"mint"}` because O
gates the key namespace below it). No auth_table lookup; no user-keyed ACL.

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
    sender: Cap::Instance[YieldSender{"mint"}]   -- in self.cnode
    -- possibly: policy fields (rate limits, etc.) baked in per §14
  endpoints:
    mint(content) → MintStatus
      -- Per the canonical authority pattern (§14, principle 17):
      -- 1. Compose payload from { domain, content } + args.
      -- 2. Place Cap::Instance[YieldSender{"mint"}] in yield-scratchpad.
      -- 3. host_yield(yield-scratchpad).
      -- 4. Kernel routes to O (which has "mint" registered in its
      --    yield_receiver_slot). O invokes MintInstance.mint internally
      --    and returns status via CALL_RESUME.
      -- 5. On resume, slot[0] holds status (and any new Issuance cap).
      -- 6. HALT to caller.
    burn(handle) → BurnStatus    -- symmetric pattern
    transfer(...) → TransferStatus
```

Setup: O mints the "mint" Sender/Receiver pair via
`kernel:mint_yield("mint")`, registers the key in its own YieldReceiver
(`kernel:merge_yield_receiver` into `yield_receiver_slot`), and mints
MintRefCaps with the YieldSender embedded. See
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
  3. MintRefCap's bytecode yields with YieldSender{"mint"}; the kernel
     walks owner edges toward the root; A's owner-edge snapshot lacks "mint";
     O's owner-edge snapshot contains "mint"; routes to O.
  4. O's bytecode reads payload (domain_X, content), invokes
     MintInstance.mint(domain_X, content) → Issuance.
  5. O places result in slot[0]; CALL_RESUME. MintRefCap resumes,
     HALTs with status to A.

Forgery resistance: a malicious A cannot yield with YieldSender{"mint"}
without holding a real MintRefCap (the YieldSender is in MintRefCap's
state, opaque from outside). And A can't mint its own YieldSender for
"mint" because O interposes over `kernel:mint_yield` and gates the key
namespace.
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
- **Bytecode admission forks** — kernel validates structural Image fields
  at construction, but instruction semantics are lazy. Illegal/reserved
  encodings panic only when reached, so cap admission does not fork on
  producer-toolchain bytecode policy.
- **Memory exhaustion mid-apply** — static memory; allocation only
  via the heap-region pattern with bounded size.
- **Page-fault nondeterminism** — page faults are used internally to
  drive lazy materialization but are deterministic: present/writable
  (permission) faults, never hardware Accessed/Dirty bits; consensus
  4 KiB granule independent of host page size; both engines charge
  identically (gas-cost.md §5). Access to undeclared addresses is a
  terminal PVM2-level fault, deterministically.
- **Lazy paging consensus footguns** — lazy materialization is
  deterministic (first-touch faults are a function of the Image +
  input; read-only page-in is charged **at the CALL** (statically, from
  the Image — no per-fault charge) and CoW per consensus page
  (depth-aware, per finding A)); materialization is a
  host-level retry below the PVM2 model (a PVM2-level page fault stays
  terminal).
  See gas-cost.md §3 / §5.
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
- **Type-as-authority footgun** — image_hash is readable (via
  `host_image_hash_chain`) for identification, but possession of a
  Cap::Instance (not type matching) is what authorizes. Treating "is of
  type X" as authority is a userspace anti-pattern (caught by linting),
  not a kernel restriction. Full lineage *walking* stays unexposed.
- **Piecewise spec mutation inconsistency** — Image is mutated as a
  unit via `set_image`. No `host_set_code` / `host_set_endpoints`.
- **Conservation violations via cap copying** — conservation lives
  either in kernel-internal tables (for kernel-assisted resources
  like Gas/Quota: copies of `Cap::Instance[Gas{meter_key}]` all name
  the same meter; debiting any copy debits the same row) or in
  authority bytecode (for userspace resources: typed handle copies
  reference the same ledger row). Either way, copying doesn't
  multiply balance — no kernel-level linearity required.

## 18. Open questions

1. **Chain-defined yield keys**: canonical patterns for chain-defined
   yield_keys (CooperativeCheckpoint, NeedHeapSpace, etc.) minted via
   `kernel:mint_yield` and registered in the YieldReceiver alongside the
   kernel:* keys (`kernel:oog`, `kernel:storage_exhausted`).

2. **EndpointRefCap variants and dispatch-side policy**: which
   policy fields (rate limit, arg filter, etc.) bake into the cap
   itself vs. live in a sidecar policy table keyed by cap identity
   at the dispatcher (§14, "Where policy attaches").

3. **Cap::Image construction**: how chain authors construct
   Cap::Image values. Probably via a `host_make_image(code: Bytes,
   endpoints: ..., mappings: ..., pinned_slots: ...) → Cap::Image`
   host call. Structural fields are validated at construction;
   instruction semantics stay lazy, so illegal/reserved encodings panic
   only when reached.

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
   chain wants to derive at bootstrap, plus the root unit handles and
   scratchpad YieldSenders listed in §12.

10. **Pinned-slot collision policy**: when `set_image` finds a
    target pinned slot is already occupied by non-pinned content,
    we currently FAIL. Should there be a "force" variant?

11. **MGMT_CNODE_SWAP semantics**: pinned-slot rules, cross-cnode
    behavior.

12. **set_image / derive_spawn validation timing for memory_mappings
    against slot types**: at the spawn/transition moment, or at next
    CALL?

13. **`image_id`-equal but `image_hash`-different Instances**: same code,
    different lineage — their `host_image_hash_chain` bytes differ.
    Document so chain authors don't conflate "same Image content" with
    "same type".

14. **Off-chain Dispatch Instance's image_hash**: derived per the
    canonical formula, or absent (ephemeral, never hashed)?

15. **Initial root-cnode key policy for spawn**: host_derive_spawn
    accepts a sparse Key-addressed Cap::CNode. Which reserved keys must
    be absent or pre-populated beyond the pinned-slot collision rules?

16. **Hierarchical orchestrator patterns**: when does decomposition
    pay off? What's the minimal canonical set of orchestrators per
    chain?

Resolved decisions on the kernel-assisted Instance design (gas / quota
/ yield routing — page size, dirty-page tracking lifetime, id
assignment policy, OOG payload shape, etc.) are captured in
[principles/kernel-assisted-instances.md](principles/kernel-assisted-instances.md).

## 19. Summary

```
Instance (always Image-bound):
  image_id:     ImageHash
  cnode:        Key-addressed sparse root cnode; pinned keys per Image;
                non-pinned mutable
  status:       Idle | Paused {...} | Faulted
  image_hash:   derived; kernel-attested chain hash:
                  genesis:                  hash(initial_image)
                  after set_image(new):     hash(image_hash_before
                                                  || hash(new))
                  via derive_spawn(new):    hash(spawner.image_hash
                                                  || hash(new))
                  via MGMT_COPY:            preserved

Cap::Image (content-addressed, copyable):
  - code:            Bytes  (bytecode embedded; illegal/reserved encodings
                             panic lazily when reached)
  - memory_mappings: [{start, size, source}]
  - endpoints:       Map<Key, EndpointDef>  (sparse, Key-keyed; no fixed 256)
  - gas_slots:       [Key]    -- slots holding Cap::Instance[Gas{meter_key}]
  - quota_slots:     [Key]    -- slots holding Cap::Instance[Quota{quota_key}]
  - pinned_slots:    Map<Key, ContentAddressedCap>
                       (ContentAddressedCap ∈ { Cap::Data, Cap::Image })
  - yield_receiver_slot: Option<Key>
                       -- slot holding Cap::Instance[YieldReceiver]
                       --   (the Instance's YieldReceiver{Vec<yield_key>})

Cap::CNode (uniformly copyable; mintable):
  - slots: Map<Key, Cap>       -- sparse, Key-addressed; no fixed capacity
                                -- hash(key) appears only in commitment/proof
                                -- calculation, not runtime slot access
  - Used for nested storage, state-snapshot/revert patterns, and as the
    cnode argument to host_derive_spawn.

Memory model:
  - Static layout per Image (fixed footprint, no dynamic growth);
    pages materialize lazily on first touch (gas-cost.md §3).
  - Persistent mapping = backed by cnode DataCap; mutations COW'd.
  - Ephemeral mapping = kernel-allocated; per-apply.
  - DataCap canonical form: page-multiple, page-aligned bytes; no
    trailing-zero stripping.
  - Size-mismatch: small DataCap zero-padded; large DataCap faults.

Apply terminations (all reflect target.slot[0] to caller.slot[0]):
  HALT  → Idle (new value)
  yield → Waiting on call stack (Paused if preserved across blocks);
          continuation is regs+pc+yield_sender; yield payload (typically
          a YieldSender / unit cap) reflects to caller via slot[0].
          (kernel OOG = host_yield of the kernel:oog key;
           payload is Cap::Instance[Gas{meter_key}].)
  fault → Faulted, then dropped
  Gas debited STM-exempt: from the meter named by the active Instance's
    gas slot; debits are per basic block at block entry (gas-cost.md §1);
    no per-CALL budget.
  Apply discipline: keep slot[0] in a safe-to-reflect state at all
    times (input scratchpad, empty, or complete output Cap::CNode
    atomically MGMT_MOVE'd in). A hard fault can happen at any
    instruction (OOG and voluntary yields only at a bb_start); partial
    slot[0] would expose mid-mutation state.

Kernel ABI:
  Invocation:           CALL, CALL_RESUME, DROP_RESUME
                        (no gas_budget — gas via gas_slots)
  Yield:                host_yield(YieldSender) routed by yield_key
  Data:                 host_read_data_cap, host_mint_data_cap
  Cap-table:            MGMT_COPY/MOVE/DROP/CNODE_SWAP
  Image / spawn:        set_image, host_derive_spawn
  Type identity:        host_image_hash_chain
  CNode:                host_mint_cnode

Kernel ABI at chain init (see §4, §12):
  Gas/storage:          scratchpad YieldSenders kernel:set_gas_meter,
                        kernel:set_storage_quota, kernel:mint_gas,
                        kernel:mint_quota; root Gas/Quota unit handles.
  Yield routing:        scratchpad YieldSenders kernel:mint_yield,
                        kernel:merge_yield_receiver, kernel:attest;
                        chain's YieldReceiver registers kernel:oog,
                        kernel:storage_exhausted (kernel is root
                        receiver for kernel:* keys).

Cap kinds (four; all copyable):
  Cap::Instance   — Instance value reference. AUTHORITY-BEARING.
                 Includes the four kernel-assisted Instances (§22):
                 Gas{meter_key}, Quota{quota_key},
                 YieldSender{yield_key}, YieldReceiver{Vec<yield_key>}.
  Cap::Image   — spec including embedded bytecode.
  Cap::Data    — arbitrary bytes.
  Cap::CNode   — variable-size cnode (mintable).
  (Type identity is the image_hash, read via host_image_hash_chain —
   not a separate cap kind; see §8.)

  Resource caps (Gas, StorageQuota) are NOT separate cap kinds —
  they are kernel-assisted Cap::Instances:
    Gas{meter_key}   — per-Instance unit handle naming a meter in the
                      kernel-internal GasMeter table. Conservation
                      lives in the table; cap copies all name the
                      same meter; no narrow linearity needed.
    Quota{quota_key} — symmetric for StorageQuota.
  Chain accesses kernel-internal GasMeter/StorageQuota by yielding the
  kernel:set_gas_meter/kernel:set_storage_quota scratchpad YieldSenders.
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

Type identity:
  host_image_hash_chain(slot, dst) → Cap::Data of the image_hash bytes
  Same-type = memcmp; subtype = fold hash(acc || hash(image)) yourself.
  Full lineage walking is not exposed.

Forgery resistance (structural):
  Genesis Kernel Instance has image_hash = hash(KernelImage).
  Post-set_image / post-derive_spawn image_hashes are recursive;
    never equal hash(any single Image).
  Cap-flow on the genesis Kernel Instance gates entry.
  Cap-runtime integrity: caps not synthesizable from bytes.

By-value with content-addressed slot references:
  CALL moves the callee Instance into a KernelFrame; the origin slot is
    empty-reserved until HALT restores it or discard clears the reservation.
  Slots only restore/update at apply termination or explicit discard.
  Sub-tree atomicity structural.
  No STM buffer required.

Snapshot/revert universal:
  MGMT_COPY of any Cap::Instance produces a content-shared reference.
  Mutations diverge per §9 case (b).
  Always available; always works.

Pinned cnode slots: kernel-locked, declared by current Image's
  `pinned_slots`. Holds Cap::Data (baked-in ro bytes) or Cap::Image
  (derive_spawn targets).

Empty-reserved origin slots: kernel-locked by call-stack metadata while a
  child Instance is running/waiting. They are not cap values and are not
  persisted.

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
properties, see [principles/sel4-mapping.md](principles/sel4-mapping.md).
