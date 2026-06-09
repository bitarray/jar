# Kernel / Chain interface design

This doc proposes the canonical architecture for the kernel ↔ chain
interface in v3, building on the four cap kinds, slot[0] scratchpad
channel, and yield/resume cascade primitives.

## Overview

The architecture has three structural pieces:

- **Kernel**: chain-spec-defined outermost runtime. Holds the canonical
  Chain Instance plus per-cycle transient instances. Implemented as a
  named-field struct in the validator binary; not generic Cap::Instance
  storage.

- **Chain**: a `Cap::Instance[ChainImage]` held by Kernel. Single source
  of truth for chain state. Its image declares the protocol's apply
  + verify + dispatch logic, and pins the Cap::Image references for
  derived role instances.

- **Derived role instances (Verify, Dispatch_k)**: per-block transient
  Cap::Instances produced by MGMT_COPY of Chain + set_image to the
  target role's image. They inherit Chain's state (via cnode
  content-sharing) while running their own role-specific bytecode.

## Kernel ABI: the scratchpad YieldSender CNode

All kernel interaction is a yield. The kernel is the implicit ROOT
YieldReceiver for every `kernel:*` yield_key — it sits at the bottom of
the call stack and catches any `kernel:*` key no in-stack frame caught.

At top-level invocation the kernel installs a CNode in the scratchpad
(slot[0]) mapping descriptive names → YieldSenders. This is the syscall
surface the chain bytecode (and any kernel-assisted Instance) sees:

```
scratchpad CNode (kernel-installed at top-level invocation):
  "kernel:mint_gas"             -> YieldSender{"kernel:mint_gas"}
  "kernel:set_gas_meter"        -> YieldSender{"kernel:set_gas_meter"}
  "kernel:mint_quota"           -> YieldSender{"kernel:mint_quota"}
  "kernel:set_storage_quota"    -> YieldSender{"kernel:set_storage_quota"}
  "kernel:mint_yield"           -> YieldSender{"kernel:mint_yield"}
  "kernel:merge_yield_receiver" -> YieldSender{"kernel:merge_yield_receiver"}
  "kernel:attest"               -> YieldSender{"kernel:attest"}
```

To invoke a syscall the guest places the chosen YieldSender in the
yield-scratchpad and `host_yield`s it (payload via slot[0]); the kernel
root receiver catches the `kernel:*` key and performs the op. The
attestation surface (top-level spec §15) is just the `kernel:attest` entry: the
kernel-injected AA Instance carries an internal YieldSender{"kernel:attest"}
and `host_yield`s it on each `AA.attest(...)`, caught by the kernel root
receiver (no marker-routed cascade).

## Kernel structure

```
Kernel (validator binary, not Cap::Instance):
  
  -- persistent across blocks:
  chain               : Cap::Instance[ChainImage]
  
  -- per-cycle transient (initialized at cycle start; dropped at end):
  verify_proto        : Cap::Instance[VerifyImage]
                        (derived from chain via MGMT_COPY + set_image)
  dispatch_protos     : Vec<Cap::Instance[Dispatch_k_Image]>
                        (one per chain-declared dispatch endpoint)
  aa                  : Cap::Instance[AAImage]
                        (kernel-injected; carries an internal
                         YieldSender{"kernel:attest"}; semantics in
                         attestation-authority.md)
  
  -- internal kernel state (off-σ):
  per-event gas budgets
  cycle_seen_keys     : Map<dispatch_endpoint_id, Set<PubKey>>
  attestation_traces  : current cycle's traces (incoming or building)
```

Kernel respects Instance access boundaries conceptually (no privileged
peek into Chain's cnode beyond what CALLs expose; standard cap-flow
rules). But its representation is direct named fields, not a generic
cnode — it's the runtime, not a userspace Instance.

## Chain Instance structure

```
ChainImage:
  code:             Bytes (canonical chain bytecode)
  memory_mappings:  declared regions
  endpoints:
    apply                      : process body events; mutate state
    transform_to_verify        : set_image to pinned VerifyImage
    transform_to_dispatch_k    : set_image to pinned Dispatch_k_Image
                                 (one such endpoint per dispatch type)
  pinned_slots:
    VERIFY_IMAGE_SLOT          : Cap::Image[VerifyImage]
    DISPATCH_0_IMAGE_SLOT      : Cap::Image[Dispatch_0_Image]
    DISPATCH_1_IMAGE_SLOT      : Cap::Image[Dispatch_1_Image]
    ...
    TRANSACT_IMAGE_SLOT        : Cap::Image[TransactImage]
                                 (used by Verify to construct Cap::Instance[Transact])
    DISPATCH_FRAME_IMAGE_SLOT  : Cap::Image[DispatchInstanceImage]
                                 (used by Verify to construct Cap::Instance[Dispatch])
    AA_IMAGE_SLOT              : Cap::Image[AAImage]
                                 (used by kernel to inject AA instances)
  gas_slots:        chain-spec policy
  
ChainImage.image_hash (derived):
  hash(KernelImage_hash || hash(ChainImage))   -- canonical chain
```

Chain's cnode holds the actual chain state:
- account balances, ledgers
- per-user authorization tables
- protocol-level state (epoch, slots, etc.)

Layout is chain-spec-defined; outside this doc's scope.

## Derivation: Verify and Dispatch_k

At block-cycle start, kernel constructs the transient role instances.

```
Kernel.setup_cycle:
  -- Derive Verify
  MGMT_COPY(chain, verify_proto)
    -- verify_proto.image       = ChainImage (inherited)
    -- verify_proto.image_hash  = chain.image_hash (preserved)
    -- verify_proto.cnode       = chain's cnode (content-shared)
  CALL(verify_proto, transform_to_verify_endpoint, gas)
    -- inside: set_image(self.pinned[VERIFY_IMAGE_SLOT]); HALT
    -- after CALL:
    --   verify_proto.image       = VerifyImage
    --   verify_proto.image_hash  = hash(chain.image_hash || hash(VerifyImage))
    --   verify_proto.cnode       = chain's cnode (still inherited),
    --                              with VerifyImage's pinned slots overlaid
  
  -- Derive each Dispatch_k
  for k in 0..N_dispatch_endpoints:
    MGMT_COPY(chain, dispatch_protos[k])
    CALL(dispatch_protos[k], transform_to_dispatch_k_endpoint, gas)
      -- inside: set_image(self.pinned[DISPATCH_k_IMAGE_SLOT]); HALT
      -- after: dispatch_protos[k] has Dispatch_k_Image, chain state,
      --        canonical image_hash
```

After setup:

```
verify_proto:
  image:       VerifyImage
  image_hash:  hash(chain.image_hash || hash(VerifyImage))
  cnode:       chain state + VerifyImage's pinned slots
  status:      Idle (ready for verify CALLs)

dispatch_protos[k]:
  image:       Dispatch_k_Image
  image_hash:  hash(chain.image_hash || hash(Dispatch_k_Image))
  cnode:       chain state + Dispatch_k_Image's pinned slots
  status:      Idle (ready for process CALLs at cycle end)
```

The image_hash chain proves canonical provenance: anyone holding a
`Cap::Instance[Verify]` can verify it derives from canonical Chain by
reading both caps' `image_hash` bytes via `host_image_hash_chain`
(`verify_instance` and `chain_spec_canonical_verify_ref`) and comparing
them — type identifies; possession authorizes.

## Pinned-slot layout

Chain-spec author must ensure pinned slot indices don't collide with
chain state slots:

```
slot[0]            : SCRATCHPAD (always; ABI convention)
slot[1..20]        : RESERVED for pinned image references
                     (VERIFY_IMAGE_SLOT, DISPATCH_*_IMAGE_SLOT, etc.)
slot[20..256]      : Chain state slots (chain-spec-defined layout)
```

When Verify or Dispatch_k's set_image installs its own pinned slots,
they go into the reserved range. State slots in [20..256) are
untouched.

VerifyImage and Dispatch_k_Image declare their pinned slots within
the reserved range — possibly different sub-ranges to avoid colliding
with each other, though that's overkill (they're derived separately
from chain, not from each other).

## Per-event verify flow (off-chain)

For each incoming event for dispatch endpoint k from gossip:

```
Kernel.handle_incoming_event(event, dispatch_k):
  -- Fresh per-event verify instance.
  MGMT_COPY(verify_proto, event_verify)
    -- content-shared from verify_proto; mutations diverge.
  
  AA_event = inject Cap::Instance[AAImage]
    -- fresh AA per event.
  
  -- Kernel records event's attestation_traces internally
  -- (kernel-private; not exposed to apply).
  kernel.current_traces = event.attestation_traces
  
  build verify_scratchpad in Kernel.slot[0]:
    blob:        Cap::Data (the event payload)
    AA:          Cap::Instance[AA_event]
    -- no traces; no mode info
  
  CALL(event_verify, verify_endpoint, gas_per_verify)
  -- VerifyImage.verify runs:
  --   reads blob from slot[0]
  --   parses; validates against chain state (visible via cnode);
  --   calls AA.attest(key, blob_hash) as needed
  --     (AA host_yields its YieldSender{"kernel:attest"}; the kernel,
  --      as root YieldReceiver for kernel:* keys, catches it and
  --      processes per attestation-authority.md; may early-fault if
  --      invalid)
  --   if reaches HALT: constructs Cap::Instance[Transact] or
  --     Cap::Instance[Dispatch] via host_derive_spawn from Chain's
  --     pinned TransactImage / DispatchInstanceImage.
  --   places resulting Cap::Instance in slot[0]
  --   HALTs
  
  if Faulted: drop event.
  if HALT:
    event_instance = Kernel.slot[0]  (reflected from event_verify)
    -- For dispatch: admit event_instance to dispatch_protos[k]'s buffer
    --   (via CALL dispatch_protos[k].admit_event(event_instance))
    -- For transact: admit to proposer's transaction pool (off-σ)
  
  MGMT_DROP(event_verify)
  -- AA_event also dropped; kernel post-processes attest records.
  
  -- Update kernel.cycle_seen_keys[k] with keys recorded during this
  -- verify (per attestation-authority.md's seen-rule mechanics).
```

The `event_verify` instance is fresh per event: its state is
verify_proto's state at the moment of MGMT_COPY (which inherits
chain state). Any mutations the verify endpoint makes are local
to event_verify; they don't pollute verify_proto or subsequent
events.

## Per-cycle process flow (off-chain → on-chain boundary)

At block boundary, before chain.apply runs:

```
Kernel.run_cycle_process:
  for k in 0..N_dispatch_endpoints:
    AA_cycle = inject Cap::Instance[AAImage]
      -- fresh AA per cycle per dispatch.
    -- Pre-load seen_keys from per-event verifies (kernel bookkeeping).
    
    build process_scratchpad in Kernel.slot[0]:
      events:    Cap::CNode containing the cycle's verified
                 Cap::Instance[Dispatch] events
      AA:        Cap::Instance[AA_cycle]
    
    CALL(dispatch_protos[k], process_endpoint, gas_per_process)
    -- Dispatch_k_Image.process runs:
    --   reads events from slot[0]
    --   sequentially processes each
    --   may call AA.attest(key, emit_blob_hash) — AA host_yields its
    --     YieldSender{"kernel:attest"}, caught by the kernel root
    --     receiver; kernel applies seen-rule, may fault if violation.
    --   may emit by writing to slot[0]: Cap::CNode of (target_path, blob)
    --   HALTs
    
    if Faulted: handle per chain-spec policy.
    if HALT:
      emits = Kernel.slot[0]  (reflected emit list)
      route emits: 
        - For target = dispatch endpoint: queue for next cycle.
        - For target = transact endpoint: add to proposer's pool.
    
    -- Kernel post-processes AA_cycle records (sign or verify per mode).
    MGMT_DROP(AA_cycle)
```

After all dispatch_protos have processed, the proposer assembles the
block body (its transaction pool + dispatch-emitted transacts +
attestation_traces produced by kernel during AA processing).

## On-chain apply

```
Kernel.apply_block(prior_state, body):
  -- Kernel state: chain at state σ_{N-1}, ready for σ_N transition.
  -- body contains: events + attestation_traces (kernel-private).
  
  AA_block = inject Cap::Instance[AAImage]
  kernel.current_traces = body.attestation_traces
  
  build apply_scratchpad in Kernel.slot[0]:
    body_data:  Cap::CNode of events (each event is Cap::Instance[Transact]
                or a raw blob to be verify-inlined by chain.apply)
    AA:         Cap::Instance[AA_block]
  
  CALL(chain, apply_endpoint, gas_block_budget)
  -- ChainImage.apply runs on canonical chain (not a copy):
  --   iterates events from slot[0]
  --   for each event: dispatches to target sub-handler
  --     (transact endpoint or Schedule slot)
  --   may call AA.attest as needed (AA host_yields its
  --     YieldSender{"kernel:attest"}, caught by the kernel root receiver)
  --   may emit additional events (next-block dispatches)
  --   mutates chain state
  --   HALTs with emits and new state hash via slot[0]
  
  if Faulted: block invalid; reject.
  if HALT:
    new_state_root = hash of chain.cnode_root
    outgoing_emits = from slot[0]
    
  -- Kernel post-processes AA_block records.
  attestation_traces = traces aggregated during apply (produce mode)
                       or empty/verified (verify mode)
  
  -- Drop transient instances.
  MGMT_DROP(verify_proto)
  for k: MGMT_DROP(dispatch_protos[k])
  MGMT_DROP(AA_block)
  
  return (new_state_root, attestation_traces, outgoing_emits)
```

After apply_block:

- Chain's state has advanced from σ_{N-1} to σ_N.
- verify_proto and dispatch_protos are dropped; transient state gone.
- Next cycle: fresh setup_cycle starts from σ_N.

## Per-block lifecycle visualized

```
σ_{N-1} (post-apply of block N-1)
  │
  ▼
Cycle for block N begins
  │
  ├─ setup_cycle:
  │    derive verify_proto from chain
  │    derive dispatch_protos from chain
  │
  ├─ for each incoming event (gossip):
  │    fresh event_verify = MGMT_COPY(verify_proto)
  │    CALL event_verify.verify(blob)
  │    admit to dispatch_protos[k] buffer
  │
  ├─ at block boundary:
  │    for each k: CALL dispatch_protos[k].process(buffered_events)
  │    route emits
  │
  ├─ apply_block:
  │    CALL chain.apply(body)
  │    chain state advances to σ_N
  │
  └─ teardown:
       drop verify_proto, dispatch_protos
  
  ▼
σ_N (committed)
  │
  ▼
Cycle for block N+1 begins (fresh derivation from σ_N)
  ...
```

The derived instances are explicitly transient per cycle. No
cross-block state in Verify or Dispatch instances. All cross-block
"memory" must live in chain state (committed in σ).

## Why "transform from Chain" instead of separate canonical instances

Alternative: each dispatch endpoint is a separate persistent
`Cap::Instance[Dispatch_k]` held in chain's cnode, accumulating state
across blocks.

Problems with the alternative:
- **Consensus risk**: state accumulation depends on gossip ordering;
  validators with different network views accumulate differently.
- **Implicit state hidden in dispatches**: anyone auditing chain
  state must inspect dispatch instances separately; they're "outside"
  chain's clean state representation.
- **Lifecycle complexity**: when does a dispatch instance get
  initialized? What if a validator joins late?

The transform-from-Chain pattern:
- **Per-block freshness**: derived at block start from canonical
  chain. All validators derive the same starting point.
- **Single source of truth**: chain state is the only persistent
  state; dispatch role instances are typed views.
- **Lifecycle is structural**: kernel-managed transient holdings;
  drop at block end.

## Comparison to legacy minimum design notes

| Legacy concept | v3 representation |
|---|---|
| `σ.transact_endpoints` flat list | Chain.apply dispatches by target_path internally; or held as Cap::Instances in chain's cnode |
| `σ.dispatch_endpoints` flat list | Chain's pinned Cap::Image[Dispatch_k_Image]; dispatch_protos derived per block |
| EventEndpointCap | Cap::Instance derived from chain via set_image; image_hash chain provides typed identity |
| Vault.verify (fresh per event) | event_verify = MGMT_COPY(verify_proto); fresh per event |
| Vault.process (per cycle) | dispatch_protos[k].process called per cycle |
| AttestationAuthority (scoped per endpoint cycle) | Kernel-injected Cap::Instance[AA]; see [attestation-authority.md] |
| caller() returns Kernel(Verify/Process) | userspace can't observe mode; kernel knows via call-stack context |
| emit_event host call | Apply writes emits to slot[0]; kernel reads on HALT |
| mint_attest_cap | AA holds an internal YieldSender{"kernel:attest"}; AA.attest host_yields it, caught by the kernel root YieldReceiver; see [attestation-authority.md] |
| setScore for buffering | Kernel-managed buffer ordering (chain-spec policy) |

The v3 vocabulary is more uniform: everything is Cap::Instance
operations + the four cap kinds + cascade primitives. The "EventEndpointCap"
and "Vault" abstractions of the legacy spec collapse into "Cap::Instance
derived from Chain via set_image."

## Open questions

1. **`Instance[Transact]` storage in block body**: does the block carry
   the original blob (with verify re-run on apply), or the verified
   `Cap::Instance[Transact]` directly (saving re-verify cost but storing
   more)? Probably blob + traces, with verify re-run; this is the
   legacy pattern.

2. **Where verified Cap::Instance[Dispatch] events accumulate**: inside
   dispatch_protos[k]'s cnode (via an admit endpoint), or in kernel's
   external buffer. The latter is simpler; the former gives the
   dispatch image structural control over its own buffer.

3. **Schedule slot semantics**: legacy treats Schedule specially.
   Under single Chain Instance, fold into chain.apply, or treat as a
   separate transform_to_schedule? Likely the former.

4. **Cross-block dispatch continuation**: if a dispatch needs to
   "remember" something across blocks (e.g., partial aggregation
   across rounds), it must emit a transact that updates chain state.
   Then next block's dispatch_proto is derived from updated chain,
   inheriting the remembered state. No special mechanism needed.

5. **Chain.apply yield**: if chain.apply yields (e.g., long
   computation), chain is Paused at block end. Next block, kernel
   CALL_RESUMEs chain. The transient role instances... still derived
   fresh from chain (which is now Paused; can we MGMT_COPY a Paused
   instance and then transform via set_image? set_image requires
   running apply, which can't happen on a Paused instance). Need to
   resolve. Probably: chain.apply doesn't yield; long-running
   computations are decomposed into per-block apply runs (each block
   processes a chunk).

These are downstream design questions; the core architecture
(transform-from-Chain) stands.
