# Generic authority capability pattern

This doc specifies the canonical userspace pattern for **authority
capabilities** in v3: caps that represent the right to invoke a
privileged operation mediated by an authoritative handler (the chain
orchestrator, the kernel, or any layer holding the marker in its
`yield_marker_slot`).

The pattern uses only existing v3 primitives:

- `host_derive_spawn` to mint marker Instances and AuthorityCap Instances.
- Standard Cap::Instance copyable semantics.
- `host_yield` with the kernel's yield-marker routing mechanism (§4).
- `yield_marker_slot` declaration in Image (§1).
- instance_hash equality for routing — no new primitives.

**No new cap kinds needed.** Earlier drafts of this doc explored
Request/Response Instance triplets, `host_same_type_as` chain checks,
exemplar Instances, Cap::Type-based routing, etc. — all superseded by
this simpler mechanism.

## The shape

```
                                      ┌─────────────────────┐
        Chain (handler)               │ yield_marker_slot   │
        ─────────────────────         │ slots:              │
        Image:                        │  [0] marker_invoke  │
          yield_marker_slot = 5       │  [1] marker_attest  │
        cnode:                        │  [2] ...            │
          [5] CNode containing ───────┴─────────────────────┘
              the markers Chain catches
        
        Chain mints AuthorityCap Instances:
        ─────────────────────
        AuthorityCap (e.g. EndpointRefCap):
          state:
            marker: Cap::Instance[marker_invoke]   <-- embedded in cnode
            target, endpoint_idx, etc.
          bytecode:
            invoke(args) → status
              -- compose payload from state + args
              -- place marker in yield scratchpad
              -- host_yield
              -- on resume, slot[0] has handler response
              -- return to caller
        
        User contract holds Cap::Instance[AuthorityCap].
        User contract CALLs AuthorityCap.invoke(args).
        AuthorityCap's bytecode is what yields.
        Kernel walks call stack; matches instance_hash; routes to Chain.
```

## The three roles

| Role | Image | Constructed by | Constructed into | Purpose |
|---|---|---|---|---|
| **Marker** | `XMarkerImage` (well-known per authority type) | Chain via `host_derive_spawn`, init typically empty | Chain's `yield_marker_slot` CNode (for catching) and inside each AuthorityCap's state (for yielding) | The routing key for yield matching |
| **AuthorityCap** | `XAuthorityCapImage` (well-known per authority pattern) | Chain via `host_derive_spawn`, init with marker + parameters | Distributed via cap-flow to user contracts | The bytecode-mediated entry point for invoking the authority |
| **Chain (handler)** | The chain orchestrator's own Image | Genesis / chain spec | Top of the chain's call hierarchy | The yield handler that processes requests |

## The mechanism, step by step

### Setup (Chain init)

```
1. Chain derives a marker for each authority type:
     marker_M = host_derive_spawn(MarkerImage, init={})
   
   marker_M's image_hash_chain = Chain.image_hash_chain || hash(MarkerImage).
   This chain is unforgeable (kernel-mediated extension).

2. Chain places Cap::Instance[marker_M] in its yield_marker_slot CNode:
     Chain.cnode[yield_marker_slot_idx].slot[k] = Cap::Instance[marker_M]
   
   This declares: "I catch yields whose marker matches marker_M."

3. (Optional, can be deferred per-grant.) Chain mints AuthorityCaps:
     auth_cap = host_derive_spawn(AuthorityCapImage,
                                  init={ marker: Cap::Instance[marker_M],
                                         ...other state... })
   
   The AuthorityCap holds the marker in its state. Crucially, the
   marker is in AuthorityCap's CNODE — accessible only to
   AuthorityCap's bytecode, not to outside observers.

4. Chain distributes Cap::Instance[auth_cap] via cap-flow to user
   contracts that should hold the authority.
```

### Invocation (user contract calling the authority)

```
1. User contract A holds Cap::Instance[auth_cap] in its cnode.

2. A's bytecode prepares args in slot[0]:
     A.slot[0] := { ...args... }

3. A invokes the AuthorityCap:
     CALL(slot containing auth_cap, "invoke", gas_budget)

4. AuthorityCap's bytecode runs (per AuthorityCapImage's spec):
   a. Read args from slot[0].
   b. Compose payload from self.state + args.
   c. Place payload in arg slot (a known slot for handler to read).
   d. Place self.cnode[marker_slot] (Cap::Instance[marker_M]) in the
      yield-scratchpad slot.
   e. host_yield(yield-scratchpad).

5. Kernel processes the yield:
   - Read marker instance_hash from yield-scratchpad.
   - Walk call stack from top down.
   - For each InstanceEntry F:
       If F.image.yield_marker_slot is set, examine F.cnode at that
       slot. For each cap there: if instance_hash equality, match.
   - First match wins. Push ReferenceEntry pointing to F.
   - F's bytecode resumes at its post-CALL continuation point with
     the payload in F's slot[0].

6. F (Chain) handles the request:
   a. Read payload from slot[0].
   b. Validate and process (route to target contract, etc.).
   c. Compose response.
   d. CALL_RESUME with response in slot[0].

7. AuthorityCap's bytecode resumes (popping the ReferenceEntry):
   a. Read response from slot[0].
   b. Place response in caller-visible slot[0].
   c. HALT.

8. A's bytecode receives the response in its slot[0] and continues.
```

### Revocation (marker rotation)

```
Chain wants to revoke all outstanding AuthorityCaps of a type:

1. Remove Cap::Instance[marker_M] from yield_marker_slot CNode.
   (Or replace with a different marker.)

2. From this moment, yields with marker_M no longer match. All
   outstanding AuthorityCaps holding marker_M will fault on yield.

3. Mint a new marker marker_M_new for the type. Place in slot.
4. Mint new AuthorityCaps with the new marker. Distribute.

Outstanding old AuthorityCaps are structurally dead. No per-cap
tracking needed.
```

## Why this is forgery-resistant

The forgery argument has one structural pillar: **marker
derivation is kernel-mediated and produces a chain-extended
image_hash that an adversary cannot replicate.**

To match Chain's marker, an adversary would need:
- An Instance with image_hash equal to `hash(Chain's chain || hash(MarkerImage))`.
- Plus byte-identical state (per instance_hash equality on full state).

For the chain: the adversary's derivation history would need to be
prefixed by Chain's derivation history. host_derive_spawn extends
the *deriver's* chain; the deriver is the adversary, not Chain. So
the adversary's chain doesn't start with Chain's chain prefix. Hash
mismatch. Forgery prevented.

For the state: the marker is typically derived with empty state, so
state matching is trivial. But state can be non-empty; the
forgery-resistance argument holds at the chain level regardless.

## Cap::Instance vs Cap::Type — for authority routing, use Cap::Instance

A core principle (also documented in README §8):

> **Cap::Type identifies an Instance's type. Cap::Instance authorizes
> invocation of a specific Instance. These are NOT
> interchangeable for authority purposes.**

A pattern like "if I hold Cap::Type{X}, I have authority X" would be
WRONG. Anyone with a Cap::Instance to any Instance in Chain's chain can
compute Cap::Type{Chain.chain + derive_steps} via host_subtype.
Cap::Type is just a type identifier, not an authority credential.

The yield-marker pattern uses **Cap::Instance** (specifically, a real
marker Instance derived via host_derive_spawn). Routing is by
instance_hash equality of Cap::Instance values, not Cap::Type values.

Cap::Type is useful for:
- Runtime type-checking ("is this Instance of type X?").
- Type-based dispatch.
- Composing types abstractly.

Cap::Type is NOT useful for:
- Authority routing.
- Authorization checks.
- Anywhere "possession proves something" matters.

If your design has a Cap::Type stored somewhere that's being treated
as an authority credential, that's a bug. Use Cap::Instance.

## Security properties preserved (V1–V9 mapping)

See [discussions/sel4-mapping.md](../discussions/sel4-mapping.md)
for the full V1–V9 analysis. Under the yield-marker pattern:

| Property | Status |
|---|---|
| V1 Authority confinement | ✓ AuthorityCap conveys one operation per cap |
| V2 Authority unforgeability | ✓ image_hash chain prevents marker forgery |
| V3 Revocation | ✓ Marker rotation revokes all caps holding the old marker |
| V4 Endpoint mediation | ✓ AuthorityCap bytecode is the only path to yielding the marker |
| V5 Cap rights | ✓ Cap-level differentiation via state baked into AuthorityCap |
| V6 Integrity | ✓ Marker forgery prevented; intermediates can't synthesize state changes |
| V7 Confidentiality from intermediates | ✓ Kernel routes directly to handler; intermediates not on call path don't see payload |
| V8 Availability | Lost from intermediates (intrinsic to layered system); mitigated by chain-level discipline |
| V9 Determinism | ✓ All operations are deterministic |

## Where policy attaches

Different AuthorityCaps can have different policies baked into their
state:

```
Mint a per-rate-limit cap:
  rate_limited_cap = host_derive_spawn(EndpointRefCapImage,
                                       init = { marker, target, endpoint_idx,
                                                rate_limit: 100/sec })

The cap's bytecode reads its own state and includes rate_limit in
payload. Chain's handler enforces the rate limit by reading the
payload.

Or: per-cap-identity sidecar tracked at Chain. AuthorityCap state
includes a cap_id (monotonic, baked in at mint time). Chain
maintains a small map: cap_id → policy. Useful when policy must be
adjustable post-grant.
```

Both patterns are capability-pure. Neither reintroduces ACL anti-
patterns.

## Comparison with earlier drafts (history)

Earlier drafts of this doc explored several mechanisms that have
been superseded:

| Earlier mechanism | Issue | Resolution |
|---|---|---|
| Request/Response Instance triplet | Required new endpoint discipline; cascade through intermediates exposed payloads | Single yield with marker; direct routing skips intermediates |
| `host_same_type_as` chain checks | Caller witness mechanism was over-engineered | Instance_hash equality on real markers (the marker is the proof) |
| Exemplar Instances for caller cert checks | Required deriving Instances just for type identification | Marker Instances serve both as exemplars and as routing keys |
| Cap::TypeWitness / Cap::Type for authority | Cap::Type is derivable from any descendant Cap::Instance; doesn't prove authority | Use Cap::Instance; Cap::Type is identification-only (§8) |
| Image_hash matching for routing | Required "fake template Instances" or Cap::Image variant; complex | Instance_hash matching with single shared marker; payload carries variations |
| Linear caps for Request/Response | Replay-during-cascade concerns | No cascade; no Request/Response wrappers; replay handled by structural routing |
| Chain-prefix check at yield | Defense in depth that became unnecessary | Instance_hash check at the marker level is sufficient |

The simpler mechanism (instance_hash + yield-marker routing) replaces
all of the above. The principle: **the marker Instance itself is the
routing key and the unforgeable proof of origin.** No separate Request,
Response, exemplar, or witness needed.

## Worked examples

### AttestationAuthority (AA)

See [discussions/attestation-authority.md](../discussions/attestation-authority.md)
for the full design with mode-invariance and seen-rule. In yield-
marker terms:

| Role | Image | Notes |
|---|---|---|
| Marker | AttestMarkerImage | Empty state; image_hash_chain rooted in kernel |
| AuthorityCap | AAImage | Bytecode for `attest(key, blob) → status`; embeds marker; handler is kernel itself |
| Handler | kernel | Has AttestMarkerImage marker in its yield_marker_slot; processes mode-aware |

User contract: `CALL(aa_cap, "attest", ...)`. AA's bytecode yields with
marker; kernel catches; runs hw_verify or hw_sign per mode; returns
AttestStatus (mode-invariant). Userspace never sees the signature.

### EndpointRefCap (chain orchestrator's user contract dispatch)

See README §14. In yield-marker terms:

| Role | Image | Notes |
|---|---|---|
| Marker | InvokeMarkerImage | Empty state; image_hash_chain rooted in Chain |
| AuthorityCap | EndpointRefCapImage | Bytecode for `invoke(args)`; embeds marker + target_address + endpoint_idx |
| Handler | Chain orchestrator | Has InvokeMarkerImage marker in its yield_marker_slot; routes to target contract |

User contract A holds Cap::Instance[EndpointRefCap(B, 5)]. CALLs invoke.
AuthorityCap's bytecode yields with marker; Chain catches; Chain
calls B.endpoint_5; returns result.

### MintInstance

See README §16. In yield-marker terms:

| Role | Image | Notes |
|---|---|---|
| Marker | MintMarkerImage | Empty state; image_hash_chain rooted in Chain |
| AuthorityCap | MintRefCapImage | Bytecode for `mint(content) → status`; embeds marker + domain |
| Handler | Chain orchestrator (with MintInstance inside it) | Catches mint yields; routes to MintInstance.mint |

User contract A holds Cap::Instance[MintRefCap(domain_X)]. CALLs mint.
AuthorityCap yields; Chain handler invokes MintInstance.mint(domain_X, content).

## Glossary

- **Marker / Marker Instance**: an Instance derived by Chain that serves as
  the routing key for a class of yields. Its instance_hash is what's
  compared during yield routing.
- **AuthorityCap**: an Instance whose state holds a marker and whose
  bytecode is the entry point for invoking the authority. Distributed
  via cap-flow to grant invocation rights.
- **Handler**: the Instance that catches the yield (has the marker in
  its yield_marker_slot). Typically the chain orchestrator or the
  kernel itself.
- **yield_marker_slot**: the Image-declared slot in an Instance's cnode
  that holds the CNode of marker Instances this Instance catches.
- **Marker rotation**: replacing markers in the yield_marker_slot to
  revoke outstanding AuthorityCaps.

## Relationship to other docs

- [README.md §1](../README.md): `yield_marker_slot` field in Image.
- [README.md §3](../README.md): kernel call stack model.
- [README.md §4](../README.md): `host_yield` ABI with marker routing;
  `host_type_of` / `host_subtype` / `host_type_eq` for Cap::Type.
- [README.md §8](../README.md): Cap::Type vs Cap::Instance distinction;
  authority is Cap::Instance.
- [README.md §14](../README.md): authority via capability flow,
  using the yield-marker mechanism.
- [README.md §15](../README.md): AttestationAuthority as an instance.
- [README.md §16](../README.md): MintInstance as an instance.
- [discussions/attestation-authority.md](../discussions/attestation-authority.md):
  AA design including mode-invariance.
- [discussions/data-flow-principle.md](../discussions/data-flow-principle.md):
  architectural derivation of why authority must go through Chain
  orchestrator under v3's single-mutator + per-context fault model.
- [discussions/sel4-mapping.md](../discussions/sel4-mapping.md):
  V1–V9 security analysis.

## Summary

The v3 authority pattern is:

> **A handler declares the marker types it catches in its
> `yield_marker_slot` CNode. Marker Instances are derived by the
> handler via `host_derive_spawn`; their image_hash chain is
> kernel-mediated and forgery-resistant. The handler mints
> AuthorityCap Instances that embed the marker in their state and
> whose bytecode is the entry point for invoking the authority.
> AuthorityCaps are distributed via cap-flow. User contracts
> invoke AuthorityCaps; AuthorityCap bytecode yields with the
> marker; kernel walks the call stack matching by instance_hash;
> handler catches and processes; result returns.**

No new cap kinds. No new kernel primitives beyond `host_yield`'s
marker routing. No Request/Response wrappers. No witness caps. No
Cap::Type-as-authority. Just Cap::Instance, instance_hash equality, and
yield_marker_slot.

The architectural justification (why this is structurally required,
not just a design choice) is in
[discussions/data-flow-principle.md](../discussions/data-flow-principle.md):
single-mutator + per-context fault → single-activation → hierarchical
call stack → cross-contract calls must go through a common parent →
Chain orchestrator is structurally the only place fault-isolated
cross-contract communication can be implemented.
