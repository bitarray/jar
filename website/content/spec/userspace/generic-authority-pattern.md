# Generic authority capability pattern

This doc specifies the canonical userspace pattern for **authority
capabilities** in v3: caps that represent the right to invoke a
privileged operation mediated by an authoritative handler (the chain
orchestrator, the kernel, or any layer that has registered the
`yield_key` in its `yield_receiver_slot`).

The pattern uses only existing v3 primitives:

- `host_derive_spawn` to mint AuthorityCap Instances.
- `kernel:mint_yield` / `kernel:merge_yield_receiver` to mint and
  compose the (YieldSender, YieldReceiver) rights.
- Standard Cap::Instance copyable semantics.
- `host_yield` with the kernel's yield_key routing mechanism (§4).
- `yield_receiver_slot` declaration in Image (§1).
- yield_key routing via owner-edge snapshots + single-resumer — no new
  primitives.

**No new cap kinds needed.** Earlier drafts of this doc explored
Request/Response Instance triplets, `host_same_type_as` chain checks,
exemplar Instances, Cap::Type-based routing, etc. — all superseded by
this simpler mechanism.

## The shape

```
                                      ┌──────────────────────────┐
        Chain (handler)               │ yield_receiver_slot      │
        ─────────────────────         │ YieldReceiver{ keys }:   │
        Image:                        │  "invoke_key"            │
          yield_receiver_slot = 5     │  "kernel:attest"         │
        cnode:                        │  ...                     │
          [5] YieldReceiver holding ──┴──────────────────────────┘
              the yield_keys Chain catches

        Chain mints AuthorityCap Instances:
        ─────────────────────
        AuthorityCap (e.g. EndpointRefCap):
          state:
            sender: YieldSender{invoke_key}   <-- embedded in cnode (opaque)
            target, endpoint: Key, etc.
          bytecode:
            invoke(args) → status
              -- compose payload from state + args
              -- place YieldSender in yield scratchpad
              -- host_yield(YieldSender)
              -- on resume, slot[0] has handler response
              -- return to caller

        User contract holds Cap::Instance[AuthorityCap].
        User contract CALLs AuthorityCap.invoke(args).
        AuthorityCap's bytecode is what yields.
        Kernel reads yield_key and routes along owner edges to the
        nearest snapshotted YieldReceiver containing the key (Chain).
```

## The three roles

| Role | Held as | Constructed by | Constructed into | Purpose |
|---|---|---|---|---|
| **YieldSender** | `YieldSender{yield_key}` (the EMIT right) | Chain via `kernel:mint_yield` (returns the Sender/Receiver pair) | Embedded in each AuthorityCap's state (for yielding) | The routing key for yield matching |
| **AuthorityCap** | `Cap::Instance[XAuthorityCapImage]` (well-known per authority pattern) | Chain via `host_derive_spawn`, init with YieldSender + parameters | Distributed via cap-flow to user contracts | The bytecode-mediated entry point for invoking the authority |
| **Chain (handler)** | The chain orchestrator's own Image; registers the `yield_key` in its `YieldReceiver` (the CATCH right) | Genesis / chain spec | Top of the chain's call hierarchy | The yield handler that processes requests |

## The mechanism, step by step

### Setup (Chain init)

```
1. Chain mints a (Sender, Receiver) pair for each authority type, under
   a fresh yield_key:
     (sender_M, receiver_M) = kernel:mint_yield(key_M)

   key_M is a string in Chain's own namespace (e.g. "invoke_key").
   kernel:mint_yield is unrestricted, but Chain holds it in its TCB and
   interposes to gate which keys descendants may mint (see forgery
   resistance below).

2. Chain registers key_M in its own YieldReceiver by merging receiver_M
   into the YieldReceiver held in its yield_receiver_slot:
     Chain.cnode[yield_receiver_slot] :=
         kernel:merge_yield_receiver(Chain's YieldReceiver, receiver_M)

   This declares: "I catch yields tagged key_M."

3. (Optional, can be deferred per-grant.) Chain mints AuthorityCaps:
     auth_cap = host_derive_spawn(AuthorityCapImage,
                                  init={ sender: sender_M,
                                         ...other state... })

   The AuthorityCap holds the YieldSender in its state. Crucially, the
   YieldSender is in AuthorityCap's CNODE — accessible only to
   AuthorityCap's bytecode, not to outside observers (opaque).

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
   d. Place self.cnode[sender_slot] (YieldSender{key_M}) in the
      yield-scratchpad slot.
   e. host_yield(yield-scratchpad).

5. Kernel processes the yield:
   - Read yield_key (key_M) from the YieldSender in the yield-scratchpad.
   - Walk owner edges from the logical current Instance toward the root.
   - The NEAREST owner edge whose snapshotted YieldReceiver contains
     key_M catches it (single-resumer). That owner frame is F (Chain).
   - Push ReferenceEntry pointing to F. (No match -> the emitter faults
     with "unhandled yield_key".)
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

### Revocation (key rotation)

```
Chain wants to revoke all outstanding AuthorityCaps of a type:

1. Drop key_M from the YieldReceiver in Chain's yield_receiver_slot
   (move out the old YieldReceiver, move in one without key_M).
   (Or re-mint the authority under a fresh key_M_new.)

2. From this moment, yields tagged key_M match no receiver. All
   outstanding AuthorityCaps holding YieldSender{key_M} will fault on
   yield ("unhandled yield_key"). SNAPSHOT CAVEAT: because a frame's
   catch-list is a per-CALL snapshot, the change takes effect for the
   subtrees of CALLs made AFTER the drop, not for sub-calls already
   in flight.

3. Mint a new pair (sender_M_new, receiver_M_new) via kernel:mint_yield
   under key_M_new; merge receiver_M_new into Chain's YieldReceiver.
4. Mint new AuthorityCaps embedding sender_M_new. Distribute.

Outstanding old AuthorityCaps are structurally dead. No per-cap
tracking needed.
```

## Why this is forgery-resistant

The forgery argument has one structural pillar: **an adversary cannot
mint a `YieldSender` for a restricted key, because the orchestrator
interposes over the unrestricted `kernel:mint_yield`.**

To emit a yield that Chain catches, an adversary would need a
`YieldSender{key_M}` for Chain's key_M. There are only two ways to
obtain one, and the chain closes both:

- Receive it from Chain. Chain only embeds it in AuthorityCaps and
  distributes those — never the bare YieldSender. AuthorityCap's CNODE
  is opaque, so a holder cannot extract the embedded Sender (it can only
  invoke the bytecode, which always composes the legitimate payload).

- Mint it itself via `kernel:mint_yield`. `kernel:mint_yield` is
  unrestricted at the kernel root, but Chain INTERPOSES over it: Chain
  registers `"kernel:mint_yield"` in its own YieldReceiver and hands
  descendants only a restricted `YieldSender{"kernel:mint_yield"}` that
  routes to Chain. Chain inspects the requested key and rejects key_M
  (and any other key it reserves), forwarding only permitted keys to the
  real kernel. So a descendant simply cannot mint Chain's key.

Because the YieldSender is a per-key right (not a derivable type), there
is no "compute it from a descendant" attack: possession of the Sender is
the whole proof, and possession is gated by the two paths above.

## Cap::Instance vs type identity — for authority routing, use Cap::Instance

A core principle (also documented in top-level spec §8):

> **An Instance's type identity is its `image_hash`. Cap::Instance
> authorizes invocation of a specific Instance. These are NOT
> interchangeable for authority purposes.**

A pattern like "if a cap's image_hash == X, I have authority X" would be
WRONG. Anyone with a Cap::Instance to any Instance in Chain's chain can
read its `image_hash` (via `host_image_hash_chain`) and fold any
`Chain.chain + derive_steps` extension themselves. The image_hash is
just a type identifier, not an authority credential.

The yield_key pattern uses **Cap::Instance** (specifically, an
AuthorityCap whose CNODE holds a `YieldSender{yield_key}`). Routing is
by the yield_key carried in that YieldSender, not by any image_hash
value. The positive authority mechanism is possession of the
YieldSender for the key — a per-key right that is not derivable from a
type.

The image_hash is useful for:
- Runtime type-checking ("is this Instance of type X?").
- Type-based dispatch.
- Composing type identifiers abstractly.

The image_hash is NOT useful for:
- Authority routing.
- Authorization checks.
- Anywhere "possession proves something" matters.

If your design treats a cap's image_hash as an authority credential,
that's a bug. Use Cap::Instance.

## Security properties preserved (V1–V9 mapping)

See [principles/sel4-mapping.md](../principles/sel4-mapping.md)
for the full V1–V9 analysis. Under the yield_key pattern:

| Property | Status |
|---|---|
| V1 Authority confinement | ✓ AuthorityCap conveys one operation per cap |
| V2 Authority unforgeability | ✓ Interposition over `kernel:mint_yield` prevents minting a restricted YieldSender |
| V3 Revocation | ✓ Dropping the key from the YieldReceiver revokes all caps emitting it (snapshot caveat) |
| V4 Endpoint mediation | ✓ AuthorityCap bytecode is the only path to the embedded YieldSender |
| V5 Cap rights | ✓ Cap-level differentiation via state baked into AuthorityCap |
| V6 Integrity | ✓ YieldSender forgery prevented; intermediates can't synthesize state changes |
| V7 Confidentiality from intermediates | ✓ Emitter-exclusion + single-resumer route straight to the nearest receiver; unregistered intermediates never see the payload |
| V8 Availability | Lost from intermediates (intrinsic to layered system); mitigated by chain-level discipline |
| V9 Determinism | ✓ All operations are deterministic |

## Where policy attaches

Different AuthorityCaps can have different policies baked into their
state:

```
Mint a per-rate-limit cap:
  rate_limited_cap = host_derive_spawn(EndpointRefCapImage,
                                       init = { sender, target, endpoint: Key,
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
| Request/Response Instance triplet | Required new endpoint discipline; cascade through intermediates exposed payloads | Single yield by key; owner-edge routing + single-resumer bypass intermediates |
| `host_same_type_as` chain checks | Caller witness mechanism was over-engineered | yield_key routing (the YieldSender is the proof) |
| Exemplar Instances for caller cert checks | Required deriving Instances just for type identification | A YieldSender{yield_key} serves both as authority and as routing key |
| Cap::TypeWitness / Cap::Type for authority | A type identifier is derivable from any descendant Cap::Instance; doesn't prove authority | Use Cap::Instance; the image_hash is identification-only (§8) |
| Image_hash matching for routing | Required "fake template Instances" or Cap::Image variant; complex | yield_key matching against the snapshotted YieldReceiver; payload carries variations |
| Linear caps for Request/Response | Replay-during-cascade concerns | No cascade; no Request/Response wrappers; replay handled by structural routing |
| Chain-prefix check at yield | Defense in depth that became unnecessary | The yield_key check at the receiver is sufficient |

The simpler mechanism (yield_key routing) replaces all of the above. The
principle: **the YieldSender{yield_key} is the routing key, and
interposition over `kernel:mint_yield` is the unforgeable proof of
origin.** No separate Request, Response, exemplar, or witness needed.

## Worked examples

### AttestationAuthority (AA)

See [principles/attestation-authority.md](../principles/attestation-authority.md)
for the full design with mode-invariance and seen-rule. In yield_key
terms:

| Role | Held as | Notes |
|---|---|---|
| YieldSender | `YieldSender{"kernel:attest"}` | The reserved attest yield_key; the Sender lives in the top-level scratchpad CNode |
| AuthorityCap | AAImage | Bytecode for `attest(key, blob) → status`; embeds the YieldSender; handler is kernel itself |
| Handler | kernel | Implicit ROOT YieldReceiver for `kernel:attest`; processes mode-aware |

User contract: `CALL(aa_cap, "attest", ...)`. AA's bytecode yields
`YieldSender{"kernel:attest"}`; the kernel (root receiver) catches; runs
hw_verify or hw_sign per mode; returns AttestStatus (mode-invariant).
Userspace never sees the signature.

### EndpointRefCap (chain orchestrator's user contract dispatch)

See top-level spec §14. In yield_key terms:

| Role | Held as | Notes |
|---|---|---|
| YieldSender | `YieldSender{invoke_key}` | invoke_key minted by Chain via `kernel:mint_yield` |
| AuthorityCap | EndpointRefCapImage | Bytecode for `invoke(args)`; embeds the YieldSender + target_address + endpoint: Key |
| Handler | Chain orchestrator | Has registered invoke_key in its YieldReceiver (`yield_receiver_slot`); routes to target contract |

User contract A holds Cap::Instance[EndpointRefCap(B, "process")]. CALLs
invoke. AuthorityCap's bytecode yields `YieldSender{invoke_key}`; Chain
catches (nearest owner-edge snapshot containing invoke_key); Chain calls
B's "process" endpoint; returns result.

### MintInstance

See top-level spec §16. In yield_key terms:

| Role | Held as | Notes |
|---|---|---|
| YieldSender | `YieldSender{mint_key}` | mint_key minted by Chain via `kernel:mint_yield` |
| AuthorityCap | MintRefCapImage | Bytecode for `mint(content) → status`; embeds the YieldSender + domain |
| Handler | Chain orchestrator (with MintInstance inside it) | Has registered mint_key in its YieldReceiver; routes mint yields to MintInstance.mint |

User contract A holds Cap::Instance[MintRefCap(domain_X)]. CALLs mint.
AuthorityCap yields `YieldSender{mint_key}`; Chain handler invokes
MintInstance.mint(domain_X, content).

## Glossary

- **YieldSender{yield_key}**: the EMIT right over a yield_key. Possession
  authorizes emitting a yield tagged yield_key; the yield_key is the
  routing key compared during yield routing. Minted (with its paired
  YieldReceiver) via `kernel:mint_yield`.
- **YieldReceiver{Vec<yield_key>}**: the CATCH right — the set of
  yield_keys an Instance catches. Held in the Instance's
  `yield_receiver_slot`. Composed via `kernel:merge_yield_receiver`.
- **AuthorityCap**: an Instance whose state holds a YieldSender (opaque
  in its CNODE) and whose bytecode is the entry point for invoking the
  authority. Distributed via cap-flow to grant invocation rights.
- **Handler**: the Instance that catches the yield (has registered the
  yield_key in its YieldReceiver). Typically the chain orchestrator or
  the kernel itself (the kernel is the implicit root receiver for
  `kernel:*` keys).
- **yield_receiver_slot**: the Image-declared slot in an Instance's cnode
  that holds the YieldReceiver listing the yield_keys this Instance
  catches.
- **Key rotation**: dropping a yield_key from the YieldReceiver (or
  re-minting under a fresh key) to revoke outstanding AuthorityCaps.

## Relationship to other docs

- [top-level spec §1](../_index.md): `yield_receiver_slot` field in Image.
- [top-level spec §3](../_index.md): kernel call stack model.
- [top-level spec §4](../_index.md): `host_yield` ABI with yield_key routing;
  `host_image_hash_chain` for reading an Instance's type identity.
- [top-level spec §8](../_index.md): type identity (image_hash) vs Cap::Instance
  distinction; authority is Cap::Instance.
- [top-level spec §14](../_index.md): authority via capability flow,
  using the yield_key mechanism.
- [top-level spec §15](../_index.md): AttestationAuthority as an instance.
- [top-level spec §16](../_index.md): MintInstance as an instance.
- [principles/attestation-authority.md](../principles/attestation-authority.md):
  AA design including mode-invariance.
- [principles/data-flow-principle.md](../principles/data-flow-principle.md):
  architectural derivation of why authority must go through Chain
  orchestrator under v3's single-mutator + per-context fault model.
- [principles/sel4-mapping.md](../principles/sel4-mapping.md):
  V1–V9 security analysis.

## Summary

The v3 authority pattern is:

> **A handler registers the yield_keys it catches in the YieldReceiver
> held in its `yield_receiver_slot`. The (YieldSender, YieldReceiver)
> pair for a key is minted via `kernel:mint_yield` (and composed via
> `kernel:merge_yield_receiver`); forgery resistance comes from the
> handler interposing over the unrestricted `kernel:mint_yield`. The
> handler mints AuthorityCap Instances that embed the YieldSender in
> their state (opaque) and whose bytecode is the entry point for
> invoking the authority. AuthorityCaps are distributed via cap-flow.
> User contracts invoke AuthorityCaps; AuthorityCap bytecode yields the
> YieldSender; the kernel reads the yield_key and routes along owner edges
> to the nearest snapshotted YieldReceiver containing the key
> (single-resumer); handler catches and processes; result returns.**

No new cap kinds. No new kernel primitives beyond `host_yield`'s
yield_key routing (plus the `kernel:*` syscall yields). No
Request/Response wrappers. No witness caps. No Cap::Type-as-authority.
Just Cap::Instance, YieldSender/YieldReceiver, and yield_receiver_slot.

The architectural justification (why this is structurally required,
not just a design choice) is in
[principles/data-flow-principle.md](../principles/data-flow-principle.md):
single-mutator + per-context fault → single-activation → hierarchical
call stack → cross-contract calls must go through a common parent →
Chain orchestrator is structurally the only place fault-isolated
cross-contract communication can be implemented.
