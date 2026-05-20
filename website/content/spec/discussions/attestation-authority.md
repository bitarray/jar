# AttestationAuthority — design

AttestationAuthority (AA) is the v3 mechanism by which userspace
declares signing / verifying obligations, while the kernel performs
all mode-aware processing (sign vs verify, local vs remote, seen-rule
enforcement). The design preserves consensus by keeping the apply's
visible state independent of mode.

## Why AA exists

Three orthogonal concerns require it:

1. **Determinism**. apply bytecode must produce the same outputs
   across all validators given the same visible inputs. So
   "should this validator sign this blob?" can't be apply-visible —
   it depends on per-validator hardware authority. Apply just
   declares the (key, blob) need; kernel decides.

2. **Aggregation deferral**. Crypto operations (hw_sign, hw_verify,
   BLS aggregate) are slow. Doing them in-line during apply would
   force the kernel to schedule crypto in the middle of pure-function
   apply. Recording obligations and processing them post-HALT
   (per-attest yield in v3) lets crypto happen at clean boundaries.

3. **Mode invariance**. Verify-mode validator and produce-mode
   proposer must run identical apply bytecode against identical
   apply-visible inputs. If apply could observe "I have incoming
   sigs" vs "I'm generating sigs", consensus would split. AA
   guarantees apply only sees blob + key + chain context; the
   sig-presence is kernel-only knowledge.

## The userspace ABI

AA is an **authority cap** in the generic pattern (see
[generic-authority-pattern.md](../userspace/generic-authority-pattern.md)).
Possession of `Cap::Instance[AA]` is the authority to request
attestations. The endpoint follows request/response Instance shape:

```
AA.attest(key: PubKey, blob: Bytes) → AttestStatus
  -- Builds an Attest request Instance with state {key, blob}.
  --   image_hash_chain: ... → kernel → AA → Attest
  -- Yields up with the Attest in slot[0]; cascade reaches kernel.
  -- Kernel handles per-attest at the yield (mode-aware).
  -- On resume, slot[0] holds an Attested response Instance.
  -- CALLs Attested.get_status → returns status to caller.

enum AttestStatus {
  Recorded,           -- request processed (signed in produce mode,
                      -- verified in verify mode); both modes return
                      -- the same value for the same input.
  InvalidKey,
  MalformedBlob,
  QuotaExceeded,
  ...                 -- mode-invariant failure modes only
}
```

Userspace does NOT see:
- A signature. (The signature lives at the block layer, in
  attestation_traces; never in apply-visible state.)
- Trace data.
- A mode indicator.
- An origin tag (local vs remote).

Userspace just declares the (key, blob) and receives a mode-
invariant status. This guarantees consensus safety: produce and
verify mode return the same status for the same apply-visible input.

## Kernel-side processing

When the apply yields with an Attest request in slot[0]:

```
Kernel.handle_attest_yield(attest_instance, context):
  -- context = which endpoint is calling, which phase (verify/process),
  --           which event in the cycle, etc. Kernel knows from call
  --           stack (caller image_hash chain).

  -- Per the generic-authority pattern, kernel calls Attest's
  -- inspection endpoint, passing a kernel-handler witness as an
  -- argument. The endpoint runs
  --   host_same_type_as(kernel_handler_witness, HANDLER_EXEMPLAR, [])
  -- to verify the witness is of the expected class. Intermediates
  -- can't mint an Instance matching the exemplar (their chain doesn't
  -- match), so they cannot read.
  (key, blob) = attest_instance.get_request_for(kernel_handler_witness)

  status: AttestStatus
  if kernel.current_mode == VerifyMode (block has incoming traces):
    -- The validator is processing a finalized block.
    sig = lookup_in_traces(kernel.current_traces, key, blob)
    if sig is None:
      -- block claims fewer attestations than apply expects;
      -- consensus failure. Fault the apply (early-discard).
      fault apply
    elif not hw_verify(key, blob, sig):
      fault apply
    else:
      status = Recorded

  elif kernel.current_mode == ProduceMode (this validator producing):
    -- Apply seen-rule per cycle:
    seen_keys = kernel.cycle_seen_keys[context.endpoint][context.cycle]
    if context.phase == verify:
      seen_keys.add(key)
      status = Recorded
    elif context.phase == process or apply:
      if key not in seen_keys:
        fault apply (seen-rule violation; proposer can't produce a
                     valid block with this attest)
      elif local_validator_has_authority(key):
        sig = hw_sign(key, blob)
        kernel.outgoing_traces.append({key, blob, sig})
        status = Recorded
      else:
        -- non-local key; record acknowledged; another validator
        -- with the key signs separately.
        status = Recorded

  -- Mode-invariant return: the same `status` value for the same
  -- apply-visible inputs. Wrap in Attested via the attest_instance's
  -- own fulfill endpoint (which only accepts a kernel-generated
  -- witness).
  answer_witness = host_derive_spawn(KernelAnswerImage,
                                     init = { status })
  attested = attest_instance.fulfill(answer_witness)
  slot[0] := attested
  CALL_RESUME
```

The kernel's mode-aware processing is entirely external to apply.
Apply sees: yield → either resume with status (kernel approved) or
fault (kernel discarded). Critically, the status enum is mode-
invariant — apply cannot distinguish produce from verify mode by
return value.

Confidentiality from intermediates is preserved structurally: both
`get_request_for(witness)` and `fulfill(answer_witness)` run
`host_same_type_as` on the cap-passed witness against pinned
exemplars of the kernel-handler and kernel-answer classes.
Intermediates routing the Attest cascade cannot mint an Instance whose
chain matches the exemplar, so they can neither inspect (key, blob)
nor fabricate a valid fulfill.

## Why this is consensus-safe

**Apply visibility**: apply sees blob, chain context (read-only),
and the (key, blob) it declared. No mode info. No traces. No sig.

**Apply outcome determinism**: identical apply-visible inputs →
identical apply outcome (HALT or fault at the same instruction).

**Mode determines kernel reaction**:
- Verify mode (validator processing block N): kernel has block's
  attestation_traces. Verifies each attest against traces. Detects
  bad/missing sigs deterministically. Faults apply identically
  across all verifiers.
- Produce mode (proposer building block N): kernel has no incoming
  traces; generates them. Applies seen-rule + local-key signing.
  Faults apply if seen-rule violated.

**Cross-validator consistency**:
- Verifiers of block N: same block, same traces → same kernel
  reactions → same apply outcomes.
- Proposer of block N: single role; either produces a valid block
  (and verifiers will verify it) or aborts (and no block N is
  proposed from this proposer).

No two validators in the same role reach divergent apply outcomes
given the same inputs.

## The seen-rule

The seen-rule restricts which keys produce mode can sign for: only
keys observed during the current cycle's verify phase.

**Purpose**: ensures subscription consistency. If endpoint k's process
phase signs with key K, then key K must have been visible during
endpoint k's per-event verify phase (i.e., someone sent an event
containing key K's signature, which we verified). This means any
node subscribed to endpoint k has seen key K; they're prepared to
sign for it if they have local authority.

Without the seen-rule, process could "invent" a key K from thin air,
and subscribers might not know about K (no opportunity to subscribe
for K's sigs).

**Mechanism**: kernel maintains per-cycle seen_keys per endpoint.
Per-event verify's attest calls add keys to the set. Per-cycle
process's attest calls check against the set.

**Enforcement timing**: at the attest yield call, kernel checks. If
seen-rule violated in produce mode → kernel faults apply early.

**Why fault is consensus-safe even though only produce mode hits it**:
- Proposer that hits seen-rule violation: apply faults; proposer
  abandons this block (or this event in the block).
- Verifiers don't see this case: they receive whatever block the
  proposer produced; if the proposer dropped the event, verifiers
  see a block without that event; they verify the block as-is.
- No verifier observes a "phantom event that proposer failed on"
  — those events simply don't appear in the produced block.

## Source distinction (without source-passing)

The apply calls `AA.attest(key, blob)`. The same call. But records
carry kernel-applied metadata that distinguishes:

```
Record metadata (kernel-only):
  phase = verify   when the call was made during endpoint.verify
  phase = process  when made during endpoint.process
  phase = apply    when made during chain.apply
```

This is inferred from the kernel's call-stack tracking. At the moment
of the attest yield, kernel knows which endpoint's apply made it.

The phase metadata drives the kernel logic:
- verify-phase records: contribute to seen_keys; never trigger
  signing (verify is per-event acknowledgment).
- process-phase or apply-phase records: subject to seen-rule;
  trigger signing (in produce mode) or sig-checking (in verify mode).

## AA lifecycle

AA is a Cap::Instance minted by kernel and injected into the scratchpad
at the start of each verify or process invocation. AA itself has no
meaningful state — it's a thin façade whose single endpoint
(`attest`) builds Attest request Instances. Since each attest call
yields independently, AA accumulates nothing across calls.

```
For per-event verify (off-chain):
  AA_event = kernel-derive Cap::Instance[AAImage]
             -- image_hash_chain: kernel-bridge → AAImage,
             --   structurally provable as kernel-minted.
  pass AA_event in slot[0] alongside blob and chain_copy
  CALL verify_endpoint
  -- per-attest yields handled inline via the yield mechanism
  -- (kernel sees each Attest, processes mode-aware, returns status).
  drop AA_event

For per-cycle process (off-chain, block boundary):
  AA_cycle = kernel-derive Cap::Instance[AAImage]
  pass AA_cycle in slot[0] alongside events and chain_copy
  CALL process_endpoint
  -- per-attest yields handled inline.
  drop AA_cycle

For on-chain apply_block:
  AA_block = kernel-derive Cap::Instance[AAImage]
  pass AA_block in slot[0] alongside body and chain
  CALL chain.apply
  -- per-attest yields handled inline.
  drop AA_block
```

AA Instances don't persist across these boundaries. They're transient
caps that grant per-invocation attestation authority and are
discarded when their invocation returns.

The image_hash chain for AA Instances:
```
AAImage.image_hash_chain = [kernel-bridge_hash, AAImage_hash]
                         = canonical AA chain prefix
```

A receiver of `Cap::Instance[AA]` can verify canonicity via
`host_same_type` against a chain-spec-known reference. Forgery
prevention: an adversary cannot construct a Cap::Instance with a chain
that begins with kernel-bridge — the chain extension is kernel-
mediated and starts from the genesis kernel.

## Why AA is an Instance at all (vs pure host call)

A pure `host_attest(key, blob)` ABI without an AA Instance would work
mechanically. Why wrap it in a Cap::Instance?

**Cap-flow auditability**: the AA Instance is passed via scratchpad
explicitly. Anyone reading the apply's input knows "this apply has
attestation authority for this cycle". Without the Instance, that
authority is implicit in being CALLed by the kernel.

**Composition**: a chain author wanting to compose attestation
(e.g., wrap with rate-limiting, audit logging, multi-validator
aggregation) can place a wrapper Instance between the endpoint and the
real AA. The wrapper CALLs the canonical AA after applying its
logic. Pure host_attest doesn't compose this way.

**Forgery resistance**: AA's image_hash chain proves canonicity.
A wrapper that claims to be AA but isn't canonical: host_same_type
detects.

**Pinning**: AA Cap::Image can be pinned in chain's slots, ensuring
chain endpoints always have access to the canonical AA reference.

These are real but the cost is small. If we wanted to strip down, a
pure `host_attest()` works too. The AA Instance is the canonical pattern.

## Early-discard semantics

When kernel decides "no point continuing" at an attest yield, apply
is faulted:

```
Kernel.attest yield processing:
  ... mode-aware logic ...
  if decision is fault:
    target Instance transitions to Faulted (cascade)
    apply's CALL returns to its caller with status=Faulted
    apply state is discarded (per fault semantics; sub-tree atomicity)
```

The fault is mode-aware-decided but apply-visible-uniform: apply
just experienced a fault during a yield. Apply doesn't know why
kernel decided to fault.

**Implication for the calling layer**: when chain.apply or
endpoint.process or endpoint.verify encounters a Faulted attest,
it can:
- Treat the entire event/transaction as invalid (drop it).
- Move on to next event (per chain-spec policy).

The fault propagates through cascade just like any other fault. The
caller's apply gets Faulted signal in phi[8] and can decide how to
proceed.

For per-event verify (off-chain): fault means event dropped; not
admitted to buffer.

For per-cycle process (off-chain): fault means... what? The cycle's
process is per-endpoint, processing all admitted events. If one
attest yields and faults, the whole process invocation faults. The
endpoint's process effectively didn't run this cycle. Probably the
chain spec policy is: drop the dispatch's outputs for this cycle.

For chain.apply (on-chain): fault means block invalid.

## Block-level vs event-level attestation

Two distinct concepts in legacy spec, both relevant in v3:

**Block-level attestation_traces**: sigs proposer attached to the
block as a whole. Used for things like the block's Schedule entries
(per legacy 04-kernel-loop).

**Event-level attestation_traces**: sigs included in each event's
payload. Used for verifying incoming events have proper attestations.

Both flow into kernel.current_traces during the relevant context:
- For event verify: event's own traces.
- For chain.apply with block-level traces: block.attestation_traces.
- For chain.apply with Schedule slot: schedule_attestation_traces.

The kernel manages which traces apply at which attest call (based
on context). Apply sees nothing of this.

## BLS aggregation

For aggregation-pattern (sigscheme used by many validators that
combine into one final sig):

```
AA.aggregate(group_key, partial_sig)
  -- declares: "this validator contributes a partial sig to the
  --  aggregate for group_key."
  -- kernel-side processing:
  --   if verify mode: kernel keeps partial sig for verification
  --     against the block's aggregated sig.
  --   if produce mode: kernel collects partials from each
  --     contributing validator; aggregates at post-HALT; attaches
  --     to outgoing block.
```

Same shape as AA.attest: userspace declares; kernel processes per
mode.

(Implementation note: cross-validator aggregation isn't possible
during a single apply pass — it requires coordination across nodes.
Likely the chain spec sets up an aggregation epoch where each node
contributes during its turn, and the aggregate is produced over
multiple blocks. Out of scope for this doc.)

## Cross-chain attestations

External chain's block headers (verified via known external pubkeys):

```
endpoint.apply, processing a cross-chain claim:
  parse external_block_header from blob
  for each (key, sig) in header's sig set:  -- userspace just declares;
                                            -- doesn't see sig
    AA.attest(key, header_hash)
  -- kernel:
  --   verify mode: looks up sig in incoming traces; hw_verify
  --   produce mode: signs with local equivalent (if applicable)
```

External pubkeys live as ordinary chain state (Cap::Data in chain's
cnode); known to chain spec; userspace bytecode references them.
No special cap kind for "external attestation."

## Summary

- AA.attest(key, blob) → AttestStatus is the generic authority
  pattern's request/response cycle: AA builds an Attest request
  Instance, yields up, kernel handles, returns mode-invariant status.
- Userspace sees no mode, no traces, no sig. Just declares a (key,
  blob) and reads back a status enum.
- The status enum is mode-invariant — produce mode and verify mode
  return the same value for the same apply-visible inputs. Consensus
  is structurally safe.
- Kernel processes per-attest at the yield boundary:
  - verify-mode: hw_verify against incoming traces; fault on failure.
  - produce-mode: seen-rule + local-key signing; fault on rule
    violation if local emit needs signing.
- The Attest Instance's inspection endpoint
  (`get_request_for(witness)`) and `fulfill(answer_witness)` both
  use cap-passed witness checks via `host_same_type_as` against
  pinned exemplars. Intermediates routing the cascade cannot mint a
  Instance whose chain matches the exemplar, so they can neither read
  (key, blob) nor fabricate a valid fulfill — V7 confidentiality
  and V6 integrity preserved structurally.
- Early-discard: kernel can fault apply if attest can't be
  satisfied. Saves wasted computation in deterministic-failure cases.
- AA Instance is kernel-derived per cycle/per event; transient;
  image_hash-chain canonical.
- The seen-rule ensures subscription consistency: keys signed for
  must have been observed via incoming verifies in the same cycle.

This is the canonical v3 attestation mechanism. It is one
instantiation of the generic authority pattern documented in
[../userspace/generic-authority-pattern.md](../userspace/generic-authority-pattern.md);
see that doc for the broader request/response Instance structure,
forgery-resistance argument via image_hash chain, and the V1–V9
security analysis.
