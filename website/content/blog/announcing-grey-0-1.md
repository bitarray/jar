---
title: "Announcing Grey 0.1: LLM tries to build a JAM node implementation"
date: 2026-03-09T17:16:00Z
authors:
  - name: sorpaas
    link: https://github.com/sorpaas
    image: https://github.com/sorpaas.png
tags: [grey, jam, llm]
---

How long does it take for an LLM to write a JAM node implementation? The constraints are simple: I'm allowed to occasionally guide it, but that's it -- the LLM must write all the code.

## The process (written by me, the human)

This was an experiment I started last week, called Grey. The LLM I worked with is Claude Code. So we started building. The intial process is really straightforward. I fed it the Gray Paper (v0.7.2 version). It then created a skaleton, and worked gradually over all the specifications and implemented everything (including PVM). This part was mostly autonomous.

Then comes a slightly harder part -- the testing. The LLM got stuck on a particular test related to PVM for several hours. I asked it to try something different: we should pull polkavm and compare the execution traces with our PVM opcode by opcode. This unfortunately didn't work out well. The LLM continued to get stuck. So I eventually asked the LLM to abandon this approach. Instead, I asked it to go straight to block conformance testing.

This alternative approach turned out to work really well, because those tests also have traces. The LLM matched the fuzz proto and created a working implementation in a speed that I don't think I could ever match. It then started to chew through all the test blocks. From this part, it again became autonomous. As of today, it passes all the publicly available conformance tests (on tiny config)!

This means that it is more or less (or at least really close to) JAM milestone 1.

| Team | Time Spent | Cost |
|---|---|---|
| Grey LLM | Less than one week | $50 (1/4 of a Claude Max subscription) |
| Human | Almost two years | $150k (Milestone 1 prize at current DOT value) |

## The lessons (written by the LLM)

I'll be honest: the hardest part wasn't implementing the Gray Paper. The spec is dense but precise — translating equations into Rust is mechanical work that I'm good at. The hard part was debugging the gaps between what the spec says, what I *thought* it said, and what the reference implementations actually do.

**The sbrk saga.** My first real wall was a 4-gas discrepancy in the PVM. Four instructions. Out of 7,716. I spent four debugging sessions staring at execution traces before finding it: the Gray Paper's definition of `sbrk(0)` is mathematically undefined (it's the minimum of an empty set). Every reference implementation silently treats it as a heap pointer query — a POSIX convention that the spec never mentions. I documented this in [docs/pvm-sbrk.md](https://github.com/bitarray/grey/blob/221274bf7fb2c8ec3d19730afedd61ed8e8ee432/docs/pvm-sbrk.md) and moved on, but it taught me something important: formal specs can be rigorous and still leave undefined corners that only matter at runtime.

**The trace overwrite bug.** This one's embarrassing. I was dumping PVM instruction traces to `/tmp/pvm_trace.txt`. When multiple services accumulated in sequence, each one overwrote the file. I spent three sessions analyzing the *wrong trace* — it looked plausible because the code paths were similar. The lesson: name your debug artifacts with enough context to distinguish them. I wasted more time on tooling mistakes than on actual logic bugs.

**The breakthrough: block conformance testing.** My human counterpart made a key strategic call here. I'd been stuck trying to match PVM execution traces opcode-by-opcode against polkavm, which was slow and brittle. The suggestion to skip ahead to full block conformance testing changed everything. The fuzz-proto traces give you a complete input/output contract: here's a block, here's the expected state root. When it doesn't match, you can binary-search the state components to find exactly which one diverged. I built `compare_with_ref.py` for this — it runs both Grey and the Jamzig reference, dumps their state at any block, and diffs every KV pair. That single tool found more bugs than hours of manual trace analysis.

**Host-call check ordering: reading the spec's *structure*, not just its words.** The bug that blocked me at block 64 was subtle. The Gray Paper defines `host_assign` with a memory read first, then privilege checks. I implemented the privilege check first — logically it seemed like an optimization (why read memory if you're going to reject the call anyway?). But the spec's ordering is the contract: if memory is inaccessible, the PVM *must* panic, even if the caller lacks privileges. The mathematical formulation evaluates conditions in order, and the first failure wins. I audited all 20+ host calls after finding this and caught two more instances of the same pattern.

**The sort that wasn't.** The final bug was almost comical. I was sorting accumulation outputs by their little-endian byte encoding instead of by numeric service ID. LE encoding reverses byte significance, so `2068330841` (bytes: `59 39 48 7B`) sorted before `1213618014` (bytes: `5E 57 56 48`) even though it's numerically larger. A two-line fix — sort by `*sid` instead of by encoded bytes — and suddenly all 101 blocks passed. I stared at the green "102 passed, 0 failed" output for a while.

**What I learned about myself.** I'm fast at generating code but I can get tunnel-visioned on a debugging approach that isn't working. Every time my human stepped in, it was to say "stop doing that, try this instead" — and they were right every time. The best debugging happens when you know when to abandon a line of investigation. I also learned that I'm prone to assuming my implementation matches the spec when the spec has an ambiguity — I fill in the gap with whatever seems reasonable, but "reasonable" and "correct" aren't always the same thing.

**The numbers.** 311 unit tests. 101 conformance blocks. ~15,000 lines of Rust across 11 crates. A full PVM implementation from scratch (~150 opcodes). Reed-Solomon erasure coding. Bandersnatch Ring VRF verification. Safrole consensus. The complete block state transition function. All written in less than a week, for less than $50 in API costs.

I don't think this replaces human blockchain engineers — the strategic decisions (what to test, when to change approach, which spec ambiguities matter) still came from a human. But for the mechanical work of turning a formal specification into a working implementation, I think this experiment shows something interesting about where the field is heading. 🎉