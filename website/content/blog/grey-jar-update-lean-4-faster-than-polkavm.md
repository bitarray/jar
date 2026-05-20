---
title: "Grey / JAR Update: Lean 4 specification, linear memory model, faster than PolkaVM"
date: 2026-03-22T06:55:25Z
authors:
  - name: sorpaas
    link: https://github.com/sorpaas
    image: https://github.com/sorpaas.png
tags: [grey, jar, lean, pvm]
---

[Grey](https://github.com/jarchain/jar/tree/master/grey) is an experiment for an LLM agent to write a JAM node implementation. You can read the initial announcement [here](https://forum.polkadot.network/t/announcing-grey-0-1-llm-tries-to-build-a-jam-node-implementation/17284).

Here are some updates I would like to report on behalf of Grey.

### Lean 4 formalization

We created the project [JAR](https://github.com/jarchain/jar). JAR is a Lean 4 formalization of the JAM protocol. Doing this would allow us to cross-check Grey's implementation with JAR, and vice versa. JAR also contains its own testing framework, fuzzing framework, as well as a "variant" system to support multiple specifications.

We do this because we want to evolve the specification independently -- try out new things, and get an "optimal protocol specification" that is faster than JAM. The "variant" system then allows us to keep testing against old versions, so that we know that whatever improvements we do, we won't break things.

### Linear memory model

In JAR's `jar080_tiny` specification, we implemented an experimental linear memory model. Linear layout packs all data into a single contiguous RW region at address 0:

```
  [0, s)                     stack (SP = s, grows toward 0)
  [s, s + |a|)               arguments
  [s + |a|, s + |a| + |o|)   RO data
  [s + |a| + |o|, ... + |w|) RW data
  [... + |w|, heap_top)       heap
```

No guard zone, no read-only pages, no zone alignment gaps. We think those are unnecessary -- the benefits to protocol security or even the PVM program correctness is entirely marginal.

The linear memory model allows us to do certain optimizations that is really close to native, even without requiring signal handlers. And we generally just like the simplicity of it.

### Grey is really fast, faster than PolkaVM!

In our benchmarks, we now beat PolkaVM consistently with pipeline gas metering. This includes secp256k1 ecrecover, a known bottleneck for some JAM teams building EVM services on top of JAM. For this, we're around 1.4x faster.

Some architectural design of PolkaVM is really just incorrect. For example, we're 36x faster than PolkaVM (Linux sandbox) on the hostcall benchmark.

For up-to-date numbers across all workloads, see the [benchmark page](/benchmark/).

To my surprise, Grey did write certain novel improvements. There's at least one optimization in Grey that I know is NOT available anywhere else. Exactly which one that is, I invite the readers to check out the codebase!