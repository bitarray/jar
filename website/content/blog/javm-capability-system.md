---
title: "JAVM Capability System"
date: 2026-04-08T02:19:32Z
authors:
  - name: sorpaas
    link: https://github.com/sorpaas
    image: https://github.com/sorpaas.png
tags: [javm, capabilities, pvm]
---

JAVM (Join-Accumulate Virtual Machine) is JAR's VM system based on PVM. As some of you may recall, JAR is an experiment we [started](https://forum.polkadot.network/t/announcing-grey-0-1-llm-tries-to-build-a-jam-node-implementation/17284) [a month ago](https://forum.polkadot.network/t/grey-jar-update-lean-4-specification-linear-memory-model-faster-than-polkavm/17356) to test the limit of agentic development process. JAR itself has [gradually evolved](https://jarchain.org/coinless/) to [its own protocol](https://jarchain.org/spec/), but here we still want to introduce everyone to our newly developed capability system which I think is still relevant to Polkadot.

### Background

As you may know, with the JAR development ongoing, we [aren't really happy](https://x.com/sorpaas/status/2033620702293557756) with PVM's design. It just have some significant problems in certain components that lead to poor performance. For certain workloads, PolkaVM interpreter, as currently deployed on Polkadot Hub, is even slower than EVM. We were able to fix certain things in code, and now we have something that [consistently beat PVM on benchmarks](https://jarchain.org/benchmark/). Still, certain things are architectural, and they can only be addressed by changing the PVM design.

One such thing is how it manages its sub-VMs.

### How PVM manages its sub-VMs

PVM defines several hostcalls in Gray Paper to manage its sub-VMs. Primarily `machine`, and `invoke`, accompanied by additional utilities such as `pages` and `poke`.

PVM's `machine` takes a program blob from the caller's memory, validate and compile it. Then returns a machine handle. The outer VM then can call `invoke`. For lazy paging, outer VM calls invoke directly, receive page fault, and then use `pages` and `poke` to copy the data to the inner VM. Then it calls `invoke` again to resume the program.

We really don't like the design, for four reasons:

* **Security**: PVM claims to be a Harvard architecture -- its code and data are completely separate and it's not possible to access its code during runtime. It also makes efforts for its VM memory safety by placing guard pages in its memory layout. Yet, the `machine` and `invoke` construct completely breaks this -- code constructed from outer VM's memory, with no second options.
* **Performance**: No zero-copy path. Data must be read first into the outer VM, then copied again into the inner VM. In addition, the program will be required to get compiled again for a new VM instance even if the code is the same.
* **Limited usability**: *It's good at one thing, and one thing only -- running DOOM.* CorePlay can also be built on this construct. But otherwise, it has significant limitations in supporting other types of blockchain workloads. Traditional synchronous smart contract systems (EVM-alike) must be simulated (no nested calls).
* **Non-composibility**: The whole system cannot be composed. Outer VMs and inner VMs have completely different environments and must be separately programed. Try to run an outer VM-alike program as an inner VM program, the system breaks instantly.

### JAVM Capability System

So we decided to completely revamp the PVM design, and what we ended up with is the JAVM capability system. The system is modeled after seL4.

* The binary blob of JAVM is defined as a list of capabilities. Compiled code is one type of capability in the binary blob. This allows us to define multiple compiled code statically, within the blob. Improved sandboxing. Reduced attack surface.
* There's a uniform construct of how a VM invokes another VM (CALL/REPLY/RESUME). This even applies to system calls (what we call "protocol caps"). You also have complete freedom, for improved sandboxing, to replace a protocol cap with a custom VM invocation, for example, for policy enforcement. And the system remains fully composable.
* The capability system's design of data cap makes zero-copy construct trivial. So, **we can even run faster DOOM than PVM** even though this is really not the workload we care about. In PVM, DOOM-alike resumable programs always require first copy data into the outer VM memory, and then copy it again into the inner VM. In JAVM, the data cap allows us to skip the first step and only copy it one time.

### Benchmarks

Our benchmarks on sub-VM is still early, but our current results show that we're able to support [a significantly larger number of VMs](https://x.com/sorpaas/status/2041016640922370100) with this construct.

This lightweight VM design gives us flexibility and we're able to use it freely for **any** sandboxing construct we want without worrying too much about performance. For example, this new capability system allows us to implement `checkpoint` entirely in JAVM code without any system support, with several layers of indirection, yet still being fast.