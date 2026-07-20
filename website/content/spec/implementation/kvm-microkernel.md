# Nub: the KVM-microkernel architecture

A design doc for moving javm into a long-running microkernel
running under KVM (or any equivalent hardware-virtualization
substrate) — with chain state σ resident entirely in the guest.
The microkernel is named **`nub`**.

The current v3 implementation track ([architecture.md](architecture.md))
continues independently. This doc covers the alternative
architecture that's been promoted past prototype.

## Status (2026-05)

- **Stage 0 (this doc).** Complete: design and decision gates
  written down.
- **Stage 1 (prototype).** Complete: a 5-commit Hyperlight + ring-0
  spike validated every architectural gate (ring 0, long mode,
  custom IDT, in-guest `#PF` handling, CR3 manipulation, CoW
  round-trip) on the i9-13900K target hardware. Measured numbers
  are recorded against the gate table below. The build-system
  spike also passed: stable rustc + `x86_64-unknown-none` + a
  one-shot `RUSTFLAGS` recipe drives the bare-metal guest build
  without `cargo-hyperlight`, custom target JSONs, or picolibc.
- **Crate skeleton.** Complete: `nub`, `nub-kernel`,
  `nub-arch-local`, `nub-arch-hyperlight`, `nub-build` are
  scaffolded with the `Arch` trait wired through both backends.
  See [§Crate layout](#crate-layout-as-of-stage-1).
- **Naming since Stage 0.** The doc was originally written around
  a "HAL" trait (hardware abstraction layer) with concrete impls
  named `HyperlightHal` / `PlainMemHal` / `PciSocHal`. The
  implementation calls the trait `Arch` instead — matching
  Linux's `arch/x86`, `arch/arm64` convention — and the impls
  are named `nub-arch-hyperlight` / `nub-arch-local` /
  `nub-arch-pci-soc` (the last still speculative). The body of
  this doc has been updated in place; a couple of mentions of
  the legacy "HAL" name remain where they refer specifically to
  the original Stage 0 sketch.

The rest of this doc retains the Stage 0 design analysis as
written (it held up under prototyping), with [§Crate layout
(as of Stage 1)](#crate-layout-as-of-stage-1) and [§Arch trait
design](#arch-trait-design-after-stage-1) capturing decisions
made during the prototype that the original design didn't have.

## Why this is worth exploring

Three threads converge on the same answer.

**(a) Memory management.** The host-userspace track invents a lot
of OS-shaped machinery for cheap cap copy and per-Instance memory
management — per-DataCap memfds with `MAP_PRIVATE` CoW, an
LSM-shard overlay model, userspace page-fault tricks (uffd / signal
handlers), a per-thread pool of 4 GiB `FlatMemory` mmaps, a
write-back protocol on unmount. Each piece is tractable. The
aggregate is several KLoC reimplementing what a real OS gives us
natively. In ring 0 with our own page tables, the whole stack
collapses into "set a CoW bit, install a `#PF` handler."

**(b) Security: no JIT in the host process.** The PolkaVM project
explicitly identified untrusted JIT'd code running in the same
process as the chain client as a hard problem — they ended up
sandboxing the JIT in a separate child process. We rejected that
for JAVM because the hostcall round-trip cost was unacceptable.
A microkernel solves both: the JIT runs inside a hardware-isolated
guest, and most "hostcalls" don't have to cross out to the host
at all (the guest carries the cap manager, σ, the canonical
encoder, the state-root computation).

**(c) Portability.** Today's recompiler is gated
`cfg(all(target_os = "linux", target_arch = "x86_64"))` —
unavailable on macOS, Windows, BSD. Routing the recompiler through
a hypervisor abstraction (KVM on Linux, Hypervisor.framework on
macOS, WHP on Windows) *expands* coverage to all those platforms,
not contracts. See *End-state architecture* below.

The `mgmt_copy` O(1) property we want is provable in both the
userspace and microkernel models (see below). The decision isn't
"is it theoretically possible," it's "which model is the cleaner
engineering bet over the next 5 years."

## End-state architecture: Arch → nub → nub-exec

Three layers, like a real OS:

```
┌──────────────────────────────────────────┐
│  nub-exec  (interpreter + recompiler)   │  ← execution backends
├──────────────────────────────────────────┤
│  nub  (the microkernel)                  │  ← cap manager, σ-filesystem,
│  (cap mgmt, state root, scheduler, the   │     IDT/page-table mgmt, JIT cache,
│   interpreter, page-fault handler)       │     port. across all Arch impls
├──────────────────────────────────────────┤
│  Arch  (CPU/MMU substrate)               │  ← swap per deployment target
└──────────────────────────────────────────┘
```

The kernel (`nub-kernel`) is **portable Rust, `no_std`**. It runs
unchanged on whatever "hardware" the `Arch` implementation
exposes. The `Arch` trait abstracts: physical memory, vCPU
control, host-callback ABI, page-fault notification. Everything
else is inside the kernel.

This is the same factoring Linux's `arch/`, NetBSD's MI/MD split,
Plan 9's portation discipline use. We get its benefits: one
correctness story, one performance story, one set of tests.

### Arch trait sketch (Stage 0 shape)

```rust
// crates/nub-kernel — pure no_std, no platform deps
pub trait Arch {
    // Memory management — Arch owns physical pages
    fn alloc_pages(&mut self, n: usize) -> Result<GuestPhysPage>;
    fn free_pages(&mut self, base: GuestPhysPage, n: usize);
    fn map_region(&mut self, /* address, perms, flags */) -> Result<()>;

    // vCPU control — what "running" means varies by Arch
    fn run_until_yield(&mut self, /* entry, regs */) -> ExitReason;

    // Host callbacks — what "asking the host" means varies by Arch
    fn read_blob(&mut self, hash: [u8; 32]) -> Result<Bytes>;
    fn write_blob(&mut self, bytes: &[u8]) -> Result<[u8; 32]>;
    fn host_notify(&mut self, event: HostEvent);
}
```

The post-prototype shape is more refined; see
[§Arch trait design (after Stage 1)](#arch-trait-design-after-stage-1).

### Three Arch implementations

| Arch | Substrate | nub-exec backend | Deployment target |
|---|---|---|---|
| **`nub-arch-hyperlight`** | KVM / Hyper-V / WHP, guest ring 0 long mode | **Recompiler** (in-guest JIT) | Linux/macOS/Windows/BSD with hardware virt |
| **`nub-arch-local`** | Plain Rust, runs in the host process | **Interpreter only** (no JIT — see below) | Any platform; portable fallback |
| **`nub-arch-pci-soc`** (future) | ARM SoC or FPGA on PCIe; nub cross-compiled to device arch | Recompiler (device-resident JIT) | Validators with execution-accelerator hardware |

**Why the Arch determines the nub-exec backend.** The recompiler
emits and executes native code; it requires hardware isolation
from the host process to avoid the JIT-injection security
property we want. So an Arch with hardware isolation
(`nub-arch-hyperlight`, `nub-arch-pci-soc`) can run the
recompiler safely. The `nub-arch-local` doesn't have an isolation
boundary — JIT'ing native code there means executing
untrusted-derived code in the host process, the exact thing we're
avoiding. So `nub-arch-local` exposes only the interpreter.

### The cross-Arch determinism invariant

The same `(prior_root, block)` input must produce byte-identical
`new_state_root` regardless of which Arch/nub-exec combination
ran the block. Validators on different deployment targets must
not diverge in consensus. This is **the load-bearing correctness
condition** for the multi-Arch deployment story; it's the same
property as cross-backend equivalence (interpreter vs recompiler)
but now also applies across hardware substrates.

Verified via property test: corpus of blocks, run through each
Arch × backend combination, state-roots compared. Already the
shape of `pvm_bench`'s gas-match assertion; promote to a hard
correctness gate.

### `nub-arch-hyperlight`: portability matrix

Hyperlight already abstracts the per-OS hypervisor:

| Host OS | Hypervisor API | Recompiler available? |
|---|---|---|
| Linux | KVM | Yes (works today) |
| macOS | Hypervisor.framework | **Yes** (on Hyperlight roadmap) |
| Windows | WHP (Windows Hypervisor Platform) | **Yes** (Hyperlight ships this) |
| FreeBSD | bhyve | **Yes** (we'd add this layer) |

The remaining portability constraint is **host CPU arch**: the
hypervisor only runs guests targeting the host's CPU, so per-arch
JIT codegen (x86-64 today; ARM64 for Apple Silicon/Graviton
later) is still our responsibility. This is the same cost we
already accept for the userspace recompiler today.

### `nub-arch-hyperlight`: nested-virt caveat in cloud

Some cloud VMs don't expose hardware virt to tenants, or charge
for it as a premium (AWS metal SKUs only without paid nested-virt;
GCP preview; Azure SKU-restricted). Validators in such
environments fall back to `nub-arch-local` (interpreter only) —
slower but functional. The cross-Arch determinism invariant is
what makes this safe.

### `nub-arch-pci-soc`: the future-proofing story

The Arch trait is the natural seam for execution-accelerator
hardware: a dedicated ARM SoC or FPGA on PCIe running the
microkernel as its firmware. The same microkernel source
cross-compiles to the device's arch; the Arch impl talks to the
device over PCIe instead of KVM.

Sketch of the protocol:

- Host writes commands to a PCIe BAR (command ring in MMIO).
- SoC receives, runs the microkernel, returns results via a
  result ring.
- Bulk transfer (cap blob fetch/write) uses DMA between host
  RAM and device memory.
- Host-side API is unchanged: `kernel.apply_block(prior_root,
  block)` returns `(new_root, deltas)`.

This is the same architectural pattern Ethereum's prover-
acceleration designs and Aptos's parallel-exec accelerators are
exploring. The fact that we accommodate it as an Arch swap, not a
rewrite, is a real win — but **purely future-proofing**. Not on
the implementation roadmap today.

### Custom compile target: a possibly-avoidable friction

Hyperlight today defaults to a custom Rust target spec
(`x86_64-hyperlight-none`) plus a `cargo-hyperlight` subcommand
plus picolibc for C dependencies. That's significant build-system
surface.

Our microkernel is pure Rust (no C deps). For pure-Rust guests,
most of what the custom target packages can be supplied via
`RUSTFLAGS` on top of **`x86_64-unknown-none`** — stable since
Rust 1.71 (August 2023). Linking against `hyperlight_guest` (the
no-libc layer of Hyperlight's guest crates) directly, without
`hyperlight_guest_bin` (the picolibc layer), should let us drop
the custom-target/cargo-hyperlight/picolibc stack.

A Stage 1 spike confirms: if `cargo build --target=x86_64-unknown-none`
with the right `RUSTFLAGS` produces a Hyperlight-loadable ELF, we
keep the friction at "supply a few linker flags." If it doesn't,
we wear the custom-target cost; not the end of the world but
worth knowing.

## Crate layout (as of Stage 1)

Today's workspace shape:

```
rust/
├── nub/                      lib  — caller-facing `Nub` handle
├── nub-kernel/               lib  — Kernel<A: Arch> + Arch trait + interp
├── nub-arch-local/           lib  — in-process Arch (software-copy memory)
├── nub-arch-hyperlight/      bin  — Hyperlight Arch (bare-metal guest, no_std + no_main)
├── nub-build/                lib  — cross-compile helper for bare-metal arch guests
│
├── javm-interpreter/         lib  — PVM interpreter, no_std (lifted from nub-exec)
├── nub-recompiler-x86/      lib  — x86_64 PVM recompiler (lifted from nub-exec)
│
└── jar-apply/                lib  — block-apply, gas, quota; built on Nub (future)
```

Dependency edges:

- `nub-kernel` depends on `javm-interpreter` (the interp is
  portable, lives with the kernel, runs against any
  `Arch::Memory`).
- `nub-arch-hyperlight` depends on `nub-kernel` +
  `nub-recompiler-x86` (the recompiler is hardware-locked to
  x86_64 + real pages, lives only with Arch impls that can run
  it).
- `nub-arch-local` depends only on `nub-kernel`.
- `nub` depends on `nub-kernel`, `nub-arch-local`, and (via
  `build.rs`) `nub-arch-hyperlight` as a guest blob.
- `jar-apply` (future) depends on `nub`.

Today's `nub-exec` crate is slated to split into
`javm-interpreter` + `nub-recompiler-x86` to make the
no_std-vs-x86-only boundary explicit. Until that split lands,
`nub-kernel` and `nub-arch-hyperlight` consume `nub-exec`
selectively via feature gates.

`nub` (the entrypoint crate) exposes a single uniform handle:

```rust
pub struct Nub { /* enum over backends */ }

impl Nub {
    pub fn new_local() -> Self;
    pub fn new_hyperlight() -> Result<Self>;
    pub fn invoke(&mut self, target: InstanceRef, endpoint: Key,
                  args: &[u8], opts: InvokeOptions) -> Result<InvokeOutcome>;
    pub fn state_root(&self) -> CapHash;
}
```

For the in-process backend, `Nub` owns a `Kernel<LocalArch>`
directly. For Hyperlight, `Nub` holds a sandbox and ships the
invocation as RPC; the *real* `Kernel<HyperlightArch>` lives
guest-side. Both expose the same surface.

## Arch trait design (after Stage 1)

The original Stage 0 `Hal` sketch put memory and vCPU primitives
on the trait. After working through how the interpreter and
recompiler actually interact with memory, the design splits
along two orthogonal axes:

1. **Execution mode**: interpreter vs recompiler.
2. **Memory mode**: hardware-paged (real CR3/PTE, CoW via `#PF`)
   vs software-copy (page table simulated in Rust, CoW via
   memcpy).

The recompiler is *hardware-locked*: it emits native x86_64
loads/stores, so it only works with hardware-paged memory. The
interpreter is portable: it can go through either memory mode.
This determines where each piece lives:

- **Interpreter → `nub-kernel`.** Shared across all Arch impls,
  parameterized over `A::Memory`. Same source compiled for both
  the host process (over `LocalArch::Memory`) and the bare-metal
  guest (over `HyperlightArch::Memory`).
- **Recompiler → outside `nub-kernel`.** It's CPU-arch-specific
  (today x86_64) and memory-mode-specific (hardware only). Lives
  in `nub-recompiler-x86`, consumed only by
  `nub-arch-hyperlight`. Future ARM Arch impls would consume a
  hypothetical `nub-recompiler-aarch64`.

The Arch trait grows accordingly:

```rust
pub trait Arch {
    type Memory: Memory;
    type Error;

    /// Create a fresh address space (working memory for one
    /// invocation). The returned `Memory` is hardware-paged or
    /// software-copy depending on the Arch impl.
    fn create_address_space(&mut self) -> Self::Memory;

    /// Drive the kernel-supplied interpreter via `A::Memory`.
    fn invoke(&mut self, target: InstanceRef, endpoint: Key,
              args: &[u8], opts: InvokeOptions)
              -> Result<InvokeOutcome, Self::Error>;

    /// Recompiler dispatch — jumps into JIT'd code. Only
    /// hardware-paged Arches implement this meaningfully;
    /// software-paged Arches return Unsupported.
    fn enter_native(&mut self, /* entry, regs, memory */)
                    -> Result<ExitReason, Self::Error>;

    fn state_root(&self) -> CapHash;
}

pub trait Memory {
    fn read_u8(&self, vaddr: u64) -> Result<u8, MemFault>;
    fn write_u8(&mut self, vaddr: u64, b: u8) -> Result<(), MemFault>;
    // u16/u32/u64 width ops (or generic-over-width)
    fn map(&mut self, vaddr: u64, size: u64, perms: Perms);
    fn set_perms(&mut self, vaddr: u64, perms: Perms);
    fn cow_fork(&self) -> Self;
    // …
}
```

Both `Memory` ops must inline cleanly to a hardware load/store
on `HyperlightArch::Memory` (where the kernel runs in the same
address space the program runs in) and to a sparse-vec/BTreeMap
lookup on `LocalArch::Memory`. Width-specific methods + careful
inlining keep the per-instruction interpreter cost competitive
with a non-traited interpreter.

The skeleton (as of Stage 1) only exposes `invoke` + `state_root`
on `Arch`; `type Memory` and `enter_native` will land alongside
the `javm-interpreter` port into `nub-kernel`.

## Kernel runtime: collections + RNG

`nub-kernel` is a real kernel — `no_std`, no host runtime to lean
on. Two design decisions worth pinning:

**Collections — `BTreeMap` everywhere by default.** Replay
determinism is load-bearing for the chain. `HashMap`'s
seed-dependent iteration order is a footgun: the moment any
state-bearing decision touches iteration, two nodes with
different seeds diverge. `alloc::collections::BTreeMap` is
no_std-clean, deterministic by construction, and `log n` lookups
are fine for the sizes the kernel touches. `HashMap` (via
`hashbrown`) earns its keep only for **non-state caches** with
adversarially-supplied keys; those use an explicit
DoS-resistant `BuildHasher` seeded from the kernel's CSPRNG.
Iteration over a `HashMap` anywhere on a state-affecting path is
a bug.

**RNG — host-seeded, in-kernel CSPRNG.** A 32-byte seed is pulled
from the host at kernel boot and never replaced; the kernel runs
a ChaCha20 CSPRNG (`rand_chacha`) downstream. The seed source
per Arch:

- `LocalArch`: from `getrandom` (host process entropy).
- `HyperlightArch`: the host shoots 32 bytes into a known
  shared-memory slot before the first guest call; the guest reads
  it during kernel init. Not RDRAND/RDSEED — host-injection is
  auditable and reproducible-when-replayed.

A single `SecureRng` and a `KernelBuildHasher` (SipHash-13 seeded
from one CSPRNG draw) are kernel globals. Per-node hasher seeds
are fine — different validators can have different hasher seeds
as long as iteration over hashmaps is never observable in state.

Deps for `nub-kernel`:

```toml
hashbrown   = { version = "0.14", default-features = false, features = ["ahash", "inline-more"] }
siphasher   = { version = "1", default-features = false }
rand_core   = { version = "0.6", default-features = false }
rand_chacha = { version = "0.3", default-features = false }
```

(Not yet wired; lands with the `KernelSeed` plumbing through
`Kernel::new`.)

## The shape

The descriptions below are written against `nub-arch-hyperlight` —
the target we'd actually implement first. `nub-arch-local` is the
degenerate case where most of these structures live in the host
process directly; the API surface is identical.

**Long-running microkernel.** One microvm per validator process,
spawned at startup, kept alive until shutdown. Pay the boot cost
**once** — even 100 ms is fine because it's amortised across
millions of blocks. JIT-compiled code, hot caps, and σ working set
all persist across blocks.

**Host (thin):**

- Spawns the microvm at process startup.
- Exposes a **virtio-blk** device backed by host storage — the
  guest formats and owns it. The host treats σ as opaque bytes;
  it does not parse or interpret the chain state.
- Exposes a network/IPC channel (virtio-net or a callback-style
  host function ABI) for block ingress, peer egress, and
  external-API routing.
- Forwards messages: "here's a block, apply it" → guest;
  "external client wants Y" → "call endpoint Y on Cap::Instance Z"
  → guest.
- Supervises the VM: restart on crash, replay from disk.

**Guest (heavy):**

- Single ring-0 function: `apply_block(prior_root, block) →
  (new_root, deltas)`. Stateful (retains JIT cache, cap working
  set, page tables) but pure externally (same inputs → same
  outputs).
- In-guest cap manager: refcounts cap objects, manages
  page-table-level CoW on `mgmt_copy`, LSM-shard storage for
  DataCaps.
- In-guest σ filesystem: content-addressed store on the
  virtio-blk device. LSM-tree shape (matches DataCap shard
  semantics). All cap encode/decode is guest-only.
- Recompiler + interpreter, both guest-resident.
- A minimal IDT entry for `#PF`, handling CoW write-faults
  in-guest at ring 0.

**Per-call flow:**

1. Host forwards `apply_block(prior_root, block)` into the guest
   (Hyperlight-style host-callable function).
2. Guest's cap manager locates `Instance[Chain]` (already in
   memory from previous block, or reloaded from virtio-blk on
   startup).
3. Guest runs each event: spawns a sub-Instance call, executes
   via JIT or interpreter, harvests mutations.
4. After all events: walk the mutated subtree, recompute hashes
   bottom-up (Merkle re-root), produce `new_state_root`.
5. Write new blobs to the in-guest filesystem (which writes
   through to virtio-blk → host disk).
6. Return `(new_root, summary)` to host.

Sub-Instance isolation is at the **PVM level** (bounds-checked
memory, gas-metered execution), not the hardware level. Hardware
isolation between sub-Instances would be overkill — the PVM is
already the sandboxing boundary. So sub-Instance "calls" are
function calls inside the recompiler's dispatch, no process
switch, no CPL transition.

## Provability: O(1) `mgmt_copy`

The original motivating question. The answer is **yes, provable**,
and the proof doesn't actually require KVM — the userspace
LSM-shard model already proves it constructively. KVM doesn't add
new theoretical capability for O(1) copy; it strengthens the
constants and the architecture.

**Userspace proof.** Every mutable cap kind is `Arc<Inner>`.
`Clone` is one atomic refcount bump. Mutations route through
`Arc::make_mut`. All amortised cost moves to *first observation
after copy*; none lands on the copy itself.

**Microkernel proof.** Cap structures live in microkernel-managed
objects with refcounts. `mgmt_copy` is a microkernel primitive
that bumps the refcount and marks DataCap page-table entries CoW.
Hardware does the rest: subsequent writes fault, handler allocates
fresh physical page, remaps writable. Constant-time work per
`mgmt_copy`, regardless of cap size.

The proof is one paragraph in either model. We can ship it as a
design-doc paragraph today; implementation choice is independent.

## Performance gains from ring-0 execution

Estimates for what the microkernel-resident recompiler buys *over
and above* the security and architecture wins:

| Gain | Mechanism | Estimated impact |
|------|-----------|------------------|
| **Eliminate JIT bounds checks** | Rely on hardware `#PF` for OOB instead of emitted `cmp/jmp` per memory op | ~30% on memory-bound workloads |
| **In-guest CoW page fault** | `#PF` → in-guest IDT handler → fix → `iretq`; no SIGSEGV | ~10× per CoW fault (10 µs → 500 ns) |
| **Huge pages for code + data** | Ring 0 controls page tables; 2 MiB/1 GiB pages easy | 10–30% TLB savings on memory-heavy code |
| **No scheduler preemption** | vCPU runs until VM-exit; no Linux preempting mid-loop | Tail-latency improvement, throughput similar |
| **W^X dance elimination** | RWX pages allowed in ring 0; no `mprotect` after emit | Tens of µs per JIT compile |

Combined: **10–30% steady-state speedup on existing `pvm_bench`
workloads**, dominated by bounds-check elimination and TLB
improvements. The CoW fault speedup is huge per-fault but only
matters in proportion to how often we fault.

**The flip side — VM-exits to the host:**

When the guest needs to call out (e.g., write a block to disk via
virtio-blk completion), it's a VM-exit + handler + VM-resume,
~1 µs round-trip. Today's equivalent inside the host process is a
function call (~5–10 ns).

But: with σ entirely in-guest and the cap manager guest-resident,
most "would-be hostcalls" don't need to cross out at all.
Cap manipulation, `mgmt_copy`, sub-Instance call, JIT compile —
all in-guest, no exit. The crossings that remain are:

- virtio-blk completion (disk I/O) — already async; one exit per
  block batch, not per byte
- virtio-net traffic — bulk; not in the hot path of execution
- External-API endpoint dispatch — one exit per external query

Net: the VM-exit cost is bounded by the *real I/O frequency*, not
by the *cap-operation frequency*. This is exactly the property
PolkaVM was looking for and didn't get with separate-process
sandboxing.

## The hard parts to validate

If we do pursue this, the design questions Stage 0 needs to
answer. Failure on any one is a reason to stop.

### 1. In-guest σ filesystem

σ is content-addressed: keys are 32-byte hashes, values are
canonical-encoded cap bytes. The guest stores σ on its virtio-blk
device. The natural shape: an LSM-style content-addressed store —
incoming writes append to a fresh shard, background compaction
merges old shards. This matches the DataCap-shard semantics
exactly; same compaction discipline applies.

Reference designs are everywhere (RocksDB, Pebble, LMDB-style
B-trees). Pick the smallest one that works. Estimated size: ~1–2
KLoC of guest code, including a tiny journal for crash
consistency.

**Risk:** crash consistency. If the guest dies between writing a
block's deltas and writing the new state-root, we need to recover
cleanly. Standard journal+commit pattern; well-understood.

### 2. Working-set cache + eviction

Long-running guest accumulates state. When memory pressure rises,
cold caps must spill back to virtio-blk and free their guest
physical pages. Reload on next access via the filesystem layer.
Same shape as a database buffer pool.

**Risk:** unbounded growth if eviction policy lags. Need an
LRU-style policy with explicit memory budget. Probably tunable
via configuration: how much guest RAM dedicated to cap cache.

> **Not the consensus eviction.** This LRU is the host's
> *content-addressed storage* buffer pool (which immutable cap blobs
> stay resident in guest RAM vs. spill to virtio-blk). It is
> **consensus-invisible**: a miss just reloads identical bytes from
> disk, and it never re-triggers a memory-materialization (#3) gas
> charge. It is distinct from the *execution memory-mapping* eviction
> that gas metering depends on, which is **deterministic** — driven by
> `MGMT_MOVE`/`MGMT_DROP` on unpinned mapped slots, never by cache
> pressure (see [gas-cost.md §3](../gas-cost.md)). Keep the two layers
> separate: LRU is fine for the storage cache, forbidden for execution
> mappings.

### 3. In-guest cap representation

The userspace-track cap structures (`Arc<InstanceInner>`,
`Arc<DataCapInner>` with shards) translate to in-guest objects
with microkernel-managed refcounts:

- `Arc<T>` ⇒ microkernel-refcounted handle.
- `Arc::make_mut` ⇒ microkernel CoW primitive: bump-and-clone the
  object metadata, mark page-table entries CoW.
- `im::OrdMap` ⇒ persistent map against the microkernel allocator
  (the `im` crate works `no_std`).
- DataCap shards ⇒ refcounted sets of guest physical pages;
  "mount" inserts page-table entries into the recompiler's
  address space.

### 4. State-root computation

Standard Merkle re-root. Each cap object has a cached hash;
mutation invalidates; root request walks the cap graph
bottom-up, recomputing for invalidated nodes only. Deterministic
iteration order (sorted by key) is required throughout.

For a block that mutates K caps, re-root walks `O(K · depth)`
nodes. Typical: <100 hash computations per block, sub-millisecond.

### 5. Microkernel determinism

Validators on different hosts (and on the same host with different
backends, interpreter vs recompiler) must produce byte-identical
`new_state_root` for the same `(prior_root, block)`. Requirements:

- **Deterministic allocator.** Cap encoded form depends only on
  protocol-defined content, not on allocation order.
- **No host-time observable.** Guest never branches on wall-clock
  or anything else the host can vary.
- **Deterministic iteration.** All collection traversal during
  state-root computation is sorted by protocol-defined key.
- **Identical JIT codegen.** Recompiler is deterministic today;
  property preserved in the guest.

None of these are novel. They are the standard discipline every
blockchain validator already follows. The microkernel doesn't add
new constraints; it just requires the discipline to apply to the
entire microkernel binary, not just the cap layer.

**Cross-Arch × cross-backend invariant.** Every Arch × backend
combination (`nub-arch-hyperlight` + recompiler, `nub-arch-local` +
interpreter, future `nub-arch-pci-soc` + recompiler) must produce
identical `new_state_root` for the same `(prior_root, block)`.
Verify via property test: corpus of blocks, run through each
combination, state-roots compared. Same shape as `pvm_bench`'s
gas-match assertion; the multi-Arch model promotes it from
benchmark sanity to a hard correctness gate.

### 6. Commit/rollback semantics

When a block is applied but not yet committed by network consensus,
the guest needs the ability to roll back. Two natural options:

(a) **`mgmt_copy` the chain Instance before applying.** The
existing CoW machinery handles the snapshot. On commit, drop the
old copy; on rollback, drop the new one.

(b) **Host buffers blocks until consensus accepts.** Only commit
once accepted. Simpler if the chain client already does this.

Both work. Probably (a) — the cap manager already has the
machinery, and it lets the guest pipeline speculation.

## Exploration plan

If the design doc clears review, the prototype proceeds in stages.
Each stage has a decision gate; we stop if the gate fails.

| Stage | Goal | Output | Time |
|-------|------|--------|------|
| 0 | This design doc | Written spec; open questions identified | **done** |
| 1 | Arch trait + boot prototype | Sketch the `Arch` trait. Build a minimal `nub-arch-hyperlight` impl: boots a guest, exposes one host-callable function, calls back to host. Also: confirm `x86_64-unknown-none` works as the compile target. Measure per-call latency, host-callback round-trip, in-guest `#PF` round-trip. | **done** (5 commits, ~1 week; all gates passed) |
| 1.5 | Crate skeleton | Lift the prototype into proper crates: `nub-kernel`, `nub-arch-local`, `nub-arch-hyperlight`, `nub`, `nub-build`. Define the `Arch` trait and `Nub` handle. Stub `invoke` / `state_root` on both backends to prove the boundary end-to-end. | **done** (5 commits) |
| 2 | σ filesystem + interpreter through `nub-kernel` | Split `nub-exec` into `javm-interpreter` (no_std, depended on by `nub-kernel`) and `nub-recompiler-x86` (x86-only, depended on by `nub-arch-hyperlight`). Wire `javm-interpreter` through `Kernel<A>::invoke` over `A::Memory` for both Arches. Implement LSM-style content-addressed σ store inside the kernel; port cap encode/decode. Assert post-state root matches host-replay across both Arches. | 1 month |
| 3 | Recompiler in-guest, delete standalone host JIT | Wire `nub-recompiler-x86` through `nub-arch-hyperlight` (via `Arch::enter_native`); **delete the userspace recompiler from the legacy `nub-exec`**; assert pvm_bench numbers hold; measure new performance (bounds-check elimination, CoW fault speedup). | 1 month |
| 4 | Production shape | Cross-Arch × backend determinism audit; commit/rollback wiring; per-OS hypervisor shim (Linux/KVM, macOS/Hypervisor.framework, Windows/WHP); observability; performance tuning. | 1 month |

Total: ~3 months from Stage 1 to a working prototype.

### Decision gates

**After Stage 0 (this doc):**
- Does the determinism story hold up under skeptical review? (We
  already handle these constraints at the blockchain level, so
  the bar is "no new categories of risk," not "novel correctness
  story.")
- Does the in-guest filesystem story look workable? (1–2 KLoC of
  guest code is plausible.)

**After Stage 1 (Arch trait + boot prototype) — all passed:**
- **Per-call latency** (host → guest function dispatch → return,
  with both sides warm). **Target: <100 µs**, ideally <10 µs.
  **Measured: ~5.9 µs** per round trip across 10,000 noop calls
  on i9-13900K. ✓
- **Host-callback round-trip** (guest → host function → guest).
  **Target: <5 µs.** **Measured: ~5.8 µs** (12.5 − 6.7); just
  over target but in the right zone. ✓
- **In-guest `#PF` round-trip** (write to CoW page → handler →
  resume). **Target: <500 ns.** **Measured: ~860 ns** for the
  pure-CoW path (D2 test) and ~7.5 µs for the full demand-paging
  path with mapping setup (C1 test). The 860 ns CoW number is
  the load-bearing one for `mgmt_copy` performance; the 7.5 µs
  full-setup number is one-shot per first-touch, not per-fault.
  ✓
- **Custom-target shed:** does `x86_64-unknown-none` work as the
  build target? **Yes.** Drop-in stable Rust + a 5-flag RUSTFLAGS
  recipe + `nub-build`'s 100-line `build.rs` helper — no
  `cargo-hyperlight`, no picolibc, no Nix shell. ✓
- Cold-boot time is *not* a hard gate — paid once, amortised
  over millions of blocks.

**After Stage 2 (`nub-arch-local` + `nub-arch-hyperlight` interpreter, σ filesystem):**
- Per-block overhead vs current userspace track on a realistic
  workload. **Target: within 2× of userspace.** (If much worse,
  redesign.)
- Cross-host AND cross-Arch determinism test: same
  `(prior_root, block)`, run on (a) two different machines and
  (b) `nub-arch-local` vs `nub-arch-hyperlight` (both running the
  interpreter at this stage). Identical `new_state_root` in
  every combination. **Target: passes.** (Load-bearing for the
  multi-Arch model.)
- Crash-and-restart test: kill the guest mid-block; verify σ on
  disk is consistent; verify reload produces identical state.

**After Stage 3 (recompiler in-guest):**
- `pvm_bench` numbers ideally **improved** by 10–30% vs the
  userspace recompiler (per the gain estimates above). At
  minimum, no worse than the userspace path.
- Cross-Arch × cross-backend invariant test: `nub-arch-hyperlight` +
  recompiler vs `nub-arch-hyperlight` + interpreter vs `nub-arch-local` +
  interpreter — all three produce identical state roots for a
  property-test corpus.

## Stage 0 deliverables (this doc)

### σ encoding and storage

σ is a content-addressed key-value store **inside the guest**.
Keys: 32-byte content hashes (blake2b). Values: canonical-encoded
cap bytes (existing `jar-cap` Image/Instance/CNode/DataCap
encoding).

Storage layout (in guest, on virtio-blk):

- LSM-style content-addressed shards.
- Hot working set in guest RAM, evicted by LRU to disk (the
  consensus-invisible storage buffer pool — see the eviction note under
  "Working-set cache + eviction"; *not* the deterministic execution-mapping
  eviction that gas metering uses).
- Background compaction merges old shards.
- A small commit journal at the head of the device records the
  current consensus state root after each accepted block.

The host never decodes any of this. The host sees the virtio-blk
device as an opaque blob of bytes.

### Host ↔ Guest interface

The host exposes these guest-callable functions (host-callbacks):

- Logging / telemetry (debug only)

The guest exposes these host-callable functions:

- `apply_block(prior_root: H256, block: Bytes) → (H256, Summary)`
- `query_endpoint(instance: H256, endpoint: Key, args: Bytes) →
  Bytes` (for external-API dispatch)
- `commit(root: H256)` and `rollback()` (consensus signalling)
- `health_check() → Status`

The transport is Hyperlight-style function-call ABI plus
virtio-blk for σ persistence. virtio-net or a host-callback
channel for the external-API surface — choice deferred to Stage 1
based on latency measurements.

### In-guest cap layout

```text
// Microkernel objects, refcounted by the kernel.

Image       (immutable, refcounted)
// Type identity is the kernel-attested image_hash carried by each
// Image/Instance (read via host_image_hash_chain), not a separate
// refcounted object.

Instance    {
  image:       ImageHandle,
  cnode:       CNodeHandle,
  state:       InstanceState (small),
  cached_hash: Option<H256>,
}

CNode       {
  slots:       OrdMap<Key, SlotHandle>,
  cached_hash: Option<H256>,
}

DataCap     {
  shards:      Vec<ShardHandle>,
  page_table:  OrdMap<u32, (shard_idx, page_offset)>,
  size:        u64,
  cached_hash: Option<H256>,
}

DataCapShard {
  base_page:   GuestPhysPageNum,
  n_pages:     u32,
  content_hash:H256,
}
```

`mgmt_copy` of any cap kind = microkernel `dup_handle`: bump
refcount, mark all child page-table entries CoW (for DataCap
shards). Constant time.

Write-fault on a CoW page = in-guest `#PF` handler allocates a
fresh guest physical page, copies content, updates the offending
mapping's PTE writable, `iretq`. Sub-µs.

### State-root algorithm

```text
fn state_root(cap: &Cap) -> H256:
    if let Some(h) = cap.cached_hash:
        return h
    h = match cap:
        Image | DataCapShard:
            blake2b(canonical_encode(cap))
        Instance { image, cnode, state }:
            blake2b(SCALE.encode {
                image_hash: state_root(image),
                cnode_hash: state_root(cnode),
                state: canonical_encode(state),
            })
        CNode { slots }:
            blake2b(SCALE.encode(
                slots.iter_sorted().map(|(slot, cap)|
                    (slot, state_root(cap)))))
        DataCap { shards, page_table, size }:
            blake2b(SCALE.encode {
                shard_hashes: shards.iter().map(state_root).collect(),
                page_table: page_table.clone(),
                size,
            })
    cap.cached_hash = Some(h)
    h
```

Mutation invalidates `cached_hash` on the mutated cap and all
ancestors up to the root. Walk dirty subtree on each `state_root`
call; reuse cached hashes elsewhere.

### Determinism analysis

Output (`new_state_root`, blob writes) must be byte-identical
across validators **and** across Arch × backend combinations
(`nub-arch-hyperlight` + recompiler vs `nub-arch-local` + interpreter vs
the future `nub-arch-pci-soc` + device-resident recompiler).
Requirements:

1. **Allocator** doesn't leak into encoded bytes. Cap encoded
   form contains only protocol-defined content.
2. **All hashing-path iteration** is sorted by protocol-defined
   key. No HashMap iteration.
3. **No host clock observable** to the guest. Block inputs +
   prior state root are the only host-supplied data.
4. **JIT codegen** deterministic. Regression test: compile the
   same blob N times, assert byte-identical output. (Per-arch:
   x86-64 codegen on `nub-arch-hyperlight`, ARM64 on `nub-arch-pci-soc`.)
5. **Read-protocol return** content-addressed (free).
6. **Microvm/device boot** deterministic. Same initial state
   every time, regardless of Arch.

None novel. Same discipline every blockchain validator follows.
The multi-Arch story sharpens it slightly: codegen determinism is
now per-arch, and cross-Arch property tests are a hard correctness
gate.

## Open questions for review

1. **Which microvm runtime under `nub-arch-hyperlight`?** Hyperlight is
   the strongest fit — ring-0 long mode, fast `OUT`-port +
   shared-memory function-call ABI (single VM-exit per call),
   KVM+WHP+MSHV abstraction. macOS not yet supported (no
   Hypervisor.framework backend); on the roadmap. Alternatives:
   raw `kvm-ioctls` plus per-OS shims (more work, more control);
   Firecracker (slower boot, but irrelevant for long-running
   model). Probably Hyperlight; reconsider after Stage 1 numbers.

2. **Can we drop the custom Rust target?** Hyperlight today uses
   `x86_64-hyperlight-none` plus `cargo-hyperlight` plus picolibc.
   For our pure-Rust microkernel we should be able to use stable
   `x86_64-unknown-none` plus `RUSTFLAGS`. Stage 1 spike: confirm
   that `cargo build --target=x86_64-unknown-none -p
   microkernel-hyperlight` produces a Hyperlight-loadable ELF. If
   yes, build-system surface shrinks dramatically. If no, we wear
   the custom-target cost.

3. **Which guest framework, if any?** Hyperlight's Guest Library
   gives us the host-callback ABI for free. We're not using it as
   an OS; we're using it as a function-execution shell with our
   own paging and IDT. Compatible.

4. **σ filesystem format.** Roll our own LSM, port RocksDB, or
   something between. ~1–2 KLoC if we roll our own; "free" but
   heavyweight if we port. Probably roll our own.

5. **virtio-blk vs Hyperlight's host-callback ABI for σ I/O.**
   virtio-blk wins on throughput (hundreds of thousands of IOPS
   via io_uring). Host-callback wins on simplicity. Stage 1 to
   measure.

6. **Commit/rollback policy.** `mgmt_copy` snapshot before apply,
   or host-buffered blocks. Cross-cutting with chain consensus
   design. Defer to chain orchestrator decisions.

7. **Validator deployment story.** Validators with hardware virt
   → `nub-arch-hyperlight` + recompiler. Without (cloud no-nested-virt)
   → `nub-arch-local` + interpreter. State-root equivalence across
   Arch × backend combinations is what makes this safe. Already in
   the doc; flag here as a deployment-guidance task.

8. **`nub-arch-pci-soc` realism.** Not for v1, but worth keeping the Arch
   trait shape compatible with: a PCIe accelerator card running
   the microkernel as firmware, accessed via MMIO command rings +
   DMA bulk transfer. Cross-CPU-arch codegen (ARM64) becomes
   necessary; the rest is an Arch impl swap. Don't design *for*
   this, but don't design *against* it either.

## Decision history

**2026-05: Commit to Stage 2.** Stages 0, 1, and 1.5 are
complete. Every Stage 1 gate passed: ring 0 + long mode + custom
IDT + in-guest `#PF` handling + CR3 manipulation + CoW round-trip
all work on the i9-13900K target hardware, and the build-system
spike passed (stable `x86_64-unknown-none` + `nub-build`
replaces `cargo-hyperlight` and picolibc). Stage 1.5 lifted the
prototype into proper crates and proved the `Arch` boundary
through both backends.

Stage 2 (~1 month) splits `nub-exec` into
`javm-interpreter` + `nub-recompiler-x86`, wires the interp
through `nub-kernel` over `Arch::Memory`, and stands up the
in-guest σ filesystem. The decision point for Stage 3 (delete
the userspace JIT, run only in-guest) is the cross-Arch
determinism audit at the end of Stage 2.

**Original Stage 0 decision text (preserved for archaeology):**
The original framing of this section asked whether to commit to a
Stage 1 prototype as a small bet (~1 engineering-week of
throwaway prototyping) for high information value about whether
the architecture was worth pursuing. The bet was made; the
information arrived; the answer was yes.
