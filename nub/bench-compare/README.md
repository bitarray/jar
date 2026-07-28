# bench-compare

Cross-engine benchmark comparison for nub: how does nub's PVM2
interpreter and JIT compare against native code, PolkaVM, Wasmtime and
Wasmer, running *the same computation*?

## Why it is a separate workspace

Wasmtime, Wasmer and PolkaVM together pull several hundred crates. None
of that ships in nub — this directory is a measuring instrument, not a
product. So it has its own `[workspace]` and its own `Cargo.lock`, and
is listed in `exclude` of the repo-root manifest.

Consequences, all intended:

- `cargo build --workspace` at the repo root never touches it. Build it
  with `--manifest-path nub/bench-compare/Cargo.toml`.
- Its dependencies never enter nub's lockfile, `cargo audit`, or any
  SBOM. **Do not "fix" this by adding it to the root workspace.**
  Dragging Wasmtime's advisory surface into nub's release artifacts
  would be actively misleading about what nub ships.
- The `nub-*` crates compile twice on a machine that builds both. Do
  not share `CARGO_TARGET_DIR` to avoid that — the two workspaces
  resolve features differently, and sharing would thrash.

## Quick start

```bash
cd nub/bench-compare
cargo run --release -p bench-build     # fan every kernel out to 5 targets
cargo run --release -- list            # what is available
cargo run --release -- validate        # do all engines agree?
cargo run --release -- run             # measure
cargo run --release -- size            # artifact size (no measurement needed)
cargo run --release -- report --write  # -> BENCHMARKS.md
```

Needs the `wasm32-unknown-unknown` target and `rust-src`:

```bash
rustup target add wasm32-unknown-unknown
rustup component add rust-src
```

The sBPF family additionally needs `bpf-linker`; without it that family
is skipped and its rows do not appear. See [Solana sBPF](#solana-sbpf).

## How one kernel reaches every engine

The compute kernels live in `nub/programs/*` as ordinary Rust libraries
exposing a single `pub fn name() -> u32`, and know nothing about any
engine.

There is **exactly one target conditional** in kernel code, and it is
worth knowing about: `gp::mul` has a `cfg(target_arch = "bpf")` arm,
because LLVM's BPF backend cannot lower a 64x64 widening multiply. It
is proven bit-identical to the `u128` path, but it does mean the five
`gp`-backed kernels are a different program on the sBPF row. See
[Solana sBPF](#solana-sbpf). Every other engine sees identical source.

`bench-build` compiles each kernel to five artifact families:

| family | artifact | consumed by |
|---|---|---|
| `pvm2` | `artifacts/pvm2/<n>.nubp` | `nub_interp`, `nub_jit_compile` |
| `native` | `artifacts/native/<n>.so` | `native` |
| `wasm32` | `artifacts/wasm32/<n>.wasm` | Wasmtime, Wasmer |
| `polkavm64` | `artifacts/polkavm64/<n>.polkavm` | PolkaVM |
| `sbpf` | `artifacts/sbpf/<n>.sbpf` | solana-sbpf (7 of 10 kernels) |

The non-PVM2 families go through a thin wrapper crate in `guests/`
which `include!`s `guests/bench-abi.rs` and exports a single
`run() -> u32`. The kernels themselves are untouched, which is what
makes adding an engine cheap.

The PVM2 family skips the wrapper: the kernel crate's own
`#[nub_rt::endpoint(0)]` binary already *is* the entry ABI, and it is
built with `nub_build::pvm2` — nub's real recipe, not a second guess at
it, so nub is measured with the flags it actually ships.

## Fairness rules

These are the rules the tool enforces. They exist so the numbers mean
something; changing one changes what is being claimed.

**1. Only the measured call is timed.** Each seam in the
`create -> compile -> spawn -> run` lifecycle exists because putting
work on the wrong side of it silently favours one engine:

- *engine creation is untimed.* Building an engine reserves guard
  regions, builds a code allocator and may spawn worker threads — a
  once-per-process cost in real use. nub has no engine object at all,
  so charging it inside `compile` flattered nub by ~1 ms.
- *instantiation is untimed in `runtime`.* Every engine does
  per-invocation setup; folding it into `run` for one and not another
  compares different work. This is why `nub_arch_local` exposes
  `ProgramInstance` at all — `run_program` used to do setup and
  execution in one call.

**1b. Four measurement kinds, because one number would hide things.**

| kind | what it measures |
|---|---|
| `runtime` | steady-state execution: one instance, invoked repeatedly |
| `invoke` | a fresh instance every sample, with compilation already done |
| `cold` | **cold recompile + execute** — the bench target |
| `compilation` | getting a program into runnable form |

`cold` is the headline: no compiled code at the start of a sample, the
program having run by the end. That is the cost a VM pays when a
work-package arrives, is turned into native code, and executed once.

**Storage is excluded from it, deliberately.** Getting a blob *into* an
engine's object store — for nub, shipping it into the sandbox, decoding
and content-hashing it — is dominated by hashing, scales with blob size
rather than code size, and belongs to a different subsystem than the
recompiler. It appears separately under `compilation` for the engines
that have such a step.

The two designs need different mechanics to measure the same thing. An
eager engine compiles inside `compile`, so that call is inside the
clock. nub compiles lazily on first entry, so it publishes once up
front (untimed) and its JIT cache is evicted before each sample (also
untimed), leaving `run` to recompile. `Caps::compiles_lazily` selects
which shape applies.

`cold` minus `invoke` is the recompile cost on its own.

`runtime` and `invoke` differ by roughly 2x for nub's interpreter,
because a fresh instance allocates and copies a flat address space
while Wasmtime maps a copy-on-write image. Reporting only one would
present a difference in *memory strategy* as a difference in
*execution speed*.

**`nub_jit` has no meaningful `runtime` row.** nub's invocation model
builds a fresh frame and address space on every call by design, so
there is no warm state for `spawn` to hoist out — its `runtime` figure
still contains per-invocation setup, and comparing it against an engine
that reuses one warm instance would understate nub. The report marks
that row with a dagger, and the headline decomposition uses `invoke`
instead, where every engine pays instantiation.

Some `runtime` rows are absent: three guests carry a never-freeing bump
arena and cannot be re-run in one instance, so they are skipped with a
logged reason rather than reported wrongly.

**2. Gas is an axis, never a normalizer.** No number is ever
gas-adjusted, scaled, or divided by a cost model. Metered and unmetered
rows sit in the same table with an explicit `metered` column, and the
report never claims a metered engine "lost" to an unmetered one.

**3. Metering mode *and cost model* are part of a row's identity**, not
flags.

PolkaVM's default is `CostModel::Simple` — a flat cost per instruction,
cheap to evaluate. nub's gas is a per-basic-block pipeline simulation
with memory tiers, which is strictly more work. Comparing nub's metered
rows only against Simple would understate what nub pays for its model,
so the `*_full` rows use `CostModelKind::Full(CacheModel::L2Hit)`.
L2Hit is the right choice specifically: it charges
`memory_access_cost: 25`, which is exactly nub's
`gas_const::MEM_CYCLES_BASE`. So `polkavm64_recompiler_sync_gas_full`
is the genuinely like-for-like row, and the Simple rows show what a
cheaper model would buy. The gap is real — on keccak, Simple charges
63k gas and Full charges 249k for the same program.

**4. Counters are set to maximum** so instrumentation runs but never
fires — we measure the cost of counting, not the cost of running out.
For nub and PolkaVM that is `i64::MAX`, not `u64::MAX`: both count gas
in an `i64` and detect exhaustion by sign, so a `u64::MAX` budget would
present as already-negative.

**5. Read metering cost off the bracketing pairs.** nub has no
unmetered mode, and adding one would fork the interpreter's hottest
loop for a path nothing in production exercises. Instead:

| pair | isolates |
|---|---|
| `polkavm64_recompiler_no_gas` ↔ `_sync_gas` | what a *cheap* cost model costs a JIT |
| `polkavm64_recompiler_no_gas` ↔ `_sync_gas_full` | what a *nub-comparable* cost model costs a JIT |
| `wasmtime_cranelift` ↔ `wasmtime_cranelift_fuel` | the same, for an optimizing JIT |

Together these bracket what nub's always-on gas costs it.

**6. Gas values are printed, never compared across engines.** Each
engine's counter has different semantics; a cross-engine gas ratio
would be meaningless. Absolute gas conformance for nub is asserted
elsewhere, against golden vectors in `nub-bench`.

**7. `vs native` is the column that matters.** `vs fastest` tells you
who won; `vs native` tells you what each engine costs relative to
running the computation with no engine at all.

## What the rows mean

| row | what it answers |
|---|---|
| `native` | the floor — this computation with no engine |
| `nub_interp` | nub's bytecode interpreter, metered |
| `nub_jit` | nub's x86-64 JIT executing in the KVM sandbox, metered |
| `nub_jit_compile` | nub's JIT *emission* alone, with no sandbox |
| `polkavm64_interpreter` | the closest interpreter comparison: same ISA family, same problem |
| `polkavm64_recompiler_*` | the closest JIT comparison, across metering levels and cost models |
| `wasmtime_cranelift` | the optimizing-JIT ceiling: how much code quality a single-pass design gives up |
| `wasmtime_cranelift_fuel` | the same, metered |
| `wasmtime_winch` | a second single-pass data point, free (same crate) |
| `wasmer_singlepass` | the design analogue — is nub's codegen competitive with a mature single-pass compiler? |

`nub_jit` runs under the **flat personality** (`nub-flat`), nub's
reference `Personality`/`GuestPersonality` pair. Executing recompiled
code needs the ring-0 substrate in `nub-arch-x86`, which needs a
personality — flat is the smallest one that exists, so the row measures
nub's engine rather than any particular kernel's semantics. It needs
`/dev/kvm`; without it the row drops out of the registry rather than
failing every measurement.

`nub_jit_compile` remains alongside it, measuring emission alone with
no sandbox. The two answer different questions: how fast the
recompiler *emits*, versus what a full cold invocation costs.

### Solana sBPF

`sbpf_interpreter` and `sbpf_jit`, via `solana-sbpf`. The other major
production chain VM with a metered register machine, so the most
obviously missing comparison.

**Built by our own pinned compiler, not Solana's.** `cargo-build-sbf`
ships a forked rustc (currently 1.84.1) and a forked LLVM; every other
family here is built by the `1.95.0` in `rust-toolchain.toml`, and a row
compiled by a different compiler *and* a different LLVM would attribute
a codegen delta to the engine — a confound `manifest.json` cannot even
express, since it records one rustc per run. Upstream rustc's own
`bpfel-unknown-none` reaches SBPFv3 instead, because **v3 reverts every
v2 divergence from stock eBPF**: `disable_lddw`, `disable_le`,
`disable_neg`, `swap_sub_reg_imm_operands`,
`move_memory_instruction_classes` and `enable_pqr` are all `self == V2`
in solana-sbpf, and `call imm` under `static_syscalls()` is pc-relative
— exactly what LLVM emits. So the old "different ISA" objection to this
row was simply wrong.

It needs one out-of-band tool, `bpf-linker`, from `$BPF_LINKER` or
`PATH`:

```bash
# prebuilt, statically linked, user-local — no system change
curl -sSL -o bl.tar.zst https://github.com/aya-rs/bpf-linker/releases/latest/download/bpf-linker-x86_64-unknown-linux-musl.tar.zst
tar --zstd -xf bl.tar.zst && export BPF_LINKER=$PWD/bpf-linker
```

Without it the sBPF artifacts are skipped and the rows simply do not
appear. That is a real cost, but a far smaller one than a compiler fork:
the *compiler* stays pinned, so only the linking step is out of band.

**Read these rows with two caveats.**

*Seven of ten kernels.* `prime-sieve` has a 100 KB writable
`static mut` and the sBPF container has no writable segment at all — the
strict v3 parser accepts exactly two `PT_LOAD` headers, `PF_R` and
`PF_X`. `ecrecover` needs ~3.8 KB of k256 lookup tables in one frame
against a 4 KiB limit, which is why Solana ships `secp256k1_recover` as
a syscall rather than letting programs link k256. `ed25519-compact`'s
field arithmetic is 76 `u128` sites. All three are properties of the
platform; Solana's own toolchain hits the same walls.

*Five of the seven run a different multiply.* LLVM's BPF backend cannot
lower a 64x64 widening multiply — `__multi3` is unsupported at every CPU
level it accepts — so `gp::mul` has a `cfg(target_arch = "bpf")` arm
that reassembles the product from four 32x32 partials. It is proven
bit-identical to the `u128` path (edge cases plus 200k pairs, in that
module's tests), so every engine agrees on the same `u32` and `validate`
passes. But `goldilocks-mul`, `poseidon2-perm`, `mini-verifier`,
`poly-eval` and `fri-fold-tree` are therefore measuring a *different
program* on this row, not just a different VM. Do not read them as
like-for-like against the other engines.

Memory sizing is the harness's choice, not Solana's on-chain policy:
the heap is 256 KiB where on-chain defaults to 32 KiB, because two
kernels exceed the latter and we are measuring the VM rather than the
chain's resource policy — the same spirit as setting gas counters to
maximum. Stack and frame limits are left at solana-sbpf's defaults,
because those *are* the ISA.

sBPF is absent from the **size** tables for the same reason `native` is:
its artifact is a real ELF rather than a compact VM container, so a
byte-exact container comparison would be measuring ELF packaging.

## Artifact size

Speed is half the story; for a chain VM the other half is how big the
program is, because the blob is what gets gossiped, stored and paid for.
`report` emits two size tables, and `bench-compare size` prints the same
ones without needing any measurement.

**Whole blob** is the file on disk. **Raw code** excludes the data
regions, and it is the figure to read — several kernels carry large
initialized data that swamps everything else. `prime-sieve` is 214 bytes
of nub code inside a 158,338-byte blob, 0.1% of it; comparing whole
blobs there compares static lookup tables, not code generators.

| family | code figure |
|---|---|
| `pvm2` | `code` |
| `polkavm64` | `code` + jump table + bitmask |
| `wasm32` | `Code`(10) + `Type`(1) + `Function`(3) + `Table`(4) + `Element`(9) + `Global`(6) |

PolkaVM's two extras are code information held *outside* the instruction
stream. Its instructions are variable-length, so the bitmask — one bit
per code byte, marking instruction starts — is what makes the stream
decodable at all; RV64EMC encodes that in the low two bits of each word.
The jump table lists legal indirect-branch targets, which `jalr rd, rs1,
imm` takes straight from a register. wasm's aux sections are the same
argument: `Type`/`Function` hold signatures the register machines encode
implicitly in their calling convention, and `Table`/`Element` are the
direct analogue of PolkaVM's jump table.

This is deliberately **broader than upstream PolkaVM's own
disassembler**, which labels only `code` as "code size". That is why the
breakdown tables exist: they show every component and every row
reconciles to the file size, so the definition can be checked rather
than taken on trust.

`native` is excluded from both tables. A host `.so` is a different kind
of object — ELF program headers, relocations, a dynamic symbol table,
and whatever of `std` the linker pulled in — not a bigger or smaller
one; it is ~1.9 MB even for the workload whose entire PVM2 code is 126
bytes. Same reason `compilation` omits it.

**No compression is involved in any of the three, and there is nothing
to disable.** nub trims trailing zeros off `ro`/`rw` and PolkaVM stores
only the initial non-zero prefix of its data sections; both are BSS
elision, exactly what ELF does with `p_filesz < p_memsz`, and wasm data
segments are explicitly offset so they carry no trailing zeros either.
No entropy coder, dictionary or transform exists in any of these
containers, and `polkavm_linker::Config` has no compression knob at all.

The varint/LEB128 encoding in PolkaVM and wasm is **instruction
encoding, not a container compressor.** It cannot be turned off — there
is no alternative encoding — and would not be worth turning off if it
could: it is precisely the axis these formats trade on. PolkaVM buys
cheap small immediates with variable-length instructions and pays a
12.5% bitmask; RISC-V pays fixed width and needs no side table. Both are
raw code, and comparing them is the point.

Guest wasm is built with debug info off and symbols stripped, so the
whole-blob column is a like-for-like comparison. Without that it is not:
PolkaVM strips at link (`Config::set_strip(true)`) and nub's linker
never copies DWARF, so an unstripped wasm would be compared against two
stripped formats — and DWARF was 86–98% of every `.wasm`.

## Engines deliberately excluded

Recorded here so they are not re-litigated:

- **wasm3** — needs a git dependency, bindgen and a C toolchain, and
  forces the wasm artifacts to be built `-C target-cpu=mvp -C
  target-feature=-sign-ext`, which degrades memcpy for *every other
  wasm row*. Dropping it is what lets the wasm family use modern
  default target features, which is the fairer comparison.
- **wazero** — needs a Go toolchain and a prebuilt shared object.
- **pvf-executor** — PolkaVM's own benchmark analysis skips it as not a
  production VM.
- **polkavm32** — nub is RV64-only, so a 32-bit family doubles the
  guest build matrix for a comparison nub cannot enter.
- **SP1 / risc0 zkVM executors** — RV32IM rather than RV64, they pull
  the whole prover tree, and their executors are instrumented for trace
  emission, so a raw ns/op would measure "emulator + trace recording"
  and mislead.
`wasmi` and `ckb-vm` are wanted but not yet wired; `wasmi` has a
feature flag reserved.

## Measurement hygiene

- **ASLR is disabled** for the measuring process, by re-exec. Layout
  randomization decides code alignment, which decides i-cache conflicts
  and branch-predictor aliasing; two runs of an identical binary can
  differ by several percent from that alone.
- **Debug builds are refused.** This suite contains interpreters;
  unoptimized numbers are not comparable to anything. Override with
  `TRUST_ME_BRO_I_KNOW_WHAT_I_AM_DOING=1` if you must.
- **The harness is built `lto = true, codegen-units = 1`.**
- **criterion does the measurement**, not a hand-rolled sample loop:
  warm-up, iteration counts chosen from a time budget rather than a
  fixed count, bootstrap confidence intervals, outlier classification.
  A hand-rolled 50-sample median was not enough to resolve these rows —
  it reported swings of 30–50% between runs of the same row as single
  authoritative numbers.
- **One process per row**, which `scripts/run.sh` enforces and
  `--exact` makes precise. This is a correctness requirement, not
  hygiene: nub's sandbox is a process-wide singleton whose guest heap is
  never swept, so several rows in one process contaminate each other —
  measured at up to 47%. Engine names also nest
  (`..._sync_gas` is a prefix of `..._sync_gas_full`), so a substring
  filter naming the shorter one silently runs both.
- **The median is reported, not the mean.** A scheduler preemption adds
  a long tail but never a short one, so the mean is biased upward by
  exactly the noise we want to exclude.
- **The confidence interval is reported alongside it**, whenever it
  exceeds 2% of the median. A row with a 30%-wide interval is a range,
  not a number, and without the interval shown it looks exactly as
  authoritative as one measured to 1%.
- Dispatch is `Box<dyn>`, costing roughly 2 ns per `run()`. The fastest
  row here is a native hash at a few µs, so that is under 0.1% — and
  every engine pays it identically, so it cannot tilt the comparison.

For serious numbers, also quiet the machine: pin to isolated cores,
disable turbo, and set the `performance` governor. `scripts/tune.sh`
does this (needs root) and `scripts/tune.sh --restore` undoes it.

## Validation

`bench-compare validate` runs every `(program, engine)` pair once and
checks two things:

1. **Every engine returns the same value** for a program. This catches
   a silently miscompiled guest — a mis-linked polkavm blob that
   computes the wrong answer would otherwise just look fast.
2. **That value matches `expected.toml`.** This catches the other
   direction: someone changing a kernel constant, where every engine
   would happily agree on the new wrong answer.

Both layers are needed; neither subsumes the other. Regenerate the
goldens with `validate --write` and review the diff.

## CI

Timing is never run in CI. Shared runners produce numbers that are
noise, and publishing them would poison `BENCHMARKS.md`'s provenance.
What is worth running there is `validate` — a genuine cross-engine
differential test of nub's interpreter — plus a cheap `--no-default-features`
build to catch the `Engine` impls drifting against nub's APIs.
