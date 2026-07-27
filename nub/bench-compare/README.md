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
cargo run --release -p bench-build     # fan every kernel out to 4 targets
cargo run --release -- list            # what is available
cargo run --release -- validate        # do all engines agree?
cargo run --release -- run             # measure
cargo run --release -- report --write  # -> BENCHMARKS.md
```

Needs the `wasm32-unknown-unknown` target and `rust-src`:

```bash
rustup target add wasm32-unknown-unknown
rustup component add rust-src
```

## How one kernel reaches every engine

The compute kernels live in `nub/programs/*` as ordinary Rust libraries
exposing a single `pub fn name() -> u32`. They contain no target
conditionals in the kernel body and know nothing about any engine.

`bench-build` compiles each to four artifact families:

| family | artifact | consumed by |
|---|---|---|
| `pvm2` | `artifacts/pvm2/<n>.nubp` | `nub_interp`, `nub_jit_compile` |
| `native` | `artifacts/native/<n>.so` | `native` |
| `wasm32` | `artifacts/wasm32/<n>.wasm` | Wasmtime, Wasmer |
| `polkavm64` | `artifacts/polkavm64/<n>.polkavm` | PolkaVM |

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

**1. Only the measured call is timed.** `compile` and `spawn` happen
before the clock starts, for every engine alike. This seam is
load-bearing: every engine does per-invocation setup (Wasmtime
instantiates a store, nub builds its flat address space and
predecodes), and folding that into `run` for one engine but not another
would compare different things. It is also why `nub_arch_local`
exposes `ProgramInstance` — nub's `run_program` used to do setup and
execution in one call, which would have understated it here.

**2. Gas is an axis, never a normalizer.** No number is ever
gas-adjusted, scaled, or divided by a cost model. Metered and unmetered
rows sit in the same table with an explicit `metered` column, and the
report never claims a metered engine "lost" to an unmetered one.

**3. Metering mode is part of a row's identity**, not a flag. Hence
four separate PolkaVM rows and two separate Cranelift rows.

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
| `polkavm64_recompiler_no_gas` ↔ `_sync_gas` ↔ `_async_gas` | what metering costs a JIT |
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
| `nub_jit_compile` | nub's JIT *emission* only (see below) |
| `polkavm64_interpreter` | the closest interpreter comparison: same ISA family, same problem |
| `polkavm64_recompiler_*` | the closest JIT comparison, at three metering levels |
| `wasmtime_cranelift` | the optimizing-JIT ceiling: how much code quality a single-pass design gives up |
| `wasmtime_cranelift_fuel` | the same, metered |
| `wasmtime_winch` | a second single-pass data point, free (same crate) |
| `wasmer_singlepass` | the design analogue — is nub's codegen competitive with a mature single-pass compiler? |

There is deliberately **no `nub_jit` runtime row yet.**
`nub-recompiler-x86` is a pure bytes producer, so its *compile* time is
measurable with no sandbox; executing its output needs the ring-0
substrate in `nub-arch-x86`, which needs a `GuestPersonality`. Until
nub ships its reference personality, `nub_jit_compile` reports emission
only, and says so rather than silently measuring something else.

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
- **solana_rbpf** — different ISA, and building guests needs an
  out-of-band Solana platform-tools download.

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
- **The median is reported, not the mean.** A scheduler preemption adds
  a long tail but never a short one, so the mean is biased upward by
  exactly the noise we want to exclude.
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
