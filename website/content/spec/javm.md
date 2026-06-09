# JAVM (PVM2) — RV64E + Xjar + EEI

JAVM is the virtual machine for JAR's guest execution. Its ISA, **PVM2**,
is **fully conformant RISC-V**: the **RV64E** base, a fixed set of standard
extensions, **one custom extension `Xjar`** (in the RV-reserved custom-0
space), and a specific **execution-environment interface (EEI)**. Nothing
in PVM2 contradicts the behavior the RISC-V unprivileged spec defines for a
base-or-standard instruction.

```
PVM2  ::=  RV64E  +  {M, C, Zbb, Zba, Zbs, Zicond, Zicclsm}  +  Xjar  +  EEI
```

## Rationale

The predecessor design of JAVM is based on the custom PVM ISA. Our
benchmarks show that the custom ISA is not necessary: with a
standard-compliant RISC-V we still get a recompiler as fast as the old
design. We therefore moved to standard RISC-V — a battle-tested ISA is less
likely to harbor design issues, and adopting new RISC-V extensions becomes
much easier.

An earlier draft of this spec framed PVM2 as RV64E with "four hard
divergences." Each has since been resolved into one of the three conformant
buckets below — the `Xjar` extension or the EEI — with no behavior change.

## How PVM2 relates to RV64E

Every part of PVM2 is one of three things, none a contradiction of the base
ISA:

- **Standard RV64E + standard extensions**, used unchanged — including
  **plain RISC-V control flow** (`jal`, `jalr`, `auipc`, branches, and the
  compressed `c.j`/`c.jr`/`c.jalr` forms all behave as the RV spec
  defines). An earlier draft routed calls through a custom `br_table`; that
  static-dispatch model has been removed.
- **The `Xjar` custom extension** (custom-0 opcode), which adds behavior in
  the blessed mold of RISC-V's own security extensions: **landing-pad
  control-flow integrity** on indirect jumps (cf. Zicfilp) and the
  **custom-0 host / control ops** (`trap`, `ecall.jar`, `ecalli`,
  `fallthrough`).
- **EEI configuration**: choices the RISC-V spec delegates to the execution
  environment — the aliased memory map, the `ecall`/`ebreak` handler,
  guaranteed misaligned support, `fence` retirement, and the absence of
  CSRs / privilege / atomics / FP.

The register model — RV64E's 15 GPRs — is plain base ISA.

## The Xjar extension

`Xjar` occupies the RV-reserved `custom-0` major opcode (`opcode =
0001011`) and adds one architectural rule beyond its custom instructions:

**Xjar CFI — every indirect-jump (`jalr`) target must be a basic-block
start.** A `jalr` (and `c.jr`/`c.jalr`) whose target lands mid-block or
mid-instruction takes a **fatal trap** (ε = panic). The valid-target set is
`bb_starts(code)` (see [Basic-block boundaries](#basic-block-boundaries-bb_starts));
a block start is an implicit landing pad.

This is the shape of the ratified RISC-V CFI extension **Zicfilp** (the
Control-Flow Integrity chapter), which constrains standard-`jalr` targets
to landing-pad instructions and faults otherwise. `Xjar`'s variant is
coarser and stricter: the landing pads are *structurally derived* from the
instruction stream (no explicit `lpad` marker, no label), **every** `jalr`
target must be one (no exemptions), and the fault is terminal. Native
`jalr` is retained.

*Why:* per-block gas is precharged at block entry, so entering a block
anywhere but its start would bypass the charge. The check is a runtime one,
derived from the instruction stream — the recompiler runs untrusted code
and never trusts a linker-supplied target table. In the x86 recompiler it
is folded into the dispatch table: a dense `offset → native` table whose
every non-block-start slot holds the panic stub, so `jalr` is a bounds
check plus the dispatch jump. `jal`/branch targets are immediates,
validated at recompile time against the same set; the linker injects
`fallthrough` markers so every reachable target is a block start.

The custom-0 host / control ops are in [Custom-0 opcodes](#custom-0-opcodes).

## Register model

PVM2 uses **RV64E's 15 GPRs** — `x1`, `x2`, `x5`–`x15` plus `x3`, `x4`,
with `x0` hardwired to zero. `x16`–`x31` do not exist in the E base
(naming one is an illegal encoding). This is plain RV64E.

`x3`/`x4` carry special meaning only by RISC-V psABI convention; the
unprivileged ISA defines them as ordinary GPRs and PVM2 executes them as
such. **The jar toolchain does not emit `x3`/`x4`** (the transpiler rejects
them at build; jar's guests use the other 13 registers), but the *runtime*
executes them so any valid RV64E blob runs — this is what keeps PVM2
conformant rather than "RV64E minus two registers."

**Host spill and gas.** An implementation must provide at least 13 host
registers; the 13 commonly-used slots (`x1`, `x2`, `x5`–`x15`) are
register-resident on every host. `x3`/`x4` are not guaranteed resident — a
host with exactly 13 registers (today's x86-64 JIT) holds them in memory
and spills on each access. Because the worst-case host spills, `x3`/`x4`
accesses are **gas-charged at memory-spill cost unconditionally** on every
host. A host with spare registers may keep them resident and run faster
than charged (permitted; gas is an upper bound, the charge is spec-fixed,
consensus unaffected). See [gas-cost.md] and [portability.md].

## EEI configuration

Each is a knob the RISC-V spec hands to the EEI/platform/profile; a
conforming RV64E implementation could be built the same way.

1. **Memory map: a 2³²-fold alias of one 4 GiB main-memory region.**
   Address computation is **stock RV64E** (full 64-bit, circular mod 2⁶⁴,
   §1.4). The EEI maps main memory so the whole 2⁶⁴ space is tiled with 2³²
   aliased copies of one 4 GiB region: address `A` is backed by byte
   `A mod 2³²`. This is ordinary incomplete address decoding (a core that
   decodes only bits [31:0] aliases its RAM). The guest can't distinguish
   it from a 32-bit mask — `load(0x1000) == load(0x1_0000_1000)` under both
   — but the instruction itself is unchanged; the *map* aliases. Isolation
   is then a host-VA fact: the runtime's execution context lives in host
   VA above 4 GiB, outside the guest's address space entirely.

   Within one alias period the 4 GiB region is partitioned:
   - `[0, CODE_BASE)` — **unmapped null guard** (`CODE_BASE = 0x0040_0000`).
   - `[CODE_BASE, DATA_BASE)` — **code**, read-only, `PC = CODE_BASE +
     byte_offset`, capped at `MAX_CODE_SIZE` (252 MiB).
   - `[DATA_BASE, 4 GiB)` — **data** (`DATA_BASE = 0x1000_0000`, 256 MiB).

   `auipc`, `jal`, `jalr`, branches compute real PC values as RV defines.
   Code is position-independent (maps at `CODE_BASE`); the transpiler
   relocates absolute data references by `+DATA_BASE`. A guest can read its
   own code (PIC idiom) but not write it (read-only).

2. **Standard `ecall`/`ebreak` → unconditional fatal trap.** They decode
   and execute as ordinary instructions; the EEI's defined handler
   terminates (ε = panic). The spec delegates exactly this — the EEI
   handles "environment calls" (§1.2), and `ebreak` returns control to the
   environment (§2.9), which here terminates. PVM2's host functionality
   lives in custom-0 (`ecalli` carries the 20-bit selector standard `ecall`
   lacks), so standard `ecall`/`ebreak` are simply "always panic." This is
   a fatal trap (instance discarded).

3. **Misaligned loads/stores fully supported** (RV §2.1.6's EEI option;
   also stated as the **Zicclsm** extension). x86 handles misaligned at
   near-native speed; single-threaded, so atomicity is moot.

4. **`fence`/`fence.i` are no-ops** — single-threaded, no I/O bus, code
   mapped read-only, so nothing to order. Conforming, encoding unchanged.

5. **No CSRs, privilege levels, atomics, or FP/vector** — all optional, not
   in the RV64E base; their encodings decode as illegal (standard
   reserved-encoding behavior for an unimplemented extension). A single
   flat privilege environment.

## Extensions included

Applied unchanged from their standard specs:

| ext | name | notes |
|---|---|---|
| M | mul / div | `mul`, `mulh*`, `mulw`, `div*`, `rem*`, `*w` |
| C | compressed | 16-bit forms; `c.jr`/`c.jalr`/`c.j` are standard control flow (the `jalr` forms carry the Xjar CFI precondition) |
| Zbb | bit manipulation | `clz`, `ctz`, `cpop`, `sext.*`, `zext.h`, `min/max[u]`, `andn`, `orn`, `xnor`, `rol/ror[i][w]`, `rev8`, `orc.b` |
| Zba | shift-add | `sh{1,2,3}add[.uw]`, `add.uw`, `slli.uw` |
| Zbs | single-bit | `bset`, `bclr`, `binv`, `bext` + imm forms |
| Zicond | int conditional | `czero.eqz`, `czero.nez` |
| Zicclsm | misaligned support | per §4.13; documents the EEI misaligned guarantee as a standard extension |

Not included: A (atomics), F/D/Q/V, Zfh, Zfa, Zicsr, Zifencei,
supervisor/hypervisor.

## Custom-0 opcodes

The host / control ops of `Xjar`, in the RV-reserved `custom-0` slot
(`opcode = 0001011`), discriminated by `funct3` (I-type bits [14:12]):

| funct3 | mnemonic | wire pattern | semantics |
|---:|---|---|---|
| 000 | `trap` | `(funct3=000) (rest=0)` | unconditional execution abort. ε = panic |
| 001 | `ecall.jar` | `(funct3=001) (rest=0)` | jar management op. φ[11] = op-code, φ[12] = subject\|object. Same as PVM opcode 3 |
| 010 | `ecalli imm` | `(funct3=010) (imm[19:0])` | host-call with 20-bit signed selector. Same as PVM opcode 10, `imm = sext20(imm[19:0])` |
| 100 | `fallthrough` | `(funct3=100) (rest=0)` | structured no-op terminator; the *following* instruction is a `bb_start`. Used by the linker to widen the bb_start set |

(`ecall.jar` is named to distinguish it from standard `ecall`, which decodes
normally but is handled by the EEI's fatal trap — so host functionality
lives here in custom-0.)

`funct3 = 011` (the removed `br_table`) is reserved. The entire `custom-1`
major opcode (`0101011`) is reserved and traps at decode. No `sbrk` /
`cmov_*` opcodes (heap growth via `ecalli`; `cmov` falls back to Zicond).

## Basic-block boundaries (`bb_starts`)

*(The mechanism behind Xjar CFI.)* PVM2 defines a static set `bb_starts ⊆
valid_pc` that both engines treat as basic-block boundaries (gas-check
sites, label sites, valid resume PCs, valid `jalr` targets / Xjar landing
pads):

```
bb_starts(code) = {0} ∪ { pc | pc immediately follows a terminator }
```

The set is **derived from the instruction stream**, never from external
metadata — both engines compute it identically by walking `code` and
flagging the byte after each terminator. This is what lets the recompiler
validate untrusted `jalr` targets safely.

**Terminators:** `trap`, `fallthrough`, `ecalli`, `ecall.jar`; all static
branches (`beq`/`bne`/`blt`/`bge`/`bltu`/`bgeu`/`c.beqz`/`c.bnez`); `jal`
and `jalr` (any `rd`, including `c.j`/`c.jr`/`c.jalr`); any reserved
encoding (defensive).

**Linker invariant.** Every reachable branch/`jal` target and every
statically-known `jalr` target must be in `bb_starts`; if not naturally
post-terminator, the linker injects a `fallthrough` before it and re-encodes
upstream offsets. Return sites are free (a call's `jalr`/`jal` is a
terminator).

**Pause-point constraint.** A `Paused { pc, regs }` state must have `pc ∈
bb_starts`; out-of-gas can only fire at the per-block gas check, which sits
at a `bb_start`. Faults stay terminal (panic/trap/page-fault discard the
instance, never resume mid-block). `bb_starts` is derived from `code`; it
is not part of the wire format.

## Reserved / EEI-trapped encodings

These standard RV encodings **panic when reached** — each for a base/EEI or
unimplemented-extension reason, not a contradiction of the base ISA:

| encoding | reason |
|---|---|
| ECALL, EBREAK, `c.ebreak` | EEI fatal-trap handler (§EEI #2) — decode/execute as standard; environment terminates |
| rs1/rs2/rd ∈ {x16..x31} | RV64E base — register does not exist |
| CSR ops (Zicsr) | unimplemented extension |
| atomics (A) | unimplemented extension |
| privileged ops (MRET/SRET/URET/WFI/SFENCE.VMA) | no privilege levels |
| FP/vector (F/D/Q/V) | unimplemented extensions |
| custom-1 major opcode (`0101011`) | unused custom slot |
| custom-0 `funct3 = 011` | unused custom encoding |

`x3`/`x4` are **not** reserved — they are valid GPRs the runtime executes;
only the jar toolchain declines to emit them. Refusal is **lazy** (decode
as illegal / trap *if executed*); the toolchain also rejects them at build
as a convenience, not the consensus rule.

## Invariants

- **PVM2 is RV64E + Xjar + EEI, no raw instruction contradictions.** Any RV
  decoder/disassembler renders *and correctly interprets* PVM2 bytes. Every
  departure from a stock RV64E core is an `Xjar` behavior (landing-pad CFI;
  custom-0 host ops) or an EEI choice (aliased map; `ecall`/`ebreak` fatal
  trap; misaligned support; `fence` retirement) — all legal RISC-V.
- Aggregate execution is deterministic for a given program + initial state
  + gas budget.
- Gas accounting is implementation-independent (single-pass pipeline model,
  `reg_done[15]` + decode throughput, block cost `max(max_done − 3, 1)`;
  `x3`/`x4` operands additionally charge memory-spill cost). See
  [gas-cost.md].
