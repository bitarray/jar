# PVM2 spec — RV64E + Xjar + EEI

PVM2 is the ISA for jar's guest execution. It is **fully conformant
RISC-V**: the **RV64E** base, a fixed set of standard extensions, **one
custom extension `Xjar`** (in the RV-reserved custom-0 opcode space), and
a specific **execution-environment interface (EEI)**. There are **no hard
divergences** — nothing in PVM2 contradicts the behavior the RISC-V
unprivileged spec defines for a base-or-standard instruction. Everything
not called out here behaves exactly as that spec defines it.

```
PVM2  ::=  RV64E  +  {M, C, Zbb, Zba, Zbs, Zicond, Zicclsm}  +  Xjar  +  EEI
```

(An earlier draft framed PVM2 as RV64E with "four hard divergences." Each
of those has since been resolved into one of the three conformant buckets
above — the `Xjar` extension or the EEI — with no behavior change.)

## How PVM2 relates to RV64E

Every part of PVM2 falls into exactly one of three buckets, none of which
is a contradiction of the base ISA:

- **Standard RV64E + standard extensions.** The base integer ISA and the
  extensions listed above, used unchanged. This includes **plain RISC-V
  control flow** — `jal`, `jalr`, `auipc`, branches, and the compressed
  `c.j`/`c.jr`/`c.jalr` forms all behave exactly as the RV spec defines.
  (An earlier draft forbade `jalr`/`auipc` and routed every call/return
  through a custom `br_table`; that static-dispatch model has been
  removed.)

- **The `Xjar` custom extension** (custom-0 opcode space). A vendor
  extension that *adds* behavior in the architecturally-blessed mold of
  RISC-V's own security extensions — it adds state/checks and keeps base
  behavior recoverable, rather than redefining a standard encoding. `Xjar`
  has two parts: **landing-pad control-flow integrity** on indirect jumps
  (modeled on the RISC-V CFI chapter, cf. Zicfilp — see
  [The Xjar extension](#the-xjar-extension)) and the **custom-0 host /
  control ops** (`trap`, `ecall.jar`, `ecalli`, `fallthrough` — see
  [Custom-0 opcodes](#custom-0-opcodes)).

- **EEI configuration.** Choices the RISC-V spec explicitly delegates to
  the execution environment, the platform memory map, or the extension
  profile: the aliased memory map, the handling of `ecall`/`ebreak`,
  guaranteed misaligned support, `fence`/`fence.i` retirement, and the
  absence of CSRs / privilege levels / atomics / FP. A conforming RV64E
  implementation could legally be configured the same way (see
  [EEI configuration](#eei-configuration)).

The register model — RV64E's 15 GPRs — is just the base ISA (see
[Register model](#register-model)).

## The Xjar extension

`Xjar` occupies the RV-reserved `custom-0` major opcode (`opcode =
0001011`) and adds one architectural rule beyond its custom instructions:
**landing-pad control-flow integrity (CFI) on indirect jumps.**

**Xjar CFI — every indirect-jump (`jalr`) target must be a basic-block
start.** A `jalr` (and the compressed `c.jr`/`c.jalr`) whose target lands
mid-block or mid-instruction takes a **fatal trap** (ε = panic). The
valid-target set is `bb_starts(code)` (see
[Basic-block boundaries](#basic-block-boundaries-bb_starts)); a basic-block
start is, in effect, an implicit landing pad.

This is exactly the shape of the ratified RISC-V CFI extension **Zicfilp**
(*The RISC-V Instruction Set Manual*, Control-Flow Integrity chapter),
which constrains the targets of standard `jalr` to designated landing-pad
instructions and raises a software-check exception otherwise. `Xjar`'s
variant differs only in being **coarser and stricter**: the landing pads
are *structurally derived* from the instruction stream (no explicit `lpad`
marker, no label), **every** `jalr` target must be one (no return /
software-guarded-branch exemptions), and the fault is **terminal** (the
EEI's fatal-trap policy — see [EEI configuration](#eei-configuration)).
Native `jalr` is retained; `Xjar` attaches the precondition to it exactly
as Zicfilp does.

*Why it exists:* per-block gas is precharged at block entry, so entering a
block anywhere but its start would bypass the charge. The check is a
*runtime* one, derived from the instruction stream — the recompiler runs
untrusted code and never trusts a linker-supplied target table. In the x86
recompiler the check is *folded into the dispatch table*: a dense `offset
→ native` table whose every non-block-start slot holds the panic stub, so
`jalr` is a bounds check plus the dispatch jump (no separate `bb_starts`
lookup) and a bad target jumps to the panic stub. `jal` and branch targets
are immediates and are validated at recompile time against the same set;
the linker injects `fallthrough` markers (below) so every reachable target
is a block start.

(Under the aliased memory map — see [EEI configuration](#eei-configuration)
— `jalr` computes a full 64-bit target as stock RV64E does; the fetch
aliases mod 2³², so the CFI check is performed on `(target mod 2³²) −
CODE_BASE ∈ bb_starts`. The recompiler realizes the alias with a low-32-bit
index mask.)

The custom-0 host / control ops are specified in
[Custom-0 opcodes](#custom-0-opcodes).

## Register model

PVM2 uses **RV64E's 15 general-purpose registers** — `x1`, `x2`, `x5`–`x15`
plus `x3`, `x4` — with `x0` hardwired to zero. `x16`–`x31` do not exist in
the E base (a 5-bit reg field naming one is an illegal encoding; see
[Reserved / EEI-trapped encodings](#reserved--eei-trapped-encodings)). This
is plain RV64E; the encoding is standard.

`x3` (`gp`) and `x4` (`tp`) carry special meaning only by RISC-V psABI
*convention*; the unprivileged ISA defines them as ordinary GPRs, and PVM2
executes them as such. **The jar toolchain does not emit `x3`/`x4`** (the
transpiler rejects them at build, and jar's own guests use the other 13
registers), but the *runtime* executes them correctly so that any valid
RV64E blob runs — this is what keeps PVM2 conformant rather than merely
"RV64E minus two registers."

**Host spill and gas.** An implementation must provide at least **13**
host registers for the guest file; the 13 commonly-used slots (`x1`, `x2`,
`x5`–`x15`) are register-resident on every conforming host. `x3`/`x4` are
**not** guaranteed register-resident — a host with exactly 13 registers
(today's x86-64 JIT) holds them in memory and **spills** on each access.
Because the worst-case conforming host spills them, **`x3`/`x4` accesses
are gas-charged at memory-spill cost unconditionally**, on every host (see
[gas-cost.md](gas-cost.md) and the host contract in
[portability.md](portability.md)). A host with spare registers may
keep them resident and run faster than charged — permitted, since the
charged cost is spec-fixed and gas is an upper bound, so consensus is
unaffected.

## EEI configuration

Each of these is a knob the RISC-V spec hands to the EEI, the platform, or
the extension profile. A conforming RV64E implementation could be built the
same way; PVM2 just fixes the setting.

1. **Memory map: a 2³²-fold alias of one 4 GiB main-memory region.**

   Address computation is **stock RV64E** — every effective address is a
   full 64-bit value, computed and wrapped modulo 2⁶⁴ exactly as the spec's
   circular address space defines (RV §1.4). The EEI then maps **main
   memory** so that the entire 2⁶⁴ space is **tiled with 2³² aliased copies
   of a single 4 GiB region**: address `A` is backed by main-memory byte
   `A mod 2³²`. This is ordinary **incomplete address decoding** — a memory
   map a conforming RV64E core can have (a core that decodes only address
   bits [31:0] aliases its RAM across the whole space).

   The guest cannot observe the difference between this and a 32-bit mask:
   register values are unchanged (a pointer compare of `0x1000` vs
   `0x1_0000_1000` is *false* under both, since both hold full 64-bit
   values), while `load(0x1000) == load(0x1_0000_1000)` is *true* under
   both (same backing byte). A load through `rs1 = 0x1_0000_1000` reads
   main-memory byte `0x1000` because the *map* aliases it, not because the
   instruction truncates. Code (instruction fetch) and `jalr` targets alias
   the same way. The recompiler realizes the alias by masking the address
   to 32 bits — an implementation detail of the map, not an architectural
   change to the instruction.

   *Isolation is a host-VA property, not an ISA mechanism.* The guest's
   hart address space is, by EEI definition, 4 GiB of real memory aliased
   everywhere, with nothing sensitive in it. The runtime's execution
   context lives in *host* virtual addresses above 4 GiB — outside the
   guest's RISC-V address space entirely — so no guest pointer can reach
   it. The 4 GiB ceiling on guest memory is a consequence of this map.

   Within one 4 GiB alias period the region is partitioned:

   - `[0, CODE_BASE)` — **unmapped null guard**. `CODE_BASE` is
     `0x0040_0000` (4 MiB), so a `PC = 0` fetch or a null data deref faults
     instead of hitting valid memory.
   - `[CODE_BASE, DATA_BASE)` — **code**, read-only, so `PC = CODE_BASE +
     byte_offset`. Capped at `MAX_CODE_SIZE` (252 MiB = `DATA_BASE −
     CODE_BASE`).
   - `[DATA_BASE, 4 GiB)` — **data** (stack/ro/rw/heap), with `DATA_BASE =
     0x1000_0000` (256 MiB).

   `auipc`, `jal`, `jalr`, and branches compute over real PC values exactly
   as RV defines. A guest can read its own code bytes (`auipc` + load, the
   PIC idiom); it cannot write them (read-only mapping). Code is
   position-independent (PC-relative internal control flow), so it maps at
   `CODE_BASE` regardless of the linked address. Data is addressed
   absolutely, so the transpiler **relocates** data references: it folds
   data-referencing `auipc` pairs to absolute `lui`+lo12 and shifts every
   data address — the folds *and* any initialised absolute data pointers —
   by `+DATA_BASE`, from the linker's `[0, extent)` layout to the runtime
   `[DATA_BASE, …)` mapping. Code-referencing `auipc` pairs stay native
   (PC-relative against `CODE_BASE`). Code low gives the null guard; data
   high keeps the whole data region contiguous above code.

2. **Standard `ecall` and `ebreak` are handled by an unconditional fatal
   trap.**

   Standard `ecall`/`ebreak` (and `c.ebreak`) **decode and execute as
   ordinary instructions**; the EEI's defined response is to **terminate**
   (ε = panic). The spec delegates exactly this: it gives the EEI "the
   handling of any interrupts or exceptions raised during execution
   including environment calls" (§1.2), and an EEI whose environment-call
   handler is "terminate" is conforming (a bare-metal EEI with no services
   is such an EEI); `ebreak`, defined to "return control to a debugging
   environment" (§2.9), in an EEI with no debugger returns control to the
   environment, which terminates.

   PVM2's host functionality does **not** ride on standard `ecall` — it
   lives in custom-0 (`ecalli` carries the 20-bit selector that standard
   `ecall` lacks; `ecall.jar` is the management op). So standard
   `ecall`/`ebreak` are simply "always panic," which is also the defensive
   behavior of refusing a stray standard environment call. This is a
   **fatal** trap (instance discarded, not resumed) — PVM2's "faults stay
   terminal" rule (see [Basic-block boundaries](#basic-block-boundaries-bb_starts)).

3. **Misaligned loads and stores are fully supported.**

   As permitted by RV §2.1.6 ("Load and Store Instructions"), PVM2 is an
   EEI that **guarantees full support for misaligned loads and stores** —
   no address-misaligned exception is ever raised. This is one of the two
   options §2.1.6 explicitly offers EEIs ("An EEI may guarantee that
   misaligned loads and stores are fully supported"); PVM2 selects it. We
   additionally implement the **Zicclsm** extension (§4.13) as the standard
   extension-level statement of the same guarantee.

   The RV-spec caveats about "might run extremely slowly" and "not
   guaranteed atomic" don't apply: PVM2 is software-recompiled (x86 handles
   misaligned at near-native speed) and single-threaded (atomicity is
   moot).

4. **`fence` and `fence.i` are no-ops.**

   `fence` orders accesses as seen by *other harts and devices*; `fence.i`
   orders instruction fetch against prior writes (self-modifying code).
   PVM2 is single-threaded, has no I/O bus, and maps code read-only — so
   neither has anything to order. Retiring them as no-ops is *conforming*
   under this configuration, not a semantic change. (Encoding unchanged.)

5. **No CSRs, no privilege levels, no atomics, no FP/vector.**

   These are *optional* — none are part of the RV64E base. PVM2 does not
   implement Zicsr (`csrr*`), the A extension (atomics), privileged modes
   (`mret`/`sret`/`uret`, WFI, SFENCE.VMA), or F/D/Q/V (FP, vector), Zfh,
   Zfa, Zifencei, supervisor/hypervisor. Their encodings therefore decode
   as illegal — the standard reserved-encoding behaviour for an
   unimplemented extension, not a redefinition. The EEI presents a single
   flat privilege environment.

6. **Extension profile.** The standard extensions M, C, Zbb, Zba, Zbs,
   Zicond, Zicclsm apply unchanged from their specs (see
   [Extensions included](#extensions-included)). Selecting an extension set
   is a profile choice.

## Extensions included

The following RV extensions apply to PVM2 unchanged from their standard
specifications.

| ext | name | notes |
|---|---|---|
| M | multiplication / division | `mul`, `mulh`, `mulhu`, `mulhsu`, `mulw`, `div`, `divu`, `rem`, `remu`, `divw`, `divuw`, `remw`, `remuw` |
| C | compressed | 16-bit forms; `c.jr`/`c.jalr`/`c.j` are standard control flow (the `jalr` forms carry the Xjar CFI precondition) |
| Zbb | basic bit manipulation | `clz`, `ctz`, `cpop` + W-variants, `sext.b`, `sext.h`, `zext.h`, `min`, `max`, `minu`, `maxu`, `andn`, `orn`, `xnor`, `rol`, `ror`, `rolw`, `rorw`, `rori`, `roriw`, `rev8`, `orc.b` |
| Zba | shift-add | `sh1add`, `sh2add`, `sh3add` + UW-variants, `add.uw`, `slli.uw` |
| Zbs | single-bit | `bset`, `bclr`, `binv`, `bext` + imm forms |
| Zicond | integer conditional | `czero.eqz`, `czero.nez` |
| Zicclsm | misaligned-access support | per §4.13: implementation guarantees misaligned loads/stores to main memory work. Adds no new instructions; documents the EEI choice in [EEI configuration](#eei-configuration) #3 as a standard extension |

Not included (explicitly): A (atomics), F/D/Q/V (FP, vector), Zfh, Zfa,
Zicsr, Zifencei, supervisor/hypervisor (see
[EEI configuration](#eei-configuration) #5).

## Custom-0 opcodes

*(The `custom-0` major opcode is RV-reserved for custom extensions; these
are the host / control ops of the `Xjar` extension.)* Four operations
occupy the RV `custom-0` opcode slot (`opcode = 0001011`). They are
discriminated by `funct3` (I-type bits [14:12]); other fields are described
per-op.

| funct3 | mnemonic | wire pattern | semantics |
|---:|---|---|---|
| 000 | `trap` | `(funct3=000) (rest=0)` | unconditional execution abort. ε = panic |
| 001 | `ecall.jar` | `(funct3=001) (rest=0)` | jar management op. φ[11] = op-code, φ[12] = subject\|object. Same semantics as PVM opcode 3 today |
| 010 | `ecalli imm` | `(funct3=010) (imm[19:0])` | host-call with 20-bit signed immediate selector. Same semantics as PVM opcode 10 today, with `imm = sext20(imm[19:0])` |
| 100 | `fallthrough` | `(funct3=100) (rest=0)` | structured no-op terminator. Decodes and retires with no effect on architectural state, but acts as a basic-block boundary: the *following* instruction is a `bb_start`. Used by the linker to widen the bb_start set before branch targets that aren't naturally post-terminator |

(`ecall.jar` is named to distinguish it from RV's standard `ecall`. The
standard `ecall`/`ebreak` encodings remain available and decode normally;
the EEI handles them by fatal trap — see
[EEI configuration](#eei-configuration) #2 — so PVM2's host functionality
lives here in custom-0, not on standard `ecall`.)

`funct3 = 011` was `br_table` in the static-dispatch draft; it is now
**reserved** (PVM2 uses plain `jalr`). There is no Image-side jump table:
control flow lives entirely in the instruction stream.

No `sbrk` opcode. Bench guests don't use sbrk (zero static occurrences
across all 12 bench programs). Real services that need dynamic heap growth
call a host function via `ecalli` — no architectural opcode required.

No `cmov_*` opcode either. The four PVM cmov variants are unused in benches
except for `cmov_iz_imm` (0.69%); we let that fall back to a Zicond + or
sequence (~4 RV insns).

## Custom-1 opcode

The entire `custom-1` major opcode (`0101011`) is reserved in PVM2 and
traps at decode. (An earlier draft used it for `callf`; the structured-call
design has since been replaced with plain RISC-V `jal`/`jalr`.) Trapping an
unused custom slot is default behaviour.

## Basic-block boundaries (`bb_starts`)

*(The mechanism behind Xjar CFI — see [The Xjar extension](#the-xjar-extension).)*
PVM2 defines a static set `bb_starts ⊆ valid_pc` that the recompiler and
interpreter treat as basic-block boundaries (gas-check sites, label-emission
sites, valid resume PCs, valid `jalr` targets / Xjar landing pads):

```
bb_starts(code) = {0} ∪ { pc | pc immediately follows a terminator }
```

The set is **derived from the instruction stream**, never from external
metadata — both engines compute it identically by walking `code` and
flagging the byte after each terminator. This is what lets the recompiler
validate untrusted `jalr` targets safely.

**Terminator instructions** (kinds whose successor PC is either undefined
or supplied by a register/branch rather than fallthrough):

- `trap`, `fallthrough`, `ecalli`, `ecall.jar` (custom-0)
- All static branches: `beq`, `bne`, `blt`, `bge`, `bltu`, `bgeu`,
  `c.beqz`, `c.bnez`
- `jal` (any `rd`) and `jalr` (any `rd`), including the compressed `c.j` /
  `c.jr` / `c.jalr` forms
- Any reserved encoding (defensive — a decoder that reaches a reserved
  instruction will trap, so the next instruction must be a fresh block
  start if reached at all)

**Linker invariant.** Every reachable target of a branch or `jal`
(immediates), and every statically-known `jalr` target (call-site function
entries, endpoint entries, `.rodata` code pointers), must be in
`bb_starts`. If a target is not naturally post-terminator, the linker
injects a `fallthrough` immediately before it and re-encodes upstream
branch/`jal`/`auipc` offsets through an offset-map pass. Return sites are
covered for free: a call's `jalr`/`jal` is a terminator, so the instruction
after it is already a block start.

**`ecall`/`ecalli` are forced block starts.** Beyond being terminators
(their successor is a `bb_start`), `ecall.jar` and `ecalli` are *also* block
starts in their own right — each is a singleton gas block, a boundary on
*both* sides. The `bb_starts` derivation adds the `ecall`'s own PC (no
linker `fallthrough` needed — it is already a boundary). This is what makes
an `ecall`'s **own** PC a valid pause point, which the gas model needs: a
host op whose own (compile-time-unknowable) gas charge cannot be met yields
and re-attempts at the `ecall` itself.

**Pause-point constraint.** A `Paused { pc, regs }` execution state must
have `pc ∈ bb_starts`. This holds for *every* way a PVM2 instance can
suspend and later resume, for three distinct reasons:

1. **Host-call resume (the live case).** A pause from a host op (`ecalli` /
   `ecall.jar` — a yield/CALL, or the HALT/`CALL_RESUME` return into the
   caller) resumes at the `next_pc` *after* the host op; since
   `ecalli`/`ecall.jar` are terminators, that `next_pc` is post-terminator
   — a `bb_start`. If instead the host op's **own** (dynamic) gas charge
   cannot be met, it OOG-yields *before* the work and resumes at the
   `ecall`'s **own** PC to re-attempt — also a `bb_start`, because
   `ecall`/`ecalli` are forced block starts (above).
2. **First entry.** A fresh invocation enters at an endpoint's `entry_pc`,
   which the linker invariant places in `bb_starts`. `entry_pc` is
   untrusted Image metadata, so this is enforced lazily, not at admission:
   an entry that is *not* a `bb_start` panics at invocation (both engines —
   the interpreter gates the entry resolve, the recompiler's prologue
   dispatches through the dense table whose non-`bb_start` slots hold the
   panic stub), exactly as for an off-`bb_start` `jalr`.
3. **Out-of-gas.** OOG fires either at an ordinary block's static
   pre-reservation check (at the block's `bb_start`) or at an `ecall`'s
   dynamic charge (at the `ecall`'s own PC — itself a `bb_start`). Either
   way the captured pc is a `bb_start`, and the check is *before* the
   charge, so no gas is spent on the un-entered block / un-run op.

**Faults must stay terminal — this is load-bearing.** The invariant above
holds only because a fault (`panic`, `trap`, and a PVM2-level page fault)
**discards** the instance rather than resuming it. A page fault in
particular would otherwise resume at the *faulting* load/store PC, which is
**mid-block** — breaking both `pc ∈ bb_starts` and the per-block gas
precharge (the same soundness hole the Xjar CFI rule closes). A GP-style
EEI may resume a page fault by supplying the page and re-executing; PVM2
must not. (A host-level read-only page-in or copy-on-write `#PF`, handled
transparently below the PVM2 model by re-executing one native instruction,
is *not* a PVM2-level resume and does not bear on this. RO page-in is a
zero-gas host-level mapping event — its gas is accounted at the CALL.)

`bb_starts` is derived from `code`; it is not part of the wire format.

> *Implementation note.* Today the runtime treats an **uncaught** OOG as a
> hard fault rather than a resumable pause (a *caught* OOG already yields).
> Making uncaught OOG a first-class resumable pause stays sound by reason 3
> above.

## Validation model: structure eager, semantics lazy

PVM2 validates a program in two layers, and the split is load-bearing for
consensus, lazy compilation, and forward-versioning.

**Structure — eager, at deblob.** The Image's *metadata* frames execution:
code *length* (`≤ MAX_CODE_SIZE`), memory-mapping bounds, slot indices,
source-path depth, endpoint indices. A malformed structural field has no
clean execution point to fault on — it would diverge between engines or
fault the host — so it is validated when the untrusted Image is admitted
(the SSZ → Image-cap "deblob"); a malformed Image is rejected with a
diagnostic. This is `O(metadata)` — it never scans the code — so it does
not foreclose lazy compilation.

**Semantics — lazy, at execution.** The *instruction stream* is **not**
screened at admission: any `code` bytes are accepted. An illegal or
reserved encoding (below), an off-`bb_start` `jalr`/`entry_pc` target (Xjar
CFI), and a standard `ecall`/`ebreak` (EEI fatal trap) are all refused
**only when reached**, as `ε = panic`. Both engines apply the identical
check at the identical point; the consensus requirement is that they *agree
on what panics*, not that the bytes were pre-screened.

Why lazy (not an eager deblob scan of the code):

- **Code-as-data.** PVM2 has no instruction bitmask, so a linear validator
  can't tell instructions from data. Arbitrary data trips the reserved
  list constantly (any reg field `∈ {x16..x31}` — bit 4 set — any word
  ending in the FP opcode, …), so an eager scan would reject legitimate
  programs that read PC-relative data. Lazy panic only ever refuses bytes
  that actually *execute*. (The transpiler relocates data to the data
  region, so conformant `.text` is pure instructions — but the runtime
  must not *depend* on that to admit an untrusted blob.)
- **Lazy compilation.** An eager scan is the `O(code)` up-front cost lazy
  compilation exists to avoid; lazy validation pairs with it — a region is
  validated when (if) it is compiled.
- **Forward versioning.** Lazy keeps *admission* independent of the
  instruction set: a future version that adds instructions changes only
  *execution*, so the cap set never forks at admission, and an old runtime
  can give a *defined* outcome for an Image whose declared version it can't
  run (rather than an implicit "panic on unknown encoding"). Extending the
  ISA is still a coordinated hard fork at execution — that part is
  irreducible.

The security requirement is therefore **engine agreement** (both engines
panic on the same bytes, charge the same per-block gas, derive the same
`bb_starts`), not pre-screening: a JIT escape is contained by the ring-3
sandbox, but a *divergence* is not, so the engines must agree.

The producer toolchain *additionally* rejects the reserved encodings below
(and `x3`/`x4`) at build time, with a diagnostic naming the first offending
instruction — a developer-experience convenience on the producer side, not
a consensus admission rule.

## Reserved / EEI-trapped encodings

The following standard RV encodings **panic when reached** (`ε = panic`,
lazy — see [Validation model](#validation-model-structure-eager-semantics-lazy)).
The right column gives the reason — each is either a base/EEI behavior or
an unimplemented-extension reservation, **not** a contradiction of the base
ISA.

| encoding | reason |
|---|---|
| ECALL, EBREAK (standard RV) and `c.ebreak` | EEI fatal-trap handler ([EEI](#eei-configuration) #2) — these decode/execute as standard instructions; the environment terminates |
| Any instruction with rs1, rs2, or rd ∈ {x16..x31} | RV64E base — register does not exist (illegal encoding) |
| All CSR ops (Zicsr): CSRRW/S/C, CSRRWI/SI/CI | unimplemented extension ([EEI](#eei-configuration) #5) |
| All atomics (A): LR.W/D, SC.W/D, AMO* | unimplemented extension ([EEI](#eei-configuration) #5) |
| All privileged ops: MRET, SRET, URET, WFI, SFENCE.VMA | no privilege levels ([EEI](#eei-configuration) #5) |
| Any FP/vector encoding (F, D, Q, V) | unimplemented extensions ([EEI](#eei-configuration) #5) |
| The entire custom-1 major opcode (`0101011`) | unused custom slot |
| custom-0 `funct3 = 011` (the removed `br_table`) | unused custom encoding |

`x3`/`x4` are **not** in this list — they are valid GPRs the runtime
executes (see [Register model](#register-model)); only the jar toolchain
declines to emit them. `auipc`, `jal`, `jalr` (and `c.jr`/`c.jalr`) are
standard PVM2 control flow (`jalr` carries the Xjar CFI precondition). A
reserved encoding above is refused **lazily**: it decodes as illegal/traps
*if executed* (an unreachable one — e.g. in a dead region — never fires).
The producer toolchain rejects them at build with a diagnostic; that
build-time check is a convenience, not the consensus rule (see
[Validation model](#validation-model-structure-eager-semantics-lazy)).

## Spec-version-independent invariants

These hold for every PVM2 conformant implementation:

- **PVM2 is RV64E + Xjar + EEI, with no raw instruction contradictions.**
  An RV decoder + disassembler can render *and correctly interpret* PVM2
  bytes — the control flow is standard RV. Every departure from a stock
  RV64E core is one of: an `Xjar`-extension behavior (landing-pad CFI on
  indirect jumps; the custom-0 host ops), or an EEI configuration choice
  (the aliased memory map; the `ecall`/`ebreak` fatal-trap handler;
  guaranteed misaligned support; `fence` retirement). All are legal RISC-V.
- The aggregate execution result is deterministic for a given program +
  initial state + gas budget. (Same as PVM today.)
- Gas accounting is implementation-independent; the gas-cost table is
  published separately ([gas-cost.md](gas-cost.md)). PVM2
  uses the single-pass pipeline model: per basic block, walk the
  instructions tracking `reg_done[15]` + decode throughput; block cost =
  `max(max_done − 3, 1)`; `x3`/`x4` operands additionally charge the
  memory-spill cost. (Gas is an EEI execution-control policy, outside the
  RV ISA proper; it is what *motivates* the Xjar CFI rule.)

## What this gets you vs RV64E

- **Fully conformant RISC-V.** Same encoding format **and** same
  instruction semantics: any RV tool reads *and* runs PVM2 bytes. Every
  deviation is a recognized RISC-V mechanism — an `Xjar` custom extension
  (whose CFI is the shape of the ratified Zicfilp) or an EEI/profile choice
  — not a contradiction of the base ISA.
- A single small custom extension `Xjar` (landing-pad CFI + four custom-0
  ops: `trap`, `ecall.jar`, `ecalli`, `fallthrough`), each part forced by
  jar's consensus / single-thread / 32-bit-memory constraints, and an EEI
  that is all legal RV64E configuration.
- Standard RV extension story: M, C, Zbb, Zba, Zbs, Zicond, Zicclsm apply
  unchanged. New `Xjar` behavior audits cleanly against "is there a
  standard extension of this shape?"
- Native control flow unlocks the standard `Zcmp`/`Zcmt` push/pop and
  table-jump extensions, and friction-free interop with RV disassemblers,
  debuggers, and analysers.
