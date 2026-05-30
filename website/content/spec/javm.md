# JAVM (PVM2) differential spec

JAVM is the virtual machine for JAR's guest execution. This
document specifies **PVM2**, the ISA that is used by JAVM, *as a delta from RV64E + standard extensions*.

## Rationale

The predecessor design of JAVM is based on PVM ISA. Our benchmarks show that the custom PVM ISA is not necessary. With a mostly-standard-compliant RISC-V, we still manage to get a recompiler that is as fast as the old design.

We therefore decide to get closer to standard RISC-V. This has enourmous advantage for JAVM. An already battle-tested ISA is less likely to have unexpected design issues. We'll also have a much easier time to adopt new RISC-V extensions.

We call the new ISA "PVM2". The specification is defined as a small set of differential from RV64E.

## Components

```
PVM2  ::=  PVM2-Base  +  RV-extensions  +  custom-0 ops
```

(Custom-1 was used in an earlier draft for `callf`; PVM2 no longer
uses it — the entire custom-1 major opcode is reserved.)

PVM2 uses **plain RISC-V control flow**: `jal`, `jalr`, `auipc`,
branches, and the compressed `c.j`/`c.jr`/`c.jalr` forms all behave as
the RV spec defines. An earlier draft forbade `jalr`/`auipc` and routed
every call/return through a custom `br_table` backed by Image-side jump
tables; that static-dispatch model has been removed. The single
control-flow divergence that remains is a *runtime* one: an indirect
jump (`jalr`) must land on a basic-block start (Category 1 #2) —
validated when it executes, never trusted from metadata.

## Two kinds of divergence

PVM2's deltas split into two cleanly separated buckets. Keeping them
apart matters: Category 1 is where PVM2 is *not* RV64E; Category 2 is
where PVM2 is a *particular* RV64E.

- **Category 1 — hard spec divergences.** The RISC-V unprivileged spec
  defines a behavior and PVM2 produces a different one — either changing
  the architectural result of an instruction both ISAs accept, or
  removing/constraining a base-ISA instruction in a way the spec does
  not grant an EEI. A stock RV64E core and PVM2 disagree exactly here.
- **Category 2 — platform / EEI configuration.** The spec explicitly
  delegates the choice to the execution-environment interface (EEI),
  the platform memory map, or the extension profile, and PVM2 selects
  one allowed point. A conforming RV64E implementation could legally be
  configured the same way — these are not divergences, just choices.

Anything in neither bucket behaves exactly as the RISC-V unprivileged
spec defines it.

## Category 1 — hard spec divergences

These are the only points where PVM2 contradicts RV64E.

1. **Memory address space wraps at 2³² — data *and* code, uniformly.**

   Every effective address is masked to 32 bits before use; the high
   32 bits are discarded regardless of what the source register holds.
   The mask is applied identically to data and to code targets, so
   there is no addressing path that escapes the 4 GiB window:

   - **Loads / stores:** `addr = (rs1 + sext(imm)) & 0xFFFFFFFF`.
     Affects `lb`, `lh`, `lw`, `ld`, `lbu`, `lhu`, `lwu`, `sb`, `sh`,
     `sw`, `sd` and all RVC equivalents.
   - **`jalr` targets:** `target = (rs1 + sext(imm)) & 0xFFFFFFFF`
     (then `offset = target − CODE_BASE`; see #2). A register value
     ≥ 2³² is truncated to its low 32 bits before the bounds/dispatch
     check, exactly as a data pointer is — *not* rejected for being
     large.

   RV64E computes a full 64-bit effective address; PVM2 does not. This
   is the one divergence that changes the result of an instruction both
   ISAs accept (a load through `rs1 = 0x1_0000_1000` reads `0x1000`,
   not `0x1_0000_1000`).

   The wrap is free on x86/ARM (a 4 GiB host reservation makes the
   guest's u32 space a native VA window) and ~1 op on RISC-V. It does
   real isolation work: it keeps a guest pointer from reaching the
   execution context the runtime maps above 4 GiB.

   The 4 GiB ceiling on the combined code+data map (Category 2 #1) is a
   *consequence* of this wrap, not a separate divergence.

2. **Every indirect-jump (`jalr`) target must be a basic-block start.**

   After the 2³² mask (#1), `jalr` computes `offset = target −
   CODE_BASE` and requires `offset ∈ bb_starts(code)` (see
   [Basic-block boundaries](#basic-block-boundaries-bb_starts)). A
   target that lands mid-block or mid-instruction faults (ε = panic).
   RV64E has no such precondition — any instruction-aligned target is a
   legal jump. PVM2 adds the trap so per-block gas is sound: gas is
   precharged at block entry, so entering a block anywhere but its
   start would bypass the charge.

   This is a *runtime* check, derived from the instruction stream — the
   recompiler runs untrusted code and never trusts a linker-supplied
   target table. In the x86 recompiler the check is *folded into the
   dispatch table*: a dense `offset → native` table whose every
   non-block-start slot holds the panic stub, so `jalr` is a bounds
   check plus the dispatch jump (no separate `bb_starts` lookup) and a
   bad target jumps to the panic stub. `jal` and branch targets are
   immediates and are validated at recompile time against the same set;
   the linker injects `fallthrough` markers (below) so every reachable
   target is a block start.

3. **Standard `ecall` and `ebreak` opcodes are reserved.**

   PVM2 has its own `ecall` and `trap` operations in custom-0 space
   (Category 2 #5). The standard RV `ecall` / `ebreak` encodings are
   reserved (decoded as illegal) so a future RV CPU running PVM2 by
   mistake doesn't accidentally do something.

   *Why Category 1:* the base ISA defines `ecall`/`ebreak` as legal
   SYSTEM instructions (`ecall` makes an environment request); making
   the standard encodings illegal — and relocating the function into
   custom-0 — is the divergence. (Reservation-flavoured: it narrows the
   decode rather than changing an accepted instruction's result.)

4. **`x3` and `x4` are reserved.**

   In RV64E, `x3` (`gp`) and `x4` (`tp`) are general-purpose registers
   populated by the OS/loader. PVM2 has no OS and no thread-local
   storage; these two registers are reserved and must not be read or
   written. Programs that do so are rejected at deblob.

   Result: 13 usable architectural registers (`x1`, `x2`, `x5`–`x15`),
   matching today's PVM register count. The encoding doesn't change —
   the 5-bit reg field still uses RV's standard layout; `x3`/`x4` are
   just statically forbidden.

   *Why Category 1 (borderline):* `gp`/`tp` are reserved by the RISC-V
   psABI *by convention*, so one could argue an EEI reserving them is a
   platform choice (Category 2). It is filed here because the
   *unprivileged ISA* defines all 15 non-zero E-registers as
   general-purpose and has no notion of a platform forbidding a GPR —
   PVM2 narrows what the base ISA permits.

## Category 2 — platform / EEI configuration choices

Each of these is a knob the RISC-V spec hands to the EEI, the platform,
or the extension profile. A conforming RV64E implementation could be
built the same way; PVM2 just fixes the setting.

1. **Memory map: code low (read-only), data high, null guard below.**
   PC is a real low-4 GiB virtual address.

   The EEI determines the mapping of resources into the address space
   and each region's permissions. PVM2 partitions it as:

   - `[0, CODE_BASE)` — **unmapped null guard**. `CODE_BASE` is
     `0x0040_0000` (4 MiB), so a `PC = 0` fetch or a null data deref
     faults instead of hitting valid memory.
   - `[CODE_BASE, DATA_BASE)` — **code**, read-only, so `PC =
     CODE_BASE + byte_offset`. Capped at `MAX_CODE_SIZE` (252 MiB =
     `DATA_BASE − CODE_BASE`).
   - `[DATA_BASE, 4 GiB)` — **data** (stack/ro/rw/heap), with
     `DATA_BASE = 0x1000_0000` (256 MiB).

   `auipc`, `jal`, `jalr`, and branches compute over real PC values
   exactly as RV defines. A guest can read its own code bytes (`auipc`
   + load, the PIC idiom); it cannot write them (read-only mapping).

   Code is position-independent (PC-relative internal control flow), so
   it maps at `CODE_BASE` regardless of the linked address. Data is
   addressed absolutely, so the transpiler **relocates** data
   references: it folds data-referencing `auipc` pairs to absolute
   `lui`+lo12 and shifts every data address — the folds *and* any
   initialised absolute data pointers — by `+DATA_BASE`, from the
   linker's `[0, extent)` layout to the runtime `[DATA_BASE, …)`
   mapping. Code-referencing `auipc` pairs stay native (PC-relative
   against `CODE_BASE`). Code low gives the null guard; data high keeps
   the whole data region contiguous above code rather than wrapping it.

2. **Misaligned loads and stores are fully supported.**

   As permitted by RV §2.1.6 ("Load and Store Instructions"), PVM2 is
   an EEI that **guarantees full support for misaligned loads and
   stores** — no address-misaligned exception is ever raised. This is
   one of the two options §2.1.6 explicitly offers EEIs ("An EEI may
   guarantee that misaligned loads and stores are fully supported");
   PVM2 selects it. We additionally implement the **Zicclsm** extension
   (§4.13) as the standard extension-level statement of the same
   guarantee. Matches today's PVM.

   The RV-spec caveats about "might run extremely slowly" and "not
   guaranteed atomic" don't apply: PVM2 is software-recompiled (x86
   handles misaligned at near-native speed) and single-threaded
   (atomicity is moot).

3. **`fence` and `fence.i` are no-ops.**

   `fence` orders accesses as seen by *other harts and devices*;
   `fence.i` orders instruction fetch against prior writes
   (self-modifying code). PVM2 is single-threaded, has no I/O bus, and
   maps code read-only — so neither has anything to order. Retiring
   them as no-ops is *conforming* under this configuration, not a
   semantic change. (Encoding unchanged.)

4. **No CSRs, no privilege levels, no atomics, no FP/vector.**

   These are *optional* — none are part of the RV64E base. PVM2 does
   not implement Zicsr (`csrr*`), the A extension (atomics), privileged
   modes (`mret`/`sret`/`uret`, WFI, SFENCE.VMA), or F/D/Q/V (FP,
   vector), Zfh, Zfa, Zifencei, supervisor/hypervisor. Their encodings
   therefore decode as illegal — which is the standard reserved-encoding
   behaviour for an unimplemented extension, not a redefinition. The EEI
   presents a single flat privilege environment.

5. **Extension profile and custom-0 ops.**

   - **Standard extensions included:** M, C, Zbb, Zba, Zbs, Zicond,
     Zicclsm — all unchanged from their specs (see
     [Extensions included](#extensions-included)). Selecting an
     extension set is a profile choice.
   - **Custom ops in custom-0:** RISC-V reserves the `custom-0` major
     opcode for non-standard extensions; PVM2 defines four ops there —
     `trap`, `ecall.jar`, `ecalli`, `fallthrough` (see
     [Custom-0 opcodes](#custom-0-opcodes)). Using the spec's
     designated custom space is configuration, not divergence.

## Extensions included

*(Category 2 #5.)* The following RV extensions apply to PVM2 unchanged
from their standard specifications. None of them touch memory
addressing beyond the base ISA's load/store ops (which carry the
Category 1 #1 mask).

| ext | name | notes |
|---|---|---|
| M | multiplication / division | `mul`, `mulh`, `mulhu`, `mulhsu`, `mulw`, `div`, `divu`, `rem`, `remu`, `divw`, `divuw`, `remw`, `remuw` |
| C | compressed | 16-bit forms; compressed loads/stores inherit PVM2-Base's address mask. `c.jr`/`c.jalr`/`c.j` are standard control flow |
| Zbb | basic bit manipulation | `clz`, `ctz`, `cpop` + W-variants, `sext.b`, `sext.h`, `zext.h`, `min`, `max`, `minu`, `maxu`, `andn`, `orn`, `xnor`, `rol`, `ror`, `rolw`, `rorw`, `rori`, `roriw`, `rev8`, `orc.b` |
| Zba | shift-add | `sh1add`, `sh2add`, `sh3add` + UW-variants, `add.uw`, `slli.uw` |
| Zbs | single-bit | `bset`, `bclr`, `binv`, `bext` + imm forms |
| Zicond | integer conditional | `czero.eqz`, `czero.nez` |
| Zicclsm | misaligned-access support | per §4.13: implementation guarantees misaligned loads/stores to main memory work. Adds no new instructions; documents the EEI choice in Category 2 #2 as a standard extension |

Not included (explicitly): A (atomics), F/D/Q/V (FP, vector), Zfh,
Zfa, Zicsr, Zifencei, supervisor/hypervisor. (Category 2 #4.)

## Custom-0 opcodes

*(Category 2 #5 — the `custom-0` major opcode is RV-reserved for
custom extensions.)* Four host / control operations occupy the RV
`custom-0` opcode slot (`opcode = 0001011`). They are discriminated by
`funct3` (I-type bits [14:12]); other fields are described per-op.

| funct3 | mnemonic | wire pattern | semantics |
|---:|---|---|---|
| 000 | `trap` | `(funct3=000) (rest=0)` | unconditional execution abort. ε = panic |
| 001 | `ecall.jar` | `(funct3=001) (rest=0)` | jar management op. φ[11] = op-code, φ[12] = subject\|object. Same semantics as PVM opcode 3 today |
| 010 | `ecalli imm` | `(funct3=010) (imm[19:0])` | host-call with 20-bit signed immediate selector. Same semantics as PVM opcode 10 today, with `imm = sext20(imm[19:0])` |
| 100 | `fallthrough` | `(funct3=100) (rest=0)` | structured no-op terminator. Decodes and retires with no effect on architectural state, but acts as a basic-block boundary: the *following* instruction is a `bb_start`. Used by the linker to widen the bb_start set before branch targets that aren't naturally post-terminator |

(Naming `ecall.jar` to distinguish from RV's standard `ecall`, which
remains reserved/illegal — Category 1 #3.)

`funct3 = 011` was `br_table` in the static-dispatch draft; it is now
**reserved** (PVM2 uses plain `jalr`). There is no Image-side jump
table: control flow lives entirely in the instruction stream.

No `sbrk` opcode. Bench guests don't use sbrk (zero static
occurrences across all 12 bench programs). Real services that
need dynamic heap growth call a host function via `ecalli` —
no architectural opcode required.

No `cmov_*` opcode either. The four PVM cmov variants are
unused in benches except for `cmov_iz_imm` (0.69%); we let
that fall back to a Zicond + or sequence (~4 RV insns).

## Custom-1 opcode

The entire `custom-1` major opcode (`0101011`) is reserved in
PVM2 and traps at decode. (An earlier draft used it for `callf`;
the structured-call design has since been replaced with plain
RISC-V `jal`/`jalr`.) Trapping an unused custom slot is default
behaviour, not a divergence.

## Basic-block boundaries (`bb_starts`)

*(The mechanism behind Category 1 #2.)* PVM2 defines a static set
`bb_starts ⊆ valid_pc` that the recompiler and interpreter treat as
basic-block boundaries (gas-check sites, label-emission sites, valid
resume PCs, valid `jalr` targets):

```
bb_starts(code) = {0} ∪ { pc | pc immediately follows a terminator }
```

The set is **derived from the instruction stream**, never from
external metadata — both engines compute it identically by walking
`code` and flagging the byte after each terminator. This is what lets
the recompiler validate untrusted `jalr` targets safely.

**Terminator instructions** (kinds whose successor PC is either
undefined or supplied by a register/branch rather than fallthrough):

- `trap`, `fallthrough`, `ecalli`, `ecall.jar` (custom-0)
- All static branches: `beq`, `bne`, `blt`, `bge`, `bltu`,
  `bgeu`, `c.beqz`, `c.bnez`
- `jal` (any `rd`) and `jalr` (any `rd`), including the compressed
  `c.j` / `c.jr` / `c.jalr` forms
- Any reserved encoding (defensive — a decoder that reaches a
  reserved instruction will trap, so the next instruction must be a
  fresh block start if reached at all)

**Linker invariant.** Every reachable target of a branch or `jal`
(immediates), and every statically-known `jalr` target (call-site
function entries, endpoint entries, `.rodata` code pointers), must be
in `bb_starts`. If a target is not naturally post-terminator, the
linker injects a `fallthrough` immediately before it and re-encodes
upstream branch/`jal`/`auipc` offsets through an offset-map pass.
Return sites are covered for free: a call's `jalr`/`jal` is a
terminator, so the instruction after it is already a block start.

**Pause-point constraint.** A `Paused { pc, regs }` execution state
must have `pc ∈ bb_starts`. Out-of-gas can only fire at the per-block
gas check, which sits at the start of a `bb_start`. `bb_starts` is
derived from `code`; it is not part of the wire format.

## Forbidden encodings (explicit list)

The following standard RV encodings are reserved and must trap at
decode time. The right column marks which divergence category each
falls under.

| encoding | category |
|---|---|
| ECALL, EBREAK (standard RV) and `c.ebreak` | 1 #3 — base instructions reserved |
| Any instruction with rs1, rs2, or rd ∈ {x3, x4} | 1 #4 — reserved registers |
| All CSR ops (Zicsr): CSRRW/S/C, CSRRWI/SI/CI | 2 #4 — unimplemented extension |
| All atomics (A): LR.W/D, SC.W/D, AMO* | 2 #4 — unimplemented extension |
| All privileged ops: MRET, SRET, URET, WFI, SFENCE.VMA | 2 #4 — no privilege levels |
| Any FP/vector encoding (F, D, Q, V) | 2 #4 — unimplemented extensions |
| The entire custom-1 major opcode (`0101011`) | 2 — unused custom slot |
| custom-0 `funct3 = 011` (the removed `br_table`) | 2 — unused custom encoding |

`auipc`, `jal`, `jalr` (and `c.jr`/`c.jalr`) are **not** forbidden —
they are standard PVM2 control flow. Programs containing any of the
reserved encodings above are rejected at deblob with a diagnostic
naming the first offending instruction.

## Spec-version-independent invariants

These hold for every PVM2 conformant implementation:

- An RV decoder + disassembler can render *and correctly interpret*
  PVM2 bytes — the control flow is standard RV. The only places PVM2
  and a stock RV64E core actually disagree are the **Category 1**
  divergences: the 2³² address wrap (data + code), the `jalr` →
  `bb_start` precondition, and the reserved `ecall`/`ebreak` and
  `x3`/`x4` encodings. Category 2 settings are legal RV64E
  configurations.
- The aggregate execution result is deterministic for a given
  program + initial state + gas budget. (Same as PVM today.)
- Gas accounting is implementation-independent; the gas-cost
  table is published separately ([08-pvm2-gas-cost.md](08-pvm2-gas-cost.md)).
  PVM2 uses the single-pass pipeline model from
  `spec/Jar/JAVM/GasCostSinglePass.lean`: per basic block, walk
  the instructions tracking `reg_done[13]` + decode throughput;
  block cost = `max(max_done − 3, 1)`. (Gas is an EEI execution-control
  policy, outside the RV ISA proper; it is what *motivates* Category 1
  #2.)

## What this gets you vs RV64E

- Same encoding format **and** same control-flow semantics: any RV
  tool reads *and* runs PVM2 bytes (modulo the Category 1 address
  wrap).
- A short, closed list of Category 1 divergences — four items, each
  forced by jar's consensus / single-thread / 32-bit-memory
  constraints, not by bikeshed choice — and a Category 2 list that is
  all legal RV64E configuration.
- Standard RV extension story: M, C, Zbb, Zba, Zbs, Zicond, Zicclsm
  apply unchanged. New extensions audit cleanly against the Category 1
  list.
- 4 custom ops only, all in custom-0: `trap`, `ecall.jar`, `ecalli`,
  `fallthrough`. Everything else is RV.
- Native control flow unlocks the standard `Zcmp`/`Zcmt` push/pop and
  table-jump extensions, and friction-free interop with RV
  disassemblers, debuggers, and analysers.
