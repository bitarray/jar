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

Everything not called out here behaves exactly as the
RISC-V unprivileged spec defines it.

### PVM2-Base — vs RV64E

Identical to RV64E (RV64 with 16-register file) except:

1. **Memory address space wraps at 2³²**, not 2⁶⁴.

   Every load and store computes `addr = (rs1 + sext(imm)) & 0xFFFFFFFF`
   before access. The high 32 bits of the address are discarded,
   regardless of what `rs1` holds. This makes the effective memory
   space exactly 4 GiB. Affects `lb`, `lh`, `lw`, `ld`, `lbu`,
   `lhu`, `lwu`, `sb`, `sh`, `sw`, `sd` and all RVC equivalents.

   The 32-bit cap may be tightened in a future profile (e.g. to
   256 MiB via `addr & 0x0FFFFFFF`) without an encoding change.

2. **PC is an instruction-stream byte-offset**, not a memory VA.

   For branches, jumps and JAL link writes, PC is treated as an
   opaque `u32` (or smaller) that indexes into the program's code
   array. PC + signed offset gives the next PC; the result is not
   a memory address and cannot be loaded/stored as one. There is
   no way to materialise a PC value as data (see (3) below).

3. **`AUIPC` is removed.** Encoding `iiiiiiiiiiiiiiiiiiii rd 0010111`
   (RV major opcode `0010111`) is reserved. Programs containing
   AUIPC are rejected at deblob.

4. **`JALR` is removed.** **`c.jr ra` is also removed.**

   PVM2 has no runtime indirect jump. *All* forms of JALR are
   reserved and rejected at deblob:

   - Uncompressed `jalr rd, rs1, imm` (RV major `1100111`).
   - Compressed `c.jr` for every `rs1` — including `c.jr ra`
     (the lld function-return idiom, `0x8082`). The linker rewrites
     every return site to `br_table table_id, ra` (custom-0, see
     below) before the program reaches deblob.
   - Compressed `c.jalr` (any rs1).

   The linker rewrites `lld`-emitted CFG patterns as follows:

   - `auipc + jalr rd, imm` with rd ≠ x0  (direct call)  →
     `addi ra, x0, 2*idx + 1` + `jal x0, callee_entry`
   - `auipc + jalr x0, imm`              (tail call)     →
     `nop` + `jal x0, callee_entry`
     (the linker preserves the caller's already-loaded `ra`)
   - `jal rd, imm` with rd ≠ x0          (direct call)   →
     `addi ra, x0, 2*idx + 1` + `jal x0, callee_entry`
     (4-byte grow to 8 bytes; align-branch-targets pass remaps
     downstream offsets)
   - `c.jr ra` / `jalr x0, x1, 0`         (function return) →
     `br_table table_id, ra` (custom-0 funct3=011)

   `jal` is unchanged from RV when `rd = x0` (static jump).

   The encoded idx (`2*idx + 1`) is the caller's position in the
   callee's `br_table` — see "Custom-0 opcodes" below. PC values
   never appear in guest registers; `ra` carries an opaque idx
   handle that's stable across pause / resume.

   This keeps the whole control-flow graph statically determinable
   in O(code-size). Validators, formal-verification tools, and
   audits can build the complete CFG by walking the bytecode once,
   resolving each `br_table table_id`'s targets from the Image's
   `jump_table` metadata.

5. **`x3` and `x4` are reserved.**

   In RV64E, `x3` (`gp`) and `x4` (`tp`) are general-purpose
   registers populated by the OS/loader. PVM2 has no OS and no
   thread-local storage; these two registers are reserved and
   must not be read or written. Programs that do so are rejected
   at deblob.

   Result: 13 usable architectural registers (`x1`, `x2`,
   `x5`–`x15`), matching today's PVM register count. The encoding
   doesn't change — the 5-bit reg field still uses RV's standard
   layout; `x3`/`x4` are just statically forbidden.

6. **`fence` is a no-op.**

   `fence` and `fence.i` have nothing to order — PVM2 is
   single-threaded with no separate I/O bus. They decode and
   retire as no-ops. (Encoding unchanged.)

7. **No CSR instructions, no privilege levels, no atomics.**

   All `csrrw`/`csrrs`/`csrrc`/`csrrwi`/`csrrsi`/`csrrci`
   (Zicsr), `mret`/`sret`/`uret` (privileged), and atomic
   ops (A extension) are reserved. Decoded as illegal.

8. **Memory alignment.** As permitted by RV §2.1.6 ("Load and
   Store Instructions"), PVM2 is an EEI that **guarantees full
   support for misaligned loads and stores** — no
   address-misaligned exception is ever raised. This is one of
   the two options §2.1.6 explicitly offers EEIs ("An EEI may
   guarantee that misaligned loads and stores are fully
   supported"); PVM2 selects it. We additionally implement the
   **Zicclsm** extension (§4.13) as the standard extension-level
   statement of the same guarantee. Matches today's PVM.

   The RV-spec caveats about "might run extremely slowly" and
   "not guaranteed atomic" don't apply: PVM2 is software-
   recompiled (x86 handles misaligned at near-native speed) and
   single-threaded (atomicity is moot).

9. **Standard `ecall` and `ebreak` opcodes are reserved.**

   PVM2 has its own `ecall` and `trap` operations in custom-0
   space (see below). The standard RV `ecall` / `ebreak` encodings
   are reserved (decoded as illegal) so a future RV CPU running
   PVM2 by mistake doesn't accidentally do something.

## Extensions included

The following RV extensions apply to PVM2 unchanged from their
standard specifications. None of them touch memory addressing
beyond the base ISA's load/store ops, none touch PC semantics,
and none require AUIPC, so PVM2-Base's divergences don't affect
them.

| ext | name | notes |
|---|---|---|
| M | multiplication / division | `mul`, `mulh`, `mulhu`, `mulhsu`, `mulw`, `div`, `divu`, `rem`, `remu`, `divw`, `divuw`, `remw`, `remuw` |
| C | compressed | 16-bit forms; compressed loads/stores inherit PVM2-Base's address mask |
| Zbb | basic bit manipulation | `clz`, `ctz`, `cpop` + W-variants, `sext.b`, `sext.h`, `zext.h`, `min`, `max`, `minu`, `maxu`, `andn`, `orn`, `xnor`, `rol`, `ror`, `rolw`, `rorw`, `rori`, `roriw`, `rev8`, `orc.b` |
| Zba | shift-add | `sh1add`, `sh2add`, `sh3add` + UW-variants, `add.uw`, `slli.uw` |
| Zbs | single-bit | `bset`, `bclr`, `binv`, `bext` + imm forms |
| Zicond | integer conditional | `czero.eqz`, `czero.nez` |
| Zicclsm | misaligned-access support | per §4.13: implementation guarantees misaligned loads/stores to main memory work. Adds no new instructions; documents the EEI choice in (8) above as a standard extension |

Not included (explicitly): A (atomics), F/D/Q/V (FP, vector), Zfh,
Zfa, Zicsr, Zifencei, supervisor/hypervisor.

## Custom-0 opcodes

Five host / control-flow operations occupy the RV `custom-0`
opcode slot (`opcode = 0001011`). They are discriminated by
`funct3` (I-type bits [14:12]); other fields are described per-op.

| funct3 | mnemonic | wire pattern | semantics |
|---:|---|---|---|
| 000 | `trap` | `(funct3=000) (rest=0)` | unconditional execution abort. ε = panic |
| 001 | `ecall.jar` | `(funct3=001) (rest=0)` | jar management op. φ[11] = op-code, φ[12] = subject\|object. Same semantics as PVM opcode 3 today |
| 010 | `ecalli imm` | `(funct3=010) (imm[19:0])` | host-call with 20-bit signed immediate selector. Same semantics as PVM opcode 10 today, with `imm = sext20(imm[19:0])` |
| 011 | `br_table table_id, rs1` | I-type: `(imm[11:0]=table_id) (rs1) (funct3=011) (rd=0)` | indirect-jump terminator. `idx = ((rs1 - 1) >> 1) as u32`; if `idx < table_size[table_id]` then `PC := Image.jump_table[table_id][idx]`, else fall through to next instruction. Used for function returns (caller passes encoded idx in `ra` via `addi ra, x0, 2*idx+1`). `rd` must be 0; nonzero is reserved |
| 100 | `fallthrough` | `(funct3=100) (rest=0)` | structured no-op terminator. Decodes and retires with no effect on architectural state, but acts as a basic-block boundary: the *following* instruction is a `bb_start`. Used by the linker to widen the bb_start set before branch targets that aren't naturally post-terminator |

(Naming `ecall.jar` to distinguish from RV's standard `ecall`,
which remains reserved/illegal.)

**br_table tables live in Image metadata**, *not* in the code
section — `code` stays a contiguous instruction stream (Harvard
discipline). The Image carries:

- `jump_table: Vec<u32>` — flattened sub-tables, concatenated;
  each entry is a PVM2 PC.
- `jump_table_offsets: Vec<u32>` — CSR-style sub-table boundaries.
  Length = `num_tables + 1`; sub-table `t` lives at
  `jump_table[jump_table_offsets[t]..jump_table_offsets[t+1]]`.

Deblob validates that every entry in `jump_table` is in
`bb_starts(code)`, that every `br_table` instruction's `table_id`
is `< num_tables`, and that the offsets array is monotonic non-
decreasing.

The linker groups functions into **weakly-connected components**
in the tail-call graph; every function in a WCC shares the same
`table_id`. This guarantees that an encoded `ra` value passed at
any caller in the chain decodes to the same resume PC at any
br_table along the chain.

No `sbrk` opcode. Bench guests don't use sbrk (zero static
occurrences across all 12 bench programs). Real services that
need dynamic heap growth call a host function via `ecalli` —
no architectural opcode required.

No `cmov_*` opcode either. The four PVM cmov variants are
unused in benches except for `cmov_iz_imm` (0.69%); we'll let
that fall back to a Zicond + or sequence (~4 RV insns) and
measure the actual impact rather than carving custom space for
it preemptively. If it shows up as a hot spot post-conversion,
we can add it then.

## Basic-block boundaries (`bb_starts`)

PVM2 defines a static set `bb_starts ⊆ valid_pc` that the
recompiler treats as basic-block boundaries (gas-check sites,
label-emission sites, valid resume PCs):

```
bb_starts(code) = {0} ∪ { pc | pc immediately follows a terminator }
```

**Terminator instructions** (kinds whose successor PC is
either undefined or supplied by an instruction-internal
mechanism rather than fallthrough):

- `trap`, `fallthrough`, `ecalli`, `ecall.jar`, `br_table`
  (custom-0)
- All static branches: `beq`, `bne`, `blt`, `bge`, `bltu`,
  `bgeu`, `c.beqz`, `c.bnez`
- `jal` (any `rd` — after linker rewriting, only `jal x0` static
  jumps remain in the static-call shape `addi + jal x0, callee`
  and standalone static jumps)
- Any reserved encoding (defensive — a decoder that reaches a
  reserved instruction will trap, and the next instruction
  must therefore be a fresh block start if reached at all)

Note that `br_table` is a terminator even though it can fall
through (out-of-range idx), because its successor PC is supplied
by the instruction itself (table lookup or explicit fallthrough)
rather than by linear fallthrough alone.

**Linker invariant.** Every reachable target of a branch, `jal`,
or `br_table` (each entry of every sub-table in
`Image.jump_table`) must be in `bb_starts`. If a target is not
naturally post-terminator, the linker injects a `fallthrough`
immediately before it and re-encodes all upstream offsets through
an offset-map pass. This is the PVM2 analogue of PVM's
`ensure_branch_targets_are_block_starts`.

**Pause-point constraint.** A `Paused { pc, regs }` execution
state must have `pc ∈ bb_starts`. Out-of-gas can only fire at
the per-block gas check, which sits at the start of a
`bb_start`; hosts that pause-on-yield (when yields are
introduced) must yield at a `bb_start` as well. `bb_starts`
is JIT-derived from `code`; it is not part of the wire
format.

## Forbidden encodings (explicit list)

The following standard RV encodings are reserved and must trap
at decode time:

- AUIPC (any operands)
- JALR — uncompressed (RV major `1100111`), all forms of `c.jr`
  (including `c.jr ra` / `0x8082`), and all forms of `c.jalr`.
  The linker rewrites function returns to `br_table` (custom-0
  funct3=011) before deblob.
- ECALL, EBREAK (standard RV encodings)
- All CSR ops (Zicsr): CSRRW, CSRRS, CSRRC, CSRRWI, CSRRSI, CSRRCI
- All atomics (A extension): LR.W/D, SC.W/D, AMO*
- All privileged ops: MRET, SRET, URET, WFI, SFENCE.VMA
- Any instruction with rs1, rs2, or rd ∈ {x3, x4}
- Any FP/vector encoding (F, D, Q, V extensions)
- The entire custom-1 major opcode (`0101011`)
- `br_table` (custom-0 funct3=011) with `rd ≠ 0`

Programs containing any of these are rejected at deblob with a
diagnostic naming the first offending instruction.

## Spec-version-independent invariants

These hold for every PVM2 conformant implementation:

- An RV decoder + disassembler can render PVM2 bytes (the encoding
  is RV-compatible). The semantics it shows may diverge per the
  list above.
- The aggregate execution result is deterministic for a given
  program + initial state + gas budget. (Same as PVM today.)
- Gas accounting is implementation-independent; the gas-cost
  table is published separately.
  PVM2 uses the single-pass pipeline model from
  `spec/Jar/JAVM/GasCostSinglePass.lean`: per basic block, walk
  the instructions tracking `reg_done[13]` + decode throughput;
  block cost = `max(max_done − 3, 1)`.