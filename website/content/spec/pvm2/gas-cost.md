# PVM2 — per-instruction gas cost table

PVM2's gas accounting uses the **single-pass pipeline model**. The
canonical definition is the Rust source
([`gas_sim.rs`](https://github.com/jarchain/jar/blob/master/rust/javm-exec/src/gas_sim.rs) +
[`gas_cost.rs`](https://github.com/jarchain/jar/blob/master/rust/javm-exec/src/gas_cost.rs)) plus this
reference doc. (An older Lean formalization under `spec/Jar/JAVM/` is
stale — it predates microkernel v3 and the 15-register file — and is
not authoritative.)
For each basic block, predecode walks the instructions once,
feeding each through
[`GasSimulator`](https://github.com/jarchain/jar/blob/master/rust/javm-exec/src/gas_sim.rs); the
final block cost is `max(max_done − 3, 1)`. This block cost is the
**#1 (execution) component only**, and it is charged **once per block,
at block entry** (the charging discipline — pre-reservation, OOG never
charges, gas never goes negative — is specified in
[gas-cost.md §1](../gas-cost.md)). The block
cost is further scaled by the **#2 memory-access-latency footprint
multiplier** (×1–4) before it is charged; that multiplier is defined in
[gas-cost.md §2](../gas-cost.md). The per-instruction
cost table (`rv_fast_cost`) and the block-driver
(`rv_gas_cost_for_block`) live in
[`rust/javm-exec/src/gas_cost.rs`](https://github.com/jarchain/jar/blob/master/rust/javm-exec/src/gas_cost.rs)
— next to PVM's table, so when PVM is eventually retired the file
shrinks rather than fragments.

The Lean spec for an earlier flat-per-instruction-sum PVM2 gas
model (`spec/Jar/JAVM/GasCostPVM2.lean`) was removed; the canonical
PVM2 gas table is now the Rust source plus this reference doc.

## Pipeline model (single-pass)

State per block: `reg_done[15]` (cycle when each register's value
is ready) + `cycle` (current decode cycle) + `decode_used` (slots
consumed this cycle) + `max_done` (running max completion).

For each instruction in program order:

1. **Decode throughput.** If `decode_used >= 4`, advance `cycle`
   by 1 and reset `decode_used = decode_slots`. Else
   `decode_used += decode_slots`.
2. **Move-reg fast path.** `is_move_reg` instructions propagate
   `reg_done[dst] = reg_done[src]` and skip the rest.
3. **Data dependency.**
   `start = max(cycle, max(reg_done[r] for r in src_mask))`.
4. **Completion.** `done = start + cycles`.
5. **Write back.** `reg_done[r] = done` for every `r` in `dst_mask`.
6. **Track.** `max_done = max(max_done, done)`.

Block cost = `max(max_done − 3, 1)`. The "−3" normalizes the
steady-state pipeline depth (3 stages: decode, dispatch, execute).

Each instruction's `FastCost` carries:

- `cycles` — execution latency
- `decode_slots` — front-end cost (1–4)
- `exec_unit` — informational only; the single-pass model doesn't
  model EU contention (decode throughput subsumes ALU/LOAD/STORE
  contention; MUL/DIV are rare enough that latency already
  serializes them via data deps)
- `src_mask` / `dst_mask` — 15-bit register bitmasks (PVM2's 15
  architectural regs map to bits 0..14, ordered x1, x2, x5..x15,
  then x3, x4 in the two high slots)
- `is_terminator` — ends the block; nothing is decoded after it
- `is_move_reg` — handled in the decode-cycle path; propagates
  `reg_done` without consuming a ROB-equivalent slot

Why single-pass (and not the full ROB / EU-contention model in
`GasCostFull.lean`):

- **Speed.** O(n) per block, one pass over the instructions, no
  inner cycle-by-cycle loop.
- **No slot limit.** Real PVM2 basic blocks can have 100+ RV
  instructions (crypto inner loops). A 32-entry ROB simulator
  would need slot recycling and is a lot more code.
- **EU contention subsumed.** The 4-wide decode bandwidth already
  caps the rate at which ALU/LOAD/STORE-class ops can begin. The
  only contended units in a ROB model are MUL/DIV, and those are
  rare + high-latency enough that data dependencies serialize
  them in practice.

## Per-instruction cost table

The columns below are: **op** (PVM2 mnemonic), **cycles**,
**decode_slots** (range when overlap-dependent), **EU**, **src**
(which RvInst fields contribute to `src_mask`), **dst** (likewise
for `dst_mask`), **term** (terminator flag), **PVM equiv** (the
PVM byte opcode this row mirrors, if any).

### Loads and stores

| op | cy | dec | EU | src | dst | term | PVM equiv |
|---|--:|--:|---|---|---|:-:|---|
| `lb` / `lh` / `lw` / `ld` / `lbu` / `lhu` / `lwu` | 25 | 1 | LOAD | rs1 | rd | | PVM 52..58 / 124..130 |
| `sb` / `sh` / `sw` / `sd` | 25 | 1 | STORE | rs1, rs2 | — | | PVM 59..62 / 120..123 |

### Upper / load-immediate

| op | cy | dec | EU | src | dst | term | PVM equiv |
|---|--:|--:|---|---|---|:-:|---|
| `lui` | 1 | 2 | NONE | — | rd | | PVM 20 `load_imm_64` |

(`addi rd, x0, imm` — used by the linker as the small-immediate
load — bills as the general `addi` row below; there's no special
fast-path.)

### Integer ALU (64-bit)

`decode_slots` = 1 when `rd` overlaps a source register, else 2
(matches PVM's overlap rule).

| op | cy | dec | EU | src | dst | term | PVM equiv |
|---|--:|--:|---|---|---|:-:|---|
| `add`, `sub`, `and`, `or`, `xor` | 1 | 1-2 | ALU | rs1, rs2 | rd | | PVM 200/201/210/211/212 |
| `addi`, `andi`, `ori`, `xori`, `sltiu`, `slli`, `srli`, `slti`, `srai` | 1 | 1-2 | ALU | rs1 | rd | | PVM 132/133/134/149/151..153/158/110 |
| `sll`, `srl`, `sra` (shifts, dec rule = `rs1 == rd`) | 1 | 2-3 | ALU | rs1, rs2 | rd | | PVM 207/208/209 |
| `slt`, `sltu` | 3 | 3 | ALU | rs1, rs2 | rd | | PVM 216/217 |

### Integer ALU (32-bit)

| op | cy | dec | EU | src | dst | term | PVM equiv |
|---|--:|--:|---|---|---|:-:|---|
| `addw`, `subw` | 2 | 2-3 | ALU | rs1, rs2 | rd | | PVM 190/191 |
| `sllw`, `srlw`, `sraw` (dec rule = `rs1 == rd`) | 2 | 3-4 | ALU | rs1, rs2 | rd | | PVM 197/198/199 |
| `addiw`, `slliw`, `srliw`, `sraiw` | 2 | 2-3 | ALU | rs1 | rd | | PVM 131/138/139/140/160 |

### M extension (multiply / divide)

| op | cy | dec | EU | src | dst | term | PVM equiv |
|---|--:|--:|---|---|---|:-:|---|
| `mul` | 3 | 1-2 | MUL | rs1, rs2 | rd | | PVM 202 |
| `mulw` | 4 | 2-3 | MUL | rs1, rs2 | rd | | PVM 192 |
| `mulh`, `mulhu` | 4 | 4 | MUL | rs1, rs2 | rd | | PVM 213/214 |
| `mulhsu` | 6 | 4 | MUL | rs1, rs2 | rd | | PVM 215 |
| `div`, `divu`, `rem`, `remu` + W-variants | 60 | 4 | DIV | rs1, rs2 | rd | | PVM 193..196/203..206 |

### Zbb — basic bit manipulation

| op | cy | dec | EU | src | dst | term | PVM equiv |
|---|--:|--:|---|---|---|:-:|---|
| `clz`, `clzw`, `cpop`, `cpopw`, `sext.b`, `sext.h`, `zext.h`, `rev8`, `orc.b` | 1 | 1 | ALU | rs1 | rd | | PVM 102-105/108/109/111 |
| `ctz`, `ctzw` | 2 | 1 | ALU | rs1 | rd | | PVM 106/107 |
| `min`, `minu`, `max`, `maxu` | 3 | 2-3 | ALU | rs1, rs2 | rd | | PVM 227..230 |
| `andn`, `orn` | 2 | 3 | ALU | rs1, rs2 | rd | | PVM 224/225 |
| `xnor` | 2 | 2-3 | ALU | rs1, rs2 | rd | | PVM 226 |
| `rol`, `ror` (dec rule = `rs1 == rd`) | 1 | 2-3 | ALU | rs1, rs2 | rd | | PVM 220/222 |
| `rori` | 1 | 1-2 | ALU | rs1 | rd | | PVM 158 |
| `rolw`, `rorw` | 2 | 3-4 | ALU | rs1, rs2 | rd | | PVM 221/223 |
| `roriw` | 2 | 2-3 | ALU | rs1 | rd | | (PVM has only 64-bit imm rot) |

### Zba — shift-add

x86's `LEA` family folds these into one cycle.

| op | cy | dec | EU | src | dst | term | PVM equiv |
|---|--:|--:|---|---|---|:-:|---|
| `sh1add`, `sh2add`, `sh3add`, `sh1add.uw`, `sh2add.uw`, `sh3add.uw`, `add.uw` | 1 | 1-2 | ALU | rs1, rs2 | rd | | (no PVM equiv) |
| `slli.uw` | 1 | 1-2 | ALU | rs1 | rd | | (no PVM equiv) |

### Zbs — single-bit

| op | cy | dec | EU | src | dst | term | PVM equiv |
|---|--:|--:|---|---|---|:-:|---|
| `bclr`, `bset`, `binv`, `bext` | 1 | 1-2 | ALU | rs1, rs2 | rd | | (no PVM equiv) |
| `bclri`, `bseti`, `binvi`, `bexti` | 1 | 1-2 | ALU | rs1 | rd | | (no PVM equiv) |

### Zicond — conditional move

| op | cy | dec | EU | src | dst | term | PVM equiv |
|---|--:|--:|---|---|---|:-:|---|
| `czero.eqz`, `czero.nez` | 2 | 2 | ALU | rs1, rs2 | rd | | PVM 218/219 `cmov_*` |

### Control flow

| op | cy | dec | EU | src | dst | term | PVM equiv |
|---|--:|--:|---|---|---|:-:|---|
| `jal rd, imm` (static jump / linker-emitted body of call) | 15 | 1 | ALU | — | rd (if `rd ≠ 0`) | ✓ | PVM 40 `jump` |
| `jalr rd, rs1, imm` (indirect jump / return; replaced `br_table`) | 22 | 1 | ALU | rs1 | — (rd = return PC, untracked) | ✓ | PVM 50 `jump_ind` |
| `beq`, `bne`, `blt`, `bge`, `bltu`, `bgeu` | 20 | 1 | ALU | rs1, rs2 | — | ✓ | PVM 170..175 |

Note: PVM has a 1-cycle fast-path for branches whose target is
opcode `0` (trap) or `2` (unlikely). The PVM2 linker rewrites
trap targets to direct traps, so this fast-path rarely fires; we
use a flat 20 (the PVM default for "live" branches).

### Custom-0 (PVM2-specific)

| op | cy | dec | EU | src | dst | term | PVM equiv |
|---|--:|--:|---|---|---|:-:|---|
| `trap` (funct3=000) | 2 | 1 | NONE | — | — | ✓ | PVM 0 `trap` |
| `ecall.jar` (funct3=001) | 100 | 4 | ALU | — | — | ✓ | PVM 3 `ecall` |
| `ecalli imm` (funct3=010) | 100 | 4 | ALU | — | — | ✓ | PVM 10 `ecalli` |
| `fallthrough` (funct3=100) | 2 | 1 | NONE | — | — | ✓ | PVM 1 `fallthrough` |

Note: `funct3=011` (the former `br_table`) is **reserved** — see
"Reserved encoding" below. PVM2 routes indirect jumps through plain
`jalr` (see "Control flow" above), not a custom table op.

Note: `ecall.jar` and `ecalli` each form their **own gas block** (a forced
block start) and are charged **dynamically** by the kernel, not through the
static per-block preamble — their true cost (a CALL frame, a host op's
work) is unknowable at compile time. The 100-cycle row above is only the
static instruction component (a floor); the kernel adds the actual
materialization cost at runtime, with out-of-gas re-attempting at the
`ecall`'s own PC. For an in-kernel CALL this dynamic charge now also
includes the callee's JIT compile (O(code), per declared code page) and
its eager read-only page-in (one charge per declared 2 MiB unit),
computed statically from the callee Image. See
[gas-cost.md §3 "ecall/ecalli blocks"](../gas-cost.md).

### Fences (no-op)

| op | cy | dec | EU | src | dst | term | PVM equiv |
|---|--:|--:|---|---|---|:-:|---|
| `fence`, `fence.i` | 1 | 1 | NONE | — | — | | (no PVM equiv; PVM2 single-thread) |

### Reserved encoding

If a reserved encoding is reached at runtime it traps. The
simulator still needs a cost row so a pathological program can't
be "free".

| op | cy | dec | EU | src | dst | term | PVM equiv |
|---|--:|--:|---|---|---|:-:|---|
| `Reserved` (any) | 2 | 1 | NONE | — | — | ✓ | — |

## Register mapping

PVM2 has 15 architectural registers (RV64E's full GPR file): `x1`,
`x2`, `x5`..`x15`, plus `x3`, `x4` (with `x0` = zero). They map to
`FastCost::src_mask` / `dst_mask` bits as follows:

| RV reg | role | mask bit |
|---|---|---:|
| `x0` | zero | (no bit; reads contribute no dep, writes have no effect) |
| `x1` (`ra`) | return-idx after linker call-rewrite | 0 |
| `x2` (`sp`) | stack pointer | 1 |
| `x5` (`t0`) | general | 2 |
| `x6` (`t1`) | general | 3 |
| `x7` (`t2`) | general | 4 |
| `x8` (`s0`/`fp`) | general | 5 |
| `x9` (`s1`) | general | 6 |
| `x10` (`a0`) | arg / return value | 7 |
| `x11` (`a1`) | arg | 8 |
| `x12` (`a2`) | arg | 9 |
| `x13` (`a3`) | arg | 10 |
| `x14` (`a4`) | arg | 11 |
| `x15` (`a5`) | arg | 12 |
| `x3` (`gp`) | general (host-spilled; see below) | 13 |
| `x4` (`tp`) | general (host-spilled; see below) | 14 |

`x3`/`x4` occupy the two high slots so the 13 commonly-used registers
keep mask bits 0..12 unchanged — every conformant program (which never
references x3/x4) produces bit-for-bit identical masks, and therefore
identical gas, as before the file grew to 15.

### x3/x4 spill cost

`x3` and `x4` are real registers the runtime executes, but they are
**not guaranteed host-register-resident**: a host with exactly 13
registers (today's x86-64 JIT) holds them in memory and spills on each
access (see [Register model in rv64e-xjar-eei.md](rv64e-xjar-eei.md#register-model)
and the host contract in [portability.md](portability.md)).

Because the worst-case conforming host spills them, the gas model charges
the **memory-spill cost** for every x3/x4 operand **unconditionally** (on
every host, whether or not it actually spills — gas is a spec-fixed upper
bound, so a register-rich host runs faster than charged without affecting
consensus). Concretely: each instruction operand position (rs1, rs2, rd)
that names `x3` or `x4` adds **`mem_cycles`** (= the LOAD/STORE latency,
default 25) to that instruction's `cycles` before it is fed to the
simulator — matching the load/op/store the recompiler's spill path emits.
An instruction touching no x3/x4 operand is charged exactly as its table
row above.

> **Footprint scaling (#2).** The `mem_cycles = 25` here is the **base**
> LOAD/STORE latency at the smallest footprint tier (×1). It is scaled by
> the memory-access footprint multiplier (×1–4, from the Instance's total
> accessible pages) before the block cost is charged — so a memory-heavy
> block in a large declared footprint pays proportionally more. The
> multiplier and tiers are normative in
> [gas-cost.md §2](../gas-cost.md); the x3/x4
> spill charge above scales with it like any other memory operand.

## Reasoning for the non-PVM rows

Some PVM2 instructions have no PVM byte-opcode equivalent
(notably Zba/Zbs and the 32-bit Zbb rotates). Their costs were
chosen to match the underlying x86 native cost the recompiler
emits:

- **Zba shift-add** maps directly to a 1-cycle `LEA` form on
  x86. ALU, 1 cycle, decode_slots follows the overlap rule.
- **Zbs single-bit** lowers to BMI2 `bzhi`/`pdep`-class
  instructions on x86 (single-cycle ALU on Skylake+).
- **Zbb 32-bit rotates** (`rolw`, `rorw`, `roriw`) are
  symmetric with their 64-bit counterparts at +1 cycle (matches
  PVM 32-bit ALU convention).

## Sync between Rust and this doc

The source of truth is
[`rust/javm-exec/src/gas_cost.rs::rv_fast_cost`](https://github.com/jarchain/jar/blob/master/rust/javm-exec/src/gas_cost.rs).
Any change to a row above must update the Rust function and vice
versa. Drift between the two should fail a future conformance
test (TODO once we have one).
