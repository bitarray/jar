# PVM2 spec — differential against PVM (jar1)

Companion to [rv64e-xjar-eei.md](rv64e-xjar-eei.md). That doc
specifies PVM2 from the RV side; this one specifies it from the
PVM side. Every PVM jar1 opcode is listed with what happens to it
in PVM2.

The **architecture is mostly unchanged**: the same 13 hot registers
used by jar-produced programs (within RV64E's full 15-GPR file), the
same 4 GiB guest memory period now specified as a 2^32-fold alias,
the gas metering shape, and the host-call mechanism. PVM2 uses **plain
RISC-V control flow**: function calls are `jal`/`auipc+jalr`, returns
are `jalr` (`c.jr ra`), and PC is a real low-4 GiB virtual address
(code mapped read-only at `CODE_BASE`). PVM's single-global-jump-
table `jump_ind` dispatch becomes a native `jalr`; the only runtime
divergence is that a `jalr` target must be a basic-block start
(validated when it executes — see
[rv64e-xjar-eei.md](rv64e-xjar-eei.md) §8). An earlier draft
routed all calls/returns through a custom `br_table` backed by
`Image.jump_table`; that static-dispatch model has been removed.
The wire encoding adopts RV+C for the ~97 ops with strict 1:1
mappings, keeps the jar-specific operations in the RV custom-0
slot, and drops everything else.

## Status legend

- **KEEP (R)** — same architectural semantics, new encoding is the
  corresponding standard RV instruction.
- **KEEP (R, CF)** — control-flow op, encoded as the standard RV
  instruction; PC is a real virtual address (code mapped at
  `CODE_BASE`), same as RV.
- **KEEP (custom-0)** — kept, but moved to RV custom-0 space.
- **DROP (static)** — removed from PVM2 because the corresponding
  PVM dynamic-dispatch opcode has no direct analogue; the linker
  lowers the source pattern to native RV control flow (`jal` /
  `auipc+jalr`, with `jalr` targets validated against the
  basic-block-start set at runtime).
- **DROP** — removed from the PVM2 spec. If the operation is ever
  needed, software lowers it to a sequence of standard RV ops.
- **DROP (fallback: …)** — removed; expected RV lowering shown.

## Per-opcode mapping (all 141 jar1 opcodes)

### No-arg (0–3)

| op | name | PVM2 status | notes |
|---:|---|---|---|
| 0 | `trap` | KEEP (custom-0) | funct3 `000` |
| 1 | `fallthrough` | KEEP (custom-0) | funct3 `100`. Repurposed: PVM's gas-hint nop is now PVM2's bb_start-widening terminator (no architectural state change, but the *next* instruction is a bb_start) |
| 2 | `unlikely` | DROP (fallback: `c.nop`) | gas hint only, no semantic effect |
| 3 | `ecall` (jar) | KEEP (custom-0) | funct3 `001`, semantically unchanged |

### One-immediate (10)

| op | name | PVM2 status | notes |
|---:|---|---|---|
| 10 | `ecalli` | KEEP (custom-0) | funct3 `010`, 20-bit signed immediate |

### One reg + 8-byte imm (20)

| op | name | PVM2 status | notes |
|---:|---|---|---|
| 20 | `load_imm_64` | DROP (fallback: `lui + addi + slli + addi` or compressed where smaller) | unused in benches; not worth a custom op |

### Two immediates / store-imm-direct (30–33)

| op | name | PVM2 status | notes |
|---:|---|---|---|
| 30 | `store_imm_u8` | DROP (fallback: `li tmp, val; sb tmp, off(x0)`) | unused in benches |
| 31 | `store_imm_u16` | DROP | unused |
| 32 | `store_imm_u32` | DROP | unused |
| 33 | `store_imm_u64` | DROP | unused |

### One offset / unconditional jump (40)

| op | name | PVM2 status | notes |
|---:|---|---|---|
| 40 | `jump` | KEEP (R, CF) | RV `jal x0, off`. Optionally `c.j off` when in range |

### One reg + one imm (50–62)

| op | name | PVM2 status | notes |
|---:|---|---|---|
| 50 | `jump_ind` | KEEP (R, CF) | RV `jalr x0, rs1, 0` (indirect jump). PVM validated the target against a global jump-table; PVM2 validates it against the basic-block-start set at runtime. See [rv64e-xjar-eei.md](rv64e-xjar-eei.md) §8 |
| 51 | `load_imm` | KEEP (R) | RV `addi rd, x0, imm` (= `li`). With C, `c.li` (2 B) when imm fits 6-bit |
| 52 | `load_u8` | KEEP (R) | RV `lbu rd, imm(x0)` |
| 53 | `load_i8` | KEEP (R) | RV `lb rd, imm(x0)` |
| 54 | `load_u16` | KEEP (R) | RV `lhu rd, imm(x0)` |
| 55 | `load_i16` | KEEP (R) | RV `lh rd, imm(x0)` |
| 56 | `load_u32` | KEEP (R) | RV `lwu rd, imm(x0)` |
| 57 | `load_i32` | KEEP (R) | RV `lw rd, imm(x0)` |
| 58 | `load_u64` | KEEP (R) | RV `ld rd, imm(x0)` |
| 59 | `store_u8` | KEEP (R) | RV `sb rs, imm(x0)` |
| 60 | `store_u16` | KEEP (R) | RV `sh rs, imm(x0)` |
| 61 | `store_u32` | KEEP (R) | RV `sw rs, imm(x0)` |
| 62 | `store_u64` | KEEP (R) | RV `sd rs, imm(x0)` |

### One reg + two imm / store-imm-ind (70–73)

| op | name | PVM2 status | notes |
|---:|---|---|---|
| 70 | `store_imm_ind_u8` | DROP (fallback: `li tmp, val; sb tmp, off(rA)`) | 75 occurrences in benches; JIT can peephole `li + sb` → `mov [mem], imm8` |
| 71 | `store_imm_ind_u16` | DROP | unused |
| 72 | `store_imm_ind_u32` | DROP | unused |
| 73 | `store_imm_ind_u64` | DROP (fallback: `li tmp, val; sd tmp, off(rA)`) | 65 occurrences |

### One reg + imm + offset (80–90)

| op | name | PVM2 status | notes |
|---:|---|---|---|
| 80 | `load_imm_jump` | KEEP (R, CF) | a direct call: native RV `jal ra, callee` (4 B), or `auipc ra, hi; jalr ra, ra, lo` for far targets. `ra` holds the real return VA (`code_base + next_pc`); the callee returns with `jalr x0, ra, 0` (`c.jr ra`) |
| 81 | `branch_eq_imm` | DROP (fallback: imm=0 → `c.beqz`; else `li tmp; beq rA, tmp, off`) | rare |
| 82 | `branch_ne_imm` | DROP (fallback: imm=0 → `c.bnez`; else `li tmp; bne rA, tmp, off`) | rare |
| 83 | `branch_lt_u_imm` | DROP | unused |
| 84 | `branch_le_u_imm` | DROP | unused |
| 85 | `branch_ge_u_imm` | DROP | unused |
| 86 | `branch_gt_u_imm` | DROP | unused |
| 87 | `branch_lt_s_imm` | DROP (fallback: `li tmp; blt rA, tmp, off`) | rare |
| 88 | `branch_le_s_imm` | DROP | unused |
| 89 | `branch_ge_s_imm` | DROP (fallback: `li tmp; bge rA, tmp, off`) | rare |
| 90 | `branch_gt_s_imm` | DROP | unused |

### Two registers (100–111, jar1)

| op | name | PVM2 status | notes |
|---:|---|---|---|
| 100 | `move_reg` | KEEP (R) | RV `addi rd, rs, 0` (= `mv`). With C, `c.mv` (2 B) |
| 101 | `sbrk` | DROP | unused in benches; production heap-grow goes via `ecalli` host fn |
| 102 | `popcount64` | KEEP (R) | RV Zbb `cpop` |
| 103 | `popcount32` | KEEP (R) | RV Zbb `cpopw` |
| 104 | `clz64` | KEEP (R) | RV Zbb `clz` |
| 105 | `clz32` | KEEP (R) | RV Zbb `clzw` |
| 106 | `ctz64` | KEEP (R) | RV Zbb `ctz` |
| 107 | `ctz32` | KEEP (R) | RV Zbb `ctzw` |
| 108 | `sign_extend_8` | KEEP (R) | RV Zbb `sext.b` |
| 109 | `sign_extend_16` | KEEP (R) | RV Zbb `sext.h` |
| 110 | `zero_extend_16` | KEEP (R) | RV Zbb `zext.h` |
| 111 | `reverse_bytes` | KEEP (R) | RV Zbb `rev8` |

### Two reg + one imm (120–161)

#### Loads / stores indirect (120–130)

| op | name | PVM2 status | notes |
|---:|---|---|---|
| 120 | `store_ind_u8` | KEEP (R) | RV `sb rs, imm(rb)` |
| 121 | `store_ind_u16` | KEEP (R) | RV `sh rs, imm(rb)` |
| 122 | `store_ind_u32` | KEEP (R) | RV `sw rs, imm(rb)`. RVC `c.sw` when in range |
| 123 | `store_ind_u64` | KEEP (R) | RV `sd rs, imm(rb)`. RVC `c.sd` when in range |
| 124 | `load_ind_u8` | KEEP (R) | RV `lbu rd, imm(rb)` |
| 125 | `load_ind_i8` | KEEP (R) | RV `lb rd, imm(rb)` |
| 126 | `load_ind_u16` | KEEP (R) | RV `lhu rd, imm(rb)` |
| 127 | `load_ind_i16` | KEEP (R) | RV `lh rd, imm(rb)` |
| 128 | `load_ind_u32` | KEEP (R) | RV `lwu rd, imm(rb)` |
| 129 | `load_ind_i32` | KEEP (R) | RV `lw rd, imm(rb)`. RVC `c.lw` when in range |
| 130 | `load_ind_u64` | KEEP (R) | RV `ld rd, imm(rb)`. RVC `c.ld` when in range |

#### ALU 32-bit + imm (131–146) + cmov-imm (147–148)

| op | name | PVM2 status | notes |
|---:|---|---|---|
| 131 | `add_imm_32` | KEEP (R) | RV `addiw rd, rs, imm`. RVC `c.addiw` when in range |
| 132 | `and_imm` | KEEP (R) | RV `andi rd, rs, imm`. RVC `c.andi` when in range |
| 133 | `xor_imm` | KEEP (R) | RV `xori rd, rs, imm` |
| 134 | `or_imm` | KEEP (R) | RV `ori rd, rs, imm` |
| 135 | `mul_imm_32` | DROP (fallback: `li tmp; mulw rd, rs, tmp`) | unused |
| 136 | `set_lt_u_imm` | KEEP (R) | RV `sltiu rd, rs, imm` |
| 137 | `set_lt_s_imm` | DROP | unused. Fallback: `slti rd, rs, imm` if needed |
| 138 | `shlo_l_imm_32` | DROP | unused. Fallback: `slliw rd, rs, sh` |
| 139 | `shlo_r_imm_32` | KEEP (R) | RV `srliw rd, rs, sh` |
| 140 | `shar_r_imm_32` | DROP | unused. Fallback: `sraiw rd, rs, sh` |
| 141 | `neg_add_imm_32` | DROP | unused |
| 142 | `set_gt_u_imm` | DROP | unused (operand-swap pseudo) |
| 143 | `set_gt_s_imm` | DROP | unused |
| 144 | `shlo_l_imm_alt_32` | DROP | unused (imm-source shift) |
| 145 | `shlo_r_imm_alt_32` | DROP | unused |
| 146 | `shar_r_imm_alt_32` | DROP | unused |
| 147 | `cmov_iz_imm` | DROP (fallback: `li tmp, imm; czero.eqz t1, tmp, rB; czero.nez t2, rA, rB; or rA, t1, t2`) | 472 occurrences; falls back to ~4 RV insns via Zicond. To be measured |
| 148 | `cmov_nz_imm` | DROP | unused |

#### ALU 64-bit + imm (149–161)

| op | name | PVM2 status | notes |
|---:|---|---|---|
| 149 | `add_imm_64` | KEEP (R) | RV `addi rd, rs, imm`. RVC `c.addi`/`c.addi16sp`/`c.li` per range |
| 150 | `mul_imm_64` | DROP (fallback: `li tmp; mul rd, rs, tmp`) | rare |
| 151 | `shlo_l_imm_64` | KEEP (R) | RV `slli`. RVC `c.slli` when in range |
| 152 | `shlo_r_imm_64` | KEEP (R) | RV `srli`. RVC `c.srli` when in range |
| 153 | `shar_r_imm_64` | KEEP (R) | RV `srai`. RVC `c.srai` when in range |
| 154 | `neg_add_imm_64` | DROP | unused |
| 155 | `shlo_l_imm_alt_64` | DROP | unused |
| 156 | `shlo_r_imm_alt_64` | DROP | unused |
| 157 | `shar_r_imm_alt_64` | DROP | unused |
| 158 | `rot_r_64_imm` | KEEP (R) | RV Zbb `rori rd, rs, sh` |
| 159 | `rot_r_64_imm_alt` | DROP | unused (imm-source rotate) |
| 160 | `rot_r_32_imm` | DROP | unused |
| 161 | `rot_r_32_imm_alt` | DROP | unused |

### Two reg + offset / branches (170–175)

| op | name | PVM2 status | notes |
|---:|---|---|---|
| 170 | `branch_eq` | KEEP (R, CF) | RV `beq rs1, rs2, off`. RVC `c.beqz` when rs2=x0 and in range |
| 171 | `branch_ne` | KEEP (R, CF) | RV `bne`. RVC `c.bnez` when rs2=x0 and in range |
| 172 | `branch_lt_u` | KEEP (R, CF) | RV `bltu` |
| 173 | `branch_lt_s` | KEEP (R, CF) | RV `blt` |
| 174 | `branch_ge_u` | KEEP (R, CF) | RV `bgeu` |
| 175 | `branch_ge_s` | KEEP (R, CF) | RV `bge` |

### Two reg + two imm (180)

| op | name | PVM2 status | notes |
|---:|---|---|---|
| 180 | `load_imm_jump_ind` | KEEP (R, CF) | the fused "load-imm + indirect-jump-with-link" pattern: native `auipc+jalr ra` (or a register-indirect `jalr ra, rs1, 0`). The `jalr` target is validated against the basic-block-start set at runtime (§8) — fn-pointer / vtable dispatch works without link-time enumeration |

### Three registers — 32-bit ALU (190–199)

| op | name | PVM2 status | notes |
|---:|---|---|---|
| 190 | `add_32` | DROP | unused (rustc emits 64-bit by default on RV64). Fallback: `addw rd, rs1, rs2` |
| 191 | `sub_32` | DROP | unused. Fallback: `subw` |
| 192 | `mul_32` | DROP | unused. Fallback: `mulw` |
| 193 | `div_u_32` | DROP | unused. Fallback: `divuw` |
| 194 | `div_s_32` | DROP | unused. Fallback: `divw` |
| 195 | `rem_u_32` | DROP | unused. Fallback: `remuw` |
| 196 | `rem_s_32` | DROP | unused. Fallback: `remw` |
| 197 | `shlo_l_32` | DROP | unused. Fallback: `sllw` |
| 198 | `shlo_r_32` | DROP | unused. Fallback: `srlw` |
| 199 | `shar_r_32` | DROP | unused. Fallback: `sraw` |

Note: dropping these is encoding-level only. The fallback RV-W
opcodes (`addw`, `mulw`, etc.) are still valid RV instructions
in PVM2 (since we include the M extension and base 64-bit ALU);
they just aren't called out as "kept PVM ops" here because no
bench guest emits them.

### Three registers — 64-bit ALU (200–209)

| op | name | PVM2 status | notes |
|---:|---|---|---|
| 200 | `add_64` | KEEP (R) | RV `add`. RVC `c.add` when rd=rs1 |
| 201 | `sub_64` | KEEP (R) | RV `sub`. RVC `c.sub` |
| 202 | `mul_64` | KEEP (R) | RV `mul` |
| 203 | `div_u_64` | DROP | unused. Fallback: `divu` |
| 204 | `div_s_64` | DROP | unused. Fallback: `div` |
| 205 | `rem_u_64` | DROP | unused. Fallback: `remu` |
| 206 | `rem_s_64` | DROP | unused. Fallback: `rem` |
| 207 | `shlo_l_64` | KEEP (R) | RV `sll` |
| 208 | `shlo_r_64` | KEEP (R) | RV `srl` |
| 209 | `shar_r_64` | DROP | unused. Fallback: `sra` |

### Three registers — bitwise + upper-mul + slt + cmov (210–219)

| op | name | PVM2 status | notes |
|---:|---|---|---|
| 210 | `and` | KEEP (R) | RV `and`. RVC `c.and` |
| 211 | `xor` | KEEP (R) | RV `xor`. RVC `c.xor` |
| 212 | `or` | KEEP (R) | RV `or`. RVC `c.or` |
| 213 | `mul_upper_s_s` | DROP | unused. Fallback: `mulh` |
| 214 | `mul_upper_u_u` | KEEP (R) | RV `mulhu` |
| 215 | `mul_upper_s_u` | DROP | unused. Fallback: `mulhsu` |
| 216 | `set_lt_u` | KEEP (R) | RV `sltu` |
| 217 | `set_lt_s` | DROP | unused. Fallback: `slt` |
| 218 | `cmov_iz` | DROP (fallback: Zicond `czero.*` + `or` sequence) | unused |
| 219 | `cmov_nz` | DROP | unused |

### Three registers — rotations + inverted-bitwise + min/max (220–230)

| op | name | PVM2 status | notes |
|---:|---|---|---|
| 220 | `rot_l_64` | DROP | unused. Fallback: Zbb `rol` |
| 221 | `rot_l_32` | DROP | unused. Fallback: Zbb `rolw` |
| 222 | `rot_r_64` | DROP | unused. Fallback: Zbb `ror` |
| 223 | `rot_r_32` | DROP | unused. Fallback: Zbb `rorw` |
| 224 | `and_inv` | DROP | unused. Fallback: Zbb `andn` |
| 225 | `or_inv` | DROP | unused. Fallback: Zbb `orn` |
| 226 | `xnor` | DROP | unused. Fallback: Zbb `xnor` |
| 227 | `max_s` | DROP | unused. Fallback: Zbb `max` |
| 228 | `max_u` | DROP | unused. Fallback: Zbb `maxu` |
| 229 | `min_s` | DROP | unused. Fallback: Zbb `min` |
| 230 | `min_u` | DROP | unused. Fallback: Zbb `minu` |

## Tally

| status | count |
|---|---:|
| KEEP (R) | 45 |
| KEEP (R, CF) | 10 (`jump`, `jump_ind`, `load_imm_jump`, `load_imm_jump_ind`, 6 reg-reg branches) |
| KEEP (custom-0) | 4 (`trap`, `fallthrough`, `ecall`, `ecalli`) |
| DROP | 82 |
| **total** | **141** |

So PVM2 has **59 of PVM's 141 opcodes** in its primary encoding
(55 RV + 4 custom-0). The other 82 are either unused (per bench
stats) or have a trivial 1-to-N RV-instruction lowering.

The **4 custom-0 opcodes** (`trap`, `fallthrough`, `ecall.jar`,
`ecalli`) carry the entire "PVM is not RV" semantic content.
Everything else — including all control flow — is standard RV
(with PVM2-Base's divergences applied uniformly).

## Architecture preserved

For clarity, all of these stay the same between PVM and PVM2:

- RV64E's 15 GPRs, with jar-produced programs using the same 13 hot
  registers and `x3`/`x4` valid but host-spilled
- 4 GiB guest memory period, specified as a 2^32-fold alias across the
  RV64E 64-bit address space
- Gas metering model (cost-per-instruction, basic-block accounting)
- Host-call interface (`ecalli` selector → host function dispatch)
- Memory mapping format (pinned slots, initial slots, RW regions),
  plus the code region mapped read-only at `CODE_BASE`

## Architecture changed: dispatch model

PVM has a single global runtime-validated indirect jump
(`jump_ind` / `load_imm_jump_ind`); targets are checked against
a deblob-time `valid_pc` bitmap.

PVM2 uses **plain RISC-V control flow**:

- `jal` / `auipc+jalr` for calls, `jalr` (`c.jr ra`) for returns,
  branches unchanged. `ra` holds a real return VA
  (`code_base + next_pc`), not an opaque handle.
- `auipc`, `jalr`, `c.jr`, `c.jalr` are all standard — they are
  *not* rejected at deblob.
- A `jalr` target is validated against the basic-block-start set
  **at runtime** (the recompiler runs untrusted code and never
  trusts a target table). `jal`/branch targets are immediates,
  validated at recompile time against the same set.
- Indirect dispatch (Rust fn pointers, vtables, switch tables)
  works natively through `jalr` — no link-time target enumeration.

The Image format changes: code is re-encoded as RV+C+custom-0 in
one or more `CodeRegion`s, referenced by a `MappingSource::Code`
mapping that maps the region read-only at `CODE_BASE`; the bitmask
and the jump table / jump-table-offsets are gone (RV+C is
self-describing in length, and `bb_starts` is derived from `code`
by both engines rather than carried on the wire).
