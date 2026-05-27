import Jar.JAVM.GasCost

/-!
# PVM2 Per-Instruction Gas Cost Table

PVM2 uses the same per-instruction cycle-cost model as PVM
(`GasCost.lean`, `GasCostSinglePass.lean`), but keyed by RV opcode
groups instead of PVM single-byte opcodes. Costs for analogous
operations are intentionally identical so that a guest's gas bill
under PVM2 is comparable to its bill under PVM.

The Rust port lives at
`rust/javm-exec/src/rv_predecode.rs::rv_gas_cost`; the two must stay
in sync.

## Cost philosophy

The cost numbers approximate x86 execution cycles for the
JIT-compiled instruction. They mirror PVM's costs 1:1 wherever
PVM has a direct equivalent — the wire encoding changes, but the
backend op is the same on the host CPU, so the cost is the same.

PVM2-only ops (`callf`, `retf`, `fallthrough`) inherit the costs
of their nearest PVM equivalents:

- `callf` → cost of PVM `load_imm_jump` (15) — same call-with-link
  cycle profile.
- `retf` → cost of PVM `jump_ind` (22) — same indirect-return shape
  (native `ret` is a predicted indirect, similar pipeline cost).
- `fallthrough` → cost of PVM `fallthrough` (2) — terminator no-op,
  same gas-block-boundary purpose.

## Opcode groups (mirrors `RvInst` in `rv_instruction.rs`)

This module is the spec-side definition of the table. A full Lean
decoder for PVM2 (RV+C+custom-0+custom-1 → `Pvm2Op`) is a follow-up;
for now we define the cost as a function of opcode kind, with the
Rust port carrying the calibration burden.

| group | members | cycles |
|---|---|---:|
| load | `lb`/`lh`/`lw`/`ld`/`lbu`/`lhu`/`lwu` (+ RVC) | 25 |
| store | `sb`/`sh`/`sw`/`sd` (+ RVC) | 25 |
| branch | `beq`/`bne`/`blt`/`bge`/`bltu`/`bgeu` (+ RVC) | 20 |
| jump | `jal` (rd=0) (+ `c.j`) | 15 |
| call | `callf` (custom-1) | 15 |
| ret | `retf` (custom-0, also `c.jr ra`) | 22 |
| fallthrough | `fallthrough` (custom-0) | 2 |
| trap | `trap` (custom-0) | 2 |
| ecalli | `ecalli` (custom-0) | 100 |
| ecall.jar | `ecall.jar` (custom-0) | 100 |
| load-imm | `addi rd, x0, imm`; `lui` | 1 |
| alu64 | `add`/`sub`/`and`/`or`/`xor`/`sll`/`srl`/`sra`/`slt`/`sltu` and imm forms | 1 |
| alu32 | `addw`/`subw`/`sllw`/`srlw`/`sraw` and imm forms | 2 |
| mul64 | `mul` | 3 |
| mul-upper | `mulh`/`mulhu` | 4 |
| mul-upper-su | `mulhsu` | 6 |
| mul32 | `mulw` | 4 |
| div | `div*`/`rem*` (all 8 variants) | 60 |
| zbb-1cy | `cpop`/`cpopw`/`clz`/`clzw`/`sext.b`/`sext.h`/`zext.h`/`rev8`/`orc.b` | 1 |
| zbb-2cy | `ctz`/`ctzw` | 2 |
| zbb-minmax | `min`/`minu`/`max`/`maxu` | 3 |
| zbb-inv | `andn`/`orn`/`xnor` | 2 |
| zbb-rot64 | `rol`/`ror`/`rori` | 1 |
| zbb-rot32 | `rolw`/`rorw`/`roriw` | 2 |
| zba | `sh1add`/`sh2add`/`sh3add` (+ uw) / `add.uw` / `slli.uw` | 1 |
| zbs | `bclr`/`bset`/`binv`/`bext` (+ imm) | 1 |
| zicond | `czero.eqz`/`czero.nez` | 2 |
| fence | `fence`/`fence.i` | 1 |
| reserved | any rejected encoding (charged in case reached) | 2 |

## Per-block cost

For PVM2, per-block gas cost is the **sum** of per-instruction
costs in the block. (PVM2 does not run the pipeline-aware
single-pass simulator from `GasCostSinglePass.lean`; the simpler
sum model is sufficient because the JIT emits one gas check per
basic block, paying the whole block's cost up front.)

```
blockCostPVM2(block) = Σ instructionCostPVM2(inst) for inst in block
```

This matches PVM's single-pass formula
(`gasCostForBlockSinglePass`) up to the absence of dispatch-width
and EU-contention modeling — both removed because PVM2's static
basic blocks pay their gas exactly once before any instruction in
the block executes, leaving no observable pipeline overlap that
the cost table would need to capture.

## Sync with Rust

The Rust implementation at
`rust/javm-exec/src/rv_predecode.rs::rv_gas_cost` must return the
same number for every opcode group listed above. A diff is the
indicator that one side has drifted.

A future task: emit `Pvm2Op` from a Lean decoder for RV+C bytes,
mirror this table as a total function over `Pvm2Op`, and prove the
sum identity against the Rust port via a conformance test vector.
-/

namespace Jar.JAVM.PVM2

open Jar.JAVM

/-- Opcode groups used by the PVM2 gas table. Mirrors the `match`
arms in `rust/javm-exec/src/rv_predecode.rs::rv_gas_cost`. -/
inductive Pvm2OpKind where
  | load
  | store
  | branch
  | jump
  | call
  | ret
  | fallthrough
  | trap
  | ecalli
  | ecallJar
  | loadImm
  | alu64
  | alu32
  | mul64
  | mulUpper
  | mulUpperSu
  | mul32
  | div
  | zbb1cy
  | zbb2cy
  | zbbMinMax
  | zbbInv
  | zbbRot64
  | zbbRot32
  | zba
  | zbs
  | zicond
  | fence
  | reserved
  deriving BEq, Repr

/-- Cycles per instruction for PVM2. Equals the matching PVM cost
    where one exists; PVM2-only ops inherit from their PVM analogue
    (see module doc).

    Invariant: the Rust port at
    `rust/javm-exec/src/rv_predecode.rs::rv_gas_cost` returns this
    same number for every opcode classified into the corresponding
    `Pvm2OpKind`. -/
def instructionCostPVM2 : Pvm2OpKind → Nat
  | .load        => 25
  | .store       => 25
  | .branch      => 20
  | .jump        => 15
  | .call        => 15
  | .ret         => 22
  | .fallthrough => 2
  | .trap        => 2
  | .ecalli      => 100
  | .ecallJar    => 100
  | .loadImm     => 1
  | .alu64       => 1
  | .alu32       => 2
  | .mul64       => 3
  | .mulUpper    => 4
  | .mulUpperSu  => 6
  | .mul32       => 4
  | .div         => 60
  | .zbb1cy      => 1
  | .zbb2cy      => 2
  | .zbbMinMax   => 3
  | .zbbInv      => 2
  | .zbbRot64    => 1
  | .zbbRot32    => 2
  | .zba         => 1
  | .zbs         => 1
  | .zicond      => 2
  | .fence       => 1
  | .reserved    => 2

/-- Per-block PVM2 gas cost = sum of per-instruction costs.
    `kinds` lists the opcode kind of each instruction in the block,
    in program order. -/
def blockCostPVM2 (kinds : List Pvm2OpKind) : Nat :=
  kinds.foldl (fun acc k => acc + instructionCostPVM2 k) 0

end Jar.JAVM.PVM2
