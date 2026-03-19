import Jar.PVM.GasCost

/-!
# PVM Gas Cost — Single-Pass Model

Alternative to the full pipeline simulation (`GasCostFull.lean`). Computes
per-basic-block gas cost in O(n) time with ~5 operations per instruction,
versus the full model's O(n × k) priority-loop simulation.

## Algorithm

State: `regDone[13]` — the cycle at which each register's value becomes ready.

For each instruction in the basic block:
1. **Decode throughput**: if decode slots would exceed 4/cycle, advance cycle
2. **Data dependency**: `start = max(decode_cycle, max(regDone[src_regs]))`
3. **Completion**: `done = start + latency`
4. **Update**: `regDone[dst_regs] = done`
5. **move_reg**: propagate `regDone[dst] = regDone[src]` (0-cycle frontend op)

Block cost = `max(maxDone - 3, 1)`, same formula as the full model.

## Differences from full pipeline simulation

The full model (`GasCostFull.lean`) tracks a 32-entry reorder buffer with
decode/dispatch/execute/finish states. Key semantic difference:

**Register write shadowing**: when two in-flight instructions write the same
register, the full model makes all subsequent readers wait for BOTH writers
(no register renaming). The single-pass model only tracks the last writer
per register, implicitly modeling register renaming. This is closer to real
out-of-order CPUs with physical register files.

**EU contention** (`cost.execUnits` unused): the full model tracks per-cycle
execution unit availability (4 ALU, 4 LOAD, 4 STORE, 1 MUL, 1 DIV). The
single-pass model omits this entirely because:

- **ALU/LOAD/STORE (4 each)**: decode throughput is 4 instructions/cycle.
  Every instruction consumes 1 ALU slot (see `loadUnit`, `storeUnit`, etc.),
  so you can never dispatch more ALU-consuming instructions per cycle than you
  can decode. The decode constraint subsumes ALU/LOAD/STORE contention.
- **MUL (1 unit)**: two independent multiplies in the same block could contend,
  but multiply latency (3-4 cycles) means data dependencies usually serialize
  them. Independent back-to-back multiplies in a single basic block are rare.
- **DIV (1 unit)**: division latency is 60 cycles. Even if two independent divs
  exist in one block, the first occupies the unit for 60 cycles — but the
  single-pass model already models this via data dependencies (if they share
  registers) or via the latency stacking (independent divs would complete at
  cycle 60 and 61, a ~1.7% difference on a 60-cycle operation).

**Dispatch width**: the full model limits dispatch to 5 instructions/cycle.
The single-pass model omits this constraint.

The single-pass model uses the same instruction cost tables (`instructionCost`),
branch cost function (`branchCost`), and cost formula as the full model.
-/

namespace Jar.PVM

/-- Single-pass simulation state. -/
structure GasSimStateSP where
  ι         : Option Nat    -- current instruction PC (none = done)
  cycle     : Nat           -- current decode cycle
  decodeUsed : Nat          -- decode slots consumed this cycle
  regDone   : Array Nat     -- cycle when each register's value is ready (13 entries)
  maxDone   : Nat           -- max completion cycle across all instructions

/-- Single-pass gas simulation: process one instruction at a time. -/
partial def gasSimSinglePass (code bitmask : ByteArray) (s : GasSimStateSP) : GasSimStateSP :=
  match s.ι with
  | none => s
  | some pc =>
    let cost := instructionCost code bitmask pc
    -- Advance cycle if decode slots would overflow
    let (cycle, decodeUsed) :=
      if s.decodeUsed + cost.decodeSlots > 4
      then (s.cycle + 1, cost.decodeSlots)
      else (s.cycle, s.decodeUsed + cost.decodeSlots)
    let nextι := if cost.isTerminator then none
                 else nextInstrPC bitmask pc
    if cost.isMoveReg then
      -- move_reg: 0-cycle frontend operation, propagate regDone from src to dst
      let regDone := if cost.destRegs.size > 0 && cost.srcRegs.size > 0 then
        let srcReg := cost.srcRegs[0]!
        let srcDone := if srcReg < s.regDone.size then s.regDone[srcReg]! else 0
        cost.destRegs.foldl (fun rd r =>
          if r < rd.size then rd.set! r srcDone else rd) s.regDone
      else s.regDone
      gasSimSinglePass code bitmask { s with ι := nextι, cycle := cycle, decodeUsed := decodeUsed, regDone := regDone }
    else
      -- Start cycle = max(decode_cycle, max(regDone[src_regs]))
      let start := cost.srcRegs.foldl (fun acc r =>
        if r < s.regDone.size then max acc s.regDone[r]! else acc) cycle
      let done := start + cost.cycles
      -- Update regDone for destination registers
      let regDone := cost.destRegs.foldl (fun rd r =>
        if r < rd.size then rd.set! r done else rd) s.regDone
      let maxDone := max s.maxDone done
      gasSimSinglePass code bitmask { ι := nextι, cycle := cycle, decodeUsed := decodeUsed, regDone := regDone, maxDone := maxDone }

/-- Compute gas cost for a basic block using the single-pass model.
    Returns `max(maxDone - 3, 1)`. -/
def gasCostForBlockSinglePass (code bitmask : ByteArray) (startPC : Nat) : Nat :=
  let initState : GasSimStateSP := {
    ι := some startPC
    cycle := 0
    decodeUsed := 0
    regDone := #[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    maxDone := 0
  }
  let finalState := gasSimSinglePass code bitmask initState
  if finalState.maxDone > 3 then finalState.maxDone - 3 else 1

end Jar.PVM
