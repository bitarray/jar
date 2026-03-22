import Jar.PVM.GasCost

/-!
# PVM Gas Cost — Full Pipeline Simulation

ROB-based pipeline simulation for per-basic-block gas metering.
Cost = `max(cycles - 3, 1)`.

Pipeline model:
- Reorder buffer: max 32 entries
- 4 decode slots per cycle
- 5 dispatch slots per cycle
- Execution units per cycle: ALU:4, LOAD:4, STORE:4, MUL:1, DIV:1
-/

namespace Jar.PVM

-- ============================================================================
-- Data Structures
-- ============================================================================

/-- ROB entry state. -/
inductive RobState where
  | dec   -- decoded, waiting for dependencies
  | wait  -- dependencies resolved, waiting for dispatch
  | exe   -- executing
  | fin   -- finished
  deriving BEq, Inhabited

/-- Reorder buffer entry. -/
structure RobEntry where
  state     : RobState
  cyclesLeft : Nat
  deps      : Array Nat       -- ROB indices this depends on
  destRegs  : Array Nat       -- registers written
  execUnits : ExecUnits       -- units required to start execution
  deriving Inhabited

/-- Pipeline simulation state. -/
structure GasSimState where
  ι                    : Option Nat       -- current instruction counter (none = done decoding)
  cycles               : Nat              -- cycle counter
  remainingDecodeSlots : Nat              -- reset to 4 each cycle
  remainingStartSlots  : Nat              -- reset to 5 each cycle
  remainingExecUnits   : ExecUnits        -- reset to (4,4,4,1,1) each cycle
  rob                  : Array RobEntry   -- reorder buffer
  deriving Inhabited

-- ============================================================================
-- Simulation helpers
-- ============================================================================

/-- Check if all dependencies of a ROB entry are finished. -/
def allDepsFinished (rob : Array RobEntry) (entry : RobEntry) : Bool :=
  entry.deps.all fun idx =>
    if h : idx < rob.size then rob[idx].state == .fin else true

/-- Can we decode the next instruction? -/
def canDecode (s : GasSimState) : Bool :=
  s.ι.isSome && s.remainingDecodeSlots > 0 && s.rob.size < 32

/-- Decode the next instruction and update state. -/
def decodeInstr (code bitmask : ByteArray) (s : GasSimState) : GasSimState :=
  match s.ι with
  | none => s
  | some pc =>
    let cost := instructionCost code bitmask pc
    -- Compute dependencies: ROB entries whose destRegs overlap with our srcRegs
    let deps := Id.run do
      let mut result : Array Nat := #[]
      for i in [:s.rob.size] do
        let entry := s.rob[i]!
        if entry.state != .fin && entry.destRegs.any (fun dr => cost.srcRegs.any (· == dr)) then
          result := result.push i
      return result
    let remainDec := s.remainingDecodeSlots - cost.decodeSlots
    let nextι := if cost.isTerminator then none
                 else nextInstrPC bitmask pc
    if cost.isMoveReg then
      -- move_reg: handled in frontend, no ROB entry
      { s with ι := nextι, remainingDecodeSlots := remainDec }
    else
      let entry : RobEntry := {
        state := .wait
        cyclesLeft := cost.cycles
        deps := deps
        destRegs := cost.destRegs
        execUnits := cost.execUnits
      }
      { s with
        ι := nextι
        remainingDecodeSlots := remainDec
        rob := s.rob.push entry }

/-- Find index of oldest WAIT entry that is ready to dispatch. -/
def findReadyEntry (s : GasSimState) : Option Nat :=
  let rec go (i : Nat) (fuel : Nat) : Option Nat :=
    match fuel with
    | 0 => none
    | fuel' + 1 =>
      if i >= s.rob.size then none
      else
        let entry := s.rob[i]!
        if entry.state == .wait &&
           allDepsFinished s.rob entry &&
           s.remainingExecUnits.canSatisfy entry.execUnits
        then some i
        else go (i + 1) fuel'
  go 0 s.rob.size

/-- Can we dispatch an instruction? -/
def canDispatch (s : GasSimState) : Bool :=
  s.remainingStartSlots > 0 && (findReadyEntry s).isSome

/-- Dispatch the oldest ready instruction. -/
def dispatch (s : GasSimState) : GasSimState :=
  match findReadyEntry s with
  | none => s
  | some idx =>
    let entry := s.rob[idx]!
    let entry' := { entry with state := .exe }
    { s with
      rob := s.rob.set! idx entry'
      remainingStartSlots := s.remainingStartSlots - 1
      remainingExecUnits := s.remainingExecUnits.sub entry.execUnits }

/-- Check if ROB is all finished (or empty). -/
def robAllFinished (s : GasSimState) : Bool :=
  s.rob.all (·.state == .fin)

/-- Advance one cycle: increment counter, reset slots, tick EXE entries. -/
def advanceCycle (s : GasSimState) : GasSimState :=
  let rob' := s.rob.map fun entry =>
    match entry.state with
    | .exe =>
      if entry.cyclesLeft <= 1 then { entry with state := .fin, cyclesLeft := 0 }
      else { entry with cyclesLeft := entry.cyclesLeft - 1 }
    | _ => entry
  { s with
    cycles := s.cycles + 1
    remainingDecodeSlots := 4
    remainingStartSlots := 5
    remainingExecUnits := { alu := 4, load := 4, store := 4, mul := 1, div := 1 }
    rob := rob' }

-- ============================================================================
-- Main simulation loop
-- ============================================================================

/-- Pipeline simulation with fuel to ensure termination. -/
partial def gasSim (code bitmask : ByteArray) (s : GasSimState) (fuel : Nat := 100000) : GasSimState :=
  match fuel with
  | 0 => s
  | fuel' + 1 =>
    -- Priority 1: Decode next instruction
    if canDecode s then
      gasSim code bitmask (decodeInstr code bitmask s) fuel'
    -- Priority 2: Dispatch oldest ready instruction
    else if canDispatch s then
      gasSim code bitmask (dispatch s) fuel'
    -- Priority 3: Done (no more instructions, ROB all finished)
    else if s.ι.isNone && robAllFinished s then
      s
    -- Priority 4: Advance cycle
    else
      gasSim code bitmask (advanceCycle s) fuel'

-- ============================================================================
-- Top-level gas cost function
-- ============================================================================

/-- Compute gas cost for a basic block using full pipeline simulation.
    Returns `max(cycles - 3, 1)`. -/
def gasCostForBlockFull (code bitmask : ByteArray) (startPC : Nat) : Nat :=
  let initState : GasSimState := {
    ι := some startPC
    cycles := 0
    remainingDecodeSlots := 4
    remainingStartSlots := 5
    remainingExecUnits := { alu := 4, load := 4, store := 4, mul := 1, div := 1 }
    rob := #[]
  }
  let finalState := gasSim code bitmask initState
  if finalState.cycles > 3 then finalState.cycles - 3 else 1

end Jar.PVM
