import Jar.JAVM
import Jar.JAVM.Decode

/-!
# JAVM Per-Basic-Block Gas Cost Model — Shared Definitions

Per-instruction cost tables and helpers shared by both the full pipeline
simulation (`GasCostFull.lean`) and the single-pass model (`GasCostSinglePass.lean`).
-/

namespace Jar.JAVM

-- ============================================================================
-- Data Structures
-- ============================================================================

/-- Execution unit requirements for an instruction. -/
structure ExecUnits where
  alu  : Nat := 0
  load : Nat := 0
  store : Nat := 0
  mul  : Nat := 0
  div  : Nat := 0
  deriving Inhabited, BEq

-- ============================================================================
-- Execution unit helpers
-- ============================================================================

/-- Check whether `avail` has enough units to satisfy `req`. -/
def ExecUnits.canSatisfy (avail req : ExecUnits) : Bool :=
  avail.alu >= req.alu && avail.load >= req.load && avail.store >= req.store &&
  avail.mul >= req.mul && avail.div >= req.div

/-- Subtract requirements from available units. -/
def ExecUnits.sub (avail req : ExecUnits) : ExecUnits :=
  { alu  := avail.alu - req.alu
    load := avail.load - req.load
    store := avail.store - req.store
    mul  := avail.mul - req.mul
    div  := avail.div - req.div }

-- ============================================================================
-- Branch cost
-- ============================================================================

/-- Branch cost 𝔟: 1 if target is unlikely(2) or trap(0), else 20. -/
def branchCost (code bitmask : ByteArray) (targetPC : Nat) : Nat :=
  -- Check if targetPC is a valid instruction start and read its opcode
  if targetPC < code.size && bitmaskGet bitmask targetPC then
    let opcode := code.get! targetPC |>.toNat
    if opcode == 0 || opcode == 2 then 1 else 20
  else 20

-- ============================================================================
-- Per-instruction cost
-- ============================================================================

/-- Result of instruction cost analysis. -/
structure InstrCost where
  cycles     : Nat
  decodeSlots : Nat
  execUnits  : ExecUnits
  destRegs   : Array Nat
  srcRegs    : Array Nat
  isTerminator : Bool   -- if true, sets ι := none after adding to ROB
  isMoveReg  : Bool     -- if true, handled in frontend only (no ROB entry)

/-- Check if destination overlaps any source register (for ifdstoverlap). -/
private def dstOverlapsSrc (dst : Nat) (srcs : Array Nat) : Bool :=
  srcs.any (· == dst)

/-- Instruction cost lookup.
    Returns cost info based on opcode. Uses code/bitmask for branch target lookup. -/
def instructionCost (code bitmask : ByteArray) (pc : Nat) (memCycles : Nat := 25) : InstrCost :=
  let opcode := if pc < code.size then code.get! pc |>.toNat else 0
  let skip := skipDistance bitmask pc
  -- Helper: extract register indices
  let rA := (regA code pc).val
  let rB := (regB code pc).val
  let rD := (regD code pc).val
  -- Default: non-terminator, not move_reg
  let mkCost (cy dc : Nat) (eu : ExecUnits) (dst src : Array Nat) (term : Bool := false) : InstrCost :=
    { cycles := cy, decodeSlots := dc, execUnits := eu,
      destRegs := dst, srcRegs := src, isTerminator := term, isMoveReg := false }
  let aluUnit : ExecUnits := { alu := 1 }
  let loadUnit : ExecUnits := { alu := 1, load := 1 }
  let storeUnit : ExecUnits := { alu := 1, store := 1 }
  let mulUnit : ExecUnits := { alu := 1, mul := 1 }
  let divUnit : ExecUnits := { alu := 1, div := 1 }
  match opcode with
  -- No-arg instructions
  | 0 => mkCost 2 1 {} #[] #[] true           -- trap
  | 1 => mkCost 2 1 {} #[] #[] true           -- fallthrough
  | 2 => mkCost 40 1 {} #[] #[] true          -- unlikely
  | 10 => mkCost 100 4 aluUnit #[] #[] true   -- ecalli

  -- Control flow
  | 40 => mkCost 15 1 aluUnit #[] #[] true    -- jump
  | 80 =>                                      -- load_imm_jump
    let (r, _, _) := extractRegImmOffset code pc skip
    mkCost 15 1 aluUnit #[r.val] #[] true
  | 50 => mkCost 22 1 aluUnit #[] #[] true    -- jump_ind
  | 180 =>                                     -- load_imm_jump_ind
    let rA' := rA; let rB' := rB
    mkCost 22 1 aluUnit #[rA'] #[rB'] true

  -- Loads (cycles = memCycles, tier-dependent)
  | 52 | 53 | 54 | 55 | 56 | 57 | 58 =>
    mkCost memCycles 1 loadUnit #[rA] #[rB]
  | 124 | 125 | 126 | 127 | 128 | 129 | 130 =>
    mkCost memCycles 1 loadUnit #[rA] #[rB]

  -- Stores (cycles = memCycles, tier-dependent)
  | 59 | 60 | 61 | 62 =>
    mkCost memCycles 1 storeUnit #[] #[rA, rB]
  | 120 | 121 | 122 | 123 =>
    mkCost memCycles 1 storeUnit #[] #[rA, rB]
  | 30 | 31 | 32 | 33 =>
    mkCost memCycles 1 storeUnit #[] #[]
  | 70 | 71 | 72 | 73 =>
    mkCost memCycles 1 storeUnit #[] #[rA]

  -- Load immediates
  | 51 => mkCost 1 1 {} #[rA] #[]             -- load_imm
  | 20 => mkCost 1 2 {} #[rA] #[]             -- load_imm_64

  -- move_reg: decoded in frontend, does NOT enter ROB
  | 100 =>
    { cycles := 0, decodeSlots := 1, execUnits := {},
      destRegs := #[rA], srcRegs := #[rB],
      isTerminator := false, isMoveReg := true }

  -- Branches (reg + imm + offset)
  | 81 | 82 | 83 | 84 | 85 | 86 | 87 | 88 | 89 | 90 =>
    let (_, _, target) := extractRegImmOffset code pc skip
    let bc := branchCost code bitmask target.toNat
    mkCost bc 1 aluUnit #[] #[rA] true

  -- Branches (two-reg + offset)
  | 170 | 171 | 172 | 173 | 174 | 175 =>
    let (_, _, target) := extractTwoRegOffset code pc skip
    let bc := branchCost code bitmask target.toNat
    mkCost bc 1 aluUnit #[] #[rA, rB] true

  -- ALU 64-bit 3-reg: add_64, sub_64, and, xor, or
  | 200 | 201 | 210 | 211 | 212 =>
    let dc := if dstOverlapsSrc rA #[rB, rD] then 1 else 2
    mkCost 1 dc aluUnit #[rA] #[rB, rD]

  -- ALU 32-bit 3-reg: add_32, sub_32
  | 190 | 191 =>
    let dc := if dstOverlapsSrc rA #[rB, rD] then 2 else 3
    mkCost 2 dc aluUnit #[rA] #[rB, rD]

  -- ALU 2-op imm 64-bit
  | 132 | 133 | 134 | 149 | 151 | 152 | 153 | 158 | 110 =>
    let dc := if dstOverlapsSrc rA #[rB] then 1 else 2
    mkCost 1 dc aluUnit #[rA] #[rB]

  -- ALU 2-op imm 32-bit
  | 131 | 138 | 139 | 140 | 160 =>
    let dc := if dstOverlapsSrc rA #[rB] then 2 else 3
    mkCost 2 dc aluUnit #[rA] #[rB]

  -- Trivial 2-op 1-cycle: popcount64, popcount32, clz64, clz32, sign_extend_8, sign_extend_16, zero_extend_16
  | 102 | 103 | 104 | 105 | 108 | 109 =>
    mkCost 1 1 aluUnit #[rA] #[rB]

  -- Trivial 2-op 2-cycle: ctz64, ctz32
  | 106 | 107 =>
    mkCost 2 1 aluUnit #[rA] #[rB]

  -- Shifts 64-bit 3-reg
  | 207 | 208 | 209 | 220 | 222 =>
    let dc := if rB == rA then 2 else 3
    mkCost 1 dc aluUnit #[rA] #[rB, rD]

  -- Shifts 32-bit 3-reg
  | 197 | 198 | 199 | 221 | 223 =>
    let dc := if rB == rA then 3 else 4
    mkCost 2 dc aluUnit #[rA] #[rB, rD]

  -- Shift alt 64-bit
  | 155 | 156 | 157 | 159 =>
    mkCost 1 3 aluUnit #[rA] #[rB]

  -- Shift alt 32-bit
  | 144 | 145 | 146 | 161 =>
    mkCost 2 4 aluUnit #[rA] #[rB]

  -- Comparisons
  | 216 | 217 =>
    mkCost 3 3 aluUnit #[rA] #[rB, rD]
  | 136 | 137 | 142 | 143 =>
    mkCost 3 3 aluUnit #[rA] #[rB]

  -- Conditional moves (3-reg)
  | 218 | 219 =>
    mkCost 2 2 aluUnit #[rA] #[rB, rD]

  -- Conditional moves imm
  | 147 | 148 =>
    mkCost 2 3 aluUnit #[rA] #[rB]

  -- Min/Max
  | 227 | 228 | 229 | 230 =>
    let dc := if dstOverlapsSrc rA #[rB, rD] then 2 else 3
    mkCost 3 dc aluUnit #[rA] #[rB, rD]

  -- and_inv, or_inv
  | 224 | 225 =>
    mkCost 2 3 aluUnit #[rA] #[rB, rD]

  -- xnor
  | 226 =>
    let dc := if dstOverlapsSrc rA #[rB, rD] then 2 else 3
    mkCost 2 dc aluUnit #[rA] #[rB, rD]

  -- neg_add_imm_64
  | 154 =>
    mkCost 2 3 aluUnit #[rA] #[rB]

  -- neg_add_imm_32
  | 141 =>
    mkCost 3 4 aluUnit #[rA] #[rB]

  -- Multiply 64-bit (3-reg)
  | 202 =>
    let dc := if dstOverlapsSrc rA #[rB, rD] then 1 else 2
    mkCost 3 dc mulUnit #[rA] #[rB, rD]
  -- mul_imm_64
  | 150 =>
    let dc := if dstOverlapsSrc rA #[rB] then 1 else 2
    mkCost 3 dc mulUnit #[rA] #[rB]

  -- Multiply 32-bit (3-reg)
  | 192 =>
    let dc := if dstOverlapsSrc rA #[rB, rD] then 2 else 3
    mkCost 4 dc mulUnit #[rA] #[rB, rD]
  -- mul_imm_32
  | 135 =>
    let dc := if dstOverlapsSrc rA #[rB] then 2 else 3
    mkCost 4 dc mulUnit #[rA] #[rB]

  -- Multiply upper
  | 213 | 214 =>
    mkCost 4 4 mulUnit #[rA] #[rB, rD]
  | 215 =>
    mkCost 6 4 mulUnit #[rA] #[rB, rD]

  -- Divide (all)
  | 193 | 194 | 195 | 196 | 203 | 204 | 205 | 206 =>
    mkCost 60 4 divUnit #[rA] #[rB, rD]

  -- Unknown/invalid opcode: default cost
  | _ => mkCost 1 1 {} #[] #[]

-- ============================================================================
-- Simulation helpers
-- ============================================================================

/-- Find the next instruction PC by scanning the bitmask. -/
def nextInstrPC (bitmask : ByteArray) (pc : Nat) : Option Nat :=
  let skip := skipDistance bitmask pc
  let npc := pc + 1 + skip
  if npc < bitmask.size then some npc else none

end Jar.JAVM
