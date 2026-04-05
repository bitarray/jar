import Jar.PVM
import Jar.PVM.Decode
import Jar.PVM.Memory
import Jar.Types.Config

/-!
# PVM Instruction Execution — Appendix A

All ~141 PVM opcodes grouped by format category.
Each instruction costs 1 gas. GP Appendix A.
-/

namespace Jar.PVM

-- ============================================================================
-- Step Result
-- ============================================================================

/-- Result of executing one instruction step. -/
inductive StepResult where
  /-- Continue execution: new PC, updated registers, updated memory. -/
  | continue (pc : Nat) (regs : Registers) (mem : Memory) : StepResult
  /-- Halt normally. -/
  | halt : StepResult
  /-- Panic (trap or invalid). -/
  | panic : StepResult
  /-- Page fault at address. -/
  | fault (addr : UInt64) : StepResult
  /-- Host call with function ID and next PC for resumption. -/
  | hostCall (id : UInt64) (regs : Registers) (mem : Memory) (nextPC : Nat) : StepResult

-- ============================================================================
-- Helpers
-- ============================================================================

/-- Get register value (bounds-checked). -/
def getReg (regs : Registers) (r : Fin 13) : UInt64 :=
  if h : r.val < regs.size then regs[r.val] else 0

/-- Set register value (bounds-checked). Returns new register file. -/
def setReg (regs : Registers) (r : Fin 13) (v : UInt64) : Registers :=
  if r.val < regs.size then regs.set! r.val v else regs

/-- Compute next PC (default: advance past current instruction). -/
def nextPC (pc : Nat) (skip : Nat) : Nat := pc + 1 + skip

/-- Dynamic jump validation. GP eq (210).
    Returns target PC or none (panic). -/
def djump (jumpTable : Array UInt32) (addr : UInt64) : Option Nat :=
  let a := addr.toNat % (2^32)
  if a == 0 then none  -- panic
  else if a == 2^32 - 2^16 then some 0  -- halt sentinel (handled by caller)
  else
    let idx := a / Z_A
    if idx == 0 || idx > jumpTable.size then none
    else some (jumpTable[idx - 1]!).toNat

-- Unsigned 32-bit truncation
def trunc32 (x : UInt64) : UInt64 := UInt64.ofNat (x.toNat % (2^32))

-- ============================================================================
-- Rotation helpers
-- ============================================================================

def rotRight64 (x : UInt64) (n : UInt64) : UInt64 :=
  let s := n.toNat % 64
  if s == 0 then x
  else (x >>> UInt64.ofNat s) ||| (x <<< UInt64.ofNat (64 - s))

def rotLeft64 (x : UInt64) (n : UInt64) : UInt64 :=
  let s := n.toNat % 64
  if s == 0 then x
  else (x <<< UInt64.ofNat s) ||| (x >>> UInt64.ofNat (64 - s))

def rotRight32 (x : UInt64) (n : UInt64) : UInt64 :=
  let v := x.toNat % (2^32)
  let s := n.toNat % 32
  if s == 0 then sext32 (UInt64.ofNat v)
  else sext32 (UInt64.ofNat ((v / 2^s + v * 2^(32 - s)) % (2^32)))

def rotLeft32 (x : UInt64) (n : UInt64) : UInt64 :=
  let v := x.toNat % (2^32)
  let s := n.toNat % 32
  if s == 0 then sext32 (UInt64.ofNat v)
  else sext32 (UInt64.ofNat ((v * 2^s + v / 2^(32 - s)) % (2^32)))

-- ============================================================================
-- Signed comparison
-- ============================================================================

def signedLt (a b : UInt64) : Bool := toSigned a < toSigned b
def signedGe (a b : UInt64) : Bool := toSigned a >= toSigned b

def signed32Lt (a b : UInt64) : Bool :=
  toSigned (sext32 a) < toSigned (sext32 b)

-- ============================================================================
-- Signed division (rounds towards zero)
-- ============================================================================

def signedDiv64 (a b : UInt64) : UInt64 :=
  if b == 0 then UInt64.ofNat (2^64 - 1)
  else
    let sa := toSigned a
    let sb := toSigned b
    toUnsigned (sa / sb)

def signedDiv32 (a b : UInt64) : UInt64 :=
  let a32 := a.toNat % (2^32)
  let b32 := b.toNat % (2^32)
  if b32 == 0 then UInt64.ofNat (2^64 - 1)
  else sext32 (UInt64.ofNat ((signedDiv64 (sext 4 (UInt64.ofNat a32)) (sext 4 (UInt64.ofNat b32))).toNat % (2^32)))

def signedRem64 (a b : UInt64) : UInt64 :=
  if b == 0 then a
  else
    let sa := toSigned a
    let sb := toSigned b
    toUnsigned (sa % sb)

def signedRem32 (a b : UInt64) : UInt64 :=
  let a32 := a.toNat % (2^32)
  let b32 := b.toNat % (2^32)
  if b32 == 0 then sext32 (UInt64.ofNat a32)
  else sext32 (UInt64.ofNat ((signedRem64 (sext 4 (UInt64.ofNat a32)) (sext 4 (UInt64.ofNat b32))).toNat % (2^32)))

-- ============================================================================
-- Upper multiplication
-- ============================================================================

def mulUpperUU (a b : UInt64) : UInt64 :=
  UInt64.ofNat ((a.toNat * b.toNat) / 2^64)

def mulUpperSS (a b : UInt64) : UInt64 :=
  let sa := (toSigned a).toInt
  let sb := (toSigned b).toInt
  let prod := sa * sb
  let result := prod / (2^64 : Int)
  toUnsigned (Int64.ofInt result)

def mulUpperSU (a b : UInt64) : UInt64 :=
  let sa := (toSigned a).toInt
  let ub := (b.toNat : Int)
  let prod := sa * ub
  let result := prod / (2^64 : Int)
  toUnsigned (Int64.ofInt result)

-- ============================================================================
-- Bit counting
-- ============================================================================

def popcount64 (x : UInt64) : UInt64 :=
  UInt64.ofNat (Id.run do
    let mut c := 0
    let mut v := x.toNat
    for _ in [:64] do
      c := c + v % 2
      v := v / 2
    return c)

def popcount32 (x : UInt64) : UInt64 :=
  popcount64 (UInt64.ofNat (x.toNat % (2^32)))

def clz64 (x : UInt64) : UInt64 :=
  if x == 0 then 64
  else UInt64.ofNat (Id.run do
    let mut c := 0
    for i in [:64] do
      if x.toNat / 2^(63 - i) % 2 == 1 then return c
      c := c + 1
    return c)

def clz32 (x : UInt64) : UInt64 :=
  let v := x.toNat % (2^32)
  if v == 0 then 32
  else UInt64.ofNat (Id.run do
    let mut c := 0
    for i in [:32] do
      if v / 2^(31 - i) % 2 == 1 then return c
      c := c + 1
    return c)

def ctz64 (x : UInt64) : UInt64 :=
  if x == 0 then 64
  else UInt64.ofNat (Id.run do
    let mut c := 0
    for i in [:64] do
      if x.toNat / 2^i % 2 == 1 then return c
      c := c + 1
    return c)

def ctz32 (x : UInt64) : UInt64 :=
  let v := x.toNat % (2^32)
  if v == 0 then 32
  else UInt64.ofNat (Id.run do
    let mut c := 0
    for i in [:32] do
      if v / 2^i % 2 == 1 then return c
      c := c + 1
    return c)

def reverseBytes64 (x : UInt64) : UInt64 :=
  UInt64.ofNat (Id.run do
    let mut r := 0
    for i in [:8] do
      let b := x.toNat / 2^(8 * i) % 256
      r := r + b * 2^(8 * (7 - i))
    return r)

-- ============================================================================
-- Arithmetic shift right
-- ============================================================================

def ashr64 (x : UInt64) (s : Nat) : UInt64 :=
  let shift := s % 64
  toUnsigned (toSigned x / Int64.ofInt (2^shift : Int))

def ashr32 (x : UInt64) (s : Nat) : UInt64 :=
  let v := sext 4 (UInt64.ofNat (x.toNat % (2^32)))
  let shift := s % 32
  sext32 (UInt64.ofNat ((ashr64 v shift).toNat % (2^32)))

-- ============================================================================
-- Single-Step Execution — GP Ψ₁
-- ============================================================================

/-- Execute one PVM instruction. GP Appendix A.
    Takes current state, returns step result. -/
def executeStep (prog : ProgramBlob) (pc : Nat) (regs : Registers) (mem : Memory)
    : StepResult :=
  let code := prog.code
  let skip := skipDistance prog.bitmask pc
  let npc := nextPC pc skip
  -- Read opcode with bitmask validation (GP eq A.19)
  let bitmaskValid := bitmaskGet prog.bitmask pc
  let opcode := if pc < code.size then code.get! pc |>.toNat else 0
  -- If bitmask is not set at pc, treat as invalid instruction → panic
  if !bitmaskValid then .panic
  else
  match opcode with
  -- ========== No-arg (0-2) ==========
  | 0 => .panic  -- trap
  | 1 => .continue npc regs mem  -- fallthrough
  | 2 => .continue npc regs mem  -- unlikely (v0.8.0: gas hint, no semantic effect)

  -- ========== One-immediate (10) ==========
  | 10 =>  -- ecalli: host call
    let imm := extractOneImm code pc skip
    .hostCall imm regs mem npc

  -- ========== Reg + Imm64 (20) ==========
  | 20 =>  -- load_imm_64
    let r := regA code pc
    let imm := extractImm64 code pc skip
    .continue npc (setReg regs r imm) mem

  -- ========== Two-immediate store (30-33) ==========
  | 30 | 31 | 32 | 33 =>  -- store_imm_u{8,16,32,64}
    let (addr, val) := extractTwoImm code pc skip
    let n := match opcode with | 30 => 1 | 31 => 2 | 32 => 4 | _ => 8
    match writeMemBytes mem addr val n with
    | .ok m' => .continue npc regs m'
    | .panic => .panic
    | .fault a => .fault a

  -- ========== Offset jump (40) ==========
  | 40 =>  -- jump
    let target := extractOffset code pc skip
    .continue target.toNat regs mem

  -- ========== Reg + Imm (50-62) ==========
  | 50 =>  -- jump_ind
    let r := regA code pc
    let imm := extractImm code pc skip 2
    let addr := getReg regs r + imm
    match djump prog.jumpTable addr with
    | none => .panic
    | some 0 => .halt
    | some t => .continue t regs mem

  | 51 =>  -- load_imm
    let r := regA code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs r imm) mem

  | 52 | 53 | 54 | 55 | 56 | 57 | 58 =>  -- load_{u8,i8,u16,i16,u32,i32,u64}
    let r := regA code pc
    let imm := extractImm code pc skip 2
    let addr := imm
    let result := match opcode with
      | 52 => readU8 mem addr
      | 53 => readI8 mem addr
      | 54 => readU16 mem addr
      | 55 => readI16 mem addr
      | 56 => readU32 mem addr
      | 57 => readI32 mem addr
      | _  => readU64 mem addr
    match result with
    | .ok v => .continue npc (setReg regs r v) mem
    | .panic => .panic
    | .fault a => .fault a

  | 59 | 60 | 61 | 62 =>  -- store_{u8,u16,u32,u64}
    let r := regA code pc
    let imm := extractImm code pc skip 2
    let addr := imm
    let val := getReg regs r
    let n := match opcode with | 59 => 1 | 60 => 2 | 61 => 4 | _ => 8
    match writeMemBytes mem addr val n with
    | .ok m' => .continue npc regs m'
    | .panic => .panic
    | .fault a => .fault a

  -- ========== Reg + 2-imm store (70-73) ==========
  | 70 | 71 | 72 | 73 =>  -- store_imm_ind_{u8,u16,u32,u64}
    let (r, immOff, immVal) := extractRegTwoImm code pc skip
    let addr := getReg regs r + immOff
    let n := match opcode with | 70 => 1 | 71 => 2 | 72 => 4 | _ => 8
    match writeMemBytes mem addr immVal n with
    | .ok m' => .continue npc regs m'
    | .panic => .panic
    | .fault a => .fault a

  -- ========== Reg + Imm + Offset (80-90) ==========
  | 80 =>  -- load_imm_jump
    let (r, imm, target) := extractRegImmOffset code pc skip
    .continue target.toNat (setReg regs r imm) mem

  | 81 | 82 | 83 | 84 | 85 | 86 | 87 | 88 | 89 | 90 =>
    -- branch_{eq,ne,lt_u,le_u,ge_u,gt_u,lt_s,le_s,ge_s,gt_s}_imm
    let (r, imm, target) := extractRegImmOffset code pc skip
    let rv := getReg regs r
    let taken := match opcode with
      | 81 => rv == imm
      | 82 => rv != imm
      | 83 => rv < imm
      | 84 => rv <= imm
      | 85 => rv >= imm
      | 86 => rv > imm
      | 87 => signedLt rv imm
      | 88 => toSigned rv <= toSigned imm
      | 89 => signedGe rv imm
      | _  => toSigned rv > toSigned imm  -- 90
    if taken then .continue target.toNat regs mem
    else .continue npc regs mem

  -- ========== Two-reg (100-111) ==========
  | 100 =>  -- move_reg
    let rD := regA code pc
    let rA := regB code pc
    -- (move_reg tracing removed)
    .continue npc (setReg regs rD (getReg regs rA)) mem

  | 101 =>  -- sbrk
      let rD := regA code pc
      let rA := regB code pc
      let (mem', addr) := sbrk mem (getReg regs rA)
      .continue npc (setReg regs rD addr) mem'

  | 102 => let rD := regA code pc; let rA := regB code pc
    .continue npc (setReg regs rD (popcount64 (getReg regs rA))) mem
  | 103 => let rD := regA code pc; let rA := regB code pc
    .continue npc (setReg regs rD (popcount32 (getReg regs rA))) mem
  | 104 => let rD := regA code pc; let rA := regB code pc
    .continue npc (setReg regs rD (clz64 (getReg regs rA))) mem
  | 105 => let rD := regA code pc; let rA := regB code pc
    .continue npc (setReg regs rD (clz32 (getReg regs rA))) mem
  | 106 => let rD := regA code pc; let rA := regB code pc
    .continue npc (setReg regs rD (ctz64 (getReg regs rA))) mem
  | 107 => let rD := regA code pc; let rA := regB code pc
    .continue npc (setReg regs rD (ctz32 (getReg regs rA))) mem
  | 108 => let rD := regA code pc; let rA := regB code pc  -- sign_extend_8
    .continue npc (setReg regs rD (sext 1 (getReg regs rA))) mem
  | 109 => let rD := regA code pc; let rA := regB code pc  -- sign_extend_16
    .continue npc (setReg regs rD (sext 2 (getReg regs rA))) mem
  | 110 => let rD := regA code pc; let rA := regB code pc  -- zero_extend_16
    .continue npc (setReg regs rD (UInt64.ofNat ((getReg regs rA).toNat % (2^16)))) mem
  | 111 => let rD := regA code pc; let rA := regB code pc  -- reverse_bytes
    .continue npc (setReg regs rD (reverseBytes64 (getReg regs rA))) mem

  -- ========== Two-reg + imm (120-161) ==========
  -- Store indirect (120-123)
  | 120 | 121 | 122 | 123 =>
    let rA := regA code pc
    let rB := regB code pc
    let imm := extractImm code pc skip 2
    let addr := getReg regs rB + imm
    let val := getReg regs rA
    let n := match opcode with | 120 => 1 | 121 => 2 | 122 => 4 | _ => 8
    match writeMemBytes mem addr val n with
    | .ok m' => .continue npc regs m'
    | .panic => .panic
    | .fault a => .fault a

  -- Load indirect (124-130)
  | 124 | 125 | 126 | 127 | 128 | 129 | 130 =>
    let rA := regA code pc
    let rB := regB code pc
    let imm := extractImm code pc skip 2
    let addr := getReg regs rB + imm
    let result := match opcode with
      | 124 => readU8 mem addr
      | 125 => readI8 mem addr
      | 126 => readU16 mem addr
      | 127 => readI16 mem addr
      | 128 => readU32 mem addr
      | 129 => readI32 mem addr
      | _   => readU64 mem addr  -- 130
    match result with
    | .ok v =>
      .continue npc (setReg regs rA v) mem
    | .panic => .panic
    | .fault a => .fault a

  -- ALU 32-bit with immediate (131-146)
  | 131 =>  -- add_imm_32
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (sext32 (trunc32 (getReg regs rB + imm)))) mem
  | 132 =>  -- and_imm
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (getReg regs rB &&& imm)) mem
  | 133 =>  -- xor_imm
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (getReg regs rB ^^^ imm)) mem
  | 134 =>  -- or_imm
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (getReg regs rB ||| imm)) mem
  | 135 =>  -- mul_imm_32
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (sext32 (trunc32 (getReg regs rB * imm)))) mem
  | 136 =>  -- set_lt_u_imm
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    let v := if getReg regs rB < imm then 1 else 0
    .continue npc (setReg regs rA v) mem
  | 137 =>  -- set_lt_s_imm
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    let v := if signedLt (getReg regs rB) imm then 1 else 0
    .continue npc (setReg regs rA v) mem
  | 138 =>  -- shlo_l_imm_32
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    let s := imm.toNat % 32
    .continue npc (setReg regs rA (sext32 (trunc32 (getReg regs rB <<< UInt64.ofNat s)))) mem
  | 139 =>  -- shlo_r_imm_32
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    let s := imm.toNat % 32
    .continue npc (setReg regs rA (sext32 (UInt64.ofNat ((getReg regs rB).toNat % (2^32) / 2^s)))) mem
  | 140 =>  -- shar_r_imm_32
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (ashr32 (getReg regs rB) (imm.toNat))) mem
  | 141 =>  -- neg_add_imm_32
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (sext32 (trunc32 (imm + trunc32 (0 - getReg regs rB))))) mem
  | 142 =>  -- set_gt_u_imm
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    let v := if getReg regs rB > imm then 1 else 0
    .continue npc (setReg regs rA v) mem
  | 143 =>  -- set_gt_s_imm
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    let v := if toSigned (getReg regs rB) > toSigned imm then 1 else 0
    .continue npc (setReg regs rA v) mem
  | 144 =>  -- shlo_l_imm_alt_32: A = sext32((imm << (B mod 32)) mod 2^32)
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    let s := (getReg regs rB).toNat % 32
    .continue npc (setReg regs rA (sext32 (trunc32 (imm <<< UInt64.ofNat s)))) mem
  | 145 =>  -- shlo_r_imm_alt_32
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    let s := (getReg regs rB).toNat % 32
    .continue npc (setReg regs rA (sext32 (UInt64.ofNat (imm.toNat % (2^32) / 2^s)))) mem
  | 146 =>  -- shar_r_imm_alt_32
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (ashr32 imm ((getReg regs rB).toNat))) mem

  -- Conditional moves with immediate (147-148)
  | 147 =>  -- cmov_iz_imm: A = (B == 0) ? imm : A
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    let v := if getReg regs rB == 0 then imm else getReg regs rA
    .continue npc (setReg regs rA v) mem
  | 148 =>  -- cmov_nz_imm: A = (B != 0) ? imm : A
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    let v := if getReg regs rB != 0 then imm else getReg regs rA
    .continue npc (setReg regs rA v) mem

  -- 64-bit ALU with immediate (149-161)
  | 149 =>  -- add_imm_64
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (getReg regs rB + imm)) mem
  | 150 =>  -- mul_imm_64
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (getReg regs rB * imm)) mem
  | 151 =>  -- shlo_l_imm_64
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (getReg regs rB <<< UInt64.ofNat (imm.toNat % 64))) mem
  | 152 =>  -- shlo_r_imm_64
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (getReg regs rB >>> UInt64.ofNat (imm.toNat % 64))) mem
  | 153 =>  -- shar_r_imm_64
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (ashr64 (getReg regs rB) (imm.toNat))) mem
  | 154 =>  -- neg_add_imm_64
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (imm + (0 - getReg regs rB))) mem
  | 155 =>  -- shlo_l_imm_alt_64
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (imm <<< UInt64.ofNat ((getReg regs rB).toNat % 64))) mem
  | 156 =>  -- shlo_r_imm_alt_64
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (imm >>> UInt64.ofNat ((getReg regs rB).toNat % 64))) mem
  | 157 =>  -- shar_r_imm_alt_64
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (ashr64 imm ((getReg regs rB).toNat))) mem
  | 158 =>  -- rot_r_64_imm
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (rotRight64 (getReg regs rB) imm)) mem
  | 159 =>  -- rot_r_64_imm_alt
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (rotRight64 imm (getReg regs rB))) mem
  | 160 =>  -- rot_r_32_imm
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (rotRight32 (getReg regs rB) imm)) mem
  | 161 =>  -- rot_r_32_imm_alt
    let rA := regA code pc; let rB := regB code pc
    let imm := extractImm code pc skip 2
    .continue npc (setReg regs rA (rotRight32 imm (getReg regs rB))) mem

  -- ========== Two-reg + offset branches (170-175) ==========
  | 170 | 171 | 172 | 173 | 174 | 175 =>
    let (rA, rB, target) := extractTwoRegOffset code pc skip
    let a := getReg regs rA
    let b := getReg regs rB
    let taken := match opcode with
      | 170 => a == b
      | 171 => a != b
      | 172 => a < b
      | 173 => signedLt a b
      | 174 => a >= b
      | _   => signedGe a b  -- 175
    if taken then .continue target.toNat regs mem
    else .continue npc regs mem

  -- ========== Two-reg + two-imm (180) ==========
  | 180 =>  -- load_imm_jump_ind
    let (rA, rB, immX, immY) := extractTwoRegTwoImm code pc skip
    let regs' := setReg regs rA immX
    let addr := getReg regs rB + immY
    match djump prog.jumpTable addr with
    | none => .panic
    | some 0 => .halt
    | some t => .continue t regs' mem

  -- ========== Three-reg (190-230) ==========
  | 190 =>  -- add_32
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (sext32 (trunc32 (getReg regs rA + getReg regs rB')))) mem
  | 191 =>  -- sub_32
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (sext32 (trunc32 (getReg regs rA + (0 - getReg regs rB'))))) mem
  | 192 =>  -- mul_32
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (sext32 (trunc32 (getReg regs rA * getReg regs rB')))) mem
  | 193 =>  -- div_u_32
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    let a := (getReg regs rA).toNat % (2^32)
    let b := (getReg regs rB').toNat % (2^32)
    let v := if b == 0 then UInt64.ofNat (2^64 - 1) else sext32 (UInt64.ofNat (a / b))
    .continue npc (setReg regs rD v) mem
  | 194 =>  -- div_s_32
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (signedDiv32 (getReg regs rA) (getReg regs rB'))) mem
  | 195 =>  -- rem_u_32
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    let a := (getReg regs rA).toNat % (2^32)
    let b := (getReg regs rB').toNat % (2^32)
    let v := if b == 0 then sext32 (UInt64.ofNat a) else sext32 (UInt64.ofNat (a % b))
    .continue npc (setReg regs rD v) mem
  | 196 =>  -- rem_s_32
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (signedRem32 (getReg regs rA) (getReg regs rB'))) mem
  | 197 =>  -- shlo_l_32
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    let s := (getReg regs rB').toNat % 32
    .continue npc (setReg regs rD (sext32 (trunc32 (getReg regs rA <<< UInt64.ofNat s)))) mem
  | 198 =>  -- shlo_r_32
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    let s := (getReg regs rB').toNat % 32
    let v := (getReg regs rA).toNat % (2^32)
    .continue npc (setReg regs rD (sext32 (UInt64.ofNat (v / 2^s)))) mem
  | 199 =>  -- shar_r_32
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (ashr32 (getReg regs rA) ((getReg regs rB').toNat))) mem

  | 200 =>  -- add_64
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (getReg regs rA + getReg regs rB')) mem
  | 201 =>  -- sub_64
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (getReg regs rA + (0 - getReg regs rB'))) mem
  | 202 =>  -- mul_64
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (getReg regs rA * getReg regs rB')) mem
  | 203 =>  -- div_u_64
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    let b := getReg regs rB'
    let v := if b == 0 then UInt64.ofNat (2^64 - 1) else getReg regs rA / b
    .continue npc (setReg regs rD v) mem
  | 204 =>  -- div_s_64
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (signedDiv64 (getReg regs rA) (getReg regs rB'))) mem
  | 205 =>  -- rem_u_64
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    let b := getReg regs rB'
    let v := if b == 0 then getReg regs rA else getReg regs rA % b
    .continue npc (setReg regs rD v) mem
  | 206 =>  -- rem_s_64
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (signedRem64 (getReg regs rA) (getReg regs rB'))) mem
  | 207 =>  -- shlo_l_64
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (getReg regs rA <<< UInt64.ofNat ((getReg regs rB').toNat % 64))) mem
  | 208 =>  -- shlo_r_64
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (getReg regs rA >>> UInt64.ofNat ((getReg regs rB').toNat % 64))) mem
  | 209 =>  -- shar_r_64
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (ashr64 (getReg regs rA) ((getReg regs rB').toNat))) mem

  -- Bitwise (210-212)
  | 210 =>  -- and
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (getReg regs rA &&& getReg regs rB')) mem
  | 211 =>  -- xor
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (getReg regs rA ^^^ getReg regs rB')) mem
  | 212 =>  -- or
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (getReg regs rA ||| getReg regs rB')) mem

  -- Upper multiplication (213-215)
  | 213 =>  -- mul_upper_s_s
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (mulUpperSS (getReg regs rA) (getReg regs rB'))) mem
  | 214 =>  -- mul_upper_u_u
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (mulUpperUU (getReg regs rA) (getReg regs rB'))) mem
  | 215 =>  -- mul_upper_s_u
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (mulUpperSU (getReg regs rA) (getReg regs rB'))) mem

  -- Comparisons (216-217)
  | 216 =>  -- set_lt_u
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (if getReg regs rA < getReg regs rB' then 1 else 0)) mem
  | 217 =>  -- set_lt_s
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (if signedLt (getReg regs rA) (getReg regs rB') then 1 else 0)) mem

  -- Conditional moves (218-219)
  | 218 =>  -- cmov_iz: D = (B == 0) ? A : D
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    let v := if getReg regs rB' == 0 then getReg regs rA else getReg regs rD
    .continue npc (setReg regs rD v) mem
  | 219 =>  -- cmov_nz: D = (B != 0) ? A : D
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    let v := if getReg regs rB' != 0 then getReg regs rA else getReg regs rD
    .continue npc (setReg regs rD v) mem

  -- Rotations (220-223)
  | 220 =>  -- rot_l_64
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (rotLeft64 (getReg regs rA) (getReg regs rB'))) mem
  | 221 =>  -- rot_l_32
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (rotLeft32 (getReg regs rA) (getReg regs rB'))) mem
  | 222 =>  -- rot_r_64
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (rotRight64 (getReg regs rA) (getReg regs rB'))) mem
  | 223 =>  -- rot_r_32
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (rotRight32 (getReg regs rA) (getReg regs rB'))) mem

  -- Inverted bitwise (224-226)
  | 224 =>  -- and_inv: D = A & ~B
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (getReg regs rA &&& (UInt64.ofNat (2^64 - 1) ^^^ getReg regs rB'))) mem
  | 225 =>  -- or_inv: D = A | ~B
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (getReg regs rA ||| (UInt64.ofNat (2^64 - 1) ^^^ getReg regs rB'))) mem
  | 226 =>  -- xnor: D = ~(A ^ B)
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    .continue npc (setReg regs rD (UInt64.ofNat (2^64 - 1) ^^^ (getReg regs rA ^^^ getReg regs rB'))) mem

  -- Min/Max (227-230)
  | 227 =>  -- max (signed)
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    let a := getReg regs rA; let b := getReg regs rB'
    .continue npc (setReg regs rD (if signedGe a b then a else b)) mem
  | 228 =>  -- max_u
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    let a := getReg regs rA; let b := getReg regs rB'
    .continue npc (setReg regs rD (if a >= b then a else b)) mem
  | 229 =>  -- min (signed)
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    let a := getReg regs rA; let b := getReg regs rB'
    .continue npc (setReg regs rD (if signedLt a b then a else b)) mem
  | 230 =>  -- min_u
    let rA := regA code pc; let rB' := regB code pc; let rD := regD code pc
    let a := getReg regs rA; let b := getReg regs rB'
    .continue npc (setReg regs rD (if a <= b then a else b)) mem

  -- ========== Unknown opcode: panic ==========
  | _ => .panic

-- ============================================================================
-- Opcode Name Lookup (for instruction tracing)
-- ============================================================================

/-- Human-readable opcode name for tracing. -/
def opcodeName (op : Nat) : String :=
  match op with
  | 0 => "trap" | 1 => "fallthrough" | 10 => "ecalli"
  | 20 => "load_imm_64"
  | 30 => "store_imm_u8" | 31 => "store_imm_u16" | 32 => "store_imm_u32" | 33 => "store_imm_u64"
  | 40 => "jump"
  | 50 => "jump_ind" | 51 => "load_imm"
  | 52 => "load_u8" | 53 => "load_i8" | 54 => "load_u16" | 55 => "load_i16"
  | 56 => "load_u32" | 57 => "load_i32" | 58 => "load_u64"
  | 59 => "store_u8" | 60 => "store_u16" | 61 => "store_u32" | 62 => "store_u64"
  | 70 => "store_imm_ind_u8" | 71 => "store_imm_ind_u16" | 72 => "store_imm_ind_u32" | 73 => "store_imm_ind_u64"
  | 80 => "load_imm_jump"
  | 81 => "branch_eq_imm" | 82 => "branch_ne_imm" | 83 => "branch_lt_u_imm"
  | 84 => "branch_le_u_imm" | 85 => "branch_ge_u_imm" | 86 => "branch_gt_u_imm"
  | 87 => "branch_lt_s_imm" | 88 => "branch_le_s_imm" | 89 => "branch_ge_s_imm"
  | 90 => "branch_gt_s_imm"
  | 100 => "move_reg" | 101 => "sbrk"
  | 102 => "popcount64" | 103 => "popcount32" | 104 => "clz64" | 105 => "clz32"
  | 106 => "ctz64" | 107 => "ctz32"
  | 108 => "sign_extend_8" | 109 => "sign_extend_16" | 110 => "zero_extend_16"
  | 111 => "reverse_bytes"
  | 120 => "store_ind_u8" | 121 => "store_ind_u16" | 122 => "store_ind_u32" | 123 => "store_ind_u64"
  | 124 => "load_ind_u8" | 125 => "load_ind_i8" | 126 => "load_ind_u16" | 127 => "load_ind_i16"
  | 128 => "load_ind_u32" | 129 => "load_ind_i32" | 130 => "load_ind_u64"
  | 131 => "add_imm_32" | 132 => "and_imm" | 133 => "xor_imm" | 134 => "or_imm"
  | 135 => "mul_imm_32" | 136 => "set_lt_u_imm" | 137 => "set_lt_s_imm"
  | 138 => "shlo_l_imm_32" | 139 => "shlo_r_imm_32" | 140 => "shar_r_imm_32"
  | 141 => "neg_add_imm_32" | 142 => "set_gt_u_imm" | 143 => "set_gt_s_imm"
  | 144 => "shlo_l_imm_alt_32" | 145 => "shlo_r_imm_alt_32" | 146 => "shar_r_imm_alt_32"
  | 147 => "cmov_iz_imm" | 148 => "cmov_nz_imm"
  | 149 => "add_imm_64" | 150 => "mul_imm_64"
  | 151 => "shlo_l_imm_64" | 152 => "shlo_r_imm_64" | 153 => "shar_r_imm_64"
  | 154 => "neg_add_imm_64"
  | 155 => "shlo_l_imm_alt_64" | 156 => "shlo_r_imm_alt_64" | 157 => "shar_r_imm_alt_64"
  | 158 => "rot_r_64_imm" | 159 => "rot_r_64_imm_alt"
  | 160 => "rot_r_32_imm" | 161 => "rot_r_32_imm_alt"
  | 170 => "branch_eq" | 171 => "branch_ne"
  | 172 => "branch_lt_u" | 173 => "branch_lt_s" | 174 => "branch_ge_u" | 175 => "branch_ge_s"
  | 180 => "load_imm_jump_ind"
  | 190 => "add_32" | 191 => "sub_32" | 192 => "mul_32"
  | 193 => "div_u_32" | 194 => "div_s_32" | 195 => "rem_u_32" | 196 => "rem_s_32"
  | 197 => "shlo_l_32" | 198 => "shlo_r_32" | 199 => "shar_r_32"
  | 200 => "add_64" | 201 => "sub_64" | 202 => "mul_64"
  | 203 => "div_u_64" | 204 => "div_s_64" | 205 => "rem_u_64" | 206 => "rem_s_64"
  | 207 => "shlo_l_64" | 208 => "shlo_r_64" | 209 => "shar_r_64"
  | 210 => "and" | 211 => "xor" | 212 => "or"
  | 213 => "mul_upper_s_s" | 214 => "mul_upper_u_u" | 215 => "mul_upper_s_u"
  | 216 => "set_lt_u" | 217 => "set_lt_s"
  | 218 => "cmov_iz" | 219 => "cmov_nz"
  | 220 => "rot_l_64" | 221 => "rot_l_32" | 222 => "rot_r_64" | 223 => "rot_r_32"
  | 224 => "and_inv" | 225 => "or_inv" | 226 => "xnor"
  | 227 => "max_s" | 228 => "max_u" | 229 => "min_s" | 230 => "min_u"
  | n => s!"op{n}"

end Jar.PVM
