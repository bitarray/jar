import Jar.Notation
import Jar.Types.Numerics
import Jar.Types.Constants

/-!
# Polkadot Virtual Machine — Appendix A

RISC-V rv64em-based virtual machine for executing service code.
References: `graypaper/text/pvm.tex`, `graypaper/text/pvm_invocations.tex`,
            `graypaper/text/overview.tex` §4.6.

## Structure
- PVM state: 13 × 64-bit registers, pageable 32-bit-addressable RAM, gas counter
- Exit reasons: halt, panic, out-of-gas, page fault, host-call
- Main invocation function Ψ
- Standard program initialization Y(p, a)
- Host-call dispatch Ψ_H
- Invocation contexts: Ψ_I (is-authorized), Ψ_R (refine), Ψ_A (accumulate)
-/

namespace Jar.PVM

-- ============================================================================
-- Constants — Appendix A
-- ============================================================================

/-- Number of general-purpose registers. -/
def numRegisters : Nat := 13

/-- Page size in bytes. Z_P = 2^12. GP §4.6. -/
def pageSize : Nat := Z_P

/-- Total addressable memory: 2^32 bytes. -/
def memorySize : Nat := 2^32

/-- Number of pages: 2^32 / Z_P. -/
def numPages : Nat := memorySize / pageSize

/-- First accessible address: Z_Z = 2^16. GP §4.6. -/
def initZoneStart : Nat := Z_Z

/-- Maximum input size for standard initialization: Z_I = 2^24. -/
def maxInitInput : Nat := Z_I

-- ============================================================================
-- PVM Types
-- ============================================================================

/-- 𝕣 : Register value. ℕ_{2^64}. GP eq (A.1). -/
abbrev Reg := RegisterValue

/-- Register file: 13 × 64-bit registers. ⟦𝕣⟧_13. -/
abbrev Registers := Array Reg

/-- Page access mode. GP eq (4.17). -/
inductive PageAccess where
  | writable    -- W : page is readable and writable
  | readable    -- R : page is readable only
  | inaccessible -- ∅ : page is not accessible
  deriving BEq, Inhabited

/-- μ : RAM state. GP eq (4.17).
    μ ≡ ⟨μ_v : 𝔹_{2^32}, μ_a : ⟦{W, R, ∅}⟧_p⟩ where p = 2^32 / Z_P. -/
structure Memory where
  /-- μ_v : Memory contents, 2^32 addressable bytes. -/
  value : ByteArray
  /-- μ_a : Per-page access flags. -/
  access : Array PageAccess

/-- PVM exit reason. GP Appendix A. -/
inductive ExitReason where
  /-- Regular termination (halt instruction). -/
  | halt : ExitReason
  /-- Irregular termination (exceptional circumstance). -/
  | panic : ExitReason
  /-- Gas exhaustion. -/
  | outOfGas : ExitReason
  /-- Page fault: attempt to access inaccessible address. -/
  | pageFault (address : Reg) : ExitReason
  /-- Host-call request: ecalli instruction with identifier. -/
  | hostCall (id : Reg) : ExitReason

/-- Complete PVM machine state. -/
structure MachineState where
  /-- ω : Register file. ⟦𝕣⟧_13. -/
  registers : Registers
  /-- μ : RAM. -/
  memory : Memory
  /-- ζ : Gas remaining. -/
  gas : SignedGas
  /-- ι : Program counter. -/
  pc : Reg

/-- Result of a PVM invocation. -/
structure InvocationResult where
  /-- Exit reason (halt/panic/oog/fault/host). -/
  exitReason : ExitReason
  /-- ω_7 : Value in register 7 at exit (status/return value). -/
  exitValue : Reg
  /-- Gas counter at exit (may be negative for OOG). -/
  gas : SignedGas
  /-- Final register file. -/
  registers : Registers
  /-- Final memory state. -/
  memory : Memory

-- ============================================================================
-- Program Blob — Appendix A
-- ============================================================================

/-- Decoded program blob. GP Appendix A.
    deblob(p) → (code, bitmask, jumpTable) -/
structure Program where
  /-- Code bytes. -/
  code : ByteArray
  /-- Bitmask: one bit per code byte, marking opcode positions. -/
  bitmask : Array Bool
  /-- Jump table for dynamic jumps. -/
  jumpTable : Array Nat

-- ============================================================================
-- Readable/Writable Sets — GP eq (4.18–4.19)
-- ============================================================================

/-- R(μ) : Set of readable addresses. GP eq (4.18).
    i ∈ R(μ) iff μ_a[⌊i / Z_P⌋] ≠ ∅ -/
def Memory.isReadable (m : Memory) (addr : Nat) : Bool :=
  let page := addr / pageSize
  if h : page < m.access.size then
    m.access[page] != .inaccessible
  else false

/-- W(μ) : Set of writable addresses. GP eq (4.19).
    i ∈ W(μ) iff μ_a[⌊i / Z_P⌋] = W -/
def Memory.isWritable (m : Memory) (addr : Nat) : Bool :=
  let page := addr / pageSize
  if h : page < m.access.size then
    m.access[page] == .writable
  else false

-- ============================================================================
-- Host-Call Dispatch — GP eq (A.36)
-- ============================================================================

/-- Host-call handler type. Takes call id, gas, registers, memory,
    and returns updated state. The host context is parameterized. -/
def HostCallHandler (ctx : Type) :=
  Reg → Gas → Registers → Memory → ctx → InvocationResult × ctx

-- Core PVM invocation (Ψ), standard initialization (Y), host-call dispatch
-- (Ψ_H), and standard invocation (Ψ_M) are implemented in Jar.PVM.Interpreter.

-- ============================================================================
-- Instruction Set Summary — Appendix A
-- ============================================================================

/-- PVM instruction categories (for documentation; not used in execution). -/
inductive InstructionCategory where
  | noArgs       -- trap, fallthrough
  | oneImmediate -- ecalli (host call)
  | regImm64     -- load_imm_64
  | twoImm       -- store_imm_u8/u16/u32/u64
  | offset       -- jump, branch_*
  | regImm       -- ALU ops, load/store with immediate
  | twoReg       -- register-register ops
  | threeReg     -- three-register ALU ops

-- PVM opcodes (~141 instructions) are fully decoded and executed in
-- Jar.PVM.Decode, Jar.PVM.Instructions, and Jar.PVM.Interpreter.

end Jar.PVM
