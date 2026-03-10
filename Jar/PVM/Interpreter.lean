import Jar.PVM
import Jar.PVM.Decode
import Jar.PVM.Memory
import Jar.PVM.Instructions

/-!
# PVM Interpreter — Appendix A

Top-level execution loop Ψ, standard initialization Y(p, a),
and host-call dispatch Ψ_H.
References: `graypaper/text/pvm.tex`, `graypaper/text/pvm_invocations.tex`.
-/

namespace Jar.PVM

-- ============================================================================
-- Top-Level Execution Loop — GP Ψ
-- ============================================================================

/-- Ψ : Core PVM execution loop. GP eq (1-3).
    Repeatedly executes single steps until halt, panic, OOG, fault, or host call.
    Gas is decremented by 1 per instruction. -/
def run (prog : ProgramBlob) (pc : Nat) (regs : Registers) (mem : Memory)
    (gas : Int64) : InvocationResult :=
  let rec go (pc : Nat) (regs : Registers) (mem : Memory)
      (gas : Int64) (fuel : Nat) : InvocationResult :=
    match fuel with
    | 0 =>
      { exitReason := .outOfGas
        exitValue := if 7 < regs.size then regs[7]! else 0
        gas := gas
        registers := regs
        memory := mem }
    | fuel' + 1 =>
      -- Check gas
      if gas <= 0 then
        { exitReason := .outOfGas
          exitValue := if 7 < regs.size then regs[7]! else 0
          gas := gas
          registers := regs
          memory := mem }
      else
        let gas' := gas - 1
        match executeStep prog pc regs mem with
        | .halt =>
          { exitReason := .halt
            exitValue := if 7 < regs.size then regs[7]! else 0
            gas := gas'
            registers := regs
            memory := mem }
        | .panic =>
          { exitReason := .panic
            exitValue := if 7 < regs.size then regs[7]! else 0
            gas := gas'
            registers := regs
            memory := mem }
        | .fault addr =>
          { exitReason := .pageFault addr
            exitValue := if 7 < regs.size then regs[7]! else 0
            gas := gas'
            registers := regs
            memory := mem }
        | .hostCall id regs' mem' =>
          { exitReason := .hostCall id
            exitValue := if 7 < regs'.size then regs'[7]! else 0
            gas := gas'
            registers := regs'
            memory := mem' }
        | .continue pc' regs' mem' =>
          go pc' regs' mem' gas' fuel'
  -- Use gas as fuel bound (can't execute more steps than gas available)
  go pc regs mem gas (gas.toNat + 1)

-- ============================================================================
-- Standard Program Initialization — GP eq (A.37-A.43)
-- ============================================================================

/-- Parse standard program blob and initialize PVM state. GP Appendix A §2.6.
    Blob format:
      encode[3](|o|) ‖ encode[3](|w|) ‖ encode[2](z) ‖ encode[3](s)
      ‖ o ‖ w ‖ encode[4](|c|) ‖ c
    Returns (ProgramBlob, initial registers, initial memory). -/
def initStandard (blob : ByteArray) (args : ByteArray)
    : Option (ProgramBlob × Registers × Memory) := do
  if blob.size < 11 then none
  let roLen := decodeLEn blob 0 3     -- |o|: read-only data length
  let rwLen := decodeLEn blob 3 3     -- |w|: writable data length
  let jumpEntries := decodeLEn blob 6 2  -- z: jump table entries
  let stackSize := decodeLEn blob 8 3 -- s: stack size in pages

  let dataStart := 11
  let roStart := dataStart
  let rwStart := roStart + roLen
  let codeLenStart := rwStart + rwLen
  if codeLenStart + 4 > blob.size then none
  let codeLen := decodeLEn blob codeLenStart 4
  let codeStart := codeLenStart + 4
  if codeStart + codeLen > blob.size then none

  -- Extract code
  let code := blob.extract codeStart (codeStart + codeLen)
  -- Bitmask follows code in the blob
  let bitmaskStart := codeStart + codeLen
  let bitmaskLen := (codeLen + 7) / 8
  let bitmask := if bitmaskStart + bitmaskLen <= blob.size then
    blob.extract bitmaskStart (bitmaskStart + bitmaskLen)
  else ByteArray.mk (Array.mkArray bitmaskLen 0)

  -- Build jump table (simplified: sequential entries from read-only data)
  let jumpTable := Array.mkArray jumpEntries 0

  let prog : ProgramBlob := { code, bitmask, jumpTable := jumpTable.map UInt32.ofNat }

  -- Memory layout (GP eq 770):
  -- [0, Z_Z): reserved (inaccessible)
  -- [Z_Z, Z_Z + |o|): read-only data
  -- [2*Z_Z + align(|o|), ...): writable heap
  -- [2^32 - 2*Z_Z - Z_I, 2^32 - Z_Z - Z_I): stack (writable)
  -- [2^32 - Z_Z - Z_I, 2^32 - Z_Z - Z_I + |args|): arguments (read-only)
  let totalPages := 2^32 / Z_P
  let access := Array.mkArray totalPages PageAccess.inaccessible
  -- Mark read-only pages
  let roPageStart := Z_Z / Z_P
  let roPages := (roLen + Z_P - 1) / Z_P
  let access := Id.run do
    let mut acc := access
    for i in [:roPages] do
      let p := roPageStart + i
      if p < acc.size then acc := acc.set! p .readable
    return acc
  -- Mark writable heap pages
  let heapStart := 2 * Z_Z + ((roLen + Z_P - 1) / Z_P * Z_P)
  let heapPageStart := heapStart / Z_P
  let heapPages := (rwLen + Z_P - 1) / Z_P
  let access := Id.run do
    let mut acc := access
    for i in [:heapPages] do
      let p := heapPageStart + i
      if p < acc.size then acc := acc.set! p .writable
    return acc
  -- Mark stack pages
  let stackBase := 2^32 - 2 * Z_Z - Z_I
  let stackPageStart := stackBase / Z_P
  let access := Id.run do
    let mut acc := access
    for i in [:stackSize] do
      let p := stackPageStart + i
      if p < acc.size then acc := acc.set! p .writable
    return acc
  -- Mark argument pages (read-only)
  let argsBase := 2^32 - Z_Z - Z_I
  let argsPageStart := argsBase / Z_P
  let argsPages := (args.size + Z_P - 1) / Z_P
  let access := Id.run do
    let mut acc := access
    for i in [:argsPages] do
      let p := argsPageStart + i
      if p < acc.size then acc := acc.set! p .readable
    return acc

  -- Initialize memory contents (simplified: zero-filled, then copy data)
  -- In practice, we'd copy o, w, and args into the right locations.
  -- For now, use a sparse representation via ByteArray.
  let memValue := ByteArray.mk (Array.mkArray (2^32) 0)
  -- Copy read-only data
  let memValue := Id.run do
    let mut m := memValue
    for i in [:roLen] do
      let srcIdx := roStart + i
      let dstIdx := Z_Z + i
      if srcIdx < blob.size && dstIdx < m.size then
        m := m.set! dstIdx (blob.get! srcIdx)
    return m
  -- Copy writable data
  let memValue := Id.run do
    let mut m := memValue
    for i in [:rwLen] do
      let srcIdx := rwStart + i
      let dstIdx := heapStart + i
      if srcIdx < blob.size && dstIdx < m.size then
        m := m.set! dstIdx (blob.get! srcIdx)
    return m
  -- Copy arguments
  let memValue := Id.run do
    let mut m := memValue
    for i in [:args.size] do
      let dstIdx := argsBase + i
      if dstIdx < m.size then
        m := m.set! dstIdx (args.get! i)
    return m

  let memory : Memory := { value := memValue, access }

  -- Registers: GP eq (803-807)
  let regs := Array.mkArray PVM_REGISTERS (0 : RegisterValue)
  let regs := regs.set! 0 (UInt64.ofNat (2^32 - 2^16))        -- PC base
  let regs := regs.set! 1 (UInt64.ofNat heapStart)              -- heap base
  let regs := regs.set! 7 (UInt64.ofNat stackBase)              -- stack pointer
  let regs := regs.set! 8 (UInt64.ofNat args.size)              -- argument length

  some (prog, regs, memory)

-- ============================================================================
-- Full PVM Invocation with Host Calls — GP Ψ_H
-- ============================================================================

/-- Ψ_H : PVM invocation with host-call dispatch. GP eq (A.36).
    Repeatedly runs PVM, handling host calls via the provided handler.
    Stops on halt, panic, OOG, or fault. -/
def runWithHostCalls (ctx : Type) [Inhabited ctx]
    (prog : ProgramBlob) (pc : Nat) (regs : Registers) (mem : Memory)
    (gas : Int64) (handler : HostCallHandler ctx) (context : ctx)
    : InvocationResult × ctx :=
  let rec go (pc : Nat) (regs : Registers) (mem : Memory) (gas : Int64)
      (context : ctx) (fuel : Nat) : InvocationResult × ctx :=
    match fuel with
    | 0 =>
      ({ exitReason := .outOfGas
         exitValue := if 7 < regs.size then regs[7]! else 0
         gas := gas, registers := regs, memory := mem }, context)
    | fuel' + 1 =>
      let result := run prog pc regs mem gas
      match result.exitReason with
      | .hostCall id =>
        -- Dispatch to host handler
        let (result', context') := handler id result.gas.toUInt64 result.registers result.memory context
        match result'.exitReason with
        | .hostCall _ =>
          -- Host handler returned continue: resume execution at next instruction
          go pc result'.registers result'.memory result'.gas context' fuel'
        | _ => (result', context')
      | _ => (result, context)
  go pc regs mem gas context (gas.toNat + 1)

-- ============================================================================
-- Standard Invocations — GP Appendix B
-- ============================================================================

/-- Ψ_M : Standard PVM invocation. GP Appendix B.
    Parses blob, initializes state, runs to completion.
    Returns (gas_remaining, output_or_error). -/
def invokeStd (blob : ByteArray) (gasLimit : Gas) (input : ByteArray)
    : Gas × (ByteArray ⊕ ExitReason) :=
  match initStandard blob input with
  | none => (0, .inr .panic)
  | some (prog, regs, mem) =>
    let result := run prog 0 regs mem (Int64.mk gasLimit)
    match result.exitReason with
    | .halt =>
      -- Output is in memory at the address in reg[10], length in reg[11]
      -- Simplified: return empty output
      (result.gas.toUInt64, .inl ByteArray.empty)
    | other => (result.gas.toUInt64, .inr other)

end Jar.PVM
