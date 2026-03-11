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
        | .hostCall id regs' mem' npc =>
          { exitReason := .hostCall id
            exitValue := if 7 < regs'.size then regs'[7]! else 0
            gas := gas'
            registers := regs'
            memory := mem'
            nextPC := npc }
        | .continue pc' regs' mem' =>
          go pc' regs' mem' gas' fuel'
  -- Use gas as fuel bound (can't execute more steps than gas available)
  go pc regs mem gas (gas.toUInt64.toNat + 1)

-- ============================================================================
-- Metadata Skipping — PolkaVM blobs may have a metadata prefix
-- ============================================================================

/-- Skip metadata prefix in a PVM program blob.
    Metadata format: E(metadata_length) ‖ metadata_bytes ‖ actual_program
    Uses JAM codec natural encoding for the length prefix. -/
def skipMetadata (blob : ByteArray) : ByteArray :=
  if blob.size < 14 then blob
  else
    -- Check if first 3 bytes look like a valid ro_size (standard program header)
    let roSize := decodeLEn blob 0 3
    if roSize + 14 <= blob.size then blob  -- Already a valid program header
    else
      -- Try to decode metadata length and skip
      match decodeJamNatural blob 0 with
      | some (metaLen, consumed) =>
        let skip := consumed + metaLen
        if skip < blob.size then blob.extract skip blob.size
        else blob
      | none => blob

-- ============================================================================
-- Standard Program Initialization — GP eq (A.37-A.43)
-- ============================================================================

/-- Round up to page boundary. -/
private def pageRound (x : Nat) : Nat := ((x + Z_P - 1) / Z_P) * Z_P

/-- Round up to zone boundary. -/
private def zoneRound (x : Nat) : Nat := ((x + Z_Z - 1) / Z_Z) * Z_Z

/-- Map a region of pages with the given access mode. -/
private def mapRegionAccess (access : Array PageAccess) (base : Nat) (size : Nat)
    (mode : PageAccess) : Array PageAccess := Id.run do
  let startPage := base / Z_P
  let numPages := (size + Z_P - 1) / Z_P
  let mut acc := access
  for i in [:numPages] do
    let p := startPage + i
    if p < acc.size then acc := acc.set! p mode
  return acc

/-- Copy data into sparse memory at a given base address. -/
private def copyToMem (m : Memory) (base : Nat) (data : ByteArray) : Memory := Id.run do
  let mut mem := m
  for i in [:data.size] do
    mem := mem.setByte (base + i) (data.get! i)
  return mem

/-- Parse standard program blob and initialize PVM state. GP Appendix A §2.6.
    Blob format (after metadata):
      E₃(|o|) ‖ E₃(|w|) ‖ E₂(z) ‖ E₃(s) ‖ o ‖ w ‖ E₄(|c|) ‖ c
    where c is a deblob-format blob.
    Returns (ProgramBlob, initial registers, initial memory). -/
def initStandard (blob' : ByteArray) (args : ByteArray)
    : Option (ProgramBlob × Registers × Memory) := do
  let blob := skipMetadata blob'
  if blob.size < 15 then none

  -- Parse header: E₃(|o|) ‖ E₃(|w|) ‖ E₂(z) ‖ E₃(s)
  let roSize := decodeLEn blob 0 3      -- |o|: read-only data size
  let rwSize := decodeLEn blob 3 3      -- |w|: read-write data size
  let heapPages := decodeLEn blob 6 2   -- z: additional heap pages
  let stackSize := decodeLEn blob 8 3   -- s: stack size in bytes

  let mut offset := 11

  -- Read read-only data
  if offset + roSize > blob.size then none
  let roData := blob.extract offset (offset + roSize)
  offset := offset + roSize

  -- Read read-write data
  if offset + rwSize > blob.size then none
  let rwData := blob.extract offset (offset + rwSize)
  offset := offset + rwSize

  -- Read E₄(|c|) and code blob
  if offset + 4 > blob.size then none
  let codeLen := decodeLEn blob offset 4
  offset := offset + 4
  if offset + codeLen > blob.size then none
  let codeBlobData := blob.extract offset (offset + codeLen)

  -- Deblob the code section
  let prog ← deblob codeBlobData

  -- Memory layout (GP eq A.42):
  let roBase := Z_Z
  let roZone := zoneRound roSize
  let rwBase := 2 * Z_Z + roZone
  let rwTotal := rwSize + heapPages * Z_P
  let rwZone := zoneRound rwTotal
  -- Check fits in 32-bit address space
  let total := 5 * Z_Z + roZone + rwZone + zoneRound stackSize + Z_I
  if total > 2^32 then none

  -- Build access map
  let totalPages := 2^32 / Z_P
  let access := Array.replicate totalPages PageAccess.inaccessible

  -- Read-only pages for ro data
  let access := mapRegionAccess access roBase (pageRound roSize) .readable

  -- Read-write pages for rw data + heap
  let access := mapRegionAccess access rwBase (pageRound rwTotal) .writable

  -- Stack: writable, below arguments
  let stackTop := 2^32 - 2 * Z_Z - Z_I
  let stackBottom := stackTop - pageRound stackSize
  let access := mapRegionAccess access stackBottom (pageRound stackSize) .writable

  -- Arguments: read-only
  let argBase := 2^32 - Z_Z - Z_I
  let access := mapRegionAccess access argBase (pageRound args.size) .readable

  -- Build sparse memory and copy data
  let mem : Memory := { pages := Dict.empty, access }
  let mem := copyToMem mem roBase roData
  let mem := copyToMem mem rwBase rwData
  let mem := copyToMem mem argBase args

  -- Registers (GP eq A.43): matching grey-pvm initialize_program
  let regs := Array.replicate PVM_REGISTERS (0 : RegisterValue)
  let regs := regs.set! 0 (UInt64.ofNat (2^32 - 2^16))        -- ω[0]: SP init
  let regs := regs.set! 1 (UInt64.ofNat stackTop)               -- ω[1]: stack top
  let regs := regs.set! 7 (UInt64.ofNat argBase)                -- ω[7]: argument base
  let regs := regs.set! 8 (UInt64.ofNat args.size)              -- ω[8]: argument length

  some (prog, regs, mem)

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
        let resumePC := result.nextPC
        let (result', context') := handler id result.gas.toUInt64 result.registers result.memory context
        match result'.exitReason with
        | .hostCall _ =>
          -- Host handler returned continue: resume execution at next PC
          go resumePC result'.registers result'.memory result'.gas context' fuel'
        | _ => (result', context')
      | _ => (result, context)
  go pc regs mem gas context (gas.toUInt64.toNat + 1)

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
    let result := run prog 0 regs mem (Int64.ofUInt64 gasLimit)
    match result.exitReason with
    | .halt =>
      -- Output is in memory at the address in reg[10], length in reg[11]
      -- Simplified: return empty output
      (result.gas.toUInt64, .inl ByteArray.empty)
    | other => (result.gas.toUInt64, .inr other)

end Jar.PVM
