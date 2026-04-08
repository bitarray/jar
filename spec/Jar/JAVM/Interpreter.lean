import Jar.JAVM
import Jar.JAVM.Decode
import Jar.JAVM.Memory
import Jar.JAVM.Instructions
import Jar.JAVM.GasCostFull
import Jar.JAVM.GasCostSinglePass

/-!
# JAVM Interpreter — Appendix A

Top-level execution loop Ψ, standard initialization Y(p, a),
and host-call dispatch Ψ_H.
References: `graypaper/text/pvm.tex`, `graypaper/text/pvm_invocations.tex`.
-/

namespace Jar.JAVM

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
            memory := mem
            lastPC := pc }
        | .trap =>
          { exitReason := .trap
            exitValue := if 7 < regs.size then regs[7]! else 0
            gas := gas'
            registers := regs
            memory := mem
            lastPC := pc }
        | .panic =>
          { exitReason := .panic
            exitValue := if 7 < regs.size then regs[7]! else 0
            gas := gas'
            registers := regs
            memory := mem
            lastPC := pc }
        | .fault addr =>
          { exitReason := .pageFault addr
            exitValue := if 7 < regs.size then regs[7]! else 0
            gas := gas'
            registers := regs
            memory := mem
            lastPC := pc }
        | .hostCall id regs' mem' npc =>
          { exitReason := .hostCall id
            exitValue := if 7 < regs'.size then regs'[7]! else 0
            gas := gas'
            registers := regs'
            memory := mem'
            nextPC := npc
            lastPC := pc }
        | .ecall regs' mem' npc =>
          { exitReason := .ecall
            exitValue := if 7 < regs'.size then regs'[7]! else 0
            gas := gas'
            registers := regs'
            memory := mem'
            nextPC := npc
            lastPC := pc }
        | .continue pc' regs' mem' =>
          go pc' regs' mem' gas' fuel'
  -- Use gas as fuel bound (can't execute more steps than gas available)
  go pc regs mem gas (gas.toUInt64.toNat + 1)

/-- Check if opcode is a basic block terminator. -/
private def isBlockTerminator (opcode : Nat) : Bool :=
  match opcode with
  | 0 | 1 | 2 => true   -- trap, fallthrough, unlikely
  | 10 => true           -- ecalli
  | 40 | 50 | 80 | 180 => true  -- jump, jump_ind, load_imm_jump, load_imm_jump_ind
  | n => (81 ≤ n && n ≤ 90) || (170 ≤ n && n ≤ 175)  -- branches

/-- Ψ : Core PVM execution loop with per-basic-block gas charging. GP v0.8.0.
    Gas is charged upfront on basic block entry using pipeline simulation cost.
    Instructions within a block execute without individual gas deduction. -/
def runBlockGasWith (costFn : ByteArray → ByteArray → Nat → Nat)
    (prog : ProgramBlob) (pc : Nat) (regs : Registers) (mem : Memory)
    (gas : Int64) : InvocationResult :=
  let rec go (pc : Nat) (regs : Registers) (mem : Memory)
      (gas : Int64) (gasCharged : Bool) (fuel : Nat) : InvocationResult :=
    match fuel with
    | 0 =>
      { exitReason := .outOfGas, exitValue := if 7 < regs.size then regs[7]! else 0
        gas := gas, registers := regs, memory := mem }
    | fuel' + 1 =>
      -- Charge gas on basic block entry
      let (gas', charged) :=
        if gasCharged then (gas, true)
        else
          let blockCost := costFn prog.code prog.bitmask pc
          let gas' := gas - Int64.ofNat blockCost
          if gas' < 0 then (gas, false)  -- will OOG below
          else (gas', true)
      if !charged then
        { exitReason := .outOfGas, exitValue := if 7 < regs.size then regs[7]! else 0
          gas := 0, registers := regs, memory := mem }
      else
        let opcode := if pc < prog.code.size then prog.code.get! pc |>.toNat else 0
        match executeStep prog pc regs mem with
        | .halt =>
          { exitReason := .halt, exitValue := if 7 < regs.size then regs[7]! else 0
            gas := gas', registers := regs, memory := mem, lastPC := pc }
        | .trap =>
          { exitReason := .trap, exitValue := if 7 < regs.size then regs[7]! else 0
            gas := gas', registers := regs, memory := mem, lastPC := pc }
        | .panic =>
          { exitReason := .panic, exitValue := if 7 < regs.size then regs[7]! else 0
            gas := gas', registers := regs, memory := mem, lastPC := pc }
        | .fault addr =>
          { exitReason := .pageFault addr, exitValue := if 7 < regs.size then regs[7]! else 0
            gas := gas', registers := regs, memory := mem, lastPC := pc }
        | .hostCall id regs' mem' npc =>
          { exitReason := .hostCall id, exitValue := if 7 < regs'.size then regs'[7]! else 0
            gas := gas', registers := regs', memory := mem', nextPC := npc, lastPC := pc }
        | .ecall regs' mem' npc =>
          { exitReason := .ecall, exitValue := if 7 < regs'.size then regs'[7]! else 0
            gas := gas', registers := regs', memory := mem', nextPC := npc, lastPC := pc }
        | .continue pc' regs' mem' =>
          -- Reset gasCharged when entering a new basic block
          let nextCharged := if isBlockTerminator opcode then false else true
          go pc' regs' mem' gas' nextCharged fuel'
  go pc regs mem gas false (gas.toUInt64.toNat + 1)

/-- Per-basic-block execution with full pipeline simulation gas. -/
def runBlockGas := runBlockGasWith gasCostForBlockFull

/-- Per-basic-block execution with single-pass gas model. -/
def runBlockGasSinglePass := runBlockGasWith gasCostForBlockSinglePass

-- ============================================================================
-- Metadata Skipping — PolkaVM blobs may have a metadata prefix
-- ============================================================================

/-- Skip metadata prefix in a PVM program blob.
    Metadata format: E(metadata_length) ‖ metadata_bytes ‖ actual_program
    When `compact` is true, uses JAM codec natural encoding for the length prefix (gp072).
    When false, uses u32 LE (jar1). -/
def skipMetadata (blob : ByteArray) (compact : Bool := true) : ByteArray :=
  if blob.size < 14 then blob
  else
    -- Check if first 3 bytes look like a valid ro_size (standard program header)
    let roSize := decodeLEn blob 0 3
    if roSize + 14 <= blob.size then blob  -- Already a valid program header
    else
      -- Try to decode metadata length and skip
      match decodeDeBlobNat blob 0 compact with
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
def initStandard (blob' : ByteArray) (args : ByteArray) (compact : Bool := true)
    : Option (ProgramBlob × Registers × Memory) := do
  let blob := skipMetadata blob' compact
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
  let prog ← deblob codeBlobData compact

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
  -- heap_top starts at end of pre-mapped rw+heap region (matching Grey)
  let heapTop := rwBase + pageRound rwTotal
  let mem : Memory := { pages := Dict.empty, access, heapTop }
  let mem := copyToMem mem roBase roData
  let mem := copyToMem mem rwBase rwData
  let mem := copyToMem mem argBase args

  -- Registers (GP eq A.43): matching javm initialize_program
  let regs := Array.replicate PVM_REGISTERS (0 : RegisterValue)
  let regs := regs.set! 0 (UInt64.ofNat (2^32 - 2^16))        -- ω[0]: RA (halt address, gp072)
  let regs := regs.set! 1 (UInt64.ofNat stackTop)               -- ω[1]: SP (stack top)
  let regs := regs.set! 7 (UInt64.ofNat argBase)                -- ω[7]: argument base
  let regs := regs.set! 8 (UInt64.ofNat args.size)              -- ω[8]: argument length

  some (prog, regs, mem)

/-- Initialize PVM from a JAR capability manifest blob.
    Parses header + cap entries. CODE cap → ProgramBlob.
    DATA caps → mapped memory regions. -/
def initCap (blob : ByteArray) (args : ByteArray)
    : Option (ProgramBlob × Registers × Memory) := do
  let (hdr, off0) ← parseJarHeader blob

  -- Parse cap entries
  let mut caps : Array JarCapEntry := #[]
  let mut off := off0
  for _ in List.range hdr.capCount do
    let (cap, nextOff) ← parseJarCapEntry blob off
    caps := caps.push cap
    off := nextOff

  -- Data section starts after all cap entries
  let dataStart := off

  -- Find the CODE cap matching invoke_cap and parse its code sub-blob
  let codeCap ← caps.find? fun c => c.isCode && c.capIndex == hdr.invokeCap
  let prog ← parseCodeSubBlob blob (dataStart + codeCap.dataOffset) codeCap.dataLen

  -- Build memory from DATA caps
  let totalPagesAll := 2^32 / Z_P
  let mut access := Array.replicate totalPagesAll PageAccess.inaccessible
  let mut mem : Memory := { pages := Dict.empty, access, heapTop := 0, guardZone := 0 }
  let mut argsBase : Nat := 0

  for cap in caps do
    if !cap.isCode then
      -- Map pages
      let startAddr := cap.basePage * Z_P
      let endAddr := startAddr + cap.pageCount * Z_P
      let pageAccess := if cap.isRW then PageAccess.writable else PageAccess.readable
      access := mapRegionAccess access startAddr endAddr pageAccess
      -- Copy initial data if present
      if cap.dataLen > 0 then
        let dataOff := dataStart + cap.dataOffset
        if dataOff + cap.dataLen <= blob.size then
          let capData := blob.extract dataOff (dataOff + cap.dataLen)
          mem := copyToMem { mem with access } startAddr capData
      -- Track args cap base address (cap_index=0 = IPC slot = args)
      if cap.capIndex == 0 then
        argsBase := startAddr

  -- Update memory access after all caps processed
  mem := { mem with access }

  -- Write arguments into args cap (cap_index=255 = IPC slot)
  if argsBase > 0 && args.size > 0 then
    mem := copyToMem mem argsBase args

  -- Registers: φ[7]=op (set by caller), φ[8]=args_base, φ[9]=args_len.
  -- No halt address — programs terminate via REPLY (ecalli 0xFF).
  -- SP is set by the program's preamble (load_imm_64 SP, stack_top).
  let regs := Array.replicate PVM_REGISTERS (0 : RegisterValue)
  let regs := regs.set! 8 (UInt64.ofNat argsBase)
  let regs := regs.set! 9 (UInt64.ofNat args.size)

  some (prog, regs, mem)

/-- Y(p, a) : Program initialization dispatched by capability model.
    - v2 (jar1): capability manifest blob format
    - none (gp072): segmented (GP v0.7.2) memory layout -/
def initProgram [JarConfig] (blob : ByteArray) (args : ByteArray)
    : Option (ProgramBlob × Registers × Memory) :=
  let compact := JarConfig.useCompactDeblob
  match JarConfig.capabilityModel with
  | .v2 => initCap blob args
  | .none => initStandard blob args compact

/-- Ψ : Core PVM run dispatched by gas model.
    Uses per-instruction (v0.7.2) or per-basic-block (v0.8.0) gas charging. -/
def runProgram [JarConfig] (prog : ProgramBlob) (pc : Nat) (regs : Registers)
    (mem : Memory) (gas : Int64) : InvocationResult :=
  match JarConfig.gasModel with
  | .perInstruction => run prog pc regs mem gas
  | .basicBlockFull => runBlockGas prog pc regs mem gas
  | .basicBlockSinglePass => runBlockGasSinglePass prog pc regs mem gas

-- ============================================================================
-- Full PVM Invocation with Host Calls — GP Ψ_H
-- ============================================================================

/-- Ψ_H : PVM invocation with host-call dispatch. GP eq (A.36).
    Repeatedly runs PVM, handling host calls via the provided handler.
    Stops on halt, panic, OOG, or fault. -/
def runWithHostCalls (ctx : Type) [Inhabited ctx]
    (prog : ProgramBlob) (pc : Nat) (regs : Registers) (mem : Memory)
    (gas : Int64) (handler : HostCallHandler ctx) (context : ctx)
    (runFn : ProgramBlob → Nat → Registers → Memory → Int64 → InvocationResult := run)
    : InvocationResult × ctx :=
  let rec go (pc : Nat) (regs : Registers) (mem : Memory) (gas : Int64)
      (context : ctx) (fuel : Nat) : InvocationResult × ctx :=
    match fuel with
    | 0 =>
      ({ exitReason := .outOfGas
         exitValue := if 7 < regs.size then regs[7]! else 0
         gas := gas, registers := regs, memory := mem }, context)
    | fuel' + 1 =>
      let result := runFn prog pc regs mem gas
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
      | .ecall =>
        -- ecall (management ops): treat same as hostCall with a sentinel ID
        -- The handler can distinguish ecall by the sentinel value
        let resumePC := result.nextPC
        let ecallSentinel : UInt64 := UInt64.ofNat (2^64 - 3)
        let (result', context') := handler ecallSentinel result.gas.toUInt64 result.registers result.memory context
        match result'.exitReason with
        | .hostCall _ => go resumePC result'.registers result'.memory result'.gas context' fuel'
        | _ => (result', context')
      | _ => (result, context)
  go pc regs mem gas context (gas.toUInt64.toNat + 1)

/-- Run PVM with host calls, returning (result, context, stepCount). -/
def runWithHostCallsTraced (ctx : Type) [Inhabited ctx]
    (prog : ProgramBlob) (pc : Nat) (regs : Registers) (mem : Memory)
    (gas : Int64) (handler : HostCallHandler ctx) (context : ctx)
    : InvocationResult × ctx × Nat :=
  let rec go (pc : Nat) (regs : Registers) (mem : Memory) (gas : Int64)
      (context : ctx) (fuel : Nat) (steps : Nat) : InvocationResult × ctx × Nat :=
    match fuel with
    | 0 =>
      ({ exitReason := .outOfGas
         exitValue := if 7 < regs.size then regs[7]! else 0
         gas := gas, registers := regs, memory := mem }, context, steps)
    | fuel' + 1 =>
      let result := run prog pc regs mem gas
      let newSteps := steps + (gas.toUInt64.toNat - result.gas.toUInt64.toNat)
      match result.exitReason with
      | .hostCall id =>
        let resumePC := result.nextPC
        let (result', context') := handler id result.gas.toUInt64 result.registers result.memory context
        match result'.exitReason with
        | .hostCall _ =>
          go resumePC result'.registers result'.memory result'.gas context' fuel' newSteps
        | _ => (result', context', newSteps)
      | _ => (result, context, newSteps)
  go pc regs mem gas context (gas.toUInt64.toNat + 1) 0

/-- Run PVM single-stepping for trace, collecting first N PCs. -/
def runTracePCs (prog : ProgramBlob) (pc : Nat) (regs : Registers) (mem : Memory)
    (gas : Int64) (maxSteps : Nat) : Array Nat × ExitReason :=
  let rec go (pc : Nat) (regs : Registers) (mem : Memory) (gas : Int64)
      (pcs : Array Nat) (fuel : Nat) : Array Nat × ExitReason :=
    if pcs.size >= maxSteps then (pcs, .outOfGas)
    else match fuel with
    | 0 => (pcs, .outOfGas)
    | fuel' + 1 =>
      if gas <= 0 then (pcs, .outOfGas)
      else
        let pcs' := pcs.push pc
        let gas' := gas - 1
        match executeStep prog pc regs mem with
        | .halt => (pcs', .halt)
        | .trap => (pcs', .trap)
        | .panic => (pcs', .panic)
        | .fault addr => (pcs', .pageFault addr)
        | .hostCall id _ _ _ => (pcs', .hostCall id)
        | .ecall _ _ _ => (pcs', .ecall)
        | .continue pc' regs' mem' => go pc' regs' mem' gas' pcs' fuel'
  go pc regs mem gas #[] (maxSteps + 1)

-- ============================================================================
-- Instruction-Level Tracing
-- ============================================================================

/-- Single instruction trace entry: PC, opcode number, register snapshot. -/
structure InstrTraceEntry where
  pc : Nat
  opcode : Nat
  regs : Array UInt64  -- snapshot of all 13 registers before execution
  deriving Inhabited

/-- Format a trace entry as a compact string. -/
def InstrTraceEntry.toString (e : InstrTraceEntry) : String :=
  let regStr := Id.run do
    let mut s := ""
    for i in [:e.regs.size] do
      if i > 0 then s := s ++ " "
      s := s ++ s!"r{i}={e.regs[i]!}"
    return s
  s!"pc={e.pc} op={e.opcode}({Jar.JAVM.opcodeName e.opcode}) {regStr}"

instance : ToString InstrTraceEntry := ⟨InstrTraceEntry.toString⟩

/-- Run PVM single-stepping with instruction trace. Captures an InstrTraceEntry
    for each instruction executed. Stops at host call, halt, panic, OOG, or fault. -/
def runWithInstrTrace (prog : ProgramBlob) (pc : Nat) (regs : Registers) (mem : Memory)
    (gas : Int64) : InvocationResult × Array InstrTraceEntry :=
  let rec go (pc : Nat) (regs : Registers) (mem : Memory)
      (gas : Int64) (trace : Array InstrTraceEntry) (fuel : Nat)
      : InvocationResult × Array InstrTraceEntry :=
    match fuel with
    | 0 =>
      ({ exitReason := .outOfGas
         exitValue := if 7 < regs.size then regs[7]! else 0
         gas := gas, registers := regs, memory := mem }, trace)
    | fuel' + 1 =>
      if gas <= 0 then
        ({ exitReason := .outOfGas
           exitValue := if 7 < regs.size then regs[7]! else 0
           gas := gas, registers := regs, memory := mem }, trace)
      else
        let code := prog.code
        let opcode := if pc < code.size then code.get! pc |>.toNat else 0
        let entry : InstrTraceEntry := {
          pc := pc
          opcode := opcode
          regs := regs  -- snapshot registers before execution
        }
        let trace' := trace.push entry
        let gas' := gas - 1
        match executeStep prog pc regs mem with
        | .halt =>
          ({ exitReason := .halt
             exitValue := if 7 < regs.size then regs[7]! else 0
             gas := gas', registers := regs, memory := mem, lastPC := pc }, trace')
        | .trap =>
          ({ exitReason := .trap
             exitValue := if 7 < regs.size then regs[7]! else 0
             gas := gas', registers := regs, memory := mem, lastPC := pc }, trace')
        | .panic =>
          ({ exitReason := .panic
             exitValue := if 7 < regs.size then regs[7]! else 0
             gas := gas', registers := regs, memory := mem, lastPC := pc }, trace')
        | .fault addr =>
          ({ exitReason := .pageFault addr
             exitValue := if 7 < regs.size then regs[7]! else 0
             gas := gas', registers := regs, memory := mem, lastPC := pc }, trace')
        | .hostCall id regs' mem' npc =>
          ({ exitReason := .hostCall id
             exitValue := if 7 < regs'.size then regs'[7]! else 0
             gas := gas', registers := regs', memory := mem',
             nextPC := npc, lastPC := pc }, trace')
        | .ecall regs' mem' npc =>
          ({ exitReason := .ecall
             exitValue := if 7 < regs'.size then regs'[7]! else 0
             gas := gas', registers := regs', memory := mem',
             nextPC := npc, lastPC := pc }, trace')
        | .continue pc' regs' mem' =>
          go pc' regs' mem' gas' trace' fuel'
  go pc regs mem gas #[] (gas.toUInt64.toNat + 1)

/-- Configuration for instruction-level tracing in host-call loops.
    When enabled, traces all instructions between host calls traceAfterCall..traceBeforeCall. -/
structure InstrTraceConfig where
  /-- Enable instruction tracing. -/
  enabled : Bool := false
  /-- Start tracing after this host call number (0-indexed). -/
  traceAfterCall : Nat := 0
  /-- Stop tracing before this host call number (exclusive). -/
  traceBeforeCall : Nat := 0

/-- Run PVM with host calls, with optional instruction-level tracing between
    specific host call numbers. Returns (result, context, stepCount, instrTrace). -/
def runWithHostCallsInstrTrace (ctx : Type) [Inhabited ctx]
    (prog : ProgramBlob) (pc : Nat) (regs : Registers) (mem : Memory)
    (gas : Int64) (handler : HostCallHandler ctx) (context : ctx)
    (traceConfig : InstrTraceConfig := {})
    : InvocationResult × ctx × Nat × Array InstrTraceEntry :=
  let rec go (pc : Nat) (regs : Registers) (mem : Memory) (gas : Int64)
      (context : ctx) (fuel : Nat) (steps : Nat) (callCount : Nat)
      (instrTrace : Array InstrTraceEntry)
      : InvocationResult × ctx × Nat × Array InstrTraceEntry :=
    match fuel with
    | 0 =>
      ({ exitReason := .outOfGas
         exitValue := if 7 < regs.size then regs[7]! else 0
         gas := gas, registers := regs, memory := mem }, context, steps, instrTrace)
    | fuel' + 1 =>
      -- Decide whether to use instruction tracing for this segment
      let useTrace := traceConfig.enabled &&
        callCount >= traceConfig.traceAfterCall &&
        callCount < traceConfig.traceBeforeCall
      let (result, segTrace) :=
        if useTrace then runWithInstrTrace prog pc regs mem gas
        else (run prog pc regs mem gas, #[])
      let instrTrace' := instrTrace ++ segTrace
      let newSteps := steps + (gas.toUInt64.toNat - result.gas.toUInt64.toNat)
      match result.exitReason with
      | .hostCall id =>
        let resumePC := result.nextPC
        let (result', context') := handler id result.gas.toUInt64 result.registers result.memory context
        match result'.exitReason with
        | .hostCall _ =>
          go resumePC result'.registers result'.memory result'.gas context' fuel' newSteps (callCount + 1) instrTrace'
        | _ => (result', context', newSteps, instrTrace')
      | _ => (result, context, newSteps, instrTrace')
  go pc regs mem gas context (gas.toUInt64.toNat + 1) 0 0 #[]

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
      let outPtr := result.registers[10]!
      let outLen := result.registers[11]!
      let output := match readByteArray result.memory outPtr outLen.toNat with
        | .ok bytes => bytes
        | .panic | .fault _ => ByteArray.empty
      (result.gas.toUInt64, .inl output)
    | other => (result.gas.toUInt64, .inr other)

end Jar.JAVM
