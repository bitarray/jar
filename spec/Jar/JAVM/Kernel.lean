import Jar.JAVM
import Jar.JAVM.Capability
import Jar.JAVM.Interpreter

/-!
# JAVM Capability Kernel

Execution engine for the jar1 capability model. Manages a pool of VMs,
dispatches ecalli/ecall through capability resolution, and handles
multi-VM CALL/REPLY/RESUME.

This replaces the flat `handleHostCall` path for jar1. gp072 continues
using the flat path unchanged.
-/

namespace Jar.JAVM.Kernel

open Jar.JAVM.Cap

-- ============================================================================
-- Core Types
-- ============================================================================

/-- Compiled code data associated with a CODE cap. -/
structure CodeCapData where
  id : Nat
  program : JAVM.ProgramBlob
  jumpTable : Array Nat

instance : Inhabited CodeCapData where
  default := { id := 0, program := { code := ByteArray.empty, bitmask := ByteArray.empty, jumpTable := #[] }, jumpTable := #[] }

/-- Backing store: flat byte array representing all physical pages. -/
structure BackingStore where
  data : ByteArray
  totalPages : Nat

/-- PVM run function type (selects gas model). -/
def PvmRunFn := JAVM.ProgramBlob → Nat → JAVM.Registers → JAVM.Memory → Int64 → JAVM.InvocationResult

/-- Kernel state: VM pool + call stack + backing store + memory. -/
structure KernelState where
  vms : Array VmInstance
  callStack : Array CallFrame
  codeCaps : Array CodeCapData
  activeVm : Nat
  untyped : UntypedCap
  backing : BackingStore
  /-- Flat PVM memory shared by all VMs (simplified model). -/
  memory : JAVM.Memory
  /-- PVM execution function (gas model dependent). -/
  pvmRun : PvmRunFn
  memCycles : Nat

/-- Result of running the kernel. -/
inductive KernelResult where
  | halt (value : Nat)
  | panic
  | outOfGas
  | pageFault (addr : Nat)
  | protocolCall (slot : Nat)

/-- Internal dispatch result. -/
inductive DispatchResult where
  | continue_
  | protocolCall (slot : Nat)
  | rootHalt (value : Nat)
  | rootPanic
  | rootOutOfGas
  | rootPageFault (addr : Nat)
  | faultHandled

-- ============================================================================
-- Constants
-- ============================================================================

def RESULT_WHAT : UInt64 := UInt64.ofNat (2^64 - 2)
def RESULT_LOW  : UInt64 := UInt64.ofNat (2^64 - 8)   -- gas limit too low
def RESULT_HUH  : UInt64 := UInt64.ofNat (2^64 - 9)   -- invalid operation
def ecalliGasCost : Nat := 10
def callOverheadGas : Nat := 10
def gasPerPage : Nat := 1500
def pageSize : Nat := 4096

-- ============================================================================
-- Backing Store Operations
-- ============================================================================

def BackingStore.read (bs : BackingStore) (pageOff byteOff len : Nat) : ByteArray :=
  let start := pageOff * pageSize + byteOff
  if start + len ≤ bs.data.size then bs.data.extract start (start + len)
  else ByteArray.empty

def BackingStore.write (bs : BackingStore) (pageOff byteOff : Nat) (src : ByteArray) : BackingStore :=
  let start := pageOff * pageSize + byteOff
  if start + src.size ≤ bs.data.size then
    let newData := Id.run do
      let mut arr := bs.data
      for i in [:src.size] do
        arr := arr.set! (start + i) src[i]!
      return arr
    { bs with data := newData }
  else bs

-- ============================================================================
-- Register Helpers
-- ============================================================================

def getReg (regs : JAVM.Registers) (i : Nat) : UInt64 :=
  if i < regs.size then regs[i]! else 0

def setReg (regs : JAVM.Registers) (i : Nat) (v : UInt64) : JAVM.Registers :=
  if i < regs.size then regs.set! i v else regs

-- ============================================================================
-- State Helpers
-- ============================================================================

def KernelState.updateVm (s : KernelState) (idx : Nat) (f : VmInstance → VmInstance) : KernelState :=
  if idx < s.vms.size then { s with vms := s.vms.set! idx (f s.vms[idx]!) } else s

def KernelState.activeInst (s : KernelState) : VmInstance := s.vms[s.activeVm]!

def KernelState.setActiveReg (s : KernelState) (i : Nat) (v : UInt64) : KernelState :=
  s.updateVm s.activeVm fun vm => { vm with registers := setReg vm.registers i v }

def KernelState.getActiveReg (s : KernelState) (i : Nat) : UInt64 :=
  getReg s.activeInst.registers i

/-- Deduct gas from active VM. Returns none if insufficient. -/
def KernelState.chargeGas (s : KernelState) (amount : Nat) : Option KernelState :=
  let vm := s.activeInst
  if vm.gas < amount then none
  else some (s.updateVm s.activeVm fun vm => { vm with gas := vm.gas - amount })

-- ============================================================================
-- Capability Indirection Resolution
-- ============================================================================

/-- Resolve a u32 cap reference with HANDLE-chain indirection.
    byte 0 = target slot, bytes 1-3 = HANDLE chain (0x00 = end).
    Returns (vm_index, cap_slot) or none. -/
def resolveCapRef (state : KernelState) (capRef : UInt32) : Option (Nat × Nat) :=
  let targetSlot := (capRef &&& 0xFF).toNat
  let ind0 := ((capRef >>> 8) &&& 0xFF).toNat
  let ind1 := ((capRef >>> 16) &&& 0xFF).toNat
  let ind2 := ((capRef >>> 24) &&& 0xFF).toNat
  let step (vmIdx : Nat) (slot : Nat) : Option Nat :=
    if slot == 0 then some vmIdx
    else if vmIdx >= state.vms.size then none
    else match state.vms[vmIdx]!.capTable.get slot with
      | some (.handle h) =>
        if h.vmId >= state.vms.size then none
        else let st := state.vms[h.vmId]!.state
          if st == .running || st == .waitingForReply then none
          else some h.vmId
      | _ => none
  do let vm1 ← step state.activeVm ind2
     let vm2 ← step vm1 ind1
     let vm3 ← step vm2 ind0
     return (vm3, targetSlot)

/-- Resolve or set WHAT. -/
def resolveOrWhat (state : KernelState) (capRef : UInt32) : KernelState × Option (Nat × Nat) :=
  match resolveCapRef state capRef with
  | some r => (state, some r)
  | none => (state.setActiveReg 7 RESULT_WHAT, none)

-- ============================================================================
-- CALL VM (HANDLE/CALLABLE → run target VM)
-- ============================================================================

def handleCallVm (state : KernelState) (targetVmId : Nat) (maxGas : Option Nat) : KernelState × DispatchResult :=
  if targetVmId >= state.vms.size then
    (state.setActiveReg 7 RESULT_WHAT, .continue_)
  else if state.vms[targetVmId]!.state != .idle then
    (state.setActiveReg 7 RESULT_WHAT, .continue_)
  else
    let callerIdx := state.activeVm
    let callerGas := state.vms[callerIdx]!.gas
    if callerGas < callOverheadGas then (state, .rootOutOfGas)
    else
      let afterOverhead := callerGas - callOverheadGas
      let calleeGas := match maxGas with
        | some limit => min afterOverhead limit
        | none => afterOverhead

      -- IPC cap: φ[12]. 0 = no cap.
      let ipcSlotVal := (getReg state.vms[callerIdx]!.registers 12).toNat &&& 0xFF
      let hasIpc := ipcSlotVal != 0

      -- Caller → WaitingForReply, deduct gas
      let state := state.updateVm callerIdx fun vm =>
        { vm with state := .waitingForReply, gas := afterOverhead - calleeGas }

      -- IPC cap transfer
      let ipcCapIdx := if hasIpc then some ipcSlotVal else none
      -- Save DATA cap mapping state before transfer (for auto-remap on REPLY)
      let ipcWasMapped := match ipcCapIdx with
        | none => none
        | some slot => match state.vms[callerIdx]!.capTable.get slot with
          | some (.data d) => match d.baseOffset, d.access with
            | some bo, some acc => some (bo, acc)
            | _, _ => none
          | _ => none
      let state := match ipcCapIdx with
        | none => state
        | some slot =>
          let (newTable, cap) := state.vms[callerIdx]!.capTable.take slot
          let s := state.updateVm callerIdx fun vm => { vm with capTable := newTable }
          match cap with
          | some c => s.updateVm targetVmId fun vm =>
              { vm with capTable := vm.capTable.set 0 c }
          | none => s

      -- Push call frame
      let frame : CallFrame := {
        callerVmId := callerIdx
        ipcCapIdx := ipcCapIdx
        ipcWasMapped := ipcWasMapped
      }
      let state := { state with callStack := state.callStack.push frame }

      -- Pass args + start callee
      let cr := state.vms[callerIdx]!.registers
      let state := state.updateVm targetVmId fun vm =>
        let r := setReg (setReg (setReg (setReg vm.registers 7 (getReg cr 7)) 8 (getReg cr 8)) 9 (getReg cr 9)) 10 (getReg cr 10)
        { vm with gas := calleeGas, caller := some callerIdx, state := .running, registers := r }

      ({ state with activeVm := targetVmId }, .continue_)

-- ============================================================================
-- REPLY (ecalli(0) = CALL on IPC slot)
-- ============================================================================

/-- Resume caller with results from callee φ[7..8]. -/
private def resumeCaller (state : KernelState) (calleeIdx callerIdx : Nat)
    (ipcCapIdx : Option Nat) (ipcWasMapped : Option (Nat × Cap.Access)) : KernelState :=
  -- Return unused gas
  let unusedGas := state.vms[calleeIdx]!.gas
  let state := state.updateVm callerIdx fun vm => { vm with gas := vm.gas + unusedGas }
  let state := state.updateVm calleeIdx fun vm => { vm with gas := 0 }
  -- Return IPC cap if any, auto-remap DATA at original base_offset
  let state := match ipcCapIdx with
    | none => state
    | some slot =>
      let (newTable, cap) := state.vms[calleeIdx]!.capTable.take 0
      let s := state.updateVm calleeIdx fun vm => { vm with capTable := newTable }
      match cap with
      | some c =>
        -- Auto-remap DATA cap at caller's original mapping
        let c : Cap := match c, ipcWasMapped with
          | Cap.data d, some (baseOff, acc) =>
            Cap.data { d with baseOffset := some baseOff, access := some acc }
          | _, _ => c
        s.updateVm callerIdx fun vm =>
          { vm with capTable := vm.capTable.set slot c }
      | none => s
  -- Pass φ[7] only + set φ[8]=0 (status = REPLY success)
  let calleeRegs := state.vms[calleeIdx]!.registers
  let state := state.updateVm callerIdx fun vm =>
    { vm with
      state := .running
      registers := setReg (setReg vm.registers
        7 (getReg calleeRegs 7))
        8 0 }
  { state with activeVm := callerIdx }

def handleReply (state : KernelState) : KernelState × DispatchResult :=
  match state.callStack.back? with
  | none =>
    let result := state.getActiveReg 7
    (state, .rootHalt result.toNat)
  | some frame =>
    let calleeIdx := state.activeVm
    let callerIdx := frame.callerVmId
    let state := { state with callStack := state.callStack.pop }
    let state := state.updateVm calleeIdx fun vm => { vm with state := .idle }
    let state := resumeCaller state calleeIdx callerIdx frame.ipcCapIdx frame.ipcWasMapped
    (state, .continue_)

-- ============================================================================
-- VM Halt/Fault Handling
-- ============================================================================

def handleVmHalt (state : KernelState) (exitValue : Nat) : KernelState × DispatchResult :=
  match state.callStack.back? with
  | none => (state, .rootHalt exitValue)
  | some frame =>
    let calleeIdx := state.activeVm
    let callerIdx := frame.callerVmId
    let state := { state with callStack := state.callStack.pop }
    let state := state.updateVm calleeIdx fun vm => { vm with state := .halted }
    let unusedGas := state.vms[calleeIdx]!.gas
    let state := state.updateVm callerIdx fun vm => { vm with gas := vm.gas + unusedGas }
    -- Halt in jar1 = treated as panic (status 2, φ[7]=HUH)
    let state := state.updateVm callerIdx fun vm =>
      { vm with state := .running
                registers := setReg (setReg vm.registers 7 RESULT_HUH) 8 2 }
    ({ state with activeVm := callerIdx }, .continue_)

/-- Handle a non-root VM fault with status code and aux value.
    status: 1=trap, 2=panic, 3=oog, 4=pagefault, 5=invalid_ecalli.
    auxValue: child's φ[7] (trap), HUH (panic), LOW (oog), fault addr (pf), imm (ecalli). -/
def handleVmFaultWith (state : KernelState) (status : UInt64) (auxValue : UInt64)
    : KernelState × DispatchResult :=
  match state.callStack.back? with
  | none => (state, .rootPanic)
  | some frame =>
    let calleeIdx := state.activeVm
    let callerIdx := frame.callerVmId
    let state := { state with callStack := state.callStack.pop }
    let state := state.updateVm calleeIdx fun vm => { vm with state := .faulted }
    let unusedGas := state.vms[calleeIdx]!.gas
    let state := state.updateVm callerIdx fun vm => { vm with gas := vm.gas + unusedGas }
    let state := state.updateVm callerIdx fun vm =>
      { vm with state := .running
                registers := setReg (setReg vm.registers 7 auxValue) 8 status }
    ({ state with activeVm := callerIdx }, .continue_)

-- ============================================================================
-- RETYPE (CALL on UNTYPED → create DATA cap)
-- ============================================================================

/-- CALL UNTYPED: φ[7]=n_pages, φ[12]=dst_slot (with indirection).
    Bumps untyped allocator, creates DATA cap at dst_slot. -/
def handleRetype (state : KernelState) : KernelState × DispatchResult :=
  let nPages := (state.getActiveReg 7).toNat
  let gasCost := ecalliGasCost + nPages * gasPerPage
  let vm := state.activeInst
  if vm.gas < gasCost then (state, .rootOutOfGas)
  else
    let state := state.updateVm state.activeVm fun vm => { vm with gas := vm.gas - gasCost }
    -- Bump allocator
    let offset := state.untyped.offset
    let newOffset := offset + nPages
    if newOffset > state.untyped.total then
      (state.setActiveReg 7 RESULT_WHAT, .continue_)
    else
      let state := { state with untyped := { state.untyped with offset := newOffset } }
      -- Resolve destination slot
      let dstRef := UInt32.ofNat (state.getActiveReg 12).toNat
      match resolveCapRef state dstRef with
      | none => (state.setActiveReg 7 RESULT_WHAT, .continue_)
      | some (dstVm, dstSlot) =>
        if !state.vms[dstVm]!.capTable.isEmpty dstSlot then
          (state.setActiveReg 7 RESULT_WHAT, .continue_)
        else
          let dataCap : DataCap := {
            backingOffset := offset
            pageCount := nPages
          }
          let state := state.updateVm dstVm fun vm =>
            { vm with capTable := vm.capTable.set dstSlot (.data dataCap) }
          (state.setActiveReg 7 (UInt64.ofNat dstSlot), .continue_)

-- ============================================================================
-- CREATE (CALL on CODE → create VM)
-- ============================================================================

/-- CALL CODE: φ[7]=bitmask (u64), φ[12]=dst_slot for HANDLE.
    Bitmask copies caps from CODE's CNode. Creates new VM + HANDLE. -/
def handleCreate (state : KernelState) (codeCapId : Nat) (codeCnodeVm : Nat)
    : KernelState × DispatchResult :=
  let bitmask := (state.getActiveReg 7).toNat
  if state.vms.size >= maxVms then
    (state.setActiveReg 7 RESULT_WHAT, .continue_)
  else
    -- Build child cap table from bitmask (copy from CODE's CNode)
    let sourceTable := state.vms[codeCnodeVm]!.capTable
    let childTable := Id.run do
      let mut table := CapTable.empty
      for bit in [:64] do
        if bitmask &&& (1 <<< bit) != 0 then
          match sourceTable.get bit with
          | some cap =>
            match cap.isCopyable with
            | true =>
              match cap.tryCopy with
              | some copy => table := table.set bit copy
              | none => pure () -- skip non-copyable
            | false => pure ()
          | none => pure ()
      return table
    let childVmId := state.vms.size
    let child : VmInstance := {
      state := .idle
      codeCapId := codeCapId
      registers := Array.replicate JAVM.numRegisters 0
      pc := 0
      capTable := childTable
      caller := none
      entryIndex := 0
      gas := 0
    }
    let state := { state with vms := state.vms.push child }
    -- Place HANDLE at dst_slot
    let dstRef := UInt32.ofNat (state.getActiveReg 12).toNat
    match resolveCapRef state dstRef with
    | none => (state.setActiveReg 7 RESULT_WHAT, .continue_)
    | some (dstVm, dstSlot) =>
      if !state.vms[dstVm]!.capTable.isEmpty dstSlot then
        (state.setActiveReg 7 RESULT_WHAT, .continue_)
      else
        let handle : HandleCap := { vmId := childVmId, maxGas := none }
        let state := state.updateVm dstVm fun vm =>
          { vm with capTable := vm.capTable.set dstSlot (.handle handle) }
        (state.setActiveReg 7 (UInt64.ofNat dstSlot), .continue_)

-- ============================================================================
-- Management Ops (ecall dispatch)
-- ============================================================================

/-- MAP pages of a DATA cap in its CNode.
    φ[7]=base_offset, φ[8]=page_offset, φ[9]=page_count, φ[10]=access (0=RO, 1=RW).
    In the Lean model, copies backing store pages into flat PVM Memory. -/
def handleMap (state : KernelState) (vmIdx : Nat) (slot : Nat) : KernelState × DispatchResult :=
  let baseOffset := (state.getActiveReg 7).toNat
  let pageOffset := (state.getActiveReg 8).toNat
  let pgCount := (state.getActiveReg 9).toNat
  let accessRaw := (state.getActiveReg 10).toNat
  let access := if accessRaw == 1 then Cap.Access.rw else Cap.Access.ro
  match state.vms[vmIdx]!.capTable.get slot with
  | some (.data d) =>
    if pageOffset + pgCount > d.pageCount then
      (state.setActiveReg 7 RESULT_WHAT, .continue_)
    else
      -- Validate/set base offset and access
      let ok := match d.baseOffset with
        | some existing => existing == baseOffset
        | none => true
      let accessOk := match d.access with
        | some existing => existing == access
        | none => true
      if !ok || !accessOk then
        (state.setActiveReg 7 RESULT_WHAT, .continue_)
      else
        -- Update DATA cap metadata
        let newBitmap := Id.run do
          let mut bm := d.mappedBitmap
          while bm.size < d.pageCount do bm := bm.push false
          for i in [pageOffset:pageOffset + pgCount] do
            if i < bm.size then bm := bm.set! i true
          return bm
        let d' : DataCap := { d with baseOffset := some baseOffset, access := some access, mappedBitmap := newBitmap }
        let state := state.updateVm vmIdx fun vm =>
          { vm with capTable := vm.capTable.set slot (.data d') }
        -- Copy backing store pages into flat PVM memory
        let state := Id.run do
          let mut s := state
          for p in [pageOffset:pageOffset + pgCount] do
            let srcOff := (d.backingOffset + p) * pageSize
            let dstAddr := (baseOffset + p) * pageSize
            let pageData := s.backing.read (d.backingOffset + p) 0 pageSize
            -- Write page into PVM memory
            let mut mem := s.memory
            for i in [:pageSize] do
              if i < pageData.size then
                mem := mem.setByte (dstAddr + i) pageData[i]!
            -- Set page access
            let pageIdx := baseOffset + p
            let mut acc := mem.access
            while acc.size <= pageIdx do acc := acc.push .inaccessible
            let pa := if access == .rw then JAVM.PageAccess.writable else JAVM.PageAccess.readable
            acc := acc.set! pageIdx pa
            s := { s with memory := { mem with access := acc } }
          return s
        (state, .continue_)
  | _ => (state.setActiveReg 7 RESULT_WHAT, .continue_)

/-- UNMAP pages of a DATA cap. φ[7]=page_offset, φ[8]=page_count.
    Zeroes pages in PVM memory, marks inaccessible. -/
def handleUnmap (state : KernelState) (vmIdx : Nat) (slot : Nat) : KernelState × DispatchResult :=
  let pageOffset := (state.getActiveReg 7).toNat
  let pgCount := (state.getActiveReg 8).toNat
  match state.vms[vmIdx]!.capTable.get slot with
  | some (.data d) =>
    match d.baseOffset with
    | none => (state, .continue_) -- not mapped, no-op
    | some baseOffset =>
      -- Clear bitmap bits
      let d' := { d with mappedBitmap := Id.run do
        let mut bm := d.mappedBitmap
        for i in [pageOffset:pageOffset + pgCount] do
          if i < bm.size then bm := bm.set! i false
        return bm }
      let state := state.updateVm vmIdx fun vm =>
        { vm with capTable := vm.capTable.set slot (.data d') }
      -- Mark pages inaccessible in PVM memory
      let state := Id.run do
        let mut s := state
        for p in [pageOffset:pageOffset + pgCount] do
          let pageIdx := baseOffset + p
          let mut acc := s.memory.access
          if pageIdx < acc.size then
            acc := acc.set! pageIdx .inaccessible
          s := { s with memory := { s.memory with access := acc } }
        return s
      (state, .continue_)
  | _ => (state.setActiveReg 7 RESULT_WHAT, .continue_)

/-- SPLIT a DATA cap. φ[7]=page_offset. Subject=DATA, object=dst slot for hi half. -/
def handleSplit (state : KernelState) (sVm : Nat) (sSlot : Nat) (oVm : Nat) (oSlot : Nat)
    : KernelState × DispatchResult :=
  let pageOff := (state.getActiveReg 7).toNat
  match state.vms[sVm]!.capTable.get sSlot with
  | some (.data d) =>
    if d.mappedBitmap.any (· == true) || pageOff == 0 || pageOff >= d.pageCount then
      (state.setActiveReg 7 RESULT_WHAT, .continue_)
    else if !state.vms[oVm]!.capTable.isEmpty oSlot then
      (state.setActiveReg 7 RESULT_WHAT, .continue_)
    else
      let lo : DataCap := { backingOffset := d.backingOffset, pageCount := pageOff }
      let hi : DataCap := { backingOffset := d.backingOffset + pageOff, pageCount := d.pageCount - pageOff }
      let state := state.updateVm sVm fun vm =>
        { vm with capTable := vm.capTable.set sSlot (.data lo) }
      let state := state.updateVm oVm fun vm =>
        { vm with capTable := vm.capTable.set oSlot (.data hi) }
      (state, .continue_)
  | _ => (state.setActiveReg 7 RESULT_WHAT, .continue_)

/-- DROP a cap. Auto-unmaps DATA. -/
def handleDrop (state : KernelState) (vmIdx : Nat) (slot : Nat) : KernelState × DispatchResult :=
  let state := state.updateVm vmIdx fun vm =>
    { vm with capTable := { vm.capTable with slots := vm.capTable.slots.set! slot none } }
  (state, .continue_)

/-- MOVE a cap between CNodes. Auto-unmaps DATA on CNode change. -/
def handleMove (state : KernelState) (sVm : Nat) (sSlot : Nat) (oVm : Nat) (oSlot : Nat)
    : KernelState × DispatchResult :=
  if sVm == oVm && sSlot == oSlot then (state, .continue_)
  else if !state.vms[oVm]!.capTable.isEmpty oSlot then
    (state.setActiveReg 7 RESULT_WHAT, .continue_)
  else
    let (newSrcTable, cap) := state.vms[sVm]!.capTable.take sSlot
    let state := state.updateVm sVm fun vm => { vm with capTable := newSrcTable }
    match cap with
    | none => (state.setActiveReg 7 RESULT_WHAT, .continue_)
    | some c =>
      -- Auto-unmap DATA on CNode change
      let c := if sVm != oVm then
        match c with
        | .data d => .data { d with mappedBitmap := d.mappedBitmap.map (fun _ => false), baseOffset := none }
        | other => other
      else c
      let state := state.updateVm oVm fun vm =>
        { vm with capTable := vm.capTable.set oSlot c }
      (state, .continue_)

/-- COPY a cap between CNodes (copyable types only). -/
def handleCopy (state : KernelState) (sVm : Nat) (sSlot : Nat) (oVm : Nat) (oSlot : Nat)
    : KernelState × DispatchResult :=
  if !state.vms[oVm]!.capTable.isEmpty oSlot then
    (state.setActiveReg 7 RESULT_WHAT, .continue_)
  else
    match state.vms[sVm]!.capTable.get sSlot with
    | some cap =>
      match cap.tryCopy with
      | some copy =>
        let state := state.updateVm oVm fun vm =>
          { vm with capTable := vm.capTable.set oSlot copy }
        (state, .continue_)
      | none => (state.setActiveReg 7 RESULT_WHAT, .continue_)
    | none => (state.setActiveReg 7 RESULT_WHAT, .continue_)

/-- DOWNGRADE HANDLE → CALLABLE. Subject=HANDLE, object=dst slot. -/
def handleDowngrade (state : KernelState) (sVm : Nat) (sSlot : Nat) (oVm : Nat) (oSlot : Nat)
    : KernelState × DispatchResult :=
  match state.vms[sVm]!.capTable.get sSlot with
  | some (.handle h) =>
    if !state.vms[oVm]!.capTable.isEmpty oSlot then
      (state.setActiveReg 7 RESULT_WHAT, .continue_)
    else
      let callable : CallableCap := { vmId := h.vmId, maxGas := h.maxGas }
      let state := state.updateVm oVm fun vm =>
        { vm with capTable := vm.capTable.set oSlot (.callable callable) }
      (state, .continue_)
  | _ => (state.setActiveReg 7 RESULT_WHAT, .continue_)

/-- SET_MAX_GAS on a HANDLE. φ[7]=gas_limit. -/
def handleSetMaxGas (state : KernelState) (vmIdx : Nat) (slot : Nat)
    : KernelState × DispatchResult :=
  let gasLimit := (state.getActiveReg 7).toNat
  let state := state.updateVm vmIdx fun vm =>
    let newTable := match vm.capTable.get slot with
      | some (.handle h) => vm.capTable.set slot (.handle { h with maxGas := some gasLimit })
      | _ => vm.capTable
    { vm with capTable := newTable }
  (state, .continue_)

/-- RESUME a FAULTED VM. Same gas model as CALL. -/
def handleResume (state : KernelState) (vmIdx : Nat) (slot : Nat)
    : KernelState × DispatchResult :=
  -- Must be called from the active VM's local cap table
  if vmIdx != state.activeVm then
    (state.setActiveReg 7 RESULT_WHAT, .continue_)
  else
    match state.vms[vmIdx]!.capTable.get slot with
    | some (.handle h) =>
      let targetVmId := h.vmId
      if targetVmId >= state.vms.size then
        (state.setActiveReg 7 RESULT_WHAT, .continue_)
      else if state.vms[targetVmId]!.state != .faulted then
        (state.setActiveReg 7 RESULT_WHAT, .continue_)
      else
        -- Gas transfer (same as CALL)
        let callerGas := state.vms[state.activeVm]!.gas
        if callerGas < callOverheadGas then (state, .rootOutOfGas)
        else
          let afterOverhead := callerGas - callOverheadGas
          let calleeGas := match h.maxGas with
            | some limit => min afterOverhead limit
            | none => afterOverhead
          let callerIdx := state.activeVm
          let state := state.updateVm callerIdx fun vm =>
            { vm with state := .waitingForReply, gas := afterOverhead - calleeGas }
          let frame : CallFrame := { callerVmId := callerIdx, ipcCapIdx := none, ipcWasMapped := none }
          let state := { state with callStack := state.callStack.push frame }
          -- FAULTED → RUNNING, registers/PC preserved, new gas
          let state := state.updateVm targetVmId fun vm =>
            { vm with state := .running, gas := calleeGas, caller := some callerIdx }
          ({ state with activeVm := targetVmId }, .continue_)
    | _ => (state.setActiveReg 7 RESULT_WHAT, .continue_)

/-- CALL(DATA) = memcpy between two DATA caps via backing store.
    φ[7]=src_offset, φ[8]=len, φ[9]=dst_offset, φ[12]=dst DATA cap ref. -/
def handleCallData (state : KernelState) (srcVm : Nat) (srcSlot : Nat)
    : KernelState × DispatchResult :=
  let srcOffset := (state.getActiveReg 7).toNat
  let len := (state.getActiveReg 8).toNat
  let dstOffset := (state.getActiveReg 9).toNat
  let dstRef := UInt32.ofNat (state.getActiveReg 12).toNat
  if dstRef.toNat == 0 then
    (state.setActiveReg 7 RESULT_WHAT, .continue_)
  else
    match resolveCapRef state dstRef with
    | none => (state.setActiveReg 7 RESULT_WHAT, .continue_)
    | some (dstVm, dstSlot) =>
      match state.vms[srcVm]!.capTable.get srcSlot, state.vms[dstVm]!.capTable.get dstSlot with
      | some (.data src), some (.data dst) =>
        let srcSize := src.pageCount * pageSize
        let dstSize := dst.pageCount * pageSize
        if srcOffset + len > srcSize || dstOffset + len > dstSize || len == 0 then
          (state.setActiveReg 7 RESULT_WHAT, .continue_)
        else
          -- Copy via backing store
          let srcData := state.backing.read src.backingOffset srcOffset len
          let state := { state with backing := state.backing.write dst.backingOffset dstOffset srcData }
          (state.setActiveReg 7 (UInt64.ofNat len), .continue_)
      | _, _ => (state.setActiveReg 7 RESULT_WHAT, .continue_)

/-- ecall dispatch: φ[11]=op, φ[12]=subject|object. -/
def dispatchEcall (state : KernelState) : KernelState × DispatchResult :=
  match state.chargeGas ecalliGasCost with
  | none => (state, .rootOutOfGas)
  | some state =>
    let op := (state.getActiveReg 11).toNat
    let phi12 := (state.getActiveReg 12).toNat
    let objectRef := UInt32.ofNat (phi12 &&& 0xFFFFFFFF)   -- low u32
    let subjectRef := UInt32.ofNat (phi12 >>> 32)          -- high u32
    match op with
    | 0x00 => -- Dynamic CALL
      match resolveCapRef state subjectRef with
      | none => (state.setActiveReg 7 RESULT_WHAT, .continue_)
      | some (vmIdx, slot) =>
        match state.vms[vmIdx]!.capTable.get slot with
        | some (.protocol p) => (state, .protocolCall p.id)
        | some (.handle h) => handleCallVm state h.vmId h.maxGas
        | some (.callable c) => handleCallVm state c.vmId c.maxGas
        | _ => (state.setActiveReg 7 RESULT_WHAT, .continue_)
    | 0x02 => -- MAP
      match resolveCapRef state subjectRef with
      | none => (state.setActiveReg 7 RESULT_WHAT, .continue_)
      | some (vmIdx, slot) => handleMap state vmIdx slot
    | 0x03 => -- UNMAP
      match resolveCapRef state subjectRef with
      | none => (state.setActiveReg 7 RESULT_WHAT, .continue_)
      | some (vmIdx, slot) => handleUnmap state vmIdx slot
    | 0x04 => -- SPLIT
      match resolveCapRef state subjectRef, resolveCapRef state objectRef with
      | some (sv, ss), some (ov, os) => handleSplit state sv ss ov os
      | _, _ => (state.setActiveReg 7 RESULT_WHAT, .continue_)
    | 0x05 => -- DROP
      match resolveCapRef state subjectRef with
      | none => (state.setActiveReg 7 RESULT_WHAT, .continue_)
      | some (vmIdx, slot) => handleDrop state vmIdx slot
    | 0x06 => -- MOVE
      match resolveCapRef state subjectRef, resolveCapRef state objectRef with
      | some (sv, ss), some (ov, os) => handleMove state sv ss ov os
      | _, _ => (state.setActiveReg 7 RESULT_WHAT, .continue_)
    | 0x07 => -- COPY
      match resolveCapRef state subjectRef, resolveCapRef state objectRef with
      | some (sv, ss), some (ov, os) => handleCopy state sv ss ov os
      | _, _ => (state.setActiveReg 7 RESULT_WHAT, .continue_)
    | 0x0A => -- DOWNGRADE
      match resolveCapRef state subjectRef, resolveCapRef state objectRef with
      | some (sv, ss), some (ov, os) => handleDowngrade state sv ss ov os
      | _, _ => (state.setActiveReg 7 RESULT_WHAT, .continue_)
    | 0x0B => -- SET_MAX_GAS
      match resolveCapRef state subjectRef with
      | some (vmIdx, slot) => handleSetMaxGas state vmIdx slot
      | none => (state.setActiveReg 7 RESULT_WHAT, .continue_)
    | 0x0D => -- RESUME
      match resolveCapRef state subjectRef with
      | some (vmIdx, slot) => handleResume state vmIdx slot
      | none => (state.setActiveReg 7 RESULT_WHAT, .continue_)
    | _ => (state.setActiveReg 7 RESULT_WHAT, .continue_)

-- ============================================================================
-- ecalli Dispatch (CALL a cap)
-- ============================================================================

def dispatchEcalli (state : KernelState) (imm : UInt32) : KernelState × DispatchResult :=
  -- Range check: ecalli only valid for 0-127. ≥128 faults the VM.
  if imm.toNat > 127 then
    -- Fault with status 5 (invalid ecalli), φ[7] = imm value
    let state := state.setActiveReg 7 (UInt64.ofNat imm.toNat)
    (state, .rootPanic) -- will be status 5 when status codes are implemented
  else
  -- Charge gas
  match state.chargeGas ecalliGasCost with
  | none => (state, .rootOutOfGas)
  | some state =>
    -- IPC slot (0) = REPLY
    if imm.toNat == ipcSlot then handleReply state
    else
      match resolveCapRef state imm with
      | none => (state.setActiveReg 7 RESULT_WHAT, .continue_)
      | some (vmIdx, slot) =>
        match state.vms[vmIdx]!.capTable.get slot with
        | some (.protocol p) => (state, .protocolCall p.id)
        | some (.handle h) => handleCallVm state h.vmId h.maxGas
        | some (.callable c) => handleCallVm state c.vmId c.maxGas
        | some (.untyped _) => handleRetype state
        | some (.code c) => handleCreate state c.id vmIdx
        | some (.data _) => handleCallData state vmIdx slot
        | none =>
          (state.setActiveReg 7 RESULT_WHAT, .continue_)

-- ============================================================================
-- Main Kernel Loop
-- ============================================================================

/-- Run the kernel until it needs host interaction or terminates.
    Uses fuel parameter for termination proof. -/
def runKernel (state : KernelState) (fuel : Nat) : KernelState × KernelResult :=
  match fuel with
  | 0 => (state, .outOfGas)
  | fuel' + 1 =>
    let vm := state.activeInst
    if vm.gas == 0 then (state, .outOfGas)
    else
      let codeCapId := vm.codeCapId
      if codeCapId >= state.codeCaps.size then (state, .panic)
      else
        let codeCap := state.codeCaps[codeCapId]!
        -- Run one PVM segment using shared memory (gas model from pvmRun)
        let result := state.pvmRun codeCap.program vm.pc vm.registers state.memory
          (Int64.ofUInt64 (UInt64.ofNat vm.gas))
        -- Sync VM state + memory back
        let state := state.updateVm state.activeVm fun v =>
          { v with registers := result.registers
                   gas := result.gas.toUInt64.toNat
                   pc := result.nextPC }
        let state := { state with memory := result.memory }
        match result.exitReason with
        | .hostCall imm =>
          let (state', dr) := dispatchEcalli state (UInt32.ofNat imm.toNat)
          match dr with
          | .continue_ => runKernel state' fuel'
          | .faultHandled => runKernel state' fuel'
          | .protocolCall slot => (state', .protocolCall slot)
          | .rootHalt v => (state', .halt v)
          | .rootPanic => (state', .panic)
          | .rootOutOfGas => (state', .outOfGas)
          | .rootPageFault a => (state', .pageFault a)
        | .ecall =>
          let (state', dr) := dispatchEcall state
          match dr with
          | .continue_ => runKernel state' fuel'
          | .faultHandled => runKernel state' fuel'
          | .protocolCall slot => (state', .protocolCall slot)
          | .rootHalt v => (state', .halt v)
          | .rootPanic => (state', .panic)
          | .rootOutOfGas => (state', .outOfGas)
          | .rootPageFault a => (state', .pageFault a)
        | .halt =>
          let exitValue := (getReg result.registers 7).toNat
          let (state', dr) := handleVmHalt state exitValue
          match dr with
          | .rootHalt v => (state', .halt v)
          | .continue_ => runKernel state' fuel'
          | _ => (state', .panic)
        | .trap =>
          -- Status 1: trap. φ[7] = child's φ[7] (trap code).
          let childR7 := getReg state.activeInst.registers 7
          let (state', dr) := handleVmFaultWith state 1 childR7
          match dr with
          | .rootPanic => (state', .panic)
          | .continue_ => runKernel state' fuel'
          | _ => (state', .panic)
        | .panic =>
          -- Status 2: runtime panic. φ[7] = HUH.
          let (state', dr) := handleVmFaultWith state 2 RESULT_HUH
          match dr with
          | .rootPanic => (state', .panic)
          | .continue_ => runKernel state' fuel'
          | _ => (state', .panic)
        | .outOfGas =>
          -- Status 3: out of gas. φ[7] = LOW.
          let (state', dr) := handleVmFaultWith state 3 RESULT_LOW
          match dr with
          | .rootPanic => (state', .outOfGas)
          | .continue_ => runKernel state' fuel'
          | _ => (state', .outOfGas)
        | .pageFault addr =>
          -- Status 4: page fault. φ[7] = fault address.
          let (state', dr) := handleVmFaultWith state 4 addr
          match dr with
          | .rootPanic => (state', .pageFault addr.toNat)
          | .continue_ => runKernel state' fuel'
          | _ => (state', .pageFault addr.toNat)

-- ============================================================================
-- Protocol Call Resume
-- ============================================================================

def resumeProtocolCall (state : KernelState) (result0 result1 : UInt64) : KernelState :=
  state.updateVm state.activeVm fun vm =>
    { vm with registers := setReg (setReg vm.registers 7 result0) 8 result1 }

-- ============================================================================
-- Kernel Initialization
-- ============================================================================

/-- Initialize a kernel from a parsed PVM program, arguments, and gas budget.
    For jar1: creates VM 0 with protocol caps 1-28, manifest caps, UNTYPED at 254.
    Sets φ[7]=op, φ[8]=args_base, φ[9]=args_len. PC=0. -/
def initKernel (prog : JAVM.ProgramBlob) (regs : JAVM.Registers) (mem : JAVM.Memory)
    (gas : Nat) (memoryPages : Nat) (pvmRun : PvmRunFn := JAVM.run) : KernelState :=
  -- Create code cap from program
  let codeCap : CodeCapData := { id := 0, program := prog, jumpTable := #[] }
  -- Build VM 0 cap table: protocol caps 1-28
  let capTable := Id.run do
    let mut table := CapTable.empty
    for id in [1:29] do
      table := table.setOriginal id (.protocol { id := id })
    -- UNTYPED at slot 254 (if memoryPages > 0)
    if memoryPages > 0 then
      table := table.set 254 (.untyped { offset := 0, total := memoryPages })
    return table
  -- Create backing store
  let backing : BackingStore := {
    data := ByteArray.mk (Array.replicate (memoryPages * pageSize) 0)
    totalPages := memoryPages
  }
  let vm0 : VmInstance := {
    state := .running
    codeCapId := 0
    registers := regs
    pc := 0
    capTable := capTable
    caller := none
    entryIndex := 0
    gas := gas
  }
  { vms := #[vm0]
    callStack := #[]
    codeCaps := #[codeCap]
    activeVm := 0
    untyped := { offset := 0, total := memoryPages }
    backing := backing
    memory := mem
    pvmRun := pvmRun
    memCycles := 25 }

/-- Get remaining gas from the active VM. -/
def KernelState.activeGas (state : KernelState) : Nat :=
  state.activeInst.gas

end Jar.JAVM.Kernel
