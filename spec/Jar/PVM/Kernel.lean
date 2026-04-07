import Jar.PVM
import Jar.PVM.Capability
import Jar.PVM.Interpreter

/-!
# PVM Capability Kernel

Execution engine for the jar1 capability model. Manages a pool of VMs,
dispatches ecalli/ecall through capability resolution, and handles
multi-VM CALL/REPLY/RESUME.

This replaces the flat `handleHostCall` path for jar1. gp072 continues
using the flat path unchanged.
-/

namespace Jar.PVM.Kernel

open Jar.PVM.Cap

-- ============================================================================
-- Core Types
-- ============================================================================

/-- Compiled code data associated with a CODE cap. -/
structure CodeCapData where
  id : Nat
  program : PVM.ProgramBlob
  jumpTable : Array Nat

instance : Inhabited CodeCapData where
  default := { id := 0, program := { code := ByteArray.empty, bitmask := ByteArray.empty, jumpTable := #[] }, jumpTable := #[] }

/-- Backing store: flat byte array representing all physical pages. -/
structure BackingStore where
  data : ByteArray
  totalPages : Nat

/-- Kernel state: VM pool + call stack + backing store. -/
structure KernelState where
  vms : Array VmInstance
  callStack : Array CallFrame
  codeCaps : Array CodeCapData
  activeVm : Nat
  untyped : UntypedCap
  backing : BackingStore
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
def ecalliGasCost : Nat := 10
def callOverheadGas : Nat := 10
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

def getReg (regs : PVM.Registers) (i : Nat) : UInt64 :=
  if i < regs.size then regs[i]! else 0

def setReg (regs : PVM.Registers) (i : Nat) (v : UInt64) : PVM.Registers :=
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
        ipcWasMapped := none
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
    (ipcCapIdx : Option Nat) : KernelState :=
  -- Return unused gas
  let unusedGas := state.vms[calleeIdx]!.gas
  let state := state.updateVm callerIdx fun vm => { vm with gas := vm.gas + unusedGas }
  let state := state.updateVm calleeIdx fun vm => { vm with gas := 0 }
  -- Return IPC cap if any
  let state := match ipcCapIdx with
    | none => state
    | some slot =>
      let (newTable, cap) := state.vms[calleeIdx]!.capTable.take 0
      let s := state.updateVm calleeIdx fun vm => { vm with capTable := newTable }
      match cap with
      | some c => s.updateVm callerIdx fun vm =>
          { vm with capTable := vm.capTable.set ( slot) c }
      | none => s
  -- Pass results + resume caller
  let calleeRegs := state.vms[calleeIdx]!.registers
  let state := state.updateVm callerIdx fun vm =>
    { vm with
      state := .running
      registers := setReg (setReg vm.registers
        7 (getReg calleeRegs 7))
        8 (getReg calleeRegs 8) }
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
    let state := resumeCaller state calleeIdx callerIdx frame.ipcCapIdx
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
    let state := state.updateVm callerIdx fun vm =>
      { vm with state := .running
                registers := setReg vm.registers 7 (UInt64.ofNat exitValue) }
    ({ state with activeVm := callerIdx }, .continue_)

def handleVmFault (state : KernelState) : KernelState × DispatchResult :=
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
                registers := setReg vm.registers 7 RESULT_WHAT }
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
      registers := Array.replicate PVM.numRegisters 0
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
    φ[7]=base_offset, φ[8]=page_offset, φ[9]=page_count. -/
def handleMap (state : KernelState) (vmIdx : Nat) (slot : Nat) : KernelState × DispatchResult :=
  -- In the Lean spec, MAP copies backing store pages into the VM's flat memory.
  -- TODO: implement when memory model is wired up
  (state, .continue_)

/-- UNMAP pages of a DATA cap. φ[7]=page_offset, φ[8]=page_count. -/
def handleUnmap (state : KernelState) (vmIdx : Nat) (slot : Nat) : KernelState × DispatchResult :=
  (state, .continue_) -- TODO

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

/-- ecall dispatch: φ[11]=op, φ[12]=subject|object. -/
def dispatchEcall (state : KernelState) : KernelState × DispatchResult :=
  match state.chargeGas ecalliGasCost with
  | none => (state, .rootOutOfGas)
  | some state =>
    let op := (state.getActiveReg 11).toNat
    let phi12 := (state.getActiveReg 12).toNat
    let subjectRef := UInt32.ofNat (phi12 &&& 0xFFFFFFFF)
    let objectRef := UInt32.ofNat (phi12 >>> 32)
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
    | 0x0A => -- DOWNGRADE: TODO (PR C)
      (state.setActiveReg 7 RESULT_WHAT, .continue_)
    | 0x0B => -- SET_MAX_GAS: TODO (PR C)
      (state.setActiveReg 7 RESULT_WHAT, .continue_)
    | 0x0D => -- RESUME: TODO (PR C)
      (state.setActiveReg 7 RESULT_WHAT, .continue_)
    | _ => (state.setActiveReg 7 RESULT_WHAT, .continue_)

-- ============================================================================
-- ecalli Dispatch (CALL a cap)
-- ============================================================================

def dispatchEcalli (state : KernelState) (imm : UInt32) : KernelState × DispatchResult :=
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
        | some (.data _) =>
          -- CALL(DATA) memcpy: TODO (PR C)
          (state.setActiveReg 7 RESULT_WHAT, .continue_)
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
        -- Run one PVM segment (uses flat memory — simplified model)
        let flatMem : PVM.Memory := { pages := Dict.empty, access := #[] } -- TODO: build from mapped DATA caps
        let result := PVM.run codeCap.program vm.pc vm.registers flatMem
          (Int64.ofUInt64 (UInt64.ofNat vm.gas))
        -- Sync VM state
        let state := state.updateVm state.activeVm fun v =>
          { v with registers := result.registers
                   gas := result.gas.toUInt64.toNat
                   pc := result.nextPC }
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
        | .halt =>
          let exitValue := (getReg result.registers 7).toNat
          let (state', dr) := handleVmHalt state exitValue
          match dr with
          | .rootHalt v => (state', .halt v)
          | .continue_ => runKernel state' fuel'
          | _ => (state', .panic)
        | .panic =>
          let (state', dr) := handleVmFault state
          match dr with
          | .rootPanic => (state', .panic)
          | .continue_ => runKernel state' fuel'
          | _ => (state', .panic)
        | .outOfGas =>
          let (state', dr) := handleVmFault state
          match dr with
          | .rootPanic => (state', .outOfGas)
          | .continue_ => runKernel state' fuel'
          | _ => (state', .outOfGas)
        | .pageFault addr =>
          let (state', dr) := handleVmFault state
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

end Jar.PVM.Kernel
