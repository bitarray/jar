import Jar.Notation
import Jar.Types
import Jar.Codec
import Jar.Crypto
import Jar.StateSerialization
import Jar.PVM
import Jar.PVM.Decode
import Jar.PVM.Memory
import Jar.PVM.Instructions
import Jar.PVM.Interpreter

/-!
# Accumulation — §12

On-chain accumulation pipeline: accseq, accpar, accone.
Host-call handlers (Ω_0 through Ω_26) for the accumulate invocation Ψ_A.
References: `graypaper/text/accumulation.tex`, `graypaper/text/pvm_invocations.tex`.

## Structure
- §12.1: Operand tuples and deferred transfers
- §12.2: Partial state for accumulation
- §12.3: accone — single-service accumulation
- §12.4: accpar — parallelized accumulation
- §12.5: accseq — sequential orchestration
- Host calls: gas(0), fetch(1), lookup(2), read(3), write(4), info(5),
  historical_lookup(6), export(7), machine(8), peek(9), poke(10),
  pages(11), invoke(12), bless(14), assign(15), designate(16),
  checkpoint(17), new(18), upgrade(19), transfer(20), eject(21),
  query(22), solicit(23), forget(24), yield(25), provide(26)
-/

namespace Jar.Accumulation
variable [JamConfig]

-- ============================================================================
-- Operand Tuple — GP eq:operandtuple
-- ============================================================================

/-- Combined work-digest/report operand for accumulation. GP §12. -/
structure OperandTuple where
  packageHash : Hash
  segmentRoot : Hash
  authorizerHash : Hash
  payloadHash : Hash
  gasLimit : Gas
  authOutput : ByteArray
  result : WorkResult

instance : Inhabited OperandTuple where
  default := {
    packageHash := default, segmentRoot := default, authorizerHash := default,
    payloadHash := default, gasLimit := 0, authOutput := ByteArray.empty,
    result := .ok ByteArray.empty }

-- ============================================================================
-- Accumulation Input — GP eq:accinput
-- ============================================================================

/-- Input to a single-service accumulation: either an operand or a deferred transfer. -/
inductive AccInput where
  | operand : OperandTuple → AccInput
  | transfer : DeferredTransfer → AccInput

-- ============================================================================
-- Partial State — GP eq:partialstate
-- ============================================================================

/-- Partial state threaded through accumulation. GP §12. -/
structure PartialState where
  accounts : Dict ServiceId ServiceAccount
  stagingKeys : Array ValidatorKey
  authQueue : Array (Array Hash)
  manager : ServiceId
  assigners : Array ServiceId
  designator : ServiceId
  registrar : ServiceId
  alwaysAccumulate : Dict ServiceId Gas

/-- Extract partial state from full state. -/
def PartialState.fromState (s : State) : PartialState :=
  { accounts := s.services
    stagingKeys := s.pendingValidators
    authQueue := s.authQueue
    manager := s.privileged.manager
    assigners := s.privileged.assigners
    designator := s.privileged.designator
    registrar := s.privileged.registrar
    alwaysAccumulate := s.privileged.alwaysAccumulate }

-- ============================================================================
-- Accumulation Output — GP eq:acconeout
-- ============================================================================

/-- Output of a single-service accumulation. GP §12. -/
structure AccOneOutput where
  postState : PartialState
  deferredTransfers : Array DeferredTransfer
  yieldHash : Option Hash
  gasUsed : Gas
  provisions : Array (ServiceId × ByteArray)
  /-- Updated opaque data (entries consumed during accumulation removed). -/
  opaqueData : Array (ByteArray × ByteArray) := #[]
  /-- Debug: exit reason string for tracing. -/
  exitReasonStr : String := ""
  /-- Debug: host call log entries. -/
  hostCallLog : Array String := #[]

-- ============================================================================
-- Host-Call Context for Accumulation
-- ============================================================================

/-- Mutable context during a single accumulation invocation. -/
structure AccContext where
  /-- Service ID being accumulated. -/
  serviceId : ServiceId
  /-- Current partial state. -/
  state : PartialState
  /-- Deferred transfers generated so far. -/
  transfers : Array DeferredTransfer
  /-- Yield value (accumulation output). -/
  yieldHash : Option Hash
  /-- Preimage provisions. -/
  provisions : Array (ServiceId × ByteArray)
  /-- Gas used so far. -/
  gasUsed : Gas
  /-- Operand tuples for this service. -/
  operands : Array OperandTuple
  /-- Current timeslot. -/
  timeslot : Timeslot
  /-- Next service ID for new service creation. -/
  nextServiceId : ServiceId
  /-- Checkpoint state: full context (for OOG/panic revert).
      Saves (partialState, opaqueData, yieldHash, transfers, provisions). -/
  checkpoint : Option (PartialState × Array (ByteArray × ByteArray) × Option Hash × Array DeferredTransfer × Array (ServiceId × ByteArray))
  /-- Entropy η'₀ for fetch mode 1. -/
  entropy : Hash
  /-- Protocol configuration blob for fetch mode 0. -/
  configBlob : ByteArray
  /-- Encoded items blob for fetch mode 14. -/
  itemsBlob : ByteArray
  /-- Individual encoded items for fetch mode 15. -/
  items : Array ByteArray
  /-- Opaque data for fallback lookups (storage/preimage from initial keyvals). -/
  opaqueData : Array (ByteArray × ByteArray)
  /-- Initial accounts snapshot for parallel semantics: host calls that read OTHER
      services' state use this instead of ctx.state.accounts. -/
  initAccounts : Dict ServiceId ServiceAccount := Dict.empty
  /-- Segment export data (for export host call). -/
  exports : Array ByteArray := #[]
  /-- Debug: host call log. -/
  hostCallLog : Array String := #[]
  /-- Debug: extra info for current host call (reset each call). -/
  debugExtra : String := ""

instance : Inhabited AccContext where
  default := {
    serviceId := 0
    state := { accounts := Dict.empty, stagingKeys := #[], authQueue := #[],
               manager := 0, assigners := #[], designator := 0, registrar := 0,
               alwaysAccumulate := Dict.empty }
    transfers := #[]
    yieldHash := none
    provisions := #[]
    gasUsed := 0
    operands := #[]
    timeslot := 0
    nextServiceId := 0
    checkpoint := none
    entropy := default
    configBlob := ByteArray.empty
    itemsBlob := ByteArray.empty
    items := #[]
    opaqueData := #[]
    exports := #[]
    hostCallLog := #[]
    debugExtra := ""
  }

-- ============================================================================
-- Opaque Data Helpers
-- ============================================================================

/-- Look up an entry in opaque data by state key, returning the value and the
    opaque data array with that entry removed (promotion). -/
private def opaquePromote (opaqueData : Array (ByteArray × ByteArray))
    (stateKey : OctetSeq 31) : Option (ByteArray × Array (ByteArray × ByteArray)) :=
  -- Find matching entry by linear scan
  let found := opaqueData.findSome? fun (k, v) =>
    if k == stateKey.data then some v else none
  match found with
  | none => none
  | some v =>
    -- Remove the first matching entry
    let opaqueData' := opaqueData.filter fun (k, _) => k != stateKey.data
    some (v, opaqueData')

/-- Promote a storage entry from opaque data into a service account's structured storage.
    Returns updated (account, opaqueData) or none if not found. -/
private def promoteStorage (acct : ServiceAccount) (opaqueData : Array (ByteArray × ByteArray))
    (targetSid : ServiceId) (keyBytes : ByteArray)
    : Option (ServiceAccount × Array (ByteArray × ByteArray)) :=
  let stateKey := StateSerialization.stateKeyForServiceData targetSid
    (StateSerialization.storageHashArg keyBytes)
  match opaquePromote opaqueData stateKey with
  | none => none
  | some (v, opaqueData') =>
    let acct' := { acct with storage := acct.storage.insert keyBytes v }
    some (acct', opaqueData')

/-- Promote a preimage lookup entry from opaque data into a service account's preimage store.
    Returns updated (account, opaqueData) or none if not found. -/
private def promotePreimageLookup (acct : ServiceAccount) (opaqueData : Array (ByteArray × ByteArray))
    (targetSid : ServiceId) (hash : Hash)
    : Option (ServiceAccount × Array (ByteArray × ByteArray)) :=
  let stateKey := StateSerialization.stateKeyForServiceData targetSid
    (StateSerialization.preimageHashArg hash)
  match opaquePromote opaqueData stateKey with
  | none => none
  | some (v, opaqueData') =>
    let acct' := { acct with preimages := acct.preimages.insert hash v }
    some (acct', opaqueData')

/-- Decode preimage info timeslots from raw bytes (compact-encoded count + E_4 each).
    This matches Grey's deserialization of preimage_info values. -/
private def decodePreimageInfoTimeslots (data : ByteArray) : Array Timeslot :=
  match Codec.Decoder.run (fun s => do
    let (count, s) ← Codec.decodeNatD s
    let mut timeslots : Array Timeslot := #[]
    let mut state := s
    for _ in [:count] do
      match Codec.decodeFixedNatD 4 state with
      | some (ts, s') =>
        timeslots := timeslots.push (UInt32.ofNat ts)
        state := s'
      | none => break
    return (timeslots, state)) data with
  | some ts => ts
  | none => #[]

/-- Promote a preimage info entry from opaque data into a service account's preimage info.
    Returns updated (account, opaqueData) or none if not found. -/
private def promotePreimageInfo (acct : ServiceAccount) (opaqueData : Array (ByteArray × ByteArray))
    (targetSid : ServiceId) (hash : Hash) (blobLen : UInt32)
    : Option (ServiceAccount × Array (ByteArray × ByteArray)) :=
  let stateKey := StateSerialization.stateKeyForServiceData targetSid
    (StateSerialization.preimageInfoHashArg blobLen hash)
  match opaquePromote opaqueData stateKey with
  | none => none
  | some (v, opaqueData') =>
    let timeslots := decodePreimageInfoTimeslots v
    let acct' := { acct with preimageInfo := acct.preimageInfo.insert (hash, blobLen) timeslots }
    some (acct', opaqueData')

-- ============================================================================
-- Host-Call Gas Cost — GP Appendix B
-- ============================================================================

/-- Base gas cost for host calls: 10 gas. -/
def hostCallGas : Nat := 10

-- ============================================================================
-- Host-Call Handlers — GP Appendix B (pvm_invocations.tex)
-- ============================================================================

/-- Get register value safely. -/
private def dbgHex (ba : ByteArray) : String := Id.run do
  let mut s := ""
  for i in [:ba.size] do
    let b := ba.get! i
    let hi := b.toNat / 16; let lo := b.toNat % 16
    let hexChar (n : Nat) : Char := if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)
    s := s ++ String.mk [hexChar hi, hexChar lo]
  return s

private def getReg (regs : PVM.Registers) (i : Nat) : UInt64 :=
  if i < regs.size then regs[i]! else 0

/-- Set register value safely. -/
private def setReg (regs : PVM.Registers) (i : Nat) (v : UInt64) : PVM.Registers :=
  if i < regs.size then regs.set! i v else regs

/-- Encode a ServiceAccount's info structure for host_info(5). GP Appendix B.
    v = E(a_c, E_8(a_b, a_t, a_g, a_m, a_o), E_4(a_i), E_8(a_f), E_4(a_r, a_a, a_p))
    = code_hash(32) ‖ balance(8) ‖ threshold(8) ‖ min_item_gas(8) ‖
      min_memo_gas(8) ‖ total_octets(8) ‖ items(4) ‖ deposit_offset(8) ‖
      creation_slot(4) ‖ last_acc(4) ‖ parent_svc(4) = 96 bytes -/
private def encodeAccountInfo (acct : ServiceAccount) : ByteArray :=
  -- Use preserved totalFootprint/itemCount values, maintained incrementally
  -- during accumulation host calls.
  let totalItems := acct.itemCount.toNat  -- a_i: item count
  let totalBytes := acct.totalFootprint   -- a_o: total storage footprint
  -- Compute threshold: B_S + B_I * items + B_L * bytes - deposit_offset
  let minBal := B_S + B_I * totalItems + B_L * totalBytes
  let threshold := minBal - min acct.gratis.toNat minBal
  acct.codeHash.data
    ++ Codec.encodeFixedNat 8 acct.balance.toNat       -- a_b
    ++ Codec.encodeFixedNat 8 threshold                 -- a_t
    ++ Codec.encodeFixedNat 8 acct.minAccGas.toNat      -- a_g
    ++ Codec.encodeFixedNat 8 acct.minOnTransferGas.toNat -- a_m
    ++ Codec.encodeFixedNat 8 totalBytes                -- a_o
    ++ Codec.encodeFixedNat 4 totalItems                -- a_i
    ++ Codec.encodeFixedNat 8 acct.gratis.toNat         -- a_f
    ++ Codec.encodeFixedNat 4 acct.creationSlot.toNat   -- a_r: creation timeslot
    ++ Codec.encodeFixedNat 4 acct.lastAccumulation.toNat -- a_a: last accumulation timeslot
    ++ Codec.encodeFixedNat 4 acct.parentServiceId      -- a_p: parent service ID

/-- Dispatch a host call during accumulation. GP §12, Appendix B.
    Returns updated invocation result and context. -/
def handleHostCall (callId : PVM.Reg) (gas : Gas) (regs : PVM.Registers)
    (mem : PVM.Memory) (ctx : AccContext) : PVM.InvocationResult × AccContext :=
  let callNum := callId.toNat
  let inputLog := s!"hc({callNum}) r7={getReg regs 7} r8={getReg regs 8} r9={getReg regs 9} r10={getReg regs 10} r11={getReg regs 11} r12={getReg regs 12}"
  let mkResult (regs' : PVM.Registers) (mem' : PVM.Memory) (gas' : Gas) : PVM.InvocationResult :=
    { exitReason := .hostCall callId  -- signals "continue" to the loop
      exitValue := if 7 < regs'.size then regs'[7]! else 0
      gas := Int64.ofUInt64 gas'
      registers := regs'
      memory := mem' }
  -- GP: Memory read failure in host calls → PANIC (⚡) — terminates PVM
  let mkPanic (regs' : PVM.Registers) (mem' : PVM.Memory) (gas' : Gas) : PVM.InvocationResult :=
    { exitReason := .panic
      exitValue := if 7 < regs'.size then regs'[7]! else 0
      gas := Int64.ofUInt64 gas'
      registers := regs'
      memory := mem' }
  let setR7 (r : PVM.Registers) (v : UInt64) := setReg r 7 v
  let gas' := if gas.toNat >= hostCallGas then gas - UInt64.ofNat hostCallGas else 0
  let (result, ctx') : PVM.InvocationResult × AccContext := match callNum with
  -- ===== gas (0): Return remaining gas in reg[7] =====
  | 0 =>
    let regs' := setR7 regs gas'
    (mkResult regs' mem gas', ctx)

  -- ===== fetch (1): ΩY — read protocol/context data =====
  -- φ[7]=buf_ptr, φ[8]=offset, φ[9]=max_len, φ[10]=mode, φ[11]=sub1, φ[12]=sub2
  -- Returns: φ'[7] = |v| (total data length) or NONE (u64::MAX)
  | 1 =>
    let bufPtr := getReg regs 7
    let offset := (getReg regs 8).toNat
    let maxLen := (getReg regs 9).toNat
    let mode := (getReg regs 10).toNat
    let sub1 := (getReg regs 11).toNat
    -- Select data based on mode (accumulate context: modes 0, 1, 14, 15)
    let data : Option ByteArray := match mode with
      | 0 => some ctx.configBlob            -- Protocol configuration
      | 1 => some ctx.entropy.data           -- Entropy η'₀
      | 14 => some ctx.itemsBlob             -- All items encoded
      | 15 =>                                 -- Single item at index sub1
        if sub1 < ctx.items.size then some ctx.items[sub1]!
        else none
      | _ => none
    match data with
    | none =>
      let regs' := setR7 regs PVM.RESULT_NONE
      (mkResult regs' mem gas', ctx)
    | some d =>
      let dataLen := d.size
      let f := min offset dataLen
      let l := min maxLen (dataLen - f)
      -- Write data[f..f+l] to memory at bufPtr
      if l > 0 then
        let src := d.extract f (f + l)
        match PVM.writeByteArray mem bufPtr src with
        | .ok mem' =>
          let regs' := setR7 regs (UInt64.ofNat dataLen)
          (mkResult regs' mem' gas', ctx)
        | _ =>
          -- Page fault on write → panic (GP: ⚡)
          (mkPanic regs mem gas', ctx)
      else
        let regs' := setR7 regs (UInt64.ofNat dataLen)
        (mkResult regs' mem gas', ctx)

  -- ===== lookup (2): Preimage lookup by hash =====
  -- φ[7]=service_id (u64::MAX=self), φ[8]=hash_ptr, φ[9]=out_ptr,
  -- φ[10]=offset, φ[11]=max_len
  -- Returns: φ'[7] = total preimage length or NONE
  | 2 =>
    let rawSid := getReg regs 7
    let hashPtr := getReg regs 8
    let outPtr := getReg regs 9
    let offset := (getReg regs 10).toNat
    let maxLen := (getReg regs 11).toNat
    -- Read the 32-byte hash from memory
    match PVM.readByteArray mem hashPtr 32 with
    | .ok hashBytes =>
      let h : Hash := ⟨hashBytes, sorry⟩
      let targetSid := if rawSid == UInt64.ofNat (2^64 - 1) then ctx.serviceId
        else if rawSid.toNat < 2^32 then UInt32.ofNat rawSid.toNat
        else ctx.serviceId
      -- Look up the preimage in the target service's preimage store
      match ctx.state.accounts.lookup targetSid with
      | none =>
        let regs' := setR7 regs PVM.RESULT_NONE
        (mkResult regs' mem gas', ctx)
      | some acct =>
        -- Try structured preimages first, then promote from opaque data
        let (acct, ctx) :=
          if acct.preimages.lookup h |>.isSome then (acct, ctx)
          else match promotePreimageLookup acct ctx.opaqueData targetSid h with
            | some (acct', opaqueData') =>
              (acct', { ctx with opaqueData := opaqueData' })
            | none => (acct, ctx)
        match acct.preimages.lookup h with
        | none =>
          let regs' := setR7 regs PVM.RESULT_NONE
          (mkResult regs' mem gas', ctx)
        | some preimage =>
          -- Update accounts with promoted preimage
          let accounts' := ctx.state.accounts.insert targetSid acct
          let state' := { ctx.state with accounts := accounts' }
          let ctx' := { ctx with state := state' }
          let vLen := preimage.size
          let f := min offset vLen
          let l := min maxLen (vLen - f)
          if l > 0 then
            let toWrite := preimage.extract f (f + l)
            match PVM.writeByteArray mem outPtr toWrite with
            | .ok mem' =>
              let regs' := setR7 regs (UInt64.ofNat vLen)
              (mkResult regs' mem' gas', ctx')
            | _ =>
              -- Page fault on write → panic (GP: ⚡)
              (mkPanic regs mem gas', ctx')
          else
            let regs' := setR7 regs (UInt64.ofNat vLen)
            (mkResult regs' mem gas', ctx')
    | _ =>
      -- Page fault on hash read → panic (GP: ⚡)
      (mkPanic regs mem gas', ctx)

  -- ===== read (3): Read from service storage =====
  -- φ[7]=service_id (u64::MAX=self), φ[8]=key_ptr, φ[9]=key_len,
  -- φ[10]=out_ptr, φ[11]=offset, φ[12]=max_len
  -- Returns: φ'[7] = total value length or NONE
  | 3 =>
    let rawSid := getReg regs 7
    let keyPtr := getReg regs 8
    let keyLen := (getReg regs 9).toNat
    let outPtr := getReg regs 10
    let offset := (getReg regs 11).toNat
    let maxLen := (getReg regs 12).toNat
    match PVM.readByteArray mem keyPtr keyLen with
    | .ok keyBytes =>
      let targetSid := if rawSid == UInt64.ofNat (2^64 - 1) then ctx.serviceId
        else if rawSid.toNat < 2^32 then UInt32.ofNat rawSid.toNat
        else ctx.serviceId  -- out of range → NONE
      match ctx.state.accounts.lookup targetSid with
      | none =>
        let regs' := setR7 regs PVM.RESULT_NONE
        (mkResult regs' mem gas', ctx)
      | some acct =>
        -- Look up in structured storage first, then fall back to opaqueData
        let (acct, ctx) :=
          if acct.storage.lookup keyBytes |>.isSome then (acct, ctx)
          else match promoteStorage acct ctx.opaqueData targetSid keyBytes with
            | some (acct', opaqueData') =>
              (acct', { ctx with opaqueData := opaqueData' })
            | none => (acct, ctx)
        match acct.storage.lookup keyBytes with
        | none =>
          let regs' := setR7 regs PVM.RESULT_NONE
          (mkResult regs' mem gas', ctx)
        | some val =>
          -- Update accounts with promoted storage
          let accounts' := ctx.state.accounts.insert targetSid acct
          let state' := { ctx.state with accounts := accounts' }
          let valSnip := if val.size > 32 then dbgHex (val.extract 0 32) ++ s!"..({val.size}B)" else dbgHex val
          let ctx' := { ctx with state := state', debugExtra := s!" read_svc={targetSid} read_key={dbgHex keyBytes} read_val={valSnip}" }
          let vLen := val.size
          let f := min offset vLen
          let l := min maxLen (vLen - f)
          if l > 0 then
            let toWrite := val.extract f (f + l)
            match PVM.writeByteArray mem outPtr toWrite with
            | .ok mem' =>
              let regs' := setR7 regs (UInt64.ofNat vLen)
              (mkResult regs' mem' gas', ctx')
            | _ =>
              -- Page fault on write → panic (GP: ⚡)
              (mkPanic regs mem gas', ctx')
          else
            let regs' := setR7 regs (UInt64.ofNat vLen)
            (mkResult regs' mem gas', ctx')
    | _ =>
      -- Page fault on key read → panic (GP: ⚡)
      (mkPanic regs mem gas', ctx)

  -- ===== write (4): Write to own storage =====
  -- φ[7]=key_ptr, φ[8]=key_len, φ[9]=val_ptr, φ[10]=val_len
  -- Returns: φ'[7] = old value length (or NONE if key didn't exist)
  | 4 =>
    let keyPtr := getReg regs 7
    let keyLen := (getReg regs 8).toNat
    let valPtr := getReg regs 9
    let valLen := (getReg regs 10).toNat
    match PVM.readByteArray mem keyPtr keyLen with
    | .ok keyBytes =>
      match ctx.state.accounts.lookup ctx.serviceId with
      | none =>
        let regs' := setR7 regs PVM.RESULT_NONE
        (mkResult regs' mem gas', ctx)
      | some acct =>
        -- Promote from opaque data if not in structured storage
        let (acct, ctx) :=
          if acct.storage.lookup keyBytes |>.isSome then (acct, ctx)
          else match promoteStorage acct ctx.opaqueData ctx.serviceId keyBytes with
            | some (acct', opaqueData') =>
              (acct', { ctx with opaqueData := opaqueData' })
            | none => (acct, ctx)
        let oldVal := acct.storage.lookup keyBytes
        let oldLen : UInt64 := match oldVal with
          | some v => UInt64.ofNat v.size
          | none => PVM.RESULT_NONE
        if valLen == 0 then
          -- Delete the key
          match oldVal with
          | some oldV =>
            let oldSize := 34 + keyBytes.size + oldV.size
            let acct' := { acct with
              storage := acct.storage.erase keyBytes
              itemCount := acct.itemCount - 1  -- items -= 1
              totalFootprint := acct.totalFootprint - oldSize }
            let accounts' := ctx.state.accounts.insert ctx.serviceId acct'
            let state' := { ctx.state with accounts := accounts' }
            let regs' := setR7 regs oldLen
            (mkResult regs' mem gas', { ctx with state := state' })
          | none =>
            -- Key didn't exist, nothing to delete
            let regs' := setR7 regs oldLen
            (mkResult regs' mem gas', ctx)
        else
          match PVM.readByteArray mem valPtr valLen with
          | .ok valBytes =>
            let newSize := 34 + keyBytes.size + valBytes.size
            let (items', footprint') := match oldVal with
              | some oldV =>
                let oldSize := 34 + keyBytes.size + oldV.size
                (acct.itemCount, acct.totalFootprint - oldSize + newSize)
              | none =>
                (acct.itemCount + 1, acct.totalFootprint + newSize)
            -- GP: Check threshold after write doesn't exceed balance
            let newMinBal := B_S + B_I * items'.toNat + B_L * footprint'
            let newThreshold := newMinBal - min acct.gratis.toNat newMinBal
            if newThreshold > acct.balance.toNat then
              let regs' := setR7 regs PVM.RESULT_FULL
              (mkResult regs' mem gas', ctx)
            else
            let acct' := { acct with
              storage := acct.storage.insert keyBytes valBytes
              itemCount := items'
              totalFootprint := footprint' }
            let accounts' := ctx.state.accounts.insert ctx.serviceId acct'
            let state' := { ctx.state with accounts := accounts' }
            let regs' := setR7 regs oldLen
            let ctxD := { ctx with debugExtra := s!" write_key={dbgHex keyBytes} write_val={dbgHex valBytes}" }
            (mkResult regs' mem gas', { ctxD with state := state' })
          | _ =>
            -- Page fault on value read → panic (GP: ⚡)
            (mkPanic regs mem gas', ctx)
    | _ =>
      -- Page fault on key read → panic (GP: ⚡)
      (mkPanic regs mem gas', ctx)

  -- ===== info (5): Service account information =====
  -- φ[7]=service_id (2^64-1=self), φ[8]=out_ptr, φ[9]=offset, φ[10]=max_len
  -- Returns: φ'[7] = |v| (96) or NONE
  | 5 =>
    let rawSid := getReg regs 7
    let outPtr := getReg regs 8
    let offset := (getReg regs 9).toNat
    let maxLen := (getReg regs 10).toNat
    let targetSid := if rawSid == UInt64.ofNat (2^64 - 1) then ctx.serviceId
      else if rawSid.toNat <= UInt32.toNat (UInt32.ofNat (2^32 - 1)) then UInt32.ofNat rawSid.toNat
      else 0  -- invalid → will return NONE
    -- GP parallel semantics: read OTHER services from initial state snapshot,
    -- read SELF from current (accumulated) state.
    let acctLookup := if targetSid == ctx.serviceId
      then ctx.state.accounts.lookup targetSid
      else ctx.initAccounts.lookup targetSid
    match acctLookup with
    | none =>
      let regs' := setR7 regs PVM.RESULT_NONE
      (mkResult regs' mem gas', ctx)
    | some acct =>
      let info := encodeAccountInfo acct
      let ctxD := { ctx with debugExtra := s!" info_target={targetSid} info_hex={dbgHex info}" }
      let dataLen := info.size
      let f := min offset dataLen
      let l := min maxLen (dataLen - f)
      if l > 0 then
        let src := info.extract f (f + l)
        match PVM.writeByteArray mem outPtr src with
        | .ok mem' =>
          let regs' := setR7 regs (UInt64.ofNat dataLen)
          (mkResult regs' mem' gas', ctxD)
        | _ =>
          -- Page fault on write → panic (GP: ⚡)
          (mkPanic regs mem gas', ctxD)
      else
        let regs' := setR7 regs (UInt64.ofNat dataLen)
        (mkResult regs' mem gas', ctxD)

  -- Host calls 6-13 (historical_lookup, export, machine, peek, poke, pages, invoke,
  -- expunge) are refine-only (GP eq:refinemutator). They are NOT available in the
  -- accumulation context (GP eq:accinvocation) and fall through to the default WHAT.

  -- ===== bless (14): Set privileged services (GP ΩB) =====
  -- φ[7] = m (manager), φ[8] = a (assigners ptr, C × 4 bytes),
  -- φ[9] = v (designator), φ[10] = r (registrar),
  -- φ[11] = o (always-acc ptr), φ[12] = n (always-acc count)
  -- GP order: read memory FIRST, then check validity.
  | 14 =>
    let newManager := getReg regs 7
    let assignPtr := getReg regs 8
    let newDesignator := getReg regs 9
    let newRegistrar := getReg regs 10
    let alwaysPtr := getReg regs 11
    let alwaysCount := (getReg regs 12).toNat
    -- Read C assigners (4 bytes each) from memory at assignPtr
    match PVM.readByteArray mem assignPtr (C * 4) with
    | .ok assignBytes =>
      -- Read always-accumulate entries: n × (4 bytes sid + 8 bytes gas) = 12 bytes each
      match PVM.readByteArray mem alwaysPtr (alwaysCount * 12) with
      | .ok alwaysBytes =>
        -- Check (m, v, r) are valid service IDs (fit in u32)
        if newManager.toNat > UInt32.toNat (UInt32.ofNat (2^32 - 1)) ||
           newDesignator.toNat > UInt32.toNat (UInt32.ofNat (2^32 - 1)) ||
           newRegistrar.toNat > UInt32.toNat (UInt32.ofNat (2^32 - 1)) then
          let regs' := setR7 regs PVM.RESULT_WHO
          (mkResult regs' mem gas', ctx)
        else
        -- Parse assigners
        let assigners : Array ServiceId := Id.run do
          let mut arr : Array ServiceId := #[]
          for i in [:C] do
            let offset := i * 4
            let v := (assignBytes.get! offset).toNat +
              (assignBytes.get! (offset + 1)).toNat * 256 +
              (assignBytes.get! (offset + 2)).toNat * 65536 +
              (assignBytes.get! (offset + 3)).toNat * 16777216
            arr := arr.push (UInt32.ofNat v)
          return arr
        -- Parse always-accumulate entries
        let alwaysAcc : Dict ServiceId Gas := Id.run do
          let mut d := Dict.empty
          for i in [:alwaysCount] do
            let offset := i * 12
            let sid := (alwaysBytes.get! offset).toNat +
              (alwaysBytes.get! (offset + 1)).toNat * 256 +
              (alwaysBytes.get! (offset + 2)).toNat * 65536 +
              (alwaysBytes.get! (offset + 3)).toNat * 16777216
            let gasVal := (alwaysBytes.get! (offset + 4)).toNat +
              (alwaysBytes.get! (offset + 5)).toNat * 256 +
              (alwaysBytes.get! (offset + 6)).toNat * 65536 +
              (alwaysBytes.get! (offset + 7)).toNat * 16777216 +
              (alwaysBytes.get! (offset + 8)).toNat * 4294967296 +
              (alwaysBytes.get! (offset + 9)).toNat * 1099511627776 +
              (alwaysBytes.get! (offset + 10)).toNat * 281474976710656 +
              (alwaysBytes.get! (offset + 11)).toNat * 72057594037927936
            d := d.insert (UInt32.ofNat sid) (UInt64.ofNat gasVal)
          return d
        let state' := { ctx.state with
          manager := UInt32.ofNat newManager.toNat
          assigners := assigners
          designator := UInt32.ofNat newDesignator.toNat
          registrar := UInt32.ofNat newRegistrar.toNat
          alwaysAccumulate := alwaysAcc }
        let regs' := setR7 regs PVM.RESULT_OK
        (mkResult regs' mem gas', { ctx with state := state' })
      | _ => (mkPanic regs mem gas', ctx)
    | _ => (mkPanic regs mem gas', ctx)

  -- ===== assign (15): Assign core authorization (GP ΩA) =====
  -- φ[7] = c (core index), φ[8] = o (pointer to Q auth hashes, 32 bytes each),
  -- φ[9] = a (new assigner service ID)
  -- GP order: read memory FIRST, then check privileges.
  -- Memory read failure → PANIC (⚡), takes priority over all other checks.
  | 15 =>
    let coreIdx := (getReg regs 7).toNat
    let hashPtr := getReg regs 8
    let newAssigner := getReg regs 9
    -- GP: Read Q * 32 bytes from memory FIRST (page fault → PANIC)
    match PVM.readByteArray mem hashPtr (Q_QUEUE * 32) with
    | .ok queueBytes =>
      if coreIdx >= C then
        let regs' := setR7 regs PVM.RESULT_CORE
        (mkResult regs' mem gas', ctx)
      else
        -- Check caller is the assigner for this core
        let assigner := if coreIdx < ctx.state.assigners.size
          then ctx.state.assigners[coreIdx]! else 0
        if ctx.serviceId != assigner then
          let regs' := setR7 regs PVM.RESULT_HUH
          (mkResult regs' mem gas', ctx)
        else if newAssigner.toNat > UInt32.toNat (UInt32.ofNat (2^32 - 1)) then
          let regs' := setR7 regs PVM.RESULT_WHO
          (mkResult regs' mem gas', ctx)
        else
          -- Parse Q hashes from the read bytes
          let queue : Array Hash := Id.run do
            let mut arr : Array Hash := #[]
            for i in [:Q_QUEUE] do
              let offset := i * 32
              let hashBytes := queueBytes.extract offset (offset + 32)
              arr := arr.push ⟨hashBytes, sorry⟩
            return arr
          -- Store auth queue for this core
          let authQueue' := if coreIdx < ctx.state.authQueue.size
            then ctx.state.authQueue.set! coreIdx queue
            else ctx.state.authQueue
          -- Update assigner for this core
          let assigners' := if coreIdx < ctx.state.assigners.size
            then ctx.state.assigners.set! coreIdx (UInt32.ofNat newAssigner.toNat)
            else ctx.state.assigners
          let state' := { ctx.state with authQueue := authQueue', assigners := assigners' }
          let regs' := setR7 regs PVM.RESULT_OK
          (mkResult regs' mem gas', { ctx with state := state' })
    | _ =>
      -- Page fault on queue read → panic (GP: ⚡)
      (mkPanic regs mem gas', ctx)

  -- ===== designate (16): Set pending validator keys (GP ΩD) =====
  -- φ[7] = o (pointer to V validator keys, 336 bytes each)
  -- GP order: read memory FIRST, then check privileges.
  | 16 =>
    let keysPtr := getReg regs 7
    let keySize := 336
    -- Read V * 336 bytes from memory FIRST (page fault → PANIC)
    match PVM.readByteArray mem keysPtr (V * keySize) with
    | .ok keysBytes =>
      -- Check caller is the designator
      if ctx.serviceId != ctx.state.designator then
        let regs' := setR7 regs PVM.RESULT_HUH
        (mkResult regs' mem gas', ctx)
      else
        let keys := Id.run do
          let mut arr : Array ValidatorKey := #[]
          for i in [:V] do
            let offset := i * keySize
            let kBytes := keysBytes.extract offset (offset + keySize)
            let vk : ValidatorKey := {
              bandersnatch := ⟨kBytes.extract 0 32, sorry⟩
              ed25519 := ⟨kBytes.extract 32 64, sorry⟩
              bls := ⟨kBytes.extract 64 208, sorry⟩
              metadata := ⟨kBytes.extract 208 336, sorry⟩
            }
            arr := arr.push vk
          return arr
        let state' := { ctx.state with stagingKeys := keys }
        let regs' := setR7 regs PVM.RESULT_OK
        (mkResult regs' mem gas', { ctx with state := state' })
    | _ =>
      -- Page fault on keys read → panic (GP: ⚡)
      (mkPanic regs mem gas', ctx)

  -- ===== checkpoint (17): Save accumulation checkpoint =====
  -- GP: y ← x. Save the full regular context so it can be restored on panic/OOG.
  | 17 =>
    let ctx' := { ctx with checkpoint := some (ctx.state, ctx.opaqueData, ctx.yieldHash, ctx.transfers, ctx.provisions) }
    let regs' := setR7 regs gas'
    (mkResult regs' mem gas', ctx')

  -- ===== new (18): Create new service account =====
  -- φ[7]=o (code hash ptr), φ[8]=l (preimage length), φ[9]=g, φ[10]=m, φ[11]=f, φ[12]=i
  | 18 =>
    let codeHashPtr := getReg regs 7
    let preimLen := getReg regs 8
    let minAccGas := getReg regs 9
    let minOnTransferGas := getReg regs 10
    let gratis := getReg regs 11
    let hintI := getReg regs 12
    match PVM.readByteArray mem codeHashPtr 32 with
    | .ok hashBytes =>
      let codeHash : Hash := ⟨hashBytes, sorry⟩
      -- Compute items/footprint for new account (preimage_info entry)
      let newItems : Nat := 2  -- preimage_info entry counts as 2 items
      let newFootprint : Nat := 81 + preimLen.toNat  -- per GP eq 9.4
      -- Compute threshold balance for new account
      let threshold : Nat := (B_S + B_I * newItems + B_L * newFootprint) - min gratis.toNat (B_S + B_I * newItems + B_L * newFootprint)
      -- Check f ≠ 0 requires caller to be manager
      if gratis != 0 && ctx.serviceId != ctx.state.manager then
        let regs' := setR7 regs PVM.RESULT_HUH
        (mkResult regs' mem gas', ctx)
      else
      -- Check caller has enough balance: balance - threshold >= callerThreshold
      -- GP: let s = x_s except s_b = (x_s)_b - a_t; if s_b < (x_s)_t → CASH
      match ctx.state.accounts.lookup ctx.serviceId with
      | none =>
        let regs' := setR7 regs PVM.RESULT_CASH
        (mkResult regs' mem gas', ctx)
      | some srcAcct =>
        -- Compute caller's own threshold
        let callerItems := srcAcct.itemCount.toNat
        let callerBytes := srcAcct.totalFootprint
        let callerMinBal := B_S + B_I * callerItems + B_L * callerBytes
        let callerThreshold := callerMinBal - min srcAcct.gratis.toNat callerMinBal
        -- Balance after deduction must still cover caller's own threshold
        let balanceAfter := if srcAcct.balance.toNat >= threshold then srcAcct.balance.toNat - threshold else 0
        if balanceAfter < callerThreshold then
          let regs' := setR7 regs PVM.RESULT_CASH
          (mkResult regs' mem gas', ctx)
        else
        -- Find service ID
        let sThreshold : Nat := 2^16  -- S per GP I.4.4
        let (newId, idOk) : ServiceId × Bool :=
          if ctx.serviceId == ctx.state.registrar &&
             hintI.toNat < sThreshold && hintI.toNat < 2^32 then
            let id := UInt32.ofNat hintI.toNat
            if (ctx.state.accounts.lookup id).isSome then (id, false) else (id, true)
          else
            let id := ctx.nextServiceId
            if (ctx.state.accounts.lookup id).isSome then (id, false) else (id, true)
        if !idOk then
          let regs' := setR7 regs PVM.RESULT_FULL
          (mkResult regs' mem gas', ctx)
        else
        -- Debit caller by threshold amount
        let srcAcct' := { srcAcct with balance := srcAcct.balance - UInt64.ofNat threshold }
        let accounts' := ctx.state.accounts.insert ctx.serviceId srcAcct'
        -- Create new account with preimage_info entry for code hash
        let newAcct : ServiceAccount := {
          storage := Dict.empty
          preimages := Dict.empty
          preimageInfo := Dict.empty.insert (codeHash, UInt32.ofNat preimLen.toNat) #[]
          gratis := gratis
          codeHash
          balance := UInt64.ofNat threshold
          minAccGas
          minOnTransferGas
          itemCount := UInt32.ofNat newItems
          creationSlot := UInt32.ofNat ctx.timeslot.toNat
          lastAccumulation := 0
          totalFootprint := newFootprint
          parentServiceId := ctx.serviceId.toNat
        }
        let accounts'' := accounts'.insert newId newAcct
        let state' := { ctx.state with accounts := accounts'' }
        -- Advance next_service_id
        let range := 2^32 - sThreshold - 2^8
        let candidate := sThreshold + ((newId.toNat - sThreshold + 42) % range)
        let nextId := Id.run do
          let mut id := candidate
          for _ in [:256] do
            if (state'.accounts.lookup (UInt32.ofNat id)).isNone then return id
            id := sThreshold + ((id - sThreshold + 1) % range)
          return id
        let ctx' := { ctx with state := state', nextServiceId := UInt32.ofNat nextId }
        -- Return new service ID in r7 (GP spec)
        let regs' := setR7 regs (UInt64.ofNat newId.toNat)
        (mkResult regs' mem gas', ctx')
    | _ =>
      -- Page fault on code hash read → panic (GP: ⚡)
      (mkPanic regs mem gas', ctx)

  -- ===== upgrade (19): Upgrade service code hash =====
  | 19 =>
    -- reg[7] = new code hash pointer (32 bytes),
    -- reg[8] = new min_acc_gas, reg[9] = new min_on_transfer_gas
    let hashPtr := getReg regs 7
    let newMinAccGas := getReg regs 8
    let newMinOnTransferGas := getReg regs 9
    match PVM.readByteArray mem hashPtr 32 with
    | .ok hashBytes =>
      let newCodeHash : Hash := ⟨hashBytes, sorry⟩
      match ctx.state.accounts.lookup ctx.serviceId with
      | none =>
        let regs' := setR7 regs PVM.RESULT_NONE
        (mkResult regs' mem gas', ctx)
      | some acct =>
        let acct' := { acct with
          codeHash := newCodeHash
          minAccGas := newMinAccGas
          minOnTransferGas := newMinOnTransferGas }
        let accounts' := ctx.state.accounts.insert ctx.serviceId acct'
        let state' := { ctx.state with accounts := accounts' }
        let regs' := setR7 regs PVM.RESULT_OK
        (mkResult regs' mem gas', { ctx with state := state' })
    | _ =>
      -- Page fault on hash read → panic (GP: ⚡)
      (mkPanic regs mem gas', ctx)

  -- ===== transfer (20): Create deferred transfer =====
  | 20 =>
    -- reg[7] = destination, reg[8] = amount, reg[9] = gas limit,
    -- reg[10] = memo pointer (M_T bytes)
    let dest := UInt32.ofNat (getReg regs 7).toNat
    let amount := getReg regs 8
    let gasLimit := getReg regs 9
    let memoPtr := getReg regs 10
    -- GP: Read memo first — page fault → PANIC (⚡)
    match PVM.readByteArray mem memoPtr W_T with
    | .ok memoBytes =>
      -- Check destination exists
      match ctx.state.accounts.lookup dest with
      | none =>
        let regs' := setR7 regs PVM.RESULT_WHO
        (mkResult regs' mem gas', ctx)
      | some destAcct =>
        -- Check dest min_memo_gas
        if gasLimit < UInt64.ofNat destAcct.minOnTransferGas.toNat then
          let regs' := setR7 regs PVM.RESULT_LOW
          (mkResult regs' mem gas', ctx)
        else
        -- Check source has enough balance
        match ctx.state.accounts.lookup ctx.serviceId with
        | none =>
          let regs' := setR7 regs PVM.RESULT_NONE
          (mkResult regs' mem gas', ctx)
        | some srcAcct =>
          if srcAcct.balance < amount then
            let regs' := setR7 regs PVM.RESULT_CASH
            (mkResult regs' mem gas', ctx)
          else
            -- GP: Check gas_limit ≤ remaining gas, otherwise panic
            if gas' < gasLimit then
              (mkPanic regs mem 0, ctx)
            else
            let gas'' := gas' - gasLimit
            let memoSeq : OctetSeq W_T := ⟨memoBytes, sorry⟩  -- size proof elided
            let xfer : DeferredTransfer := {
              source := ctx.serviceId, dest, amount
              memo := memoSeq
              gas := gasLimit
            }
            -- Debit the source balance
            let srcAcct' := { srcAcct with balance := srcAcct.balance - amount }
            let accounts' := ctx.state.accounts.insert ctx.serviceId srcAcct'
            let state' := { ctx.state with accounts := accounts' }
            let ctx' := { ctx with state := state', transfers := ctx.transfers.push xfer }
            let regs' := setR7 regs PVM.RESULT_OK
            (mkResult regs' mem gas'', ctx')
    | _ =>
      -- Page fault on memo read → panic (GP: ⚡)
      (mkPanic regs mem gas', ctx)

  -- ===== eject (21): Remove service account (GP eq ΩJ) =====
  -- φ[7] = d (target service), φ[8] = o (hash_ptr, 32 bytes)
  -- Full GP checks: code_hash, item count, preimage request, age
  | 21 =>
    let sid := UInt32.ofNat (getReg regs 7).toNat
    let hashPtr := getReg regs 8
    -- Read hash h from memory first (page fault → panic)
    match PVM.readByteArray mem hashPtr 32 with
    | .ok hashBytes =>
      let h : Hash := ⟨hashBytes, sorry⟩
      -- Check: d != self AND d exists in accounts
      if sid == ctx.serviceId then
        let regs' := setR7 regs PVM.RESULT_WHO
        (mkResult regs' mem gas', ctx)
      else
        -- Promote preimage info for the target from opaque data if needed
        let (targetAcct, ctx) := match ctx.state.accounts.lookup sid with
          | some acct => (some acct, ctx)
          | none => (none, ctx)
        match targetAcct with
        | none =>
          let regs' := setR7 regs PVM.RESULT_WHO
          (mkResult regs' mem gas', ctx)
        | some ejected =>
          -- GP: Check d.codehash == encode[32](self_id)
          let selfIdEncoded := Codec.encodeFixedNat 32 ctx.serviceId.toNat
          let selfIdHash : Hash := ⟨selfIdEncoded, sorry⟩
          if ejected.codeHash != selfIdHash then
            let regs' := setR7 regs PVM.RESULT_WHO
            (mkResult regs' mem gas', ctx)
          else
          -- GP: l = max(81, d.octets) - 81
          let l := (max 81 ejected.totalFootprint) - 81
          let blobLen := UInt32.ofNat l
          -- Promote preimage info from opaque data if needed
          let (ejected, ctx) :=
            if (ejected.preimageInfo.lookup (h, blobLen)).isSome then (ejected, ctx)
            else match promotePreimageInfo ejected ctx.opaqueData sid h blobLen with
              | some (acct', opaqueData') => (acct', { ctx with opaqueData := opaqueData' })
              | none => (ejected, ctx)
          -- Update accounts with promoted info
          let accounts' := ctx.state.accounts.insert sid ejected
          let ctx := { ctx with state := { ctx.state with accounts := accounts' } }
          -- GP: d_i = 2 (item count must be exactly 2 for eject)
          let items := ejected.itemCount.toNat
          if items != 2 then
            let regs' := setR7 regs PVM.RESULT_HUH
            (mkResult regs' mem gas', ctx)
          else
          match ejected.preimageInfo.lookup (h, blobLen) with
          | none =>
            let regs' := setR7 regs PVM.RESULT_HUH
            (mkResult regs' mem gas', ctx)
          | some ts =>
            -- GP: Check requests[(h,l)] = [x, y] with y < t - D_EXPUNGE
            if ts.size != 2 then
              let regs' := setR7 regs PVM.RESULT_HUH
              (mkResult regs' mem gas', ctx)
            else
            let y := ts[1]!.toNat
            if !(y + D_EXPUNGE < ctx.timeslot.toNat) then
              let regs' := setR7 regs PVM.RESULT_HUH
              (mkResult regs' mem gas', ctx)
            else
            -- All checks passed: eject the service
            match ctx.state.accounts.lookup ctx.serviceId with
            | none =>
              let regs' := setR7 regs PVM.RESULT_NONE
              (mkResult regs' mem gas', ctx)
            | some callerAcct =>
              let callerAcct' := { callerAcct with balance := callerAcct.balance + ejected.balance }
              let accounts' := ctx.state.accounts.erase sid
              let accounts' := accounts'.insert ctx.serviceId callerAcct'
              let state' := { ctx.state with accounts := accounts' }
              -- Remove all opaque data entries belonging to the ejected service
              let od := ctx.opaqueData.filter fun (k, _) =>
                StateSerialization.extractServiceIdFromDataKey k != sid
              let regs' := setR7 regs PVM.RESULT_OK
              (mkResult regs' mem gas', { ctx with state := state', opaqueData := od })
    | _ =>
      -- Page fault on hash read → panic (GP: ⚡)
      (mkPanic regs mem gas', ctx)

  -- ===== query (22): Query preimage request status (GP ΩQ) =====
  -- φ[7] = o (hash pointer), φ[8] = z (blob length)
  -- Always queries self service. Returns packed timeslot info:
  --   0 timeslots: r7=0, r8=0
  --   1 timeslot:  r7 = 1 + (ts[0] << 32), r8 = 0
  --   2 timeslots: r7 = 2 + (ts[0] << 32), r8 = ts[1]
  --   3+ timeslots: r7 = 3 + (ts[0] << 32), r8 = ts[1] + (ts[2] << 32)
  --   Not found: r7 = NONE, r8 = 0
  | 22 =>
    let hashPtr := getReg regs 7
    let blobLen := UInt32.ofNat (getReg regs 8).toNat
    match PVM.readByteArray mem hashPtr 32 with
    | .ok hashBytes =>
      let h : Hash := ⟨hashBytes, sorry⟩
      match ctx.state.accounts.lookup ctx.serviceId with
      | none =>
        let regs' := setR7 regs PVM.RESULT_NONE
        let regs' := setReg regs' 8 0
        (mkResult regs' mem gas', ctx)
      | some acct =>
        -- Promote from opaque data if needed
        let (acct, ctx) :=
          if (acct.preimageInfo.lookup (h, blobLen)).isSome then (acct, ctx)
          else match promotePreimageInfo acct ctx.opaqueData ctx.serviceId h blobLen with
            | some (acct', opaqueData') => (acct', { ctx with opaqueData := opaqueData' })
            | none => (acct, ctx)
        -- Update accounts with promoted preimage info
        let accounts' := ctx.state.accounts.insert ctx.serviceId acct
        let state' := { ctx.state with accounts := accounts' }
        let ctx := { ctx with state := state' }
        match acct.preimageInfo.lookup (h, blobLen) with
        | none =>
          let regs' := setR7 regs PVM.RESULT_NONE
          let regs' := setReg regs' 8 0
          (mkResult regs' mem gas', ctx)
        | some timeslots =>
          let (r7val, r8val) : UInt64 × UInt64 := match timeslots.size with
            | 0 => (0, 0)
            | 1 =>
              let ts0 := (timeslots[0]!).toNat
              (UInt64.ofNat (1 + (ts0 <<< 32)), 0)
            | 2 =>
              let ts0 := (timeslots[0]!).toNat
              let ts1 := (timeslots[1]!).toNat
              (UInt64.ofNat (2 + (ts0 <<< 32)), UInt64.ofNat ts1)
            | _ =>
              let ts0 := (timeslots[0]!).toNat
              let ts1 := (timeslots[1]!).toNat
              let ts2 := (timeslots[2]!).toNat
              (UInt64.ofNat (3 + (ts0 <<< 32)), UInt64.ofNat (ts1 + (ts2 <<< 32)))
          let regs' := setR7 regs r7val
          let regs' := setReg regs' 8 r8val
          (mkResult regs' mem gas', ctx)
    | _ =>
      -- Page fault on hash read → panic (GP: ⚡)
      (mkPanic regs mem gas', ctx)

  -- ===== solicit (23): Request preimage (GP ΩS) =====
  -- φ[7] = hash pointer, φ[8] = blob length
  | 23 =>
    let hashPtr := getReg regs 7
    let blobLen := UInt32.ofNat (getReg regs 8).toNat
    match PVM.readByteArray mem hashPtr 32 with
    | .ok hashBytes =>
      let h : Hash := ⟨hashBytes, sorry⟩
      match ctx.state.accounts.lookup ctx.serviceId with
      | none =>
        let regs' := setR7 regs PVM.RESULT_HUH
        (mkResult regs' mem gas', ctx)
      | some acct =>
        -- Promote from opaque data if needed
        let (acct, ctx) :=
          if (acct.preimageInfo.lookup (h, blobLen)).isSome then (acct, ctx)
          else match promotePreimageInfo acct ctx.opaqueData ctx.serviceId h blobLen with
            | some (acct', opaqueData') => (acct', { ctx with opaqueData := opaqueData' })
            | none => (acct, ctx)
        match acct.preimageInfo.lookup (h, blobLen) with
        | some ts =>
          if ts.size == 2 then
            -- Already has [x, y] — append timeslot to get [x, y, t]
            let acct' := { acct with
              preimageInfo := acct.preimageInfo.insert (h, blobLen) (ts.push ctx.timeslot) }
            let accounts' := ctx.state.accounts.insert ctx.serviceId acct'
            let state' := { ctx.state with accounts := accounts' }
            let regs' := setR7 regs PVM.RESULT_OK
            (mkResult regs' mem gas', { ctx with state := state' })
          else
            -- Already solicited with different state
            let regs' := setR7 regs PVM.RESULT_HUH
            (mkResult regs' mem gas', ctx)
        | none =>
          -- New solicitation: create entry with empty timeslots
          let newItems := acct.itemCount + 2
          let newFootprint := acct.totalFootprint + 81 + blobLen.toNat
          let acct' := { acct with
            preimageInfo := acct.preimageInfo.insert (h, blobLen) #[]
            itemCount := newItems
            totalFootprint := newFootprint }
          -- Check minimum balance requirement
          let minBal := B_S + B_I * newItems.toNat + B_L * newFootprint
          let threshold := minBal - min acct'.gratis.toNat minBal
          if threshold > acct'.balance.toNat then
            -- Insufficient balance: undo and return FULL
            let regs' := setR7 regs PVM.RESULT_FULL
            (mkResult regs' mem gas', ctx)
          else
            let accounts' := ctx.state.accounts.insert ctx.serviceId acct'
            let state' := { ctx.state with accounts := accounts' }
            let regs' := setR7 regs PVM.RESULT_OK
            (mkResult regs' mem gas', { ctx with state := state' })
    | _ =>
      -- Page fault on hash read → panic (GP: ⚡)
      (mkPanic regs mem gas', ctx)

  -- ===== forget (24): Forget preimage request (GP ΩF) =====
  -- φ[7] = hash pointer, φ[8] = blob length
  | 24 =>
    let hashPtr := getReg regs 7
    let blobLen := UInt32.ofNat (getReg regs 8).toNat
    match PVM.readByteArray mem hashPtr 32 with
    | .ok hashBytes =>
      let h : Hash := ⟨hashBytes, sorry⟩
      match ctx.state.accounts.lookup ctx.serviceId with
      | none =>
        let regs' := setR7 regs PVM.RESULT_HUH
        (mkResult regs' mem gas', ctx)
      | some acct =>
        -- Promote from opaque data if needed
        let (acct, ctx) :=
          if (acct.preimageInfo.lookup (h, blobLen)).isSome then (acct, ctx)
          else match promotePreimageInfo acct ctx.opaqueData ctx.serviceId h blobLen with
            | some (acct', opaqueData') => (acct', { ctx with opaqueData := opaqueData' })
            | none => (acct, ctx)
        match acct.preimageInfo.lookup (h, blobLen) with
        | none =>
          let regs' := setR7 regs PVM.RESULT_HUH
          (mkResult regs' mem gas', ctx)
        | some ts =>
          -- GP ΩF: behavior depends on timeslot count
          if ts.size == 0 then
            -- [] → remove entry entirely
            let acct' := { acct with
              preimageInfo := acct.preimageInfo.erase (h, blobLen)
              preimages := acct.preimages.erase h
              itemCount := acct.itemCount - 2
              totalFootprint := acct.totalFootprint - (81 + blobLen.toNat) }
            -- Also remove preimage data and preimage_info from opaque data
            let preimageDataKey := StateSerialization.stateKeyForServiceData ctx.serviceId
              (StateSerialization.preimageHashArg h)
            let preimageInfoKey := StateSerialization.stateKeyForServiceData ctx.serviceId
              (StateSerialization.preimageInfoHashArg blobLen h)
            let od := ctx.opaqueData.filter fun (k, _) =>
              k != preimageDataKey.data && k != preimageInfoKey.data
            let accounts' := ctx.state.accounts.insert ctx.serviceId acct'
            let state' := { ctx.state with accounts := accounts' }
            let regs' := setR7 regs PVM.RESULT_OK
            (mkResult regs' mem gas', { ctx with state := state', opaqueData := od })
          else if ts.size == 1 then
            -- [x] → set forget time: [x, t]
            let acct' := { acct with
              preimageInfo := acct.preimageInfo.insert (h, blobLen) (ts.push ctx.timeslot) }
            let accounts' := ctx.state.accounts.insert ctx.serviceId acct'
            let state' := { ctx.state with accounts := accounts' }
            let regs' := setR7 regs PVM.RESULT_OK
            (mkResult regs' mem gas', { ctx with state := state' })
          else if ts.size == 2 && ts[1]!.toNat + D_EXPUNGE < ctx.timeslot.toNat then
            -- [x, y] with y < t - D → remove
            let acct' := { acct with
              preimageInfo := acct.preimageInfo.erase (h, blobLen)
              preimages := acct.preimages.erase h
              itemCount := acct.itemCount - 2
              totalFootprint := acct.totalFootprint - (81 + blobLen.toNat) }
            -- Also remove preimage data and preimage_info from opaque data
            let preimageDataKey := StateSerialization.stateKeyForServiceData ctx.serviceId
              (StateSerialization.preimageHashArg h)
            let preimageInfoKey := StateSerialization.stateKeyForServiceData ctx.serviceId
              (StateSerialization.preimageInfoHashArg blobLen h)
            let od := ctx.opaqueData.filter fun (k, _) =>
              k != preimageDataKey.data && k != preimageInfoKey.data
            let accounts' := ctx.state.accounts.insert ctx.serviceId acct'
            let state' := { ctx.state with accounts := accounts' }
            let regs' := setR7 regs PVM.RESULT_OK
            (mkResult regs' mem gas', { ctx with state := state', opaqueData := od })
          else if ts.size == 3 && ts[1]!.toNat + D_EXPUNGE < ctx.timeslot.toNat then
            -- [x, y, w] with y < t - D → [w, t]
            let acct' := { acct with
              preimageInfo := acct.preimageInfo.insert (h, blobLen) #[ts[2]!, ctx.timeslot] }
            let accounts' := ctx.state.accounts.insert ctx.serviceId acct'
            let state' := { ctx.state with accounts := accounts' }
            let regs' := setR7 regs PVM.RESULT_OK
            (mkResult regs' mem gas', { ctx with state := state' })
          else
            let regs' := setR7 regs PVM.RESULT_HUH
            (mkResult regs' mem gas', ctx)
    | _ =>
      -- Page fault on hash read → panic (GP: ⚡)
      (mkPanic regs mem gas', ctx)

  -- ===== yield (25): Set accumulation output hash =====
  | 25 =>
    -- reg[7] = hash pointer (32 bytes in memory)
    let hashPtr := getReg regs 7
    match PVM.readByteArray mem hashPtr 32 with
    | .ok hashBytes =>
      let h : Hash := ⟨hashBytes, sorry⟩
      let regs' := setR7 regs PVM.RESULT_OK
      (mkResult regs' mem gas', { ctx with yieldHash := some h })
    | _ =>
      -- Page fault on hash read → panic (GP: ⚡)
      (mkPanic regs mem gas', ctx)

  -- ===== provide (26): Provide preimage data (GP ΩP) =====
  -- φ[7] = s (target service, NONE = self), φ[8] = o (data ptr), φ[9] = z (data len)
  | 26 =>
    let rawTarget := getReg regs 7
    let targetSid := if rawTarget == PVM.RESULT_NONE then ctx.serviceId
      else if rawTarget.toNat <= UInt32.toNat (UInt32.ofNat (2^32 - 1)) then UInt32.ofNat rawTarget.toNat
      else 0  -- invalid → will return WHO
    -- Check target validity first (but after determining target)
    if rawTarget != PVM.RESULT_NONE && rawTarget.toNat > UInt32.toNat (UInt32.ofNat (2^32 - 1)) then
      let regs' := setR7 regs PVM.RESULT_WHO
      (mkResult regs' mem gas', ctx)
    else
    let dataPtr := getReg regs 8
    let dataLen := (getReg regs 9).toNat
    match PVM.readByteArray mem dataPtr dataLen with
    | .ok preimageData =>
      let h := Crypto.blake2b preimageData
      let blobLen := UInt32.ofNat dataLen
      match ctx.state.accounts.lookup targetSid with
      | none =>
        let regs' := setR7 regs PVM.RESULT_WHO
        (mkResult regs' mem gas', ctx)
      | some acct =>
        -- Promote preimage_info from opaque data if needed
        let (acct, ctx) :=
          if (acct.preimageInfo.lookup (h, blobLen)).isSome then (acct, ctx)
          else match promotePreimageInfo acct ctx.opaqueData targetSid h blobLen with
            | some (acct', opaqueData') => (acct', { ctx with opaqueData := opaqueData' })
            | none => (acct, ctx)
        -- Check if there's a preimage_info entry for (hash, len)
        if (acct.preimageInfo.lookup (h, blobLen)).isSome then
          let acct' := { acct with preimages := acct.preimages.insert h preimageData }
          let accounts' := ctx.state.accounts.insert targetSid acct'
          let state' := { ctx.state with accounts := accounts' }
          let provision := (targetSid, preimageData)
          let regs' := setR7 regs PVM.RESULT_OK
          (mkResult regs' mem gas', { ctx with
            state := state'
            provisions := ctx.provisions.push provision })
        else
          let regs' := setR7 regs PVM.RESULT_HUH
          (mkResult regs' mem gas', ctx)
    | _ =>
      -- Page fault on data read → panic (GP: ⚡)
      (mkPanic regs mem gas', ctx)

  -- ===== Unknown host call =====
  | _ =>
    let regs' := setR7 regs PVM.RESULT_WHAT
    (mkResult regs' mem gas', ctx)
  let outR7 := if 7 < result.registers.size then result.registers[7]! else 0
  let extra := ctx'.debugExtra
  let gasAfter := result.gas.toUInt64
  let ctx'' := { ctx' with hostCallLog := ctx'.hostCallLog.push s!"{inputLog}->r7={outR7} gas={gasAfter}{extra}", debugExtra := "" }
  (result, ctx'')

-- ============================================================================
-- accone — Single-Service Accumulation — GP eq:accone
-- ============================================================================

/-- Encode accumulation arguments for PVM input. GP Appendix B §B.8.
    Format: varint(timeslot) ‖ varint(service_id) ‖ varint(item_count)
    Items are accessed via fetch host call (modes 14/15), NOT embedded in args. -/
private def encodeAccArgs (timeslot : Timeslot) (serviceId : ServiceId)
    (itemCount : Nat) : ByteArray :=
  Codec.encodeNat timeslot.toNat
    ++ Codec.encodeNat serviceId.toNat
    ++ Codec.encodeNat itemCount

/-- Encode a single operand item for fetch mode 14/15.
    Format: 0x00 (discriminator) ‖ package_hash(32) ‖ segment_root(32) ‖
    authorizer_hash(32) ‖ payload_hash(32) ‖ gas(varint) ‖ result_encoding -/
private def encodeOperandItem (op : OperandTuple) : ByteArray :=
  let buf := ByteArray.mk #[0]  -- operand discriminator
  buf ++ op.packageHash.data ++ op.segmentRoot.data
    ++ op.authorizerHash.data ++ op.payloadHash.data
    ++ Codec.encodeNat op.gasLimit.toNat
    ++ Codec.encodeWorkResult op.result
    ++ Codec.encodeLengthPrefixed op.authOutput

/-- Encode a single transfer item for fetch mode 14/15.
    Format: 0x01 (discriminator) ‖ sender(4) ‖ dest(4) ‖ amount(8) ‖ memo(128) ‖ gas(8) -/
private def encodeTransferItem (t : DeferredTransfer) : ByteArray :=
  let buf := ByteArray.mk #[1]  -- transfer discriminator
  let memo := t.memo.data ++ ByteArray.mk (Array.replicate (128 - min 128 t.memo.data.size) 0)
  buf ++ Codec.encodeFixedNat 4 t.source.toNat
    ++ Codec.encodeFixedNat 4 t.dest.toNat
    ++ Codec.encodeFixedNat 8 t.amount.toNat
    ++ memo
    ++ Codec.encodeFixedNat 8 t.gas.toNat

/-- Build items blob for fetch mode 14. Format: varint(count) ‖ item₀ ‖ item₁ ‖ ...
    Order: transfers first, then operands (matching Rust). -/
private def buildItemsBlob (operands : Array OperandTuple)
    (transfers : Array DeferredTransfer) : ByteArray × Array ByteArray :=
  -- Transfers first, then operands (matching Rust order)
  let transferItems := transfers.map encodeTransferItem
  let operandItems := operands.map encodeOperandItem
  let items := transferItems ++ operandItems
  let blob := Codec.encodeNat items.size
    ++ items.foldl (init := ByteArray.empty) (· ++ ·)
  (blob, items)

/-- Accumulate a single service. GP §12 eq:accone.
    Gathers all operands and transfers for this service,
    invokes Ψ_A (PVM accumulate), and collects outputs. -/
def accone (ps : PartialState) (serviceId : ServiceId)
    (operands : Array OperandTuple) (transfers : Array DeferredTransfer)
    (freeGas : Gas) (timeslot : Timeslot)
    (entropy : Hash) (configBlob : ByteArray)
    (itemsBlob : ByteArray) (items : Array ByteArray)
    (opaqueData : Array (ByteArray × ByteArray) := #[])
    (initAccounts : Dict ServiceId ServiceAccount := Dict.empty) : AccOneOutput :=
  -- Look up service account
  match ps.accounts.lookup serviceId with
  | none =>
    -- Service doesn't exist: no-op
    { postState := ps, deferredTransfers := #[], yieldHash := none,
      gasUsed := 0, provisions := #[], opaqueData }
  | some acct =>
    -- Compute total gas available
    let operandGas := operands.foldl (init := (0 : UInt64)) fun acc op => acc + op.gasLimit
    let transferGas := transfers.foldl (init := (0 : UInt64)) fun acc t => acc + t.gas
    let totalGas := freeGas + operandGas + transferGas

    -- Credit incoming transfer amounts to service balance (GP eq B.9)
    let transferBalance := transfers.foldl (init := (0 : UInt64)) fun acc t => acc + t.amount
    let acct' := { acct with balance := acct.balance + transferBalance }
    let ps := { ps with accounts := ps.accounts.insert serviceId acct' }

    -- Compute next available service ID (GP eq B.10)
    -- i = S + (H(E_N(s) ++ η'₀ ++ E_N(τ')) mod (2^32 - S - 2^8))
    let sThreshold : Nat := 2^16  -- S per GP I.4.4
    let hashInput := Codec.encodeNat serviceId.toNat ++ entropy.data
      ++ Codec.encodeNat timeslot.toNat
    let hashBytes := Crypto.blake2b hashInput
    let hashVal : Nat :=
      (hashBytes.data.get! 0).toNat +
      (hashBytes.data.get! 1).toNat * 256 +
      (hashBytes.data.get! 2).toNat * 65536 +
      (hashBytes.data.get! 3).toNat * 16777216
    let range : Nat := 2^32 - sThreshold - 2^8
    let rawNextId := sThreshold + (hashVal % range)
    -- check(): ensure not already in use (simplified: unlikely to collide)
    let nextId := if (ps.accounts.lookup (UInt32.ofNat rawNextId)).isNone
      then rawNextId
      else Id.run do
        let mut id := sThreshold + ((rawNextId - sThreshold + 1) % range)
        for _ in [:256] do
          if (ps.accounts.lookup (UInt32.ofNat id)).isNone then return id
          id := sThreshold + ((id - sThreshold + 1) % range)
        return id

    -- Look up service code blob from preimage store, falling back to opaque data
    -- If found in opaque, promote to preimage store and remove from opaqueData
    -- Use acct' (which has credited transfer balance) as the base
    let acctCredited := acct'
    let (codeOpt, acctFinal, opaqueData') := match acctCredited.preimages.lookup acctCredited.codeHash with
      | some blob => (some blob, acctCredited, opaqueData)
      | none =>
        match promotePreimageLookup acctCredited opaqueData serviceId acctCredited.codeHash with
        | some (acctPromoted, opaqueData') =>
          (acctPromoted.preimages.lookup acctCredited.codeHash, acctPromoted, opaqueData')
        | none => (none, acctCredited, opaqueData)
    -- Update accounts with promoted code blob (preserving credited balance)
    let ps := { ps with accounts := ps.accounts.insert serviceId acctFinal }

    -- Build accumulation context
    let ctx : AccContext := {
      serviceId
      state := ps
      transfers := #[]
      yieldHash := none
      provisions := #[]
      gasUsed := 0
      operands
      timeslot
      nextServiceId := UInt32.ofNat nextId
      checkpoint := none
      entropy
      initAccounts
      configBlob
      itemsBlob
      items
      opaqueData := opaqueData'
    }

    match codeOpt with
    | none =>
      -- Code not available: skip PVM execution, credit transfers only (GP eq 12.24)
      { postState := ps, deferredTransfers := #[], yieldHash := none,
        gasUsed := 0, provisions := #[], opaqueData := opaqueData',
        exitReasonStr := "" }
    | some codeBlob =>
      -- Encode accumulation arguments
      let itemCount := transfers.size + operands.size
      let args := encodeAccArgs timeslot serviceId itemCount
      -- Initialize PVM with service code and arguments
      match PVM.initStandard codeBlob args with
      | none =>
        -- Invalid program blob: panic
        { postState := ps, deferredTransfers := #[], yieldHash := none,
          gasUsed := totalGas, provisions := #[], opaqueData := opaqueData' }
      | some (prog, regs, mem) =>
        -- Run PVM with host-call dispatch via handleHostCall
        let (result, ctx') := PVM.runWithHostCalls AccContext
          prog 5 regs mem (Int64.ofUInt64 totalGas)
          (fun callId gas regs' mem' c =>
            handleHostCall callId gas regs' mem' c)
          ctx
        -- On halt: use accumulated state; on panic/OOG: revert to checkpoint
        -- GP: regular dimension (x) on halt, exceptional dimension (y) on panic/OOG/fault
        let (finalState, finalTransfers, finalYield, finalProvisions, revertedOpaque) := match result.exitReason with
          | .halt =>
            -- GP Ψ_M (eq A.36): On halt, o = μ'[φ'_7..φ'_7+φ'_8].
            -- If |o| = 32, the accumulation output hash is o.
            -- The yield host call also sets yieldHash; halt output overrides/combines.
            let haltYield :=
              let outPtr := getReg result.registers 7
              let outLen := getReg result.registers 8
              -- GP: o = μ'[φ'_7..+φ'_8] if N_{φ'_7..+φ'_8} ⊆ V_μ'
              -- Addresses are 32-bit, so full u64 range must fit in [0, 2^32)
              if outLen == 32 && outPtr.toNat < 2^32 && outPtr.toNat + 32 <= 2^32 then
                match PVM.readByteArray result.memory outPtr 32 with
                | .ok bytes => some (⟨bytes, sorry⟩ : Hash)
                | _ => none
              else none
            -- Use halt output if available, otherwise use yield host call result
            let yield := match haltYield with
              | some h => some h
              | none => ctx'.yieldHash
            (ctx'.state, ctx'.transfers, yield, ctx'.provisions, ctx'.opaqueData)
          | _ =>
            -- Panic/OOG/fault: revert to checkpoint (exceptional dimension)
            -- GP: y (exceptional context) is returned for non-halt exits
            match ctx'.checkpoint with
            | some (savedState, savedOpaque, savedYield, savedTransfers, savedProvisions) =>
              (savedState, savedTransfers, savedYield, savedProvisions, savedOpaque)
            | none =>
              (ps, #[], none, #[], opaqueData')
        -- Note: a_a (last accumulation timeslot) is updated in the δ‡ step
        -- in State.lean's performAccumulation, not here in accone.
        let gasUsed := totalGas - (if result.gas.toUInt64 > totalGas then 0 else result.gas.toUInt64)
        let exitStr := match result.exitReason with
          | .halt => s!"halt(gas={gasUsed})"
          | .panic => s!"panic(gas={gasUsed})"
          | .outOfGas => "oog"
          | .hostCall n => s!"hostcall({n})"
          | .pageFault addr => s!"pageFault({addr})"
        { postState := finalState
          deferredTransfers := finalTransfers
          yieldHash := finalYield
          gasUsed
          provisions := finalProvisions
          opaqueData := revertedOpaque
          exitReasonStr := exitStr
          hostCallLog := ctx'.hostCallLog }

-- ============================================================================
-- accpar — Parallelized Accumulation — GP eq:accpar
-- ============================================================================

/-- Group work digests by service ID. -/
def groupByService (reports : Array WorkReport) : Dict ServiceId (Array OperandTuple) :=
  reports.foldl (init := Dict.empty) fun acc report =>
    report.digests.foldl (init := acc) fun acc' digest =>
      let op : OperandTuple := {
        packageHash := report.availSpec.packageHash
        segmentRoot := report.availSpec.segmentRoot
        authorizerHash := report.authorizerHash
        payloadHash := digest.payloadHash
        gasLimit := digest.gasLimit
        authOutput := report.authOutput
        result := digest.result
      }
      let existing := match acc'.lookup digest.serviceId with
        | some ops => ops
        | none => #[]
      acc'.insert digest.serviceId (existing.push op)

/-- Group deferred transfers by destination service. -/
def groupTransfersByDest (transfers : Array DeferredTransfer) : Dict ServiceId (Array DeferredTransfer) :=
  transfers.foldl (init := Dict.empty) fun acc t =>
    let existing := match acc.lookup t.dest with
      | some ts => ts
      | none => #[]
    acc.insert t.dest (existing.push t)

/-- R merge function from GP eq:accpar. R(o, a, b) = b if a == o, else a.
    Selects the manager's change (a) unless it didn't change (a==o), in which case
    the individual service's change (b) is used. -/
private def privR (o a b : ServiceId) : ServiceId :=
  if a == o then b else a

/-- Privilege snapshot: captures the privilege-related fields from a PartialState
    for the purpose of the GP R-merge after accumulation. -/
private structure PrivSnapshot where
  manager : ServiceId
  assigners : Array ServiceId
  designator : ServiceId
  registrar : ServiceId
  alwaysAccumulate : Dict ServiceId Gas
  stagingKeys : Array ValidatorKey
  authQueue : Array (Array Hash)

private def privSnap (ps : PartialState) : PrivSnapshot :=
  { manager := ps.manager, assigners := ps.assigners, designator := ps.designator,
    registrar := ps.registrar, alwaysAccumulate := ps.alwaysAccumulate,
    stagingKeys := ps.stagingKeys, authQueue := ps.authQueue }

/-- Accumulate all affected services in parallel. GP §12 eq:accpar.
    Services are accumulated sequentially, but host calls that read other services'
    state (info, read, lookup, query) use a snapshot of the INITIAL state to ensure
    parallel semantics: each service's computation is independent of accumulation order.
    Returns (updated partial state, new deferred transfers, yield outputs, gas used). -/
def accpar (ps : PartialState) (reports : Array WorkReport)
    (transfers : Array DeferredTransfer) (freeGasMap : Dict ServiceId Gas)
    (timeslot : Timeslot) (entropy : Hash) (configBlob : ByteArray)
    (opaqueData : Array (ByteArray × ByteArray) := #[])
    : PartialState × Array DeferredTransfer × Array (ServiceId × Hash) × Dict ServiceId Gas × Array (ServiceId × String) × Array (ByteArray × ByteArray) :=
  let operandGroups := groupByService reports
  let transferGroups := groupTransfersByDest transfers

  -- Collect all affected service IDs (sorted ascending, matching Rust BTreeSet order)
  -- Include always-accumulate services from freeGasMap (GP: f parameter in Δ*)
  let serviceIds := ((operandGroups.keys ++ transferGroups.keys ++ freeGasMap.keys).eraseDups).mergeSort (· < ·)

  -- Save the initial privileges for R-merge.
  let initPriv := privSnap ps
  -- Save initial accounts snapshot for parallel read semantics.
  let initAccts := ps.accounts

  -- Accumulate each service sequentially. Cross-service writes (eject, provide, new)
  -- take effect immediately. But host calls that READ other services' state use
  -- the initial state snapshot (ps.accounts) via the initAccounts field in AccContext.
  let (ps', allTransfers, allYields, gasMap, exitReasons, opaqueData', perServicePriv) := serviceIds.foldl
    (init := (ps, #[], #[], Dict.empty (K := ServiceId) (V := Gas), #[], opaqueData,
             Dict.empty (K := ServiceId) (V := PrivSnapshot)))
    fun (ps, xfers, yields, gm, exits, od, perSvc) sid =>
      let ops := match operandGroups.lookup sid with | some o => o | none => #[]
      let txs := match transferGroups.lookup sid with | some t => t | none => #[]
      let freeGas := match freeGasMap.lookup sid with | some g => g | none => 0
      let (itemsBlob, items) := buildItemsBlob ops txs
      -- Snapshot privileges BEFORE this service runs, to detect changes.
      let privBefore := privSnap ps
      let result := accone ps sid ops txs freeGas timeslot entropy configBlob
        itemsBlob items od initAccts
      let svcPriv := privSnap result.postState
      let ps' := result.postState
      let od' := result.opaqueData
      let xfers' := xfers ++ result.deferredTransfers
      let logStr := if result.hostCallLog.size > 0
        then " hostCalls=[" ++ String.intercalate "; " result.hostCallLog.toList ++ "]"
        else ""
      let exits' := exits.push (sid, result.exitReasonStr ++ logStr)
      let yields' := match result.yieldHash with
        | some h => yields.push (sid, h)
        | none => yields
      let gm' := gm.insert sid (UInt64.ofNat result.gasUsed.toNat)
      let changed := privBefore.manager != svcPriv.manager ||
        privBefore.designator != svcPriv.designator ||
        privBefore.registrar != svcPriv.registrar ||
        privBefore.assigners != svcPriv.assigners ||
        privBefore.alwaysAccumulate.keys != svcPriv.alwaysAccumulate.keys ||
        privBefore.stagingKeys.size != svcPriv.stagingKeys.size ||
        privBefore.authQueue.size != svcPriv.authQueue.size
      let perSvc' := if changed then perSvc.insert sid svcPriv else perSvc
      (ps', xfers', yields', gm', exits', od', perSvc')

  -- GP privilege R-merge: privileges are determined by specific services.
  -- Helper: get a service's privilege snapshot, or initial if not accumulated.
  let deltaPriv (s : ServiceId) : PrivSnapshot :=
    match perServicePriv.lookup s with
    | some p => p
    | none => initPriv

  let m := initPriv.manager
  let v := initPriv.designator
  let r := initPriv.registrar

  -- e* = Delta(m)_e — manager service's result
  let eStar := deltaPriv m

  -- (m', z') from manager's result
  let m' := eStar.manager
  let z' := eStar.alwaysAccumulate

  -- a'_c = R(a_c, (e*_a)_c, ((Delta(a_c)_e)_a)_c) for each core c
  let a' : Array ServiceId := Id.run do
    let mut arr := Array.empty
    for c in [:initPriv.assigners.size] do
      let a_c := initPriv.assigners[c]!
      let eStar_a_c := if c < eStar.assigners.size then eStar.assigners[c]! else a_c
      let delta_ac := deltaPriv a_c
      let delta_ac_a_c := if c < delta_ac.assigners.size then delta_ac.assigners[c]! else a_c
      arr := arr.push (privR a_c eStar_a_c delta_ac_a_c)
    return arr

  -- v' = R(v, e*_v, (Delta(v)_e)_v)
  let deltaV := deltaPriv v
  let v' := privR v eStar.designator deltaV.designator

  -- r' = R(r, e*_r, (Delta(r)_e)_r)
  let deltaR := deltaPriv r
  let r' := privR r eStar.registrar deltaR.registrar

  -- Apply privilege merge to the sequentially-accumulated account state.
  -- authQueue and stagingKeys are correctly handled by sequential accumulation
  -- (assign and designate host calls), so we don't override them here.
  let psFinal : PartialState := { ps' with
    manager := m'
    assigners := a'
    designator := v'
    registrar := r'
    alwaysAccumulate := z'
  }

  (psFinal, allTransfers, allYields, gasMap, exitReasons, opaqueData')

-- ============================================================================
-- accseq — Sequential Accumulation — GP eq:accseq
-- ============================================================================

/-- Full sequential accumulation pipeline. GP §12 eq:accseq.
    Orchestrates multiple rounds of accpar, feeding deferred transfers
    from one round into the next. -/
def accseq (gasLimit : Gas) (reports : Array WorkReport)
    (initialTransfers : Array DeferredTransfer)
    (ps : PartialState) (freeGasMap : Dict ServiceId Gas)
    (timeslot : Timeslot) (entropy : Hash) (configBlob : ByteArray)
    (opaqueData : Array (ByteArray × ByteArray) := #[])
    : Nat × PartialState × Array (ServiceId × Hash) × Dict ServiceId Gas × Array (ServiceId × String) × Array (ByteArray × ByteArray) :=
  -- Round 1: accumulate work-report operands + initial deferred transfers
  let (ps1, newXfers1, yields1, gasMap1, exits1, od1) := accpar ps reports initialTransfers freeGasMap timeslot entropy configBlob opaqueData
  let round1Gas := gasMap1.values.foldl (init := (0 : Nat)) fun acc g => acc + g.toNat

  -- Subsequent rounds: process deferred transfers until none remain or gas exhausted.
  -- GP §12 eq:accseq: g* = g + Σ(t.gas) — augment budget with transfer gas each round.
  let maxRounds := 10
  let (psFinal, allYields, gasMapFinal, allExits, odFinal) := Id.run do
    let mut curPs := ps1
    let mut curXfers := newXfers1
    let mut curYields := yields1
    let mut curGasMap := gasMap1
    let mut curExits := exits1
    let mut curOd := od1
    let mut remainingGas : Nat := gasLimit.toNat - min round1Gas gasLimit.toNat
    for _ in [:maxRounds] do
      if curXfers.size == 0 then break
      -- Augment gas budget with transfer gas (GP eq 12.18-12.19)
      let transferGas := curXfers.foldl (init := (0 : Nat)) fun acc t => acc + t.gas.toNat
      remainingGas := remainingGas + transferGas
      if remainingGas == 0 then break
      let (ps', xfers', yields', gasMap', exits', od') :=
        accpar curPs #[] curXfers Dict.empty timeslot entropy configBlob curOd
      let roundGas := gasMap'.values.foldl (init := (0 : Nat)) fun acc g => acc + g.toNat
      remainingGas := remainingGas - min roundGas remainingGas
      curPs := ps'
      curXfers := xfers'
      curYields := curYields ++ yields'
      curGasMap := gasMap'.entries.foldl (init := curGasMap) fun acc (k, v) =>
        let existing := match acc.lookup k with | some g => g | none => 0
        acc.insert k (existing + v)
      curExits := curExits ++ exits'
      curOd := od'
    return (curPs, curYields, curGasMap, curExits, curOd)

  (reports.size, psFinal, allYields, gasMapFinal, allExits, odFinal)

-- ============================================================================
-- Top-Level Accumulation — GP §12
-- ============================================================================

/-- Result of block-level accumulation. -/
structure AccumulationResult where
  /-- Updated service accounts. -/
  services : Dict ServiceId ServiceAccount
  /-- Updated privileged services. -/
  privileged : PrivilegedServices
  /-- Updated authorization queue. -/
  authQueue : Array (Array Hash)
  /-- Updated staging validator keys. -/
  stagingKeys : Array ValidatorKey
  /-- Accumulation output pairs (service → hash). -/
  outputs : Array (ServiceId × Hash)
  /-- Per-service gas usage. -/
  gasUsage : Dict ServiceId Gas
  /-- Remaining opaque data after accumulation (consumed entries removed). -/
  remainingOpaqueData : Array (ByteArray × ByteArray) := #[]
  /-- Debug: per-service exit reason strings. -/
  exitReasons : Array (ServiceId × String) := #[]

/-- Build the 134-byte protocol configuration blob for fetch mode 0.
    Format: E_8(B_I, B_L, B_S) ‖ E_2(C) ‖ E_4(D, E) ‖ E_8(G_A, G_I, G_R, G_T) ‖
    E_2(H, I, J, K) ‖ E_4(L) ‖ E_2(N, O, P, Q, R, T, U, V) ‖
    E_4(W_A, W_B, W_C, W_E, W_M, W_P, W_R, W_T, W_X, Y) = 134 bytes. -/
private def buildConfigBlob : ByteArray :=
  -- E_8 values (3 × 8 = 24 bytes)
  Codec.encodeFixedNat 8 B_I
  ++ Codec.encodeFixedNat 8 B_L
  ++ Codec.encodeFixedNat 8 B_S
  -- E_2 values (1 × 2 = 2 bytes)
  ++ Codec.encodeFixedNat 2 C
  -- E_4 values (2 × 4 = 8 bytes)
  ++ Codec.encodeFixedNat 4 D_EXPUNGE
  ++ Codec.encodeFixedNat 4 E
  -- E_8 values (4 × 8 = 32 bytes)
  ++ Codec.encodeFixedNat 8 G_A
  ++ Codec.encodeFixedNat 8 G_I
  ++ Codec.encodeFixedNat 8 G_R
  ++ Codec.encodeFixedNat 8 G_T
  -- E_2 values (4 × 2 = 8 bytes)
  ++ Codec.encodeFixedNat 2 H_RECENT
  ++ Codec.encodeFixedNat 2 I_MAX_ITEMS
  ++ Codec.encodeFixedNat 2 J_MAX_DEPS
  ++ Codec.encodeFixedNat 2 K_MAX_TICKETS
  -- E_4 value (1 × 4 = 4 bytes)
  ++ Codec.encodeFixedNat 4 L_MAX_ANCHOR
  -- E_2 values (8 × 2 = 16 bytes)
  ++ Codec.encodeFixedNat 2 N_TICKETS
  ++ Codec.encodeFixedNat 2 O_POOL
  ++ Codec.encodeFixedNat 2 P
  ++ Codec.encodeFixedNat 2 Q_QUEUE
  ++ Codec.encodeFixedNat 2 R_ROTATION
  ++ Codec.encodeFixedNat 2 T_MAX_EXTRINSICS
  ++ Codec.encodeFixedNat 2 U_TIMEOUT
  ++ Codec.encodeFixedNat 2 V
  -- E_4 values (10 × 4 = 40 bytes)
  ++ Codec.encodeFixedNat 4 W_A
  ++ Codec.encodeFixedNat 4 W_B
  ++ Codec.encodeFixedNat 4 W_C
  ++ Codec.encodeFixedNat 4 W_E
  ++ Codec.encodeFixedNat 4 W_M
  ++ Codec.encodeFixedNat 4 W_P
  ++ Codec.encodeFixedNat 4 W_R
  ++ Codec.encodeFixedNat 4 W_T
  ++ Codec.encodeFixedNat 4 W_X
  ++ Codec.encodeFixedNat 4 Y_TAIL

/-- Perform block-level accumulation. GP §12.
    Takes available work-reports that have been assured and
    runs the full accseq pipeline. -/
def accumulate (state : State) (reports : Array WorkReport)
    (timeslot : Timeslot)
    (opaqueData : Array (ByteArray × ByteArray)) : AccumulationResult :=
  let ps := PartialState.fromState state
  let freeGasMap := state.privileged.alwaysAccumulate

  -- Total gas budget: g = max(G_T, G_A × C + Σ χZ). GP eq 12.25.
  let alwaysGas := freeGasMap.values.foldl (init := 0) fun acc g => acc + g.toNat
  let totalGas := max G_T (G_A * C + alwaysGas)

  let configBlob := buildConfigBlob

  let (_, ps', outputs, gasUsage, exitReasons, remainingOpaque) := accseq
    (UInt64.ofNat totalGas) reports #[] ps freeGasMap timeslot
    state.entropy.current configBlob opaqueData

  { services := ps'.accounts
    privileged := {
      manager := ps'.manager
      assigners := ps'.assigners
      designator := ps'.designator
      registrar := ps'.registrar
      alwaysAccumulate := ps'.alwaysAccumulate
    }
    authQueue := ps'.authQueue
    stagingKeys := ps'.stagingKeys
    outputs
    gasUsage
    remainingOpaqueData := remainingOpaque
    exitReasons }

end Jar.Accumulation
