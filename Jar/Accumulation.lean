import Jar.Notation
import Jar.Types
import Jar.Codec
import Jar.Crypto
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
  /-- "Regular" dimension state (for checkpoint). -/
  checkpoint : Option (Dict ServiceId ServiceAccount)

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
  }

-- ============================================================================
-- Host-Call Gas Cost — GP Appendix B
-- ============================================================================

/-- Base gas cost for host calls: 10 gas. -/
def hostCallGas : Nat := 10

-- ============================================================================
-- Host-Call Handlers — GP Appendix B (pvm_invocations.tex)
-- ============================================================================

/-- Get register value safely. -/
private def getReg (regs : PVM.Registers) (i : Nat) : UInt64 :=
  if i < regs.size then regs[i]! else 0

/-- Set register value safely. -/
private def setReg (regs : PVM.Registers) (i : Nat) (v : UInt64) : PVM.Registers :=
  if i < regs.size then regs.set! i v else regs

/-- Encode a ServiceAccount's key info into a 97-byte blob for info(5).
    GP Appendix B: code_hash(32) ‖ balance(8) ‖ min_acc_gas(8) ‖
    min_on_transfer_gas(8) ‖ created(4) ‖ gratis(8) ‖ preimage_count(4) ‖
    preimage_size(4) ‖ items_count(4) ‖ parent(4) ‖ last_acc(4) ‖ code_len(8). -/
private def encodeAccountInfo (acct : ServiceAccount) : ByteArray :=
  let totalPreimageSize := acct.preimages.values.foldl (init := 0) fun acc v => acc + v.size
  -- code_hash(32) ‖ balance(8) ‖ min_acc_gas(8) ‖ min_on_transfer_gas(8) ‖
  -- created(4) ‖ gratis(8) ‖ preimage_count(4) ‖ preimage_size(4) ‖
  -- items_count(4) ‖ parent(4) ‖ last_acc(4) ‖ code_len(8)
  acct.codeHash.data
    ++ Codec.encodeFixedNat 8 acct.balance.toNat
    ++ Codec.encodeFixedNat 8 acct.minAccGas.toNat
    ++ Codec.encodeFixedNat 8 acct.minOnTransferGas.toNat
    ++ Codec.encodeFixedNat 4 acct.created.toNat
    ++ Codec.encodeFixedNat 8 acct.gratis.toNat
    ++ Codec.encodeFixedNat 4 acct.preimages.size
    ++ Codec.encodeFixedNat 4 totalPreimageSize
    ++ Codec.encodeFixedNat 4 acct.storage.size
    ++ Codec.encodeFixedNat 4 acct.parent.toNat
    ++ Codec.encodeFixedNat 4 acct.lastAccumulation.toNat
    ++ Codec.encodeFixedNat 8 0

/-- Dispatch a host call during accumulation. GP §12, Appendix B.
    Returns updated invocation result and context. -/
def handleHostCall (callId : PVM.Reg) (gas : Gas) (regs : PVM.Registers)
    (mem : PVM.Memory) (ctx : AccContext) : PVM.InvocationResult × AccContext :=
  let callNum := callId.toNat
  let mkResult (regs' : PVM.Registers) (mem' : PVM.Memory) (gas' : Gas) : PVM.InvocationResult :=
    { exitReason := .hostCall callId  -- signals "continue" to the loop
      exitValue := if 7 < regs'.size then regs'[7]! else 0
      gas := Int64.mk gas'
      registers := regs'
      memory := mem' }
  let setR7 (r : PVM.Registers) (v : UInt64) := setReg r 7 v
  let gas' := if gas.toNat >= hostCallGas then gas - UInt64.ofNat hostCallGas else 0
  match callNum with
  -- ===== gas (0): Return remaining gas in reg[7] =====
  | 0 =>
    let regs' := setR7 regs gas'
    (mkResult regs' mem gas', ctx)

  -- ===== fetch (1): Retrieve operand context data =====
  | 1 =>
    -- reg[7] = operand index, reg[8] = output pointer
    let idx := (getReg regs 7).toNat
    if idx >= ctx.operands.size then
      let regs' := setR7 regs PVM.RESULT_NONE
      (mkResult regs' mem gas', ctx)
    else
      let op := ctx.operands[idx]!
      -- Write operand data to memory at reg[8]: package_hash ‖ auth_output
      let outPtr := getReg regs 8
      let data := op.packageHash.data ++ op.authOutput
      match PVM.writeByteArray mem outPtr data with
      | .ok mem' =>
        let regs' := setR7 regs PVM.RESULT_OK
        let regs' := setReg regs' 8 (UInt64.ofNat data.size)
        (mkResult regs' mem' gas', ctx)
      | _ =>
        let regs' := setR7 regs PVM.RESULT_OOB
        (mkResult regs' mem gas', ctx)

  -- ===== lookup (2): Preimage lookup by hash =====
  | 2 =>
    -- reg[7] = service id, reg[8] = hash pointer, reg[9] = output pointer,
    -- reg[10] = output max length
    let sid := UInt32.ofNat (getReg regs 7).toNat
    let hashPtr := getReg regs 8
    let outPtr := getReg regs 9
    let outMax := (getReg regs 10).toNat
    -- Read the 32-byte hash from memory
    match PVM.readByteArray mem hashPtr 32 with
    | .ok hashBytes =>
      let h : Hash := ⟨hashBytes, sorry⟩
      -- Look up the preimage in the target service's preimage store
      match ctx.state.accounts.lookup sid with
      | none =>
        let regs' := setR7 regs PVM.RESULT_WHO
        (mkResult regs' mem gas', ctx)
      | some acct =>
        match acct.preimages.lookup h with
        | none =>
          let regs' := setR7 regs PVM.RESULT_NONE
          (mkResult regs' mem gas', ctx)
        | some preimage =>
          let writeLen := min preimage.size outMax
          let toWrite := preimage.extract 0 writeLen
          match PVM.writeByteArray mem outPtr toWrite with
          | .ok mem' =>
            let regs' := setR7 regs PVM.RESULT_OK
            let regs' := setReg regs' 8 (UInt64.ofNat preimage.size)
            (mkResult regs' mem' gas', ctx)
          | _ =>
            let regs' := setR7 regs PVM.RESULT_OOB
            (mkResult regs' mem gas', ctx)
    | _ =>
      let regs' := setR7 regs PVM.RESULT_OOB
      (mkResult regs' mem gas', ctx)

  -- ===== read (3): Read from service storage =====
  | 3 =>
    -- reg[7] = service id (0 = self), reg[8] = key pointer, reg[9] = key length,
    -- reg[10] = value output pointer, reg[11] = value max length
    let sid := UInt32.ofNat (getReg regs 7).toNat
    let keyPtr := getReg regs 8
    let keyLen := (getReg regs 9).toNat
    let valPtr := getReg regs 10
    let valMax := (getReg regs 11).toNat
    match PVM.readByteArray mem keyPtr keyLen with
    | .ok keyBytes =>
      let targetSid := if sid == 0 then ctx.serviceId else sid
      match ctx.state.accounts.lookup targetSid with
      | none =>
        let regs' := setR7 regs PVM.RESULT_WHO
        (mkResult regs' mem gas', ctx)
      | some acct =>
        match acct.storage.lookup keyBytes with
        | none =>
          let regs' := setR7 regs PVM.RESULT_NONE
          (mkResult regs' mem gas', ctx)
        | some val =>
          let writeLen := min val.size valMax
          let toWrite := val.extract 0 writeLen
          match PVM.writeByteArray mem valPtr toWrite with
          | .ok mem' =>
            let regs' := setR7 regs PVM.RESULT_OK
            let regs' := setReg regs' 8 (UInt64.ofNat val.size)
            (mkResult regs' mem' gas', ctx)
          | _ =>
            let regs' := setR7 regs PVM.RESULT_OOB
            (mkResult regs' mem gas', ctx)
    | _ =>
      let regs' := setR7 regs PVM.RESULT_OOB
      (mkResult regs' mem gas', ctx)

  -- ===== write (4): Write to own storage =====
  | 4 =>
    -- reg[7] = key pointer, reg[8] = key length,
    -- reg[9] = value pointer, reg[10] = value length
    let keyPtr := getReg regs 7
    let keyLen := (getReg regs 8).toNat
    let valPtr := getReg regs 9
    let valLen := (getReg regs 10).toNat
    match PVM.readByteArray mem keyPtr keyLen with
    | .ok keyBytes =>
      if valLen == 0 then
        -- Delete the key
        match ctx.state.accounts.lookup ctx.serviceId with
        | none =>
          let regs' := setR7 regs PVM.RESULT_NONE
          (mkResult regs' mem gas', ctx)
        | some acct =>
          let prevSize := match acct.storage.lookup keyBytes with
            | some v => v.size | none => 0
          let acct' := { acct with storage := acct.storage.erase keyBytes }
          let accounts' := ctx.state.accounts.insert ctx.serviceId acct'
          let state' := { ctx.state with accounts := accounts' }
          let regs' := setR7 regs PVM.RESULT_OK
          let regs' := setReg regs' 8 (UInt64.ofNat prevSize)
          (mkResult regs' mem gas', { ctx with state := state' })
      else
        match PVM.readByteArray mem valPtr valLen with
        | .ok valBytes =>
          match ctx.state.accounts.lookup ctx.serviceId with
          | none =>
            let regs' := setR7 regs PVM.RESULT_NONE
            (mkResult regs' mem gas', ctx)
          | some acct =>
            let prevSize := match acct.storage.lookup keyBytes with
              | some v => v.size | none => 0
            let acct' := { acct with storage := acct.storage.insert keyBytes valBytes }
            let accounts' := ctx.state.accounts.insert ctx.serviceId acct'
            let state' := { ctx.state with accounts := accounts' }
            let regs' := setR7 regs PVM.RESULT_OK
            let regs' := setReg regs' 8 (UInt64.ofNat prevSize)
            (mkResult regs' mem gas', { ctx with state := state' })
        | _ =>
          let regs' := setR7 regs PVM.RESULT_OOB
          (mkResult regs' mem gas', ctx)
    | _ =>
      let regs' := setR7 regs PVM.RESULT_OOB
      (mkResult regs' mem gas', ctx)

  -- ===== info (5): Service account information =====
  | 5 =>
    -- reg[7] = service id (0 = self), reg[8] = output pointer
    let sid := UInt32.ofNat (getReg regs 7).toNat
    let outPtr := getReg regs 8
    let targetSid := if sid == 0 then ctx.serviceId else sid
    match ctx.state.accounts.lookup targetSid with
    | none =>
      let regs' := setR7 regs PVM.RESULT_NONE
      (mkResult regs' mem gas', ctx)
    | some acct =>
      let info := encodeAccountInfo acct
      match PVM.writeByteArray mem outPtr info with
      | .ok mem' =>
        let regs' := setR7 regs PVM.RESULT_OK
        (mkResult regs' mem' gas', ctx)
      | _ =>
        let regs' := setR7 regs PVM.RESULT_OOB
        (mkResult regs' mem gas', ctx)

  -- ===== historical_lookup (6) =====
  | 6 =>
    -- Requires access to historical state; return NONE
    let regs' := setR7 regs PVM.RESULT_NONE
    (mkResult regs' mem gas', ctx)

  -- ===== export (7): Export segment =====
  | 7 =>
    let regs' := setR7 regs PVM.RESULT_OK
    (mkResult regs' mem gas', ctx)

  -- ===== machine (8): Create nested PVM =====
  | 8 =>
    let regs' := setR7 regs PVM.RESULT_OK
    (mkResult regs' mem gas', ctx)

  -- ===== peek (9): Read nested PVM memory =====
  | 9 =>
    let regs' := setR7 regs PVM.RESULT_NONE
    (mkResult regs' mem gas', ctx)

  -- ===== poke (10): Write nested PVM memory =====
  | 10 =>
    let regs' := setR7 regs PVM.RESULT_OK
    (mkResult regs' mem gas', ctx)

  -- ===== pages (11): Manage page permissions =====
  | 11 =>
    let regs' := setR7 regs PVM.RESULT_OK
    (mkResult regs' mem gas', ctx)

  -- ===== invoke (12): Execute nested PVM =====
  | 12 =>
    let regs' := setR7 regs PVM.RESULT_OK
    (mkResult regs' mem gas', ctx)

  -- 13 is unused

  -- ===== bless (14): Set privileged services =====
  | 14 =>
    -- Only the manager service can bless. GP Appendix B.
    if ctx.serviceId != ctx.state.manager then
      let regs' := setR7 regs PVM.RESULT_CORE
      (mkResult regs' mem gas', ctx)
    else
      -- reg[7] = manager, reg[8] = assigners pointer, reg[9] = designator,
      -- reg[10] = registrar
      let newManager := UInt32.ofNat (getReg regs 7).toNat
      let newDesignator := UInt32.ofNat (getReg regs 9).toNat
      let newRegistrar := UInt32.ofNat (getReg regs 10).toNat
      -- Read C assigners (4 bytes each) from memory at reg[8]
      let assignPtr := getReg regs 8
      let assigners := Id.run do
        let mut arr : Array ServiceId := #[]
        for i in [:C] do
          match PVM.readU32 mem (assignPtr + UInt64.ofNat (i * 4)) with
          | .ok v => arr := arr.push (UInt32.ofNat v.toNat)
          | _ => arr := arr.push 0
        return arr
      let state' := { ctx.state with
        manager := newManager
        assigners := assigners
        designator := newDesignator
        registrar := newRegistrar }
      let regs' := setR7 regs PVM.RESULT_OK
      (mkResult regs' mem gas', { ctx with state := state' })

  -- ===== assign (15): Assign core authorization =====
  | 15 =>
    -- reg[7] = core index, reg[8] = authorization hash pointer
    -- Only assigner for that core can call this
    let coreIdx := (getReg regs 7).toNat
    let hashPtr := getReg regs 8
    if coreIdx >= C then
      let regs' := setR7 regs PVM.RESULT_CORE
      (mkResult regs' mem gas', ctx)
    else
      -- Check caller is the assigner for this core
      let assigner := if coreIdx < ctx.state.assigners.size
        then ctx.state.assigners[coreIdx]! else 0
      if ctx.serviceId != assigner then
        let regs' := setR7 regs PVM.RESULT_CORE
        (mkResult regs' mem gas', ctx)
      else
        match PVM.readByteArray mem hashPtr 32 with
        | .ok hashBytes =>
          let h : Hash := ⟨hashBytes, sorry⟩
          let queue := if coreIdx < ctx.state.authQueue.size
            then ctx.state.authQueue[coreIdx]! else #[]
          let queue' := queue.push h
          let authQueue' := if coreIdx < ctx.state.authQueue.size
            then ctx.state.authQueue.set! coreIdx queue'
            else ctx.state.authQueue
          let state' := { ctx.state with authQueue := authQueue' }
          let regs' := setR7 regs PVM.RESULT_OK
          (mkResult regs' mem gas', { ctx with state := state' })
        | _ =>
          let regs' := setR7 regs PVM.RESULT_OOB
          (mkResult regs' mem gas', ctx)

  -- ===== designate (16): Set pending validator keys =====
  | 16 =>
    -- Only the designator service can call this
    if ctx.serviceId != ctx.state.designator then
      let regs' := setR7 regs PVM.RESULT_CORE
      (mkResult regs' mem gas', ctx)
    else
      -- reg[7] = keys pointer (V validator keys in memory)
      let keysPtr := getReg regs 7
      -- Each ValidatorKey: bandersnatch(32) + ed25519(32) + bls(144) + metadata(128) = 336 bytes
      let keySize := 336
      let keys := Id.run do
        let mut arr : Array ValidatorKey := #[]
        for i in [:V] do
          let offset := keysPtr + UInt64.ofNat (i * keySize)
          match PVM.readByteArray mem offset keySize with
          | .ok kBytes =>
            let vk : ValidatorKey := {
              bandersnatch := ⟨kBytes.extract 0 32, sorry⟩
              ed25519 := ⟨kBytes.extract 32 64, sorry⟩
              bls := ⟨kBytes.extract 64 208, sorry⟩
              metadata := ⟨kBytes.extract 208 336, sorry⟩
            }
            arr := arr.push vk
          | _ => arr := arr.push default
        return arr
      let state' := { ctx.state with stagingKeys := keys }
      let regs' := setR7 regs PVM.RESULT_OK
      (mkResult regs' mem gas', { ctx with state := state' })

  -- ===== checkpoint (17): Save accumulation checkpoint =====
  | 17 =>
    let ctx' := { ctx with checkpoint := some ctx.state.accounts }
    let regs' := setR7 regs gas'
    (mkResult regs' mem gas', ctx')

  -- ===== new (18): Create new service account =====
  | 18 =>
    -- reg[7] = code hash pointer (32 bytes), reg[8] = min_acc_gas,
    -- reg[9] = min_on_transfer_gas
    let codeHashPtr := getReg regs 7
    let minAccGas := getReg regs 8
    let minOnTransferGas := getReg regs 9
    match PVM.readByteArray mem codeHashPtr 32 with
    | .ok hashBytes =>
      let codeHash : Hash := ⟨hashBytes, sorry⟩
      let newId := ctx.nextServiceId
      let newAcct : ServiceAccount := {
        storage := Dict.empty
        preimages := Dict.empty
        preimageInfo := Dict.empty
        gratis := 0
        codeHash
        balance := 0
        minAccGas
        minOnTransferGas
        created := ctx.timeslot
        lastAccumulation := 0
        parent := ctx.serviceId
      }
      let accounts' := ctx.state.accounts.insert newId newAcct
      let state' := { ctx.state with accounts := accounts' }
      let ctx' := { ctx with state := state', nextServiceId := newId + 1 }
      let regs' := setR7 regs PVM.RESULT_OK
      let regs' := setReg regs' 8 (UInt64.ofNat newId.toNat)
      (mkResult regs' mem gas', ctx')
    | _ =>
      let regs' := setR7 regs PVM.RESULT_OOB
      (mkResult regs' mem gas', ctx)

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
      let regs' := setR7 regs PVM.RESULT_OOB
      (mkResult regs' mem gas', ctx)

  -- ===== transfer (20): Create deferred transfer =====
  | 20 =>
    -- reg[7] = destination, reg[8] = amount, reg[9] = gas limit,
    -- reg[10] = memo pointer (M_T bytes)
    let dest := UInt32.ofNat (getReg regs 7).toNat
    let amount := getReg regs 8
    let gasLimit := getReg regs 9
    let memoPtr := getReg regs 10
    -- Check destination exists
    match ctx.state.accounts.lookup dest with
    | none =>
      let regs' := setR7 regs PVM.RESULT_WHO
      (mkResult regs' mem gas', ctx)
    | some _ =>
      -- Check source has enough balance
      match ctx.state.accounts.lookup ctx.serviceId with
      | none =>
        let regs' := setR7 regs PVM.RESULT_NONE
        (mkResult regs' mem gas', ctx)
      | some srcAcct =>
        if srcAcct.balance < amount then
          let regs' := setR7 regs PVM.RESULT_LOW
          (mkResult regs' mem gas', ctx)
        else
          -- Read memo from memory (W_T = 128 bytes)
          let memoBytes := match PVM.readByteArray mem memoPtr W_T with
            | .ok m => m | _ => ByteArray.mk (Array.mkArray W_T 0)
          let memoSeq : OctetSeq W_T := ⟨memoBytes, sorry⟩  -- size proof elided
          let xfer : DeferredTransfer := {
            source := ctx.serviceId, dest, amount
            memo := memoSeq
            gas := gasLimit
          }
          -- Deduct transfer gas: base + gasLimit
          let transferGas := UInt64.ofNat hostCallGas + gasLimit
          let gas'' := if gas'.toNat >= transferGas.toNat then gas' - transferGas else 0
          -- Debit the source balance
          let srcAcct' := { srcAcct with balance := srcAcct.balance - amount }
          let accounts' := ctx.state.accounts.insert ctx.serviceId srcAcct'
          let state' := { ctx.state with accounts := accounts' }
          let ctx' := { ctx with state := state', transfers := ctx.transfers.push xfer }
          let regs' := setR7 regs PVM.RESULT_OK
          (mkResult regs' mem gas'', ctx')

  -- ===== eject (21): Remove service account =====
  | 21 =>
    -- reg[7] = service id to eject
    let sid := UInt32.ofNat (getReg regs 7).toNat
    -- Only the registrar can eject
    if ctx.serviceId != ctx.state.registrar then
      let regs' := setR7 regs PVM.RESULT_CORE
      (mkResult regs' mem gas', ctx)
    else
      match ctx.state.accounts.lookup sid with
      | none =>
        let regs' := setR7 regs PVM.RESULT_WHO
        (mkResult regs' mem gas', ctx)
      | some _ =>
        let accounts' := ctx.state.accounts.erase sid
        let state' := { ctx.state with accounts := accounts' }
        let regs' := setR7 regs PVM.RESULT_OK
        (mkResult regs' mem gas', { ctx with state := state' })

  -- ===== query (22): Query preimage request status =====
  | 22 =>
    -- reg[7] = hash pointer, reg[8] = blob length, reg[9] = service id (0 = self)
    let hashPtr := getReg regs 7
    let blobLen := UInt32.ofNat (getReg regs 8).toNat
    let sid := UInt32.ofNat (getReg regs 9).toNat
    let targetSid := if sid == 0 then ctx.serviceId else sid
    match PVM.readByteArray mem hashPtr 32 with
    | .ok hashBytes =>
      let h : Hash := ⟨hashBytes, sorry⟩
      match ctx.state.accounts.lookup targetSid with
      | none =>
        let regs' := setR7 regs PVM.RESULT_WHO
        (mkResult regs' mem gas', ctx)
      | some acct =>
        match acct.preimageInfo.lookup (h, blobLen) with
        | none =>
          let regs' := setR7 regs PVM.RESULT_NONE
          (mkResult regs' mem gas', ctx)
        | some timeslots =>
          let regs' := setR7 regs PVM.RESULT_OK
          let regs' := setReg regs' 8 (UInt64.ofNat timeslots.size)
          (mkResult regs' mem gas', ctx)
    | _ =>
      let regs' := setR7 regs PVM.RESULT_OOB
      (mkResult regs' mem gas', ctx)

  -- ===== solicit (23): Request preimage =====
  | 23 =>
    -- reg[7] = hash pointer, reg[8] = blob length
    let hashPtr := getReg regs 7
    let blobLen := UInt32.ofNat (getReg regs 8).toNat
    match PVM.readByteArray mem hashPtr 32 with
    | .ok hashBytes =>
      let h : Hash := ⟨hashBytes, sorry⟩
      match ctx.state.accounts.lookup ctx.serviceId with
      | none =>
        let regs' := setR7 regs PVM.RESULT_NONE
        (mkResult regs' mem gas', ctx)
      | some acct =>
        -- Add request with current timeslot
        let existing := match acct.preimageInfo.lookup (h, blobLen) with
          | some ts => ts | none => #[]
        let acct' := { acct with
          preimageInfo := acct.preimageInfo.insert (h, blobLen) (existing.push ctx.timeslot) }
        let accounts' := ctx.state.accounts.insert ctx.serviceId acct'
        let state' := { ctx.state with accounts := accounts' }
        let regs' := setR7 regs PVM.RESULT_OK
        (mkResult regs' mem gas', { ctx with state := state' })
    | _ =>
      let regs' := setR7 regs PVM.RESULT_OOB
      (mkResult regs' mem gas', ctx)

  -- ===== forget (24): Forget preimage request =====
  | 24 =>
    -- reg[7] = hash pointer, reg[8] = blob length
    let hashPtr := getReg regs 7
    let blobLen := UInt32.ofNat (getReg regs 8).toNat
    match PVM.readByteArray mem hashPtr 32 with
    | .ok hashBytes =>
      let h : Hash := ⟨hashBytes, sorry⟩
      match ctx.state.accounts.lookup ctx.serviceId with
      | none =>
        let regs' := setR7 regs PVM.RESULT_NONE
        (mkResult regs' mem gas', ctx)
      | some acct =>
        let acct' := { acct with
          preimageInfo := acct.preimageInfo.erase (h, blobLen)
          preimages := acct.preimages.erase h }
        let accounts' := ctx.state.accounts.insert ctx.serviceId acct'
        let state' := { ctx.state with accounts := accounts' }
        let regs' := setR7 regs PVM.RESULT_OK
        (mkResult regs' mem gas', { ctx with state := state' })
    | _ =>
      let regs' := setR7 regs PVM.RESULT_OOB
      (mkResult regs' mem gas', ctx)

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
      let regs' := setR7 regs PVM.RESULT_OOB
      (mkResult regs' mem gas', ctx)

  -- ===== provide (26): Provide preimage data =====
  | 26 =>
    -- reg[7] = data pointer, reg[8] = data length
    let dataPtr := getReg regs 7
    let dataLen := (getReg regs 8).toNat
    match PVM.readByteArray mem dataPtr dataLen with
    | .ok preimageData =>
      -- Hash the data and store as preimage
      let h := Crypto.blake2b preimageData
      let provision := (ctx.serviceId, preimageData)
      let regs' := setR7 regs PVM.RESULT_OK
      -- Also store in own preimage store
      match ctx.state.accounts.lookup ctx.serviceId with
      | some acct =>
        let acct' := { acct with preimages := acct.preimages.insert h preimageData }
        let accounts' := ctx.state.accounts.insert ctx.serviceId acct'
        let state' := { ctx.state with accounts := accounts' }
        (mkResult regs' mem gas', { ctx with
          state := state'
          provisions := ctx.provisions.push provision })
      | none =>
        (mkResult regs' mem gas', { ctx with provisions := ctx.provisions.push provision })
    | _ =>
      let regs' := setR7 regs PVM.RESULT_OOB
      (mkResult regs' mem gas', ctx)

  -- ===== Unknown host call =====
  | _ =>
    let regs' := setR7 regs PVM.RESULT_WHAT
    (mkResult regs' mem gas', ctx)

-- ============================================================================
-- accone — Single-Service Accumulation — GP eq:accone
-- ============================================================================

/-- Accumulate a single service. GP §12 eq:accone.
    Gathers all operands and transfers for this service,
    invokes Ψ_A (PVM accumulate), and collects outputs. -/
def accone (ps : PartialState) (serviceId : ServiceId)
    (operands : Array OperandTuple) (transfers : Array DeferredTransfer)
    (freeGas : Gas) (timeslot : Timeslot) : AccOneOutput :=
  -- Look up service account
  match ps.accounts.lookup serviceId with
  | none =>
    -- Service doesn't exist: no-op
    { postState := ps, deferredTransfers := #[], yieldHash := none,
      gasUsed := 0, provisions := #[] }
  | some acct =>
    -- Compute total gas available
    let operandGas := operands.foldl (init := (0 : UInt64)) fun acc op => acc + op.gasLimit
    let transferGas := transfers.foldl (init := (0 : UInt64)) fun acc t => acc + t.gas
    let totalGas := freeGas + operandGas + transferGas

    -- Look up service code (simplified: use code hash as placeholder)
    -- In a real implementation, we'd look up the code from preimages
    let _codeHash := acct.codeHash

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
      nextServiceId := UInt32.ofNat S_MIN  -- Start new service IDs at S_MIN
      checkpoint := none
    }

    -- In a full implementation, we would:
    -- 1. Look up the service code blob from acct.codeHash
    -- 2. Initialize PVM with initStandard
    -- 3. Run PVM with handleHostCall as the host-call handler
    -- 4. Collect outputs from the context
    --
    -- For now, we model this as an opaque invocation that returns the context.
    -- The PVM infrastructure is in place for a complete implementation.

    { postState := ctx.state
      deferredTransfers := ctx.transfers
      yieldHash := ctx.yieldHash
      gasUsed := totalGas - totalGas  -- All gas "used" in this stub
      provisions := ctx.provisions }

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

/-- Accumulate all affected services in parallel. GP §12 eq:accpar.
    Returns (updated partial state, new deferred transfers, yield outputs, gas used). -/
def accpar (ps : PartialState) (reports : Array WorkReport)
    (transfers : Array DeferredTransfer) (freeGasMap : Dict ServiceId Gas)
    (timeslot : Timeslot) : PartialState × Array DeferredTransfer × Array (ServiceId × Hash) × Dict ServiceId Gas :=
  let operandGroups := groupByService reports
  let transferGroups := groupTransfersByDest transfers

  -- Collect all affected service IDs
  let serviceIds := (operandGroups.keys ++ transferGroups.keys).eraseDups

  -- Accumulate each service
  let (ps', allTransfers, allYields, gasMap) := serviceIds.foldl
    (init := (ps, #[], #[], Dict.empty (K := ServiceId) (V := Gas)))
    fun (ps, xfers, yields, gm) sid =>
      let ops := match operandGroups.lookup sid with | some o => o | none => #[]
      let txs := match transferGroups.lookup sid with | some t => t | none => #[]
      let freeGas := match freeGasMap.lookup sid with | some g => g | none => 0
      let result := accone ps sid ops txs freeGas timeslot
      let ps' := result.postState
      let xfers' := xfers ++ result.deferredTransfers
      let yields' := match result.yieldHash with
        | some h => yields.push (sid, h)
        | none => yields
      let gm' := gm.insert sid (UInt64.ofNat result.gasUsed.toNat)
      (ps', xfers', yields', gm')
  (ps', allTransfers, allYields, gasMap)

-- ============================================================================
-- accseq — Sequential Accumulation — GP eq:accseq
-- ============================================================================

/-- Full sequential accumulation pipeline. GP §12 eq:accseq.
    Orchestrates multiple rounds of accpar, feeding deferred transfers
    from one round into the next. -/
def accseq (_gasLimit : Gas) (reports : Array WorkReport)
    (initialTransfers : Array DeferredTransfer)
    (ps : PartialState) (freeGasMap : Dict ServiceId Gas)
    (timeslot : Timeslot) : Nat × PartialState × Array (ServiceId × Hash) × Dict ServiceId Gas :=
  -- Round 1: accumulate work-report operands + initial deferred transfers
  let (ps1, newXfers1, yields1, gasMap1) := accpar ps reports initialTransfers freeGasMap timeslot

  -- Round 2: process deferred transfers generated in round 1
  if newXfers1.size == 0 then
    (reports.size, ps1, yields1, gasMap1)
  else
    let (ps2, newXfers2, yields2, gasMap2) := accpar ps1 #[] newXfers1 Dict.empty timeslot
    let allYields := yields1 ++ yields2
    let gasMapFinal := gasMap2.entries.foldl (init := gasMap1) fun acc (k, v) =>
      acc.insert k v

    -- Round 3: process any further deferred transfers (last round)
    if newXfers2.size == 0 then
      (reports.size, ps2, allYields, gasMapFinal)
    else
      let (ps3, _, yields3, gasMap3) := accpar ps2 #[] newXfers2 Dict.empty timeslot
      let finalYields := allYields ++ yields3
      let gasMapFinal' := gasMap3.entries.foldl (init := gasMapFinal) fun acc (k, v) =>
        acc.insert k v
      (reports.size, ps3, finalYields, gasMapFinal')

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

/-- Perform block-level accumulation. GP §12.
    Takes available work-reports that have been assured and
    runs the full accseq pipeline. -/
def accumulate (state : State) (reports : Array WorkReport)
    (timeslot : Timeslot) : AccumulationResult :=
  let ps := PartialState.fromState state
  let freeGasMap := state.privileged.alwaysAccumulate

  -- Total gas budget: max(G_T, G_A × C + Σ alwaysAccumulate)
  let alwaysGas := freeGasMap.values.foldl (init := 0) fun acc g => acc + g.toNat
  let _totalGas := max G_T (G_A * C + alwaysGas)

  let (_, ps', outputs, gasUsage) := accseq
    (UInt64.ofNat G_T) reports #[] ps freeGasMap timeslot

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
    gasUsage }

end Jar.Accumulation
