import Jar.Notation
import Jar.Types
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

/-- Dispatch a host call during accumulation. GP §12, Appendix B.
    Returns updated invocation result and context. -/
def handleHostCall (callId : PVM.Reg) (gas : Gas) (regs : PVM.Registers)
    (mem : PVM.Memory) (ctx : AccContext) : PVM.InvocationResult × AccContext :=
  let callNum := callId.toNat
  -- Default: return with WHAT error (unknown host call)
  let mkResult (regs' : PVM.Registers) (mem' : PVM.Memory) (gas' : Gas) : PVM.InvocationResult :=
    { exitReason := .hostCall callId  -- signals "continue" to the loop
      exitValue := if 7 < regs'.size then regs'[7]! else 0
      gas := Int64.mk gas'
      registers := regs'
      memory := mem' }
  let setR7 (regs : PVM.Registers) (v : UInt64) : PVM.Registers :=
    if 7 < regs.size then regs.set! 7 v else regs
  let gas' := if gas.toNat >= hostCallGas then gas - UInt64.ofNat hostCallGas else 0
  match callNum with
  -- ===== gas (0): Return remaining gas in reg[7] =====
  | 0 =>
    let regs' := setR7 regs gas'
    (mkResult regs' mem gas', ctx)

  -- ===== fetch (1): Retrieve context data =====
  | 1 =>
    -- Simplified: return NONE for now
    let regs' := setR7 regs PVM.RESULT_NONE
    (mkResult regs' mem gas', ctx)

  -- ===== lookup (2): Historical preimage lookup =====
  | 2 =>
    let regs' := setR7 regs PVM.RESULT_NONE
    (mkResult regs' mem gas', ctx)

  -- ===== read (3): Read from own storage =====
  | 3 =>
    -- reg[3] = key pointer, reg[4] = key length
    -- reg[5] = output buffer pointer, reg[6] = output buffer length
    let regs' := setR7 regs PVM.RESULT_NONE
    (mkResult regs' mem gas', ctx)

  -- ===== write (4): Write to own storage =====
  | 4 =>
    let regs' := setR7 regs PVM.RESULT_OK
    (mkResult regs' mem gas', ctx)

  -- ===== info (5): Service account information =====
  | 5 =>
    let regs' := setR7 regs PVM.RESULT_NONE
    (mkResult regs' mem gas', ctx)

  -- ===== historical_lookup (6) =====
  | 6 =>
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
    -- Only the manager service can bless
    if ctx.serviceId != ctx.state.manager then
      let regs' := setR7 regs PVM.RESULT_CORE
      (mkResult regs' mem gas', ctx)
    else
      -- Simplified: read new privilege config from registers/memory
      let regs' := setR7 regs PVM.RESULT_OK
      (mkResult regs' mem gas', ctx)

  -- ===== assign (15): Assign core authorization =====
  | 15 =>
    let regs' := setR7 regs PVM.RESULT_OK
    (mkResult regs' mem gas', ctx)

  -- ===== designate (16): Set validator keys =====
  | 16 =>
    if ctx.serviceId != ctx.state.designator then
      let regs' := setR7 regs PVM.RESULT_CORE
      (mkResult regs' mem gas', ctx)
    else
      let regs' := setR7 regs PVM.RESULT_OK
      (mkResult regs' mem gas', ctx)

  -- ===== checkpoint (17): Save accumulation checkpoint =====
  | 17 =>
    -- Save current accounts as the "regular dimension" checkpoint
    let ctx' := { ctx with checkpoint := some ctx.state.accounts }
    let regs' := setR7 regs gas'
    (mkResult regs' mem gas', ctx')

  -- ===== new (18): Create new service account =====
  | 18 =>
    let newId := ctx.nextServiceId
    let newAcct : ServiceAccount := {
      storage := Dict.empty
      preimages := Dict.empty
      preimageInfo := Dict.empty
      gratis := 0
      codeHash := Hash.zero
      balance := 0
      minAccGas := 0
      minOnTransferGas := 0
      created := ctx.timeslot
      lastAccumulation := 0
      parent := ctx.serviceId
    }
    let accounts' := ctx.state.accounts.insert newId newAcct
    let state' := { ctx.state with accounts := accounts' }
    let ctx' := { ctx with state := state', nextServiceId := newId + 1 }
    let regs' := setR7 regs PVM.RESULT_OK
    (mkResult regs' mem gas', ctx')

  -- ===== upgrade (19): Upgrade service code hash =====
  | 19 =>
    let regs' := setR7 regs PVM.RESULT_OK
    (mkResult regs' mem gas', ctx)

  -- ===== transfer (20): Create deferred transfer =====
  | 20 =>
    -- reg[3] = destination, reg[4] = amount, reg[5] = gas limit
    -- reg[6] = memo pointer
    let dest := if 3 < regs.size then UInt32.ofNat (regs[3]!).toNat else 0
    let amount := if 4 < regs.size then regs[4]! else 0
    let gasLimit := if 5 < regs.size then regs[5]! else 0
    let xfer : DeferredTransfer := {
      source := ctx.serviceId
      dest := dest
      amount := amount
      memo := default
      gas := gasLimit
    }
    let transferGas := UInt64.ofNat hostCallGas + gasLimit
    let gas'' := if gas'.toNat >= transferGas.toNat then gas' - transferGas else 0
    let ctx' := { ctx with transfers := ctx.transfers.push xfer }
    let regs' := setR7 regs PVM.RESULT_OK
    (mkResult regs' mem gas'', ctx')

  -- ===== eject (21): Remove service account =====
  | 21 =>
    let regs' := setR7 regs PVM.RESULT_OK
    (mkResult regs' mem gas', ctx)

  -- ===== query (22): Query preimage request =====
  | 22 =>
    let regs' := setR7 regs PVM.RESULT_NONE
    (mkResult regs' mem gas', ctx)

  -- ===== solicit (23): Request preimage =====
  | 23 =>
    let regs' := setR7 regs PVM.RESULT_OK
    (mkResult regs' mem gas', ctx)

  -- ===== forget (24): Forget preimage =====
  | 24 =>
    let regs' := setR7 regs PVM.RESULT_OK
    (mkResult regs' mem gas', ctx)

  -- ===== yield (25): Set accumulation output =====
  | 25 =>
    -- reg[3] = hash pointer (32 bytes in memory)
    let regs' := setR7 regs PVM.RESULT_OK
    -- Simplified: read hash from memory at reg[3]
    let ctx' := { ctx with yieldHash := some Hash.zero }
    (mkResult regs' mem gas', ctx')

  -- ===== provide (26): Provide preimage data =====
  | 26 =>
    let regs' := setR7 regs PVM.RESULT_OK
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
