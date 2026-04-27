import Jar.Notation
import Jar.Types
import Jar.Crypto
import Jar.Codec
import Jar.JAVM
import Jar.JAVM.Interpreter
import Jar.JAVM.Memory

/-!
# Services — §8, §9, §12, §14

Service account model, accumulation, refinement, and the work pipeline.
References: `graypaper/text/accounts.tex`, `graypaper/text/accumulation.tex`,
            `graypaper/text/work_packages_and_reports.tex`,
            `graypaper/text/authorization.tex`.

## Structure
- §9: Service account model and minimum balance
- §8: Authorization: is-authorized Ψ_I
- §14: Refinement: work-item execution Ψ_R
- §12: Accumulation: on-chain processing Ψ_A
- §14.12: Work-report computation Ξ(p, c)
- §17: Auditing protocol
-/

namespace Jar.Services
variable [JarConfig]

-- ============================================================================
-- §9 — Minimum Balance
-- ============================================================================

/-- Check if a service can afford its current storage footprint.
    Delegates to EconModel.canAffordStorage. -/
def canAffordStorage (acct : ServiceAccount) : Bool :=
  @EconModel.canAffordStorage JarConfig.EconType JarConfig.TransferType _ acct.econ acct.itemCount.toNat acct.totalFootprint B_I B_L B_S

-- ============================================================================
-- §8 — Authorization (Ψ_I)
-- ============================================================================

/-- Ψ_I : Is-authorized invocation. GP §8.
    Executes the authorizer code to check if a work-package is authorized.
    Runs in PVM without host calls (pure computation).
    Returns (authorized?, remaining gas). -/
def isAuthorized
    (authorizerCode : ByteArray)
    (authToken : ByteArray)
    (gasLimit : Gas) : Bool × Gas :=
  match JAVM.initProgram authorizerCode authToken with
  | none => (false, 0)
  | some (prog, regs, mem) =>
    let result := JAVM.runProgram prog 0 regs mem (Int64.ofUInt64 gasLimit)
    match result.exitReason with
    | .halt => (result.exitValue == 0, result.gas.toUInt64)
    | _ => (false, result.gas.toUInt64)

-- ============================================================================
-- §14 — Refinement (Ψ_R, In-Core Computation)
-- ============================================================================

/-- Encode refine arguments: payload ‖ import segments. GP §14. -/
private def encodeRefineArgs (payload : ByteArray) (imports : Array ByteArray) : ByteArray :=
  Codec.encodeFixedNat 4 imports.size
    ++ Codec.encodeLengthPrefixed payload
    ++ imports.foldl (init := ByteArray.empty) fun acc seg =>
      acc ++ Codec.encodeLengthPrefixed seg

/-- Refine host call context: tracks exported segments during refinement. -/
structure RefineContext where
  /-- Work item payload (accessible via fetch mode 2). -/
  payload : ByteArray
  /-- Resolved import segment data (accessible via fetch mode 3). -/
  imports : Array ByteArray
  /-- Exported segments accumulated during refinement. -/
  exports : Array ByteArray
  /-- Export offset for global segment indexing. -/
  exportOffset : Nat
  deriving Inhabited

/-- Handle a refine host call. GP §14 host calls:
    0=gas, 2=fetch, 3=historical_lookup, 4=export, 5=machine.
    Returns (result, updated context) where result.exitReason = .hostCall _
    means "continue execution" (the handler wrote return values into registers). -/
private def handleRefineHostCall
    (callId : JAVM.Reg) (gas : Gas) (regs : JAVM.Registers) (mem : JAVM.Memory)
    (ctx : RefineContext) : JAVM.InvocationResult × RefineContext :=
  -- gp072: callId maps directly to host call number (no shift).
  -- jar1 (v2): dispatch handled by capability kernel, not this function.
  -- Host call gas cost: g=10
  let hostGasCost : Gas := 10
  if gas < hostGasCost then
    -- Out of gas
    ({ exitReason := .outOfGas, exitValue := 0, gas := 0,
       registers := regs, memory := mem }, ctx)
  else
    let gas' := gas - hostGasCost
    let regs' := regs -- will be modified per host call
    match callId with
    | 255 =>
      -- REPLY: program termination via ecalli(0xFF)
      ({ exitReason := .halt, exitValue := if 7 < regs.size then regs[7]! else 0,
         gas := Int64.ofUInt64 gas', registers := regs, memory := mem }, ctx)
    | 0 =>
      -- gas(): return remaining gas in φ[7]
      let regs' := regs.set! 7 gas'
      ({ exitReason := .hostCall 0, exitValue := 0,
         gas := Int64.ofUInt64 gas', registers := regs', memory := mem }, ctx)
    | 2 =>
      -- fetch(): read work-item context data
      -- φ[7]=buf_ptr, φ[8]=offset, φ[9]=max_len, φ[10]=mode
      let mode := if 10 < regs.size then regs[10]! else 0
      let data := match mode with
        | 2 => some ctx.payload -- payload
        | 3 => -- import segment at index φ[11]
          let idx := if 11 < regs.size then (regs[11]!).toNat else 0
          if h : idx < ctx.imports.size then some ctx.imports[idx] else none
        | _ => none
      match data with
      | none =>
        let regs' := regs.set! 7 (UInt64.ofNat (2^64 - 1)) -- NONE
        ({ exitReason := .hostCall 0, exitValue := 0,
           gas := Int64.ofUInt64 gas', registers := regs', memory := mem }, ctx)
      | some d =>
        let offset := if 8 < regs.size then regs[8]!.toNat else 0
        let maxLen := if 9 < regs.size then regs[9]!.toNat else 0
        let bufPtr := if 7 < regs.size then regs[7]! else 0
        let f := min offset d.size
        let l := min maxLen (d.size - f)
        let slice := d.extract f (f + l)
        let mem' := match JAVM.writeByteArray mem bufPtr slice with
          | .ok m => m
          | _ => mem -- page fault: silently ignore (will be caught by PVM)
        let regs' := regs.set! 7 (UInt64.ofNat d.size)
        ({ exitReason := .hostCall 0, exitValue := 0,
           gas := Int64.ofUInt64 gas', registers := regs', memory := mem' }, ctx)
    | 4 =>
      -- export(): append a segment to exports
      -- φ[7] = pointer to segment data
      let ptr := if 7 < regs.size then regs[7]! else 0
      -- W_G = segment size (W_P × W_E, typically 6 × 684 = 4104)
      let segmentSize := JarConfig.config.W_P * 684
      match JAVM.readByteArray mem ptr segmentSize with
      | .ok segData =>
        let idx := ctx.exportOffset + ctx.exports.size
        let ctx' := { ctx with exports := ctx.exports.push segData }
        let regs' := regs.set! 7 (UInt64.ofNat idx)
        ({ exitReason := .hostCall 0, exitValue := 0,
           gas := Int64.ofUInt64 gas', registers := regs', memory := mem }, ctx')
      | _ =>
        let regs' := regs.set! 7 (UInt64.ofNat (2^64 - 3)) -- OOB
        ({ exitReason := .hostCall 0, exitValue := 0,
           gas := Int64.ofUInt64 gas', registers := regs', memory := mem }, ctx)
    | _ =>
      -- Unimplemented: return WHAT (2^64 - 2)
      let regs' := regs.set! 7 (UInt64.ofNat (2^64 - 2))
      ({ exitReason := .hostCall 0, exitValue := 0,
         gas := Int64.ofUInt64 gas', registers := regs', memory := mem }, ctx)

/-- Ψ_R : Refine invocation. GP §14.
    Executes a work-item's refinement code in the PVM with host call dispatch.
    Returns (result, gas_used, exported_segments). -/
def refine
    (serviceCode : ByteArray)
    (payload : ByteArray)
    (gasLimit : Gas)
    (imports : Array ByteArray) : WorkResult × Gas :=
  let args := encodeRefineArgs payload imports
  match JAVM.initProgram serviceCode args with
  | none => (.err .panic, 0)
  | some (prog, regs, mem) =>
    let ctx : RefineContext := {
      payload := payload, imports := imports,
      exports := #[], exportOffset := 0 }
    let runFn := match JarConfig.gasModel with
      | .perInstruction => JAVM.run
      | .basicBlockFull => JAVM.runBlockGas
      | .basicBlockSinglePass => JAVM.runBlockGasSinglePass
    let (result, _ctx') := JAVM.runWithHostCalls RefineContext
      prog 0 regs mem (Int64.ofUInt64 gasLimit)
      handleRefineHostCall ctx runFn
    let gasUsed := gasLimit - result.gas.toUInt64
    match result.exitReason with
    | .halt =>
      -- Output is in memory starting at address in reg[7], length reg[8]
      let outAddr := if 7 < result.registers.size then result.registers[7]! else 0
      let outLen := if 8 < result.registers.size then result.registers[8]! else 0
      match JAVM.readByteArray result.memory outAddr outLen.toNat with
      | .ok output => (.ok output, gasUsed)
      | _ => (.ok ByteArray.empty, gasUsed)
    | .panic => (.err .panic, gasUsed)
    | .outOfGas => (.err .outOfGas, gasLimit)
    | _ => (.err .panic, gasUsed)

/-- Import segment resolver: given a segment root hash and index,
    returns the reconstructed segment data (4104 bytes).
    In a full node, this retrieves erasure-coded chunks from the DA layer
    and reconstructs via Reed-Solomon. GP §14.2. -/
abbrev ImportResolver := Hash → Nat → Option ByteArray

/-- Ξ(p, c) : Work-report computation. GP eq (14.12).
    Given a work-package p and context c, computes the work-report
    by running authorization and then refining each work-item.
    `resolveImport` provides segment data for work-item imports —
    requires guarantor-level DA infrastructure (not yet implemented). -/
def computeWorkReport
    (pkg : WorkPackage)
    (context : RefinementContext)
    (services : Dict ServiceId ServiceAccount)
    (resolveImport : ImportResolver := fun _ _ => none) : Option (WorkReport × Gas) :=
  -- Look up authorizer code from auth code host's preimage store
  let authCode := match services.lookup pkg.authCodeHost with
    | some acct => acct.preimages.lookup (OctetSeq.mk! pkg.authCodeHash.data 32)
    | none => none
  match authCode with
  | none => none
  | some code =>
    -- Run is-authorized
    let (authorized, authGasUsed) := isAuthorized code pkg.authToken (UInt64.ofNat G_I)
    if !authorized then none
    else
      -- Refine each work item
      let digests := pkg.items.map fun item =>
        let svcCode := match services.lookup item.serviceId with
          | some acct => acct.preimages.lookup (OctetSeq.mk! item.codeHash.data 32)
          | none => none
        match svcCode with
        | none =>
          { serviceId := item.serviceId
            codeHash := item.codeHash
            payloadHash := Crypto.blake2b item.payload
            gasLimit := item.accGasLimit
            result := WorkResult.err .badCode
            gasUsed := 0
            importsCount := item.imports.size
            extrinsicsCount := item.extrinsics.size
            extrinsicsSize := 0
            exportsCount := item.exportsCount : WorkDigest }
        | some code =>
          let importData := item.imports.map fun (hash, idx) =>
            (resolveImport hash idx).getD ByteArray.empty
          let (result, gasUsed) := refine code item.payload item.gasLimit importData
          { serviceId := item.serviceId
            codeHash := item.codeHash
            payloadHash := Crypto.blake2b item.payload
            gasLimit := item.accGasLimit
            result
            gasUsed := UInt64.ofNat gasUsed.toNat
            importsCount := item.imports.size
            extrinsicsCount := item.extrinsics.size
            extrinsicsSize := 0
            exportsCount := item.exportsCount : WorkDigest }
      let report : WorkReport := {
        availSpec := {
          packageHash := Crypto.blake2b (Codec.encodeLengthPrefixed pkg.authToken)
          bundleLength := 0
          erasureRoot := Hash.zero
          segmentRoot := Hash.zero
          segmentCount := 0
        }
        context
        coreIndex := ⟨0, JarConfig.valid.hC⟩
        authorizerHash := pkg.authCodeHash
        authOutput := ByteArray.empty
        segmentRootLookup := Dict.empty
        digests
        authGasUsed := UInt64.ofNat (G_I - authGasUsed.toNat)
      }
      some (report, UInt64.ofNat (G_I - authGasUsed.toNat))

-- ============================================================================
-- §12 — Accumulation (On-Chain Processing)
-- ============================================================================

/-- Accumulation input: either an operand (from work-report) or a transfer. -/
inductive AccumulationInput where
  /-- Operand from a work-report result. -/
  | operand : WorkDigest → AccumulationInput
  /-- Deferred transfer from another service. -/
  | transfer : DeferredTransfer → AccumulationInput

-- Ψ_A is implemented in Jar.Accumulation.accone with full PVM execution.

-- ============================================================================
-- §12 — On-Transfer Handler (Ψ_T)
-- ============================================================================

/-- Encode on-transfer arguments for PVM input.
    Format: source(4) ‖ dest(4) ‖ amount(8) ‖ memo(W_T) ‖ gas(8). -/
private def encodeTransferArgs (t : DeferredTransfer) : ByteArray :=
  Codec.encodeFixedNat 4 t.source.toNat
    ++ Codec.encodeFixedNat 4 t.dest.toNat
    ++ @EconModel.encodeTransferAmount JarConfig.EconType JarConfig.TransferType _ t.payload
    ++ t.memo.data
    ++ Codec.encodeFixedNat 8 t.gas.toNat

/-- Ψ_T : On-transfer invocation. GP §12.
    Called when a service receives a deferred transfer.
    Runs service code in PVM with the transfer's gas budget.
    Returns updated service account. -/
def onTransfer
    (serviceCode : ByteArray)
    (_serviceId : ServiceId)
    (transfer : DeferredTransfer)
    (acct : ServiceAccount) : ServiceAccount :=
  let args := encodeTransferArgs transfer
  match JAVM.initProgram serviceCode args with
  | none => acct
  | some (prog, regs, mem) =>
    let result := JAVM.runProgram prog 0 regs mem (Int64.ofUInt64 transfer.gas)
    match result.exitReason with
    | .halt =>
      -- On-transfer completed successfully; credit the transfer payload
      { acct with econ := @EconModel.creditTransfer JarConfig.EconType JarConfig.TransferType _ acct.econ transfer.payload }
    | _ =>
      -- Panic/OOG/fault: still credit the payload but no side-effects
      { acct with econ := @EconModel.creditTransfer JarConfig.EconType JarConfig.TransferType _ acct.econ transfer.payload }

-- ============================================================================
-- §17 — Auditing (off-chain, left opaque)
-- ============================================================================

/-- Check if a work-report is valid by re-executing the refinement.
    Used by auditors to verify guarantor claims. GP §17.
    Off-chain operation — deliberately left opaque. -/
opaque auditWorkReport
    (report : WorkReport)
    (pkg : WorkPackage)
    (context : RefinementContext) : Bool :=
  false

-- ============================================================================
-- §12 — Host-Call Interface (Summary)
-- ============================================================================

/-- Host-call identifiers available during accumulation. GP §12. -/
inductive HostCall where
  /-- Ω_G : Query remaining gas. -/
  | gas
  /-- Ω_L : Lookup value in service storage. -/
  | lookup
  /-- Ω_R : Read from own storage. -/
  | read
  /-- Ω_W : Write to own storage. -/
  | write
  /-- Ω_I : Service info query. -/
  | info
  /-- Ω_B : Set privileged services (manager only). -/
  | bless
  /-- Ω_A : Assign core authorization. -/
  | assign
  /-- Ω_D : Designate validator keys. -/
  | designate
  /-- Ω_C : Checkpoint gas. -/
  | checkpoint
  /-- Ω_N : Create new service. -/
  | newService
  /-- Ω_U : Upgrade service code. -/
  | upgrade
  /-- Ω_T : Transfer balance. -/
  | transfer
  /-- Ω_Q : Remove service. -/
  | quit
  /-- Ω_S : Solicit preimage. -/
  | solicit
  /-- Ω_F : Forget preimage. -/
  | forget
  /-- Ω_H : Historical state lookup. -/
  | historicalLookup
  /-- Ω_E : Fetch preimage data. -/
  | fetch
  /-- Ω_Y : Yield accumulation output. -/
  | yield
  /-- Ω_P : Provide preimage data. -/
  | provide
  /-- Ω_M : Empower (privileged operations). -/
  | empower
  deriving BEq

end Jar.Services
