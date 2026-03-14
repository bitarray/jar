import Jar.Notation
import Jar.Types
import Jar.Crypto
import Jar.Codec
import Jar.PVM
import Jar.PVM.Interpreter
import Jar.PVM.Memory

/-!
# Services — §9, §12, §14

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
variable [JamConfig]

-- ============================================================================
-- §9 — Minimum Balance
-- ============================================================================

/-- Minimum balance for a service account. GP eq (9.8).
    Accounts must maintain sufficient balance to cover their storage costs.
    min_balance(a) = B_S + B_I × |items| + B_L × |bytes|
    where items/bytes count storage and preimage entries. -/
def minimumBalance (acct : ServiceAccount) : Balance :=
  let itemCount := acct.storage.entries.length + acct.preimageInfo.entries.length
  let byteCount := acct.preimages.entries.foldl (init := 0)
    fun acc kv => acc + kv.2.size
  UInt64.ofNat (Jar.B_S + Jar.B_I * itemCount + Jar.B_L * byteCount)

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
  match PVM.initStandard authorizerCode authToken with
  | none => (false, 0)
  | some (prog, regs, mem) =>
    let result := PVM.run prog 0 regs mem (Int64.ofUInt64 gasLimit)
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

/-- Ψ_R : Refine invocation. GP §14.
    Executes a work-item's refinement code in the PVM without host calls.
    Returns (result, gas_used). -/
def refine
    (serviceCode : ByteArray)
    (payload : ByteArray)
    (gasLimit : Gas)
    (imports : Array ByteArray) : WorkResult × Gas :=
  let args := encodeRefineArgs payload imports
  match PVM.initStandard serviceCode args with
  | none => (.err .panic, 0)
  | some (prog, regs, mem) =>
    let result := PVM.run prog 0 regs mem (Int64.ofUInt64 gasLimit)
    let gasUsed := gasLimit - result.gas.toUInt64
    match result.exitReason with
    | .halt =>
      -- Output is in memory starting at address in reg[10], length reg[11]
      let outAddr := if 10 < result.registers.size then result.registers[10]! else 0
      let outLen := if 11 < result.registers.size then result.registers[11]! else 0
      match PVM.readByteArray result.memory outAddr outLen.toNat with
      | .ok output => (.ok output, gasUsed)
      | _ => (.ok ByteArray.empty, gasUsed)
    | .panic => (.err .panic, gasUsed)
    | .outOfGas => (.err .outOfGas, gasLimit)
    | _ => (.err .panic, gasUsed)

/-- Ξ(p, c) : Work-report computation. GP eq (14.12).
    Given a work-package p and context c, computes the work-report
    by running authorization and then refining each work-item. -/
def computeWorkReport
    (pkg : WorkPackage)
    (context : RefinementContext)
    (services : Dict ServiceId ServiceAccount) : Option (WorkReport × Gas) :=
  -- Look up authorizer code from auth code host's preimage store
  let authCode := match services.lookup pkg.authCodeHost with
    | some acct => acct.preimages.lookup ⟨pkg.authCodeHash.data, sorry⟩
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
          | some acct => acct.preimages.lookup ⟨item.codeHash.data, sorry⟩
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
          let importData := item.imports.map fun _ => ByteArray.empty  -- Segments resolved externally
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
        coreIndex := ⟨0, sorry⟩
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
    ++ Codec.encodeFixedNat 8 t.amount.toNat
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
  match PVM.initStandard serviceCode args with
  | none => acct
  | some (prog, regs, mem) =>
    let result := PVM.run prog 0 regs mem (Int64.ofUInt64 transfer.gas)
    match result.exitReason with
    | .halt =>
      -- On-transfer completed successfully; credit the transfer amount
      { acct with balance := acct.balance + transfer.amount }
    | _ =>
      -- Panic/OOG/fault: still credit the amount but no side-effects
      { acct with balance := acct.balance + transfer.amount }

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
  | gas          -- Ω_G : Query remaining gas
  | lookup       -- Ω_L : Lookup value in service storage
  | read         -- Ω_R : Read from own storage
  | write        -- Ω_W : Write to own storage
  | info         -- Ω_I : Service info query
  | bless        -- Ω_B : Set privileged services (manager only)
  | assign       -- Ω_A : Assign core authorization
  | designate    -- Ω_D : Designate validator keys
  | checkpoint   -- Ω_C : Checkpoint gas
  | newService   -- Ω_N : Create new service
  | upgrade      -- Ω_U : Upgrade service code
  | transfer     -- Ω_T : Transfer balance
  | quit         -- Ω_Q : Remove service
  | solicit      -- Ω_S : Solicit preimage
  | forget       -- Ω_F : Forget preimage
  | historicalLookup -- Ω_H : Historical state lookup
  | fetch        -- Ω_E : Fetch preimage data
  | yield        -- Ω_Y : Yield accumulation output
  | provide      -- Ω_P : Provide preimage data
  | empower      -- Ω_M : Empower (privileged operations)
  deriving BEq

end Jar.Services
