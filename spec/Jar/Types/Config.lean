import Lean.Data.Json

/-!
# Protocol Configuration — Gray Paper Appendix I.4.4

Runtime-configurable protocol parameters supporting multiple variants
(full GP v0.7.2, tiny test config, custom variants).

Parameters that differ across variants live in `Params`. Parameters that
are identical across all known variants remain as global defs in `Constants.lean`.
-/

namespace Jar

-- ============================================================================
-- Protocol Configuration
-- ============================================================================

/-- Protocol configuration: parameters that differ across variants.
    Verified against `grey/crates/grey-types/src/config.rs`. -/
structure Params where
  -- Consensus & Validators
  /-- V : Total number of validators. -/
  V : Nat
  /-- C : Total number of cores. -/
  C : Nat
  /-- E : Epoch length in timeslots. -/
  E : Nat
  /-- N : Ticket entries per validator. -/
  N_TICKETS : Nat
  /-- Y : Ticket submission end slot. -/
  Y_TAIL : Nat
  /-- K : Max tickets per extrinsic. -/
  K_MAX_TICKETS : Nat
  /-- R : Validator-core rotation period in timeslots. -/
  R_ROTATION : Nat
  /-- H : Recent history size in blocks. -/
  H_RECENT : Nat
  -- Gas allocations
  /-- G_A : Gas allocated per work-report accumulation. -/
  G_A : Nat
  /-- G_I : Gas allocated for Is-Authorized. -/
  G_I : Nat
  /-- G_R : Gas allocated for Refine. -/
  G_R : Nat
  /-- G_T : Total accumulation gas per block. -/
  G_T : Nat
  -- Authorization
  /-- O : Authorization pool size per core. -/
  O_POOL : Nat
  /-- Q : Authorization queue size per core. -/
  Q_QUEUE : Nat
  -- Work processing
  /-- I : Max work items per package. -/
  I_MAX_ITEMS : Nat
  /-- J : Max dependency items in a work-report. -/
  J_MAX_DEPS : Nat
  /-- T : Max extrinsics per work-package. -/
  T_MAX_EXTRINSICS : Nat
  /-- U : Availability timeout in timeslots. -/
  U_TIMEOUT : Nat
  -- Preimages
  /-- D : Preimage expunge period in timeslots. -/
  D_EXPUNGE : Nat
  /-- L : Max lookup anchor age in timeslots. -/
  L_MAX_ANCHOR : Nat
  -- Economic
  /-- B_I : Additional minimum balance per mapping item. -/
  B_I : Nat
  /-- B_L : Additional minimum balance per data octet. -/
  B_L : Nat
  /-- B_S : Base minimum balance for a service. -/
  B_S : Nat
  -- Erasure
  /-- W_P : Erasure pieces per segment. -/
  W_P : Nat

-- ============================================================================
-- Variable Validator Set (GP#514)
-- ============================================================================

/-- Valid validator count: multiples of 3 in [6, 3*(C+1)]. GP#514 §safrole.
    V = {3c | c ∈ ℕ, 2 ≤ c ≤ C+1} = {6, 9, 12, ..., 3*(C+1)}. -/
def Params.isValidValCount (cfg : Params) (z : Nat) : Bool :=
  z >= 6 && z <= 3 * (cfg.C + 1) && z % 3 == 0

-- ============================================================================
-- Positivity Proofs
-- ============================================================================

/-- Positivity proofs required for Fin types to be inhabited. -/
structure Params.Valid (cfg : Params) : Prop where
  hV : 0 < cfg.V
  hC : 0 < cfg.C
  hE : 0 < cfg.E
  hN : 0 < cfg.N_TICKETS

-- ============================================================================
-- JamConfig Typeclass
-- ============================================================================

/-- PVM memory model. Controls program initialization layout. -/
inductive MemoryModel where
  /-- GP v0.7.2: 4 disjoint regions with per-page RO/RW/inaccessible permissions. -/
  | segmented
  /-- Contiguous linear: single RW region at address 0, no guard zone. -/
  | linear
  deriving BEq, Inhabited

/-- PVM gas metering model. -/
inductive GasModel where
  /-- GP v0.7.2: 1 gas per instruction. -/
  | perInstruction
  /-- Per-basic-block cost via full pipeline simulation (ROB + EU contention). -/
  | basicBlockFull
  /-- Per-basic-block cost via single-pass O(n) model (register-done tracking). -/
  | basicBlockSinglePass
  deriving BEq, Inhabited

/-- PVM capability model. -/
inductive CapabilityModel where
  /-- No capability model (v0.7.2 / jar1 v1). -/
  | none
  /-- Capability-based execution (JAVM v2). -/
  | v2
  deriving BEq, Inhabited

-- ============================================================================
-- Economic Model Typeclass (defined here so JamConfig can reference it)
-- ============================================================================

/-- Abstraction over the economic model for service accounts.
    Pure logic — no encoding/serialization methods (those are in EconEncode).
    Instances are provided for BalanceEcon and QuotaEcon in Accounts.lean. -/
class EconModel (econ : Type) (xfer : Type) where
  /-- Check if a service can afford the given storage footprint.
      bI, bL, bS are the storage deposit constants (from Params). -/
  canAffordStorage : econ → (items : Nat) → (bytes : Nat) → (bI bL bS : Nat) → Bool
  /-- Debit the creator's econ for new service creation.
      `newGratis` is the new account's gratis value (from register).
      `callerItems`/`callerBytes` are the caller's current storage footprint.
      Returns none if insufficient funds/quota. -/
  debitForNewService : econ → (newItems newBytes : Nat) → (newGratis : UInt64) → (callerItems callerBytes : Nat) → (bI bL bS : Nat) → Option econ
  /-- Create initial econ state for a newly created service. -/
  newServiceEcon : (items : Nat) → (bytes : Nat) → (gratis : UInt64) → (bI bL bS : Nat) → econ
  /-- Credit an incoming transfer's economic payload. -/
  creditTransfer : econ → xfer → econ
  /-- Check transfer affordability and return debited econ.
      Returns none if insufficient balance (BalanceEcon only). -/
  debitTransfer : econ → (amount : UInt64) → Option econ
  /-- Absorb an ejected service's economic value. -/
  absorbEjected : econ → (ejected : econ) → econ
  /-- Set storage quota (jar1 only).
      Returns none if not supported by this economic model. -/
  setQuota : econ → (maxItems : UInt64) → (maxBytes : UInt64) → Option econ
  /-- Create transfer payload from the amount register value. -/
  makeTransferPayload : (amountReg : UInt64) → xfer
  /-- Encode transfer payload as 8 bytes (for PVM on-transfer arguments). -/
  encodeTransferAmount : xfer → ByteArray
  /-- Encode econ fields for the info host call (5).
      Must produce exactly 24 bytes. bI, bL, bS are the storage deposit constants. -/
  encodeInfo : econ → (items : Nat) → (bytes : Nat) → (bI bL bS : Nat) → ByteArray
  /-- Serialize econ fields for state Merklization.
      Must produce exactly 16 bytes. -/
  serializeEcon : econ → ByteArray
  /-- Deserialize econ fields. Returns (econ, bytes consumed) or none. -/
  deserializeEcon : (data : ByteArray) → (offset : Nat) → Option (econ × Nat)
  /-- Convert econ fields to JSON key-value pairs for ServiceAccount serialization. -/
  econToJson : econ → List (String × Lean.Json)
  /-- Parse econ fields from JSON. -/
  econFromJson? : Lean.Json → Except String econ
  /-- Convert transfer payload to JSON key-value pairs. -/
  xferToJson : xfer → List (String × Lean.Json)
  /-- Parse transfer payload from JSON. -/
  xferFromJson? : Lean.Json → Except String xfer

-- ============================================================================
-- JamConfig Typeclass
-- ============================================================================

/-- JamConfig: provides protocol configuration and validity proofs.
    Used by struct types and Fin-based index aliases.
    Extended by `JamVariant` (in `Jar/Variant.lean`) to add PVM function fields. -/
class JamConfig where
  /-- Variant name, e.g. "gp072_tiny", "gp072_full". -/
  name : String
  config : Params
  valid : Params.Valid config
  /-- PVM memory layout for program initialization. -/
  memoryModel : MemoryModel := .segmented
  /-- PVM gas metering strategy. -/
  gasModel : GasModel := .perInstruction
  /-- PVM capability model: .none = flat memory, .v2 = capability-based. -/
  capabilityModel : CapabilityModel := .none
  /-- PVM blob deblob encoding: true = JAM compact natural, false = u32 LE (jar1). -/
  useCompactDeblob : Bool := true
  /-- Whether validator set size is variable (GP#514). When true, designate
      hostcall accepts a length argument and active core count scales with
      validator count. Default false for gp072 variants. -/
  variableValidators : Bool := false
  /-- Economic model type for service accounts (BalanceEcon or QuotaEcon). -/
  EconType : Type
  /-- Transfer payload type (BalanceTransfer or QuotaTransfer). -/
  TransferType : Type
  /-- BEq instance for economic model (required for state comparison). -/
  [econBEq : BEq EconType]
  /-- Inhabited instance for economic model (required for default construction). -/
  [econInhabited : Inhabited EconType]
  /-- BEq instance for transfer payload. -/
  [xferBEq : BEq TransferType]
  /-- Inhabited instance for transfer payload. -/
  [xferInhabited : Inhabited TransferType]
  /-- Repr instance for economic model (for debugging). -/
  [econRepr : Repr EconType]
  /-- Repr instance for transfer payload (for debugging). -/
  [xferRepr : Repr TransferType]
  /-- EconModel instance linking EconType and TransferType. -/
  [econModel : EconModel EconType TransferType]

-- Forward typeclass instances from JamConfig fields
instance [j : JamConfig] : BEq j.EconType := j.econBEq
instance [j : JamConfig] : Inhabited j.EconType := j.econInhabited
instance [j : JamConfig] : BEq j.TransferType := j.xferBEq
instance [j : JamConfig] : Inhabited j.TransferType := j.xferInhabited
instance [j : JamConfig] : Repr j.EconType := j.econRepr
instance [j : JamConfig] : Repr j.TransferType := j.xferRepr
instance [j : JamConfig] : EconModel j.EconType j.TransferType := j.econModel

-- ============================================================================
-- Standard Configurations
-- ============================================================================

/-- Full specification constants (Gray Paper v0.7.2). -/
def Params.full : Params where
  V := 1023; C := 341; E := 600; N_TICKETS := 2
  Y_TAIL := 500; K_MAX_TICKETS := 16; R_ROTATION := 10; H_RECENT := 8
  G_A := 10_000_000; G_I := 50_000_000; G_R := 5_000_000_000; G_T := 3_500_000_000
  O_POOL := 8; Q_QUEUE := 80
  I_MAX_ITEMS := 16; J_MAX_DEPS := 8; T_MAX_EXTRINSICS := 128; U_TIMEOUT := 5
  D_EXPUNGE := 19_200; L_MAX_ANCHOR := 14_400
  B_I := 10; B_L := 1; B_S := 100
  W_P := 6

/-- Tiny test configuration.
    Verified against `grey/crates/grey-types/src/config.rs` Config::tiny() (Rust side). -/
def Params.tiny : Params where
  V := 6; C := 2; E := 12; N_TICKETS := 3
  Y_TAIL := 10; K_MAX_TICKETS := 3; R_ROTATION := 4; H_RECENT := 8
  G_A := 10_000_000; G_I := 50_000_000; G_R := 1_000_000_000; G_T := 20_000_000
  O_POOL := 8; Q_QUEUE := 80
  I_MAX_ITEMS := 16; J_MAX_DEPS := 8; T_MAX_EXTRINSICS := 128; U_TIMEOUT := 5
  D_EXPUNGE := 32; L_MAX_ANCHOR := 14_400
  B_I := 10; B_L := 1; B_S := 100
  W_P := 1_026

-- ============================================================================
-- Validity Proofs
-- ============================================================================

theorem Params.full_valid : Params.Valid Params.full where
  hV := by decide
  hC := by decide
  hE := by decide
  hN := by decide

theorem Params.tiny_valid : Params.Valid Params.tiny where
  hV := by decide
  hC := by decide
  hE := by decide
  hN := by decide

-- ============================================================================
-- Convenience Accessors
-- ============================================================================

/-- Access config field via JamConfig typeclass. -/
abbrev cfg [j : JamConfig] : Params := j.config

end Jar
