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

/-- PVM heap management model. -/
inductive HeapModel where
  /-- GP v0.7.2: sbrk instruction (opcode 101). -/
  | sbrk
  /-- GP v0.8.0: grow_heap hostcall (hostcall 1). -/
  | growHeap
  deriving BEq, Inhabited

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
  /-- PVM heap management: sbrk instruction or grow_heap hostcall. -/
  heapModel : HeapModel := .sbrk
  /-- Hostcall numbering version: 0 = v0.7.2, 1 = v0.8.0 (+1 shift for grow_heap). -/
  hostcallVersion : Nat := 0

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
