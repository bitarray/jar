/-!
# Protocol Configuration — Gray Paper Appendix I.4.4

Runtime-configurable protocol parameters supporting multiple variants
(full GP v0.7.2, tiny test config, custom variants).

Parameters that differ across variants live in `Config`. Parameters that
are identical across all known variants remain as global defs in `Constants.lean`.
-/

namespace Jar

-- ============================================================================
-- Protocol Configuration
-- ============================================================================

/-- Protocol configuration: parameters that differ across variants.
    Verified against `grey/crates/grey-types/src/config.rs`. -/
structure Config where
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
structure Config.Valid (cfg : Config) : Prop where
  hV : 0 < cfg.V
  hC : 0 < cfg.C
  hE : 0 < cfg.E
  hN : 0 < cfg.N_TICKETS

-- ============================================================================
-- JamConfig Typeclass
-- ============================================================================

/-- JamConfig: provides protocol configuration and validity proofs.
    Used by struct types and Fin-based index aliases.
    Extended by `JamVariant` (in `Jar/Variant.lean`) to add PVM function fields. -/
class JamConfig where
  config : Config
  valid : Config.Valid config

-- ============================================================================
-- Standard Configurations
-- ============================================================================

/-- Full specification constants (Gray Paper v0.7.2). -/
def Config.full : Config where
  V := 1023; C := 341; E := 600; N_TICKETS := 2
  Y_TAIL := 500; K_MAX_TICKETS := 16; R_ROTATION := 10; H_RECENT := 8
  G_A := 10_000_000; G_I := 50_000_000; G_R := 5_000_000_000; G_T := 3_500_000_000
  O_POOL := 8; Q_QUEUE := 80
  I_MAX_ITEMS := 16; J_MAX_DEPS := 8; T_MAX_EXTRINSICS := 128; U_TIMEOUT := 5
  D_EXPUNGE := 19_200; L_MAX_ANCHOR := 14_400
  B_I := 10; B_L := 1; B_S := 100
  W_P := 6

/-- Tiny test configuration.
    Verified against `grey/crates/grey-types/src/config.rs` Config::tiny(). -/
def Config.tiny : Config where
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

theorem Config.full_valid : Config.Valid Config.full where
  hV := by decide
  hC := by decide
  hE := by decide
  hN := by decide

theorem Config.tiny_valid : Config.Valid Config.tiny where
  hV := by decide
  hC := by decide
  hE := by decide
  hN := by decide

-- ============================================================================
-- Convenience Accessors
-- ============================================================================

/-- Access config field via JamConfig typeclass. -/
abbrev cfg [j : JamConfig] : Config := j.config

end Jar
