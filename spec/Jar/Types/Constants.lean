import Jar.Notation
import Jar.Types.Config

/-!
# Protocol Constants — Gray Paper Appendix I.4.4

Constants that are **identical across all protocol variants** (full, tiny, custom).
Variant-specific parameters (V, C, E, gas limits, etc.) are in `Config.lean`.

References: `graypaper/text/definitions.tex` lines 240–290,
            `graypaper/preamble.tex` lines 248–289.
-/

namespace Jar

-- ============================================================================
-- Timing
-- ============================================================================

/-- P : Slot period in seconds. GP: 𝖯 = 6. -/
def P : Nat := 6

-- ============================================================================
-- Auditing
-- ============================================================================

/-- A : Audit tranche period in seconds. GP: 𝖠 = 8. -/
def A_TRANCHE : Nat := 8

/-- F : Audit bias factor. GP: 𝖥 = 2. -/
def F_BIAS : Nat := 2

-- ============================================================================
-- Size limits
-- ============================================================================

/-- W_A : Max is-authorized code size. GP: 𝖶_A = 64,000. -/
def W_A : Nat := 64_000

/-- W_B : Max work-package blob size. GP: 𝖶_B = 13,791,360. -/
def W_B : Nat := 13_791_360

/-- W_C : Max service code size. GP: 𝖶_C = 4,000,000. -/
def W_C : Nat := 4_000_000

/-- W_E : Erasure coding piece size. GP: 𝖶_E = 684. -/
def W_E : Nat := 684

/-- W_G : Segment size. For full config: W_P × W_E = 6 × 684 = 4,104.
    Note: W_P is in Config since it differs between full (6) and tiny (1026). -/
def W_G [j : JarConfig] : Nat := j.config.W_P * W_E

/-- W_M : Max segment imports. GP: 𝖶_M = 3,072. -/
def W_M : Nat := 3_072

/-- W_R : Max work-report variable-size blob. GP: 𝖶_R = 49,152. -/
def W_R : Nat := 49_152

/-- W_T : Transfer memo size. GP: 𝖶_T = 128. -/
def W_T : Nat := 128

/-- W_X : Max segment exports. GP: 𝖶_X = 3,072. -/
def W_X : Nat := 3_072

-- ============================================================================
-- PVM configuration
-- ============================================================================

/-- Z_P : PVM page size. GP: 𝖹_P = 2^12 = 4,096. -/
def Z_P : Nat := 4096

/-- Z_Z : PVM initialization zone size. GP: 𝖹_Z = 2^16 = 65,536. -/
def Z_Z : Nat := 65536

/-- Z_I : PVM initialization input size. GP: 𝖹_I = 2^24 = 16,777,216. -/
def Z_I : Nat := 16_777_216

/-- Z_A : PVM dynamic address alignment. GP: 𝖹_A = 2. -/
def Z_A : Nat := 2

/-- Number of PVM registers. 13 in the GP. -/
def PVM_REGISTERS : Nat := 13

-- ============================================================================
-- Minimum public service index
-- ============================================================================

/-- S : Minimum public service index. GP: 𝖲 = 256. -/
def S_MIN : Nat := 256

-- ============================================================================
-- Time
-- ============================================================================

/-- JAM Common Era epoch: 1200 UTC on January 1, 2025.
    = 1,735,732,800 seconds after Unix Epoch. -/
def JAM_EPOCH_UNIX : Nat := 1_735_732_800

-- ============================================================================
-- Backward-compatibility aliases (access config via JarConfig)
-- ============================================================================

section ConfigAliases
variable [j : JarConfig]

/-- V via JarConfig. -/
abbrev V : Nat := j.config.V
/-- C via JarConfig. -/
abbrev C : Nat := j.config.C
/-- E via JarConfig. -/
abbrev E : Nat := j.config.E
/-- N_TICKETS via JarConfig. -/
abbrev N_TICKETS : Nat := j.config.N_TICKETS
/-- Y_TAIL via JarConfig. -/
abbrev Y_TAIL : Nat := j.config.Y_TAIL
/-- K_MAX_TICKETS via JarConfig. -/
abbrev K_MAX_TICKETS : Nat := j.config.K_MAX_TICKETS
/-- R_ROTATION via JarConfig. -/
abbrev R_ROTATION : Nat := j.config.R_ROTATION
/-- H_RECENT via JarConfig. -/
abbrev H_RECENT : Nat := j.config.H_RECENT
/-- G_A via JarConfig. -/
abbrev G_A : Nat := j.config.G_A
/-- G_I via JarConfig. -/
abbrev G_I : Nat := j.config.G_I
/-- G_R via JarConfig. -/
abbrev G_R : Nat := j.config.G_R
/-- G_T via JarConfig. -/
abbrev G_T : Nat := j.config.G_T
/-- O_POOL via JarConfig. -/
abbrev O_POOL : Nat := j.config.O_POOL
/-- Q_QUEUE via JarConfig. -/
abbrev Q_QUEUE : Nat := j.config.Q_QUEUE
/-- I_MAX_ITEMS via JarConfig. -/
abbrev I_MAX_ITEMS : Nat := j.config.I_MAX_ITEMS
/-- J_MAX_DEPS via JarConfig. -/
abbrev J_MAX_DEPS : Nat := j.config.J_MAX_DEPS
/-- T_MAX_EXTRINSICS via JarConfig. -/
abbrev T_MAX_EXTRINSICS : Nat := j.config.T_MAX_EXTRINSICS
/-- U_TIMEOUT via JarConfig. -/
abbrev U_TIMEOUT : Nat := j.config.U_TIMEOUT
/-- D_EXPUNGE via JarConfig. -/
abbrev D_EXPUNGE : Nat := j.config.D_EXPUNGE
/-- L_MAX_ANCHOR via JarConfig. -/
abbrev L_MAX_ANCHOR : Nat := j.config.L_MAX_ANCHOR
/-- B_I via JarConfig. -/
abbrev B_I : Nat := j.config.B_I
/-- B_L via JarConfig. -/
abbrev B_L : Nat := j.config.B_L
/-- B_S via JarConfig. -/
abbrev B_S : Nat := j.config.B_S
/-- W_P via JarConfig. -/
abbrev W_P : Nat := j.config.W_P

end ConfigAliases

-- ============================================================================
-- GP#514 — Variable Validator Set Helpers
-- ============================================================================

section VariableValidators
variable [j : JarConfig]

/-- Active core count: C for fixed validators, len(validators)/3 for variable.
    GP#514: only the first len(κ)/3 cores are active. -/
def activeCoreCount (validators : Array α) : Nat :=
  if j.variableValidators then validators.size / 3 else j.config.C

/-- Effective validator count: actual set size for variable, V for fixed. -/
def effectiveValCount (validators : Array α) : Nat :=
  if j.variableValidators then validators.size else j.config.V

/-- Dynamic N_TICKETS: ceil(2*E / len(pendingset')) for variable validators.
    More tickets per validator when fewer validators, to fill the accumulator.
    GP#514 §safrole. -/
def dynamicTicketsPerValidator (pendingValidatorCount : Nat) : Nat :=
  if j.variableValidators && pendingValidatorCount > 0
  then (2 * j.config.E + pendingValidatorCount - 1) / pendingValidatorCount
  else j.config.N_TICKETS

end VariableValidators

end Jar
