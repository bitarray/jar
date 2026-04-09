import VersoManual
import Jar.State

open Verso.Genre Manual

set_option verso.docstring.allowMissing true

#doc (Manual) "State Transition" =>

The block-level state transition function `Υ(σ, B) = σ'` (GP eq 4.1).

# Timekeeping

{docstring Jar.newTimeslot}

{docstring Jar.epochIndex}

{docstring Jar.epochSlot}

{docstring Jar.isEpochChange}

# Header Validation (§5)

{docstring Jar.validateHeader}

{docstring Jar.validateHeaderNoSeal}

{docstring Jar.validateAuthor}

{docstring Jar.validateEpochMarkerContents}

{docstring Jar.validateExtrinsic}

{docstring Jar.validatePreimages}

{docstring Jar.validateAssuranceOrder}

{docstring Jar.validateAssuranceIndices}

{docstring Jar.validateAssuranceAnchors}

{docstring Jar.validateAssuranceSignatures}

{docstring Jar.validateGuaranteeIndices}

{docstring Jar.validateGuaranteeTimeslots}

{docstring Jar.validateGuaranteeSignatures}

# Recent History (§4.2)

{docstring Jar.updateParentStateRoot}

{docstring Jar.computeAccumulateRoot}

{docstring Jar.collectReportedPackages}

{docstring Jar.updateRecentHistory}

# Entropy (§6.3)

{docstring Jar.updateEntropy}

# Validator Management (§6)

{docstring Jar.updateActiveValidators}

{docstring Jar.updatePreviousValidators}

# Work-Report Pipeline and Disputes

Judgment processing, report availability, and guarantee integration are covered
in the *Work-Report Pipeline* chapter. The key functions — `updateJudgments`,
`reportsPostJudgment`, `reportsPostAssurance`, `reportsPostGuarantees`, and
`filterOffenders` — are documented there.

# Authorization Pool

{docstring Jar.updateAuthPool}

# Accumulation (§12)

{docstring Jar.AccumulationResult}

{docstring Jar.performAccumulation}

# Preimages (§12.7)

{docstring Jar.integratePreimages}

# Statistics (§13)

{docstring Jar.ValidatorRecord.zero}

{docstring Jar.CoreStatistics.zero}

{docstring Jar.updateStatistics}

# State Transition

{docstring Jar.stateTransition}

{docstring Jar.stateTransitionWithOpaque}

{docstring Jar.stateTransitionNoSealCheck}
