import VersoManual
import Jar.Types

open Verso.Genre Manual

set_option verso.docstring.allowMissing true

#doc (Manual) "Type Definitions" =>

Core type definitions for the JAM protocol, mapping Gray Paper structures
to Lean 4 (GP §4, §6–§12).

# Validator Types (§6)

{docstring Jar.ValidatorKey}

{docstring Jar.Ticket}

{docstring Jar.SealKeySeries}

{docstring Jar.SafroleState}

{docstring Jar.Entropy}

# Service Account Types (§8)

{docstring Jar.ServiceAccount}

{docstring Jar.PrivilegedServices}

{docstring Jar.DeferredTransfer}

# Work Types (§11)

{docstring Jar.WorkError}

{docstring Jar.WorkResult}

{docstring Jar.WorkDigest}

{docstring Jar.AvailabilitySpec}

{docstring Jar.RefinementContext}

{docstring Jar.WorkReport}

{docstring Jar.PendingReport}

{docstring Jar.WorkItem}

{docstring Jar.WorkPackage}

# Block Header Types (§5)

{docstring Jar.EpochMarker}

{docstring Jar.Header}

# Extrinsic Types (§7–§10)

{docstring Jar.Judgment}

{docstring Jar.Verdict}

{docstring Jar.Culprit}

{docstring Jar.Fault}

{docstring Jar.DisputesExtrinsic}

{docstring Jar.TicketProof}

{docstring Jar.Guarantee}

{docstring Jar.Assurance}

{docstring Jar.Extrinsic}

{docstring Jar.Block}

# State Types (§4)

{docstring Jar.JudgmentsState}

{docstring Jar.RecentBlockInfo}

{docstring Jar.RecentHistory}

{docstring Jar.ValidatorRecord}

{docstring Jar.CoreStatistics}

{docstring Jar.ServiceStatistics}

{docstring Jar.ActivityStatistics}

{docstring Jar.State}
