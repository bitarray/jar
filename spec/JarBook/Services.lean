import VersoManual
import Jar.Services

open Verso.Genre Manual
open Jar.Services

set_option verso.docstring.allowMissing true

#doc (Manual) "Service Invocations" =>

Service entry points that the protocol invokes via the PVM (GP §11, Appendix B).

# Balance

{docstring Jar.Services.minimumBalance}

# Is-Authorized

The is-authorized invocation checks whether a work-package's authorization token
is accepted by the service's authorizer code.

{docstring Jar.Services.isAuthorized}

# Refinement

Refinement transforms a work item into a work result by running the service's
refine code in the PVM.

{docstring Jar.Services.refine}

# Work-Report Computation

Combines is-authorized and refinement to produce a complete work report
from a work package.

{docstring Jar.Services.computeWorkReport}

# On-Transfer

Invoked when a deferred transfer arrives at a service during accumulation.

{docstring Jar.Services.onTransfer}

# Auditing

{docstring Jar.Services.auditWorkReport}
