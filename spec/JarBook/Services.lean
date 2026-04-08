import VersoManual
import Jar.Services

open Verso.Genre Manual
open Jar.Services

set_option verso.docstring.allowMissing true

#doc (Manual) "Service Invocations" =>

Service entry points that the protocol invokes via the JAVM (GP §11, Appendix B).

In jar1, service code runs inside the capability kernel. Protocol capabilities
(GAS, FETCH, STORAGE\_R, etc.) replace direct host-call numbers — the kernel
dispatches `ecalli` to the appropriate protocol cap, which exits to the host.
REPLY returns results to the calling VM rather than writing to a halt address.
See the *Capability Kernel* chapter for the execution model.

# Storage Affordability

{docstring Jar.Services.canAffordStorage}

# Is-Authorized

The is-authorized invocation checks whether a work-package's authorization token
is accepted by the service's authorizer code.

{docstring Jar.Services.isAuthorized}

# Refinement

Refinement transforms a work item into a work result by running the service's
refine code in the JAVM.

{docstring Jar.Services.refine}

# Work-Report Computation

Combines is-authorized and refinement to produce a complete work report
from a work package.

{docstring Jar.Services.computeWorkReport}

# On-Transfer

Invoked when a deferred transfer arrives at a service during accumulation.

{docstring Jar.Services.onTransfer}

