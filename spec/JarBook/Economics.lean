import VersoManual
import Jar.Types

open Verso.Genre Manual
open Jar

set_option verso.docstring.allowMissing true

#doc (Manual) "Economic Model" =>

jar1 uses a *coinless* economy. There are no tokens, no balance transfers, and no
storage rent. Instead, storage capacity is governed by quotas - a privileged
*quota service* (chi\_Q) sets per-service limits on storage items and bytes.

This is a fundamental departure from the Gray Paper's balance-based model (gp072
variants), where services must hold sufficient token balance to cover storage
deposit costs. In jar1, the quota service acts as a governance mechanism:
services that exceed their quota cannot write new storage items.

# The EconModel Typeclass

The protocol abstracts over economic models via the `EconModel` typeclass,
which defines operations for storage affordability checks, transfer handling,
service creation debits, and quota management.

{docstring EconModel}

# Quota-Based Economy (jar1)

{docstring QuotaEcon}

{docstring QuotaTransfer}

In the quota model, `canAffordStorage` checks whether the service's current item
count and byte count are within the quota limits. Transfers carry no token amount -
`QuotaTransfer` is a unit type for pure message-passing. The `setQuota` operation
(host call 28, available to the privileged quota service) adjusts a service's
storage limits.

This means jar1 removes the Gray Paper
