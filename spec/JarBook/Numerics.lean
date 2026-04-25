import VersoManual
import Jar.Types.Numerics

open Verso.Genre Manual

set_option verso.docstring.allowMissing true

#doc (Manual) "Numeric Types" =>

Domain-specific numeric types used throughout the protocol (GP §3.4).

These aliases are small, but they do important specification work. They make it
clear when a value is just an arbitrary machine integer and when it represents a
protocol quantity with its own range, unit, or validation rules.

# Resource Quantities

The resource-oriented numeric types describe fungible protocol quantities: value,
gas, and machine-sized register contents. In practice, these are the numbers
that move through execution, accounting, and metering.

{docstring Jar.Balance}

{docstring Jar.Gas}

{docstring Jar.SignedGas}

{docstring Jar.RegisterValue}

`Balance`, `Gas`, and `RegisterValue` all use 64-bit machine representations,
but they are not interchangeable at the specification level. The alias names
preserve intent: balances measure economic value, gas measures execution budget,
and register values represent raw machine words inside the execution model.

`SignedGas` is the odd one out because it carries signed arithmetic where the
execution rules need it. That makes the distinction between metering values and
plain unsigned counters explicit in the spec.

# Identifiers and Indices

The remaining numeric aliases identify protocol objects or position values inside
bounded sets. Some are fixed-width identifiers such as timeslots and service IDs;
others are configuration-dependent finite indices.

{docstring Jar.Timeslot}

{docstring Jar.ServiceId}

{docstring Jar.BlobLength}

{docstring Jar.CoreIndex}

{docstring Jar.ValidatorIndex}

{docstring Jar.EpochIndex}

{docstring Jar.TicketEntryIndex}

The fixed-width aliases (`Timeslot`, `ServiceId`, `BlobLength`) are simple
32-bit quantities chosen to match protocol structure. The index aliases are more
interesting because they are bounded by the active `JarConfig`: a `CoreIndex`
must fit within the configured core count, a `ValidatorIndex` must fit within
the validator set, and an `EpochIndex` must fit within the configured epoch
length.

This is why some of these types are modeled as `Fin ...` rather than plain
integers. The bound is carried in the type itself, so invalid indices are ruled
out earlier and more explicitly than they would be with unchecked numeric values.

`TicketEntryIndex` is intentionally looser: it is represented as a raw `Nat`,
with bound checks performed by validation logic rather than by the type itself.
