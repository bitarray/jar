import VersoManual
import Jar.Variant

open Verso.Genre Manual
open Jar

set_option verso.docstring.allowMissing true

#doc (Manual) "The jar1 Variant" =>

JAR defines multiple protocol variants via the `JarVariant` typeclass. This
document describes *jar1* — the latest variant, which extends the Gray Paper's
base protocol with a capability-based execution model (JAVM), a coinless
quota-based economy, variable validator sets, and single-pass gas metering.

Earlier variants (`gp072\_full`, `gp072\_tiny`) use the Gray Paper's original
flat-memory PVM model and balance-based token economy. They are preserved for
conformance testing but not documented here.

# Variant Configuration

Each variant is a `JarConfig` instance that selects protocol parameters,
memory model, gas model, economic types, and codec functions.

{docstring JarConfig}

The `JarVariant` class extends `JarConfig` with overridable JAVM execution
functions and codec implementations.

{docstring JarVariant}

# jar1 Settings

The jar1 variant uses these configuration choices:

- *Memory model*: capability-based (DATA caps manage physical pages with exclusive mapping)
- *Gas model*: basicBlockSinglePass (O(n) pipeline simulation per basic block)
- *Capability model*: v2 (multi-VM kernel, capability-based)
- *Blob encoding*: u32 LE count prefixes (not JAM compact natural encoding)
- *Variable validators*: enabled (GP\#514 — active core count scales with validator count)
- *Economic model*: QuotaEcon (coinless, quota-based storage limits)
- *Transfer payload*: QuotaTransfer (pure message-passing, no token amount)
- *Codec*: Codec.Jar1 namespace (u32 LE field encoding throughout)
