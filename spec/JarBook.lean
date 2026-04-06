import VersoManual
import Jar

import JarBook.Notation
import JarBook.Numerics
import JarBook.Constants
import JarBook.Types
import JarBook.Crypto
import JarBook.Consensus
import JarBook.State
import JarBook.Services
import JarBook.PVM
import JarBook.Capability
import JarBook.Accumulation
import JarBook.Codec
import JarBook.Merkle
import JarBook.Erasure

open Verso.Genre Manual

set_option pp.rawOnError true

#doc (Manual) "JAR: Join-Accumulate Refine" =>
%%%
authors := ["JAR Contributors"]
%%%

JAR is a blockchain protocol based on JAM (Join-Accumulate Machine). This document describes the `jar1` variant — the latest protocol version. The `jar1` variant extends the Gray Paper's PVM with a capability-based execution model (JAVM): Harvard architecture, multi-VM kernel with synchronous CALL/REPLY, and seL4-style capabilities for memory, code, and VM ownership. Earlier variants (`gp072_full`, `gp072_tiny`) use the Gray Paper's original flat-memory PVM model and are preserved for conformance testing but not documented here.

{include 0 JarBook.Notation}

{include 0 JarBook.Numerics}

{include 0 JarBook.Constants}

{include 0 JarBook.Types}

{include 0 JarBook.Crypto}

{include 0 JarBook.Consensus}

{include 0 JarBook.State}

{include 0 JarBook.Services}

{include 0 JarBook.PVM}

{include 0 JarBook.Capability}

{include 0 JarBook.Accumulation}

{include 0 JarBook.Codec}

{include 0 JarBook.Merkle}

{include 0 JarBook.Erasure}
