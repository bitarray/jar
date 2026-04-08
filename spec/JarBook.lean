import VersoManual
import Jar

import JarBook.Variant
import JarBook.Notation
import JarBook.Numerics
import JarBook.Constants
import JarBook.Crypto
import JarBook.Types
import JarBook.Economics
import JarBook.Consensus
import JarBook.JAVM
import JarBook.Capability
import JarBook.Kernel
import JarBook.Services
import JarBook.Pipeline
import JarBook.Accumulation
import JarBook.State
import JarBook.Codec
import JarBook.Merkle
import JarBook.Erasure

open Verso.Genre Manual

set_option pp.rawOnError true

#doc (Manual) "JAR: Join-Accumulate Refine" =>
%%%
authors := ["JAR Contributors"]
%%%

JAR is a blockchain protocol based on JAM (Join-Accumulate Machine). This document describes the `jar1` variant — the latest protocol version. The `jar1` variant extends the Gray Paper's PVM with a capability-based execution model (JAVM): multi-VM kernel with synchronous CALL/REPLY and seL4-style capabilities for memory, code, and VM ownership. It also replaces the token-based economy with a coinless quota system. Earlier variants (`gp072\_full`, `gp072\_tiny`) are preserved for conformance testing but not documented here.

{include 0 JarBook.Variant}

{include 0 JarBook.Notation}

{include 0 JarBook.Numerics}

{include 0 JarBook.Constants}

{include 0 JarBook.Crypto}

{include 0 JarBook.Types}

{include 0 JarBook.Economics}

{include 0 JarBook.Consensus}

{include 0 JarBook.JAVM}

{include 0 JarBook.Capability}

{include 0 JarBook.Kernel}

{include 0 JarBook.Services}

{include 0 JarBook.Pipeline}

{include 0 JarBook.Accumulation}

{include 0 JarBook.State}

{include 0 JarBook.Codec}

{include 0 JarBook.Merkle}

{include 0 JarBook.Erasure}
