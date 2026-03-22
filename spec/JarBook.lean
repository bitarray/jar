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
import JarBook.Accumulation
import JarBook.Codec
import JarBook.Merkle
import JarBook.Erasure

open Verso.Genre Manual

set_option pp.rawOnError true

#doc (Manual) "JAR: JAM Axiomatic Reference" =>
%%%
authors := ["JAR Contributors"]
%%%

JAR (JAM Axiomatic Reference) is a Lean 4 formalization of the JAM blockchain
protocol as specified in the Gray Paper v0.7.2.

Each chapter corresponds to a section of the Gray Paper, presenting the
formal Lean definitions alongside explanatory prose.

{include 0 JarBook.Notation}

{include 0 JarBook.Numerics}

{include 0 JarBook.Constants}

{include 0 JarBook.Types}

{include 0 JarBook.Crypto}

{include 0 JarBook.Consensus}

{include 0 JarBook.State}

{include 0 JarBook.Services}

{include 0 JarBook.PVM}

{include 0 JarBook.Accumulation}

{include 0 JarBook.Codec}

{include 0 JarBook.Merkle}

{include 0 JarBook.Erasure}
