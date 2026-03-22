import VersoManual
import Jar.Notation

open Verso.Genre Manual

set_option verso.docstring.allowMissing true

#doc (Manual) "Notation and Conventions" =>

The Gray Paper defines a rich mathematical notation for specifying the JAM protocol.
JAR maps these to Lean 4 types as closely as possible (GP §3).

# Optional Substitution

{docstring substituteIfNone}

# Exceptional Values

{docstring Exceptional}

# Dictionaries

The Gray Paper's partial-function / dictionary type `D⟨K, V⟩` is modeled as an
association list.

{docstring Dict}

{docstring Dict.empty}

{docstring Dict.lookup}

{docstring Dict.insert}

{docstring Dict.erase}

{docstring Dict.size}

{docstring Dict.keys}

{docstring Dict.values}

{docstring Dict.subtract}

{docstring Dict.union}

# Sequences

{docstring Array.cyclicGet}

{docstring Array.lastN}

# Octet Sequences

Fixed-length byte strings `Y_n` are modeled as a `ByteArray` bundled with a size proof.

{docstring OctetSeq}

The 256-bit hash type `H` is `OctetSeq 32`.

{docstring Hash}

{docstring Hash.zero}

# Cryptographic Key Types

{docstring Ed25519PublicKey}

{docstring BandersnatchPublicKey}

{docstring BlsPublicKey}

{docstring BandersnatchRingRoot}

# Signature Types

{docstring Ed25519Signature}

{docstring BandersnatchSignature}

{docstring BandersnatchRingVrfProof}

{docstring BlsSignature}
