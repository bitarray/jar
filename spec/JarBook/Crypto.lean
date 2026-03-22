import VersoManual
import Jar.Crypto

open Verso.Genre Manual
open Jar.Crypto

set_option verso.docstring.allowMissing true

#doc (Manual) "Cryptographic Primitives" =>

Hash functions, signature schemes, and VRF operations used by JAM (GP §3.8, Appendix E).
All primitives are declared `opaque` — their correctness is axiomatic.

# Hash Functions

{docstring Jar.Crypto.blake2b}

{docstring Jar.Crypto.keccak256}

# Ed25519

{docstring Jar.Crypto.ed25519Verify}

{docstring Jar.Crypto.ed25519Sign}

# Bandersnatch

{docstring Jar.Crypto.bandersnatchVerify}

{docstring Jar.Crypto.bandersnatchSign}

{docstring Jar.Crypto.bandersnatchOutput}

# Bandersnatch Ring VRF

{docstring Jar.Crypto.bandersnatchRingRoot}

{docstring Jar.Crypto.bandersnatchRingVerify}

{docstring Jar.Crypto.bandersnatchRingSign}

{docstring Jar.Crypto.bandersnatchRingOutput}

# BLS12-381

{docstring Jar.Crypto.blsVerify}

{docstring Jar.Crypto.blsSign}

# Contexts

Signing contexts ensure domain separation between different protocol operations.

{docstring Jar.Crypto.ctxEntropy}

{docstring Jar.Crypto.ctxTicketSeal}

{docstring Jar.Crypto.ctxFallbackSeal}

{docstring Jar.Crypto.ctxGuarantee}

{docstring Jar.Crypto.ctxAvailable}

{docstring Jar.Crypto.ctxAnnounce}

{docstring Jar.Crypto.ctxAudit}

{docstring Jar.Crypto.ctxValid}

{docstring Jar.Crypto.ctxInvalid}

{docstring Jar.Crypto.ctxBeefy}

# Utility

{docstring Jar.Crypto.seqFromHash}

{docstring Jar.Crypto.shuffle}
