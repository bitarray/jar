import VersoManual
import Jar.Erasure

open Verso.Genre Manual
open Jar.Erasure

set_option verso.docstring.allowMissing true

#doc (Manual) "Erasure Coding" =>

Reed-Solomon erasure coding over GF(2^16) for data availability (GP Appendix H).
Ensures that any 342 of 1023 chunks suffice to reconstruct the original data.

# Galois Field GF(2^16)

{docstring Jar.Erasure.GF16}

{docstring Jar.Erasure.CANTOR_BASIS}

GF(2^16) arithmetic uses log/exp tables built from the Cantor basis.
Multiplication operates via log/exp table lookups; inversion uses
Fermat's little theorem (a^{-1} = a^{65534}).

{docstring Jar.Erasure.gfMul}

{docstring Jar.Erasure.gfInv}

# Fast Fourier Transform

The core of the erasure coding is an additive FFT over GF(2^16), following
the Cantor basis construction. The FFT transforms data symbols into
evaluation points; the IFFT inverts the transform for recovery.

{docstring Jar.Erasure.fft}

{docstring Jar.Erasure.ifft}

# Encoding and Recovery

{docstring Jar.Erasure.dataShards}

{docstring Jar.Erasure.recoveryShards}

{docstring Jar.Erasure.erasureCode}

{docstring Jar.Erasure.erasureRecover}

# Segment Operations

{docstring Jar.Erasure.split}

{docstring Jar.Erasure.join}

{docstring Jar.Erasure.erasureCodeSegment}

{docstring Jar.Erasure.recoverSegment}
