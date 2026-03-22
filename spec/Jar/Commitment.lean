import Jar.Commitment.Field
import Jar.Commitment.ReedSolomon
import Jar.Commitment.Merkle
import Jar.Commitment.Transcript
import Jar.Commitment.Utils
import Jar.Commitment.Encode
import Jar.Commitment.Sumcheck
import Jar.Commitment.DA
import Jar.Commitment.Proof
import Jar.Commitment.Prover
import Jar.Commitment.Verifier
import Jar.Commitment.Circuit
import Jar.Commitment.WitnessEncoding
import Jar.Commitment.WIProof
import Jar.Commitment.Threshold

/-!
# Polynomial Commitment — Ligerito + Accidental Computer

Commit to polynomials with compact proofs and efficient verification
over binary extension fields GF(2^32) / GF(2^128).

## Architecture

**Cryptographic stack** (layers 1–11):

1. **Field** — GF(2^32) and GF(2^128) arithmetic
2. **ReedSolomon** — Binary field FFT and RS encoding
3. **Merkle** — BLAKE3 complete binary Merkle tree
4. **Transcript** — Fiat-Shamir transcript
5. **Utils** — Lagrange/Kronecker basis, multilinear folding
6. **Encode** — Column-major matrix encoding pipeline
7. **Sumcheck** — Partial sumcheck with tensorized dot product
8. **DA** — Tensor ZODA: the "accidental computer" core
9. **Proof** — Proof data structures and configs
10. **Prover** — Ligerito prover + DA bridge
11. **Verifier** — Symmetric verification

**Circuit stack** (general-purpose WI proofs):

12. **Circuit** — Constraint system (AND, XOR, Eq, FieldMul, Boolean, Range)
13. **WitnessEncoding** — Witness → multilinear polynomial encoding
14. **WIProof** — Witness-indistinguishable proof system

**Threshold** (the light client story):

15. **Threshold** — Threshold signature verification via native sumcheck.
    No circuit needed — the accidental computer insight means sumcheck
    directly verifies popcount and boolean claims over the committed
    polynomial. Two sumcheck instances:
    - Sum claim: `Σ W(x) = count` (degree-1, proves popcount)
    - Bool claim: `Σ W(x)·(W(x)+1) = 0` (degree-2, proves all bits ∈ {0,1})

## Light client flow

```
Full node                              Light client
─────────                              ────────────
1. Collect validator signatures
2. DA-encode block (tensor ZODA)       Encoding IS the commitment.
3. proveThreshold via sumcheck    ───→ 4. Verify sum sumcheck
   (ZERO additional encoding cost)     5. Verify boolean sumcheck
                                       6. Check W(r) from opening
                                       7. Check count ≥ threshold
                                       8. Accept block ✓
```

## References

- Ligerito: https://angeris.github.io/papers/ligerito.pdf
- The Accidental Computer: https://angeris.github.io/papers/accidental-computer.pdf
- ZODA: https://eprint.iacr.org/2025/034.pdf
-/

namespace Jar.Commitment

-- Core types
export Field (GF32 GF128 gf32Add gf32Mul gf32Inv embedGF32)
export DA (EncodedBlock)
export Proof (LigeritoProof ProverConfig VerifierConfig mkProverConfig mkVerifierConfig)
export Prover (prove proveFromDABlock)
export Verifier (verify)

-- Circuit-based WI proofs (general purpose)
export Circuit (Circuit CircuitBuilder WireId Witness Constraint)
export WitnessEncoding (WitnessPolynomial ConstraintPolynomial LigeritoInstance)
export WIProof (WIProof proveCircuit verifyProof proveAndVerify)

-- Threshold (adder tree circuit, committed via DA for free)
export Threshold (ThresholdWires buildThresholdCircuit buildThresholdWitness
                  verifyThreshold checkThreshold proveThreshold
                  proveThresholdFromBlock verifyThresholdProof)

end Jar.Commitment
