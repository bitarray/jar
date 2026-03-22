import Jar.Notation
import Jar.Types.Numerics
import Jar.Codec

/-!
# Cryptographic Primitives — §3.8, Appendices F–G

- Blake2b-256 hash `ℋ` (§3.8.1)
- Keccak-256 hash `ℋ_K` (§3.8.1)
- Ed25519 signatures (§3.8.2)
- Bandersnatch VRF and RingVRF (§3.8.2, Appendix G)
- BLS12-381 signatures (§3.8.2)
- Fisher-Yates shuffle `F` (Appendix F)

References: `graypaper/text/notation.tex` §3.8,
            `graypaper/text/bandersnatch.tex`,
            `graypaper/text/utilities.tex`.
-/

namespace Jar.Crypto

-- ============================================================================
-- §3.8.1 — Hash Functions
-- ============================================================================

/-- ℋ(m) : Blake2b 256-bit hash. GP §3.8.1.
    blake2b : 𝔹 → ℍ. RFC 7693.
    Deliberately left abstract — intended to be axiomatically specified
    or linked via FFI to a concrete cryptographic implementation. -/
@[extern "jar_blake2b"]
opaque blake2b (m : ByteArray) : Hash := default

/-- ℋ_K(m) : Keccak 256-bit hash. GP §3.8.1.
    keccak256 : 𝔹 → ℍ. Bertoni et al. 2013, EYP.
    Deliberately left abstract — intended to be axiomatically specified
    or linked via FFI to a concrete cryptographic implementation. -/
@[extern "jar_keccak256"]
opaque keccak256 (m : ByteArray) : Hash := default

-- ============================================================================
-- §3.8.2 — Ed25519 Signatures (RFC 8032)
-- ============================================================================

/-- V̄_k⟨m⟩ : Ed25519 signature verification. GP §3.8.2.
    Returns true iff sig is a valid Ed25519 signature of message m
    under public key k.
    Deliberately left abstract — intended to be axiomatically specified
    or linked via FFI to a concrete cryptographic implementation. -/
@[extern "jar_ed25519_verify"]
opaque ed25519Verify
  (key : Ed25519PublicKey)
  (message : ByteArray)
  (sig : Ed25519Signature) : Bool := false

/-- V̄_k⟨m⟩ : Ed25519 signing (requires secret key knowledge). GP §3.8.2.
    sign_k(m) ∈ V̄_k⟨m⟩ ⊂ 𝔹_64.
    Deliberately left abstract — intended to be axiomatically specified
    or linked via FFI to a concrete cryptographic implementation. -/
@[extern "jar_ed25519_sign"]
opaque ed25519Sign
  (secretKey : ByteArray)
  (message : ByteArray) : Ed25519Signature := default

-- ============================================================================
-- §3.8.2 / Appendix G — Bandersnatch VRF
-- ============================================================================

/-- Ṽ_k^x⟨m⟩ : Bandersnatch signature verification. GP §3.8.2, Appendix G eq (G.1).
    Singly-contextualized Schnorr-like signature under IETF VRF template.
    verify(k, context, message, sig) = ⊤ iff valid.
    Deliberately left abstract — intended to be axiomatically specified
    or linked via FFI to a concrete cryptographic implementation. -/
@[extern "jar_bandersnatch_verify"]
opaque bandersnatchVerify
  (key : BandersnatchPublicKey)
  (context : ByteArray)
  (message : ByteArray)
  (sig : BandersnatchSignature) : Bool := false

/-- Ṽ_k^x⟨m⟩ : Bandersnatch signing (requires secret key). GP §3.8.2.
    Deliberately left abstract — intended to be axiomatically specified
    or linked via FFI to a concrete cryptographic implementation. -/
@[extern "jar_bandersnatch_sign"]
opaque bandersnatchSign
  (secretKey : ByteArray)
  (context : ByteArray)
  (message : ByteArray) : BandersnatchSignature := default

/-- Y(s) : VRF output extraction. GP Appendix G eq (G.2).
    Extracts the first 32 bytes of the VRF output from a signature.
    banderout(s) ∈ ℍ. Influenced by context but not by message.
    Deliberately left abstract — intended to be axiomatically specified
    or linked via FFI to a concrete cryptographic implementation. -/
@[extern "jar_bandersnatch_output"]
opaque bandersnatchOutput
  (sig : BandersnatchSignature) : Hash := default

-- ============================================================================
-- §3.8.2 / Appendix G — Bandersnatch Ring VRF
-- ============================================================================

/-- R(keys) : Ring root generation. GP Appendix G eq (G.3).
    getringroot(⟦B̃⟧) ∈ B° ⊂ 𝔹_144.
    Commits to a set of Bandersnatch public keys.
    Deliberately left abstract — intended to be axiomatically specified
    or linked via FFI to a concrete cryptographic implementation. -/
@[extern "jar_bandersnatch_ring_root"]
opaque bandersnatchRingRoot
  (keys : Array BandersnatchPublicKey) : BandersnatchRingRoot := default

/-- V°_r^x⟨m⟩ : Ring VRF proof verification. GP Appendix G eq (G.4).
    zk-SNARK-enabled anonymous proof of secret knowledge within a set.
    Deliberately left abstract — intended to be axiomatically specified
    or linked via FFI to a concrete cryptographic implementation. -/
/- NOTE: ringSize must match the number of keys used to compute root.
   For tiny config tests ringSize=6; for full JAM ringSize=V=1023. -/
@[extern "jar_bandersnatch_ring_verify"]
opaque bandersnatchRingVerify
  (root : BandersnatchRingRoot)
  (context : ByteArray)
  (message : ByteArray)
  (proof : BandersnatchRingVrfProof)
  (ringSize : UInt32) : Bool := false

/-- V°_r^x⟨m⟩ : Ring VRF proof generation (requires secret key).
    Deliberately left abstract — intended to be axiomatically specified
    or linked via FFI to a concrete cryptographic implementation. -/
/- NOTE: ringSize must match the number of keys used to compute root. -/
@[extern "jar_bandersnatch_ring_sign"]
opaque bandersnatchRingSign
  (secretKey : ByteArray)
  (root : BandersnatchRingRoot)
  (context : ByteArray)
  (message : ByteArray)
  (ringSize : UInt32) : BandersnatchRingVrfProof := default

/-- Y(p) : VRF output extraction from ring proof. GP Appendix G eq (G.5).
    banderout(p) ∈ ℍ. Same VRF output semantics as regular signatures.
    Deliberately left abstract — intended to be axiomatically specified
    or linked via FFI to a concrete cryptographic implementation. -/
@[extern "jar_bandersnatch_ring_output"]
opaque bandersnatchRingOutput
  (proof : BandersnatchRingVrfProof) : Hash := default

-- ============================================================================
-- §3.8.2 — BLS12-381 Signatures
-- ============================================================================

/-- BLS signature verification. GP §3.8.2.
    Used for Beefy finality commitments.
    Deliberately left abstract — intended to be axiomatically specified
    or linked via FFI to a concrete cryptographic implementation. -/
@[extern "jar_bls_verify"]
opaque blsVerify
  (key : BlsPublicKey)
  (message : ByteArray)
  (sig : BlsSignature) : Bool := false

/-- BLS signing (requires secret key). GP §3.8.2.
    Deliberately left abstract — intended to be axiomatically specified
    or linked via FFI to a concrete cryptographic implementation. -/
@[extern "jar_bls_sign"]
opaque blsSign
  (secretKey : ByteArray)
  (message : ByteArray) : BlsSignature := default

-- ============================================================================
-- Signing Contexts — GP §I.4.5 (definitions.tex)
-- ============================================================================

/- GP uses $-prefixed names (e.g. $jam_entropy) for context strings, but the
   $ is a naming convention in the spec — the actual byte strings do NOT include
   the $ character. This matches the grey Rust implementation. -/
/-- X_E : On-chain entropy generation. GP eq (6.27). -/
def ctxEntropy : ByteArray := "jam_entropy".toUTF8
/-- X_T : Ticket generation and regular block seal. GP eq (6.24). -/
def ctxTicketSeal : ByteArray := "jam_ticket_seal".toUTF8
/-- X_F : Fallback block seal. GP eq (6.25). -/
def ctxFallbackSeal : ByteArray := "jam_fallback_seal".toUTF8
/-- X_G : Guarantee statements. GP eq (11.31). -/
def ctxGuarantee : ByteArray := "jam_guarantee".toUTF8
/-- X_A : Availability assurances. GP eq (11.12). -/
def ctxAvailable : ByteArray := "jam_available".toUTF8
/-- X_N : Audit announcement statements. GP eq (17.7). -/
def ctxAnnounce : ByteArray := "jam_announce".toUTF8
/-- X_U : Audit selection entropy. GP eq (17.3). -/
def ctxAudit : ByteArray := "jam_audit".toUTF8
/-- X_V : Judgments for valid work-reports. GP eq (10.5). -/
def ctxValid : ByteArray := "jam_valid".toUTF8
/-- X_I : Judgments for invalid work-reports. GP eq (10.5). -/
def ctxInvalid : ByteArray := "jam_invalid".toUTF8
/-- X_B : Accumulate-result-root MMR commitment. GP eq (19.1). -/
def ctxBeefy : ByteArray := "jam_beefy".toUTF8

-- ============================================================================
-- Appendix F — Fisher-Yates Shuffle
-- ============================================================================

/-- Numeric-sequence-from-hash. GP Appendix F eq (F.2).
    seqFromHash(l, h) : ℍ → ⟦ℕ_{2^32}⟧_l
    Generates l pseudorandom 32-bit naturals from hash h using Blake2b. -/
def seqFromHash (l : Nat) (h : Hash) : Array Nat :=
  Array.ofFn (n := l) fun ⟨i, _⟩ =>
    -- blake2b(h ++ encode_4(⌊i/8⌋))[4*(i%8) .. +4]
    let blockIndex := i / 8
    let offset := 4 * (i % 8)
    let hashInput := h.data ++ Codec.encodeFixedNat 4 blockIndex
    let digest := blake2b hashInput
    -- Decode 4 LE bytes starting at offset
    let b0 := digest.data.data[offset]!.toNat
    let b1 := digest.data.data[offset + 1]!.toNat
    let b2 := digest.data.data[offset + 2]!.toNat
    let b3 := digest.data.data[offset + 3]!.toNat
    b0 + b1 * 256 + b2 * 65536 + b3 * 16777216

/-- Fisher-Yates shuffle with numeric randomness source. GP Appendix F eq (F.1).
    F(s, r) : ⟦T⟧_l × ⟦ℕ⟧_{l:} → ⟦T⟧_l
    Selection variant: pick element at random index j from working copy,
    place it in output[i], fill gap at j with last remaining element. -/
def fisherYatesShuffle [Inhabited α] (s : Array α) (r : Array Nat) : Array α := Id.run do
  let n := s.size
  let mut working := s
  let mut result : Array α := #[]
  for idx in [:n] do
    let remaining := n - idx
    let j := r[idx]! % remaining
    result := result.push working[j]!
    working := working.set! j working[remaining - 1]!
  return result

/-- Fisher-Yates shuffle with hash entropy. GP Appendix F eq (F.3).
    F(s, h) : ⟦T⟧_l × ℍ → ⟦T⟧_l -/
def shuffle [Inhabited α] (s : Array α) (h : Hash) : Array α :=
  fisherYatesShuffle s (seqFromHash s.size h)

end Jar.Crypto
