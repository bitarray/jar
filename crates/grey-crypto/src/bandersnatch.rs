//! Bandersnatch VRF and Ring VRF primitives (Appendix G of the Gray Paper).
//!
//! Provides:
//! - Keypair generation and VRF signing for block authoring
//! - Ring VRF proof verification for ticket proofs
//! - Ring commitment (γZ) computation from validator Bandersnatch keys
//! - VRF output extraction (ticket ID)

use ark_vrf::reexports::ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::suites::bandersnatch::{self as suite, *};

use std::sync::OnceLock;

type Suite = suite::BandersnatchSha512Ell2;

// ---------------------------------------------------------------------------
// Keypair generation and signing
// ---------------------------------------------------------------------------

/// A Bandersnatch keypair for block sealing and VRF signatures.
pub struct BandersnatchKeypair {
    secret: ark_vrf::Secret<Suite>,
}

impl BandersnatchKeypair {
    /// Generate a keypair from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let secret = ark_vrf::Secret::<Suite>::from_seed(seed);
        Self { secret }
    }

    /// Get the compressed 32-byte public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        let public = self.secret.public();
        let mut buf = Vec::new();
        public
            .0
            .serialize_compressed(&mut buf)
            .expect("public key serialization");
        let mut key = [0u8; 32];
        let len = buf.len().min(32);
        key[..len].copy_from_slice(&buf[..len]);
        key
    }

    /// Create a VRF signature (96 bytes) for entropy contribution (HV).
    ///
    /// Returns `[32-byte VRF output point | 64-byte proof]`.
    /// The first 32 bytes can be passed to `vrf_output_hash` for entropy extraction.
    pub fn vrf_sign(&self, input_data: &[u8], ad: &[u8]) -> [u8; 96] {
        use ark_vrf::ietf::Prover as IetfProver;

        let mut result = [0u8; 96];
        let Some(input) = ark_vrf::Input::<Suite>::new(input_data) else {
            return self.deterministic_vrf_bytes(input_data);
        };

        // Compute VRF output: γ = secret * H(input)
        let output = self.secret.output(input);
        // Generate IETF VRF proof
        let proof = self.secret.prove(input, output, ad);

        // Serialize output point (first 32 bytes)
        let mut out_buf = Vec::new();
        output.0.serialize_compressed(&mut out_buf).ok();
        let out_len = out_buf.len().min(32);
        result[..out_len].copy_from_slice(&out_buf[..out_len]);

        // Serialize proof (remaining 64 bytes)
        let mut proof_buf = Vec::new();
        proof.serialize_compressed(&mut proof_buf).ok();
        let proof_len = proof_buf.len().min(64);
        result[32..32 + proof_len].copy_from_slice(&proof_buf[..proof_len]);

        result
    }

    /// Create a seal signature (96 bytes) for the block seal (HS).
    pub fn seal_sign(&self, unsigned_header_hash: &[u8], ad: &[u8]) -> [u8; 96] {
        self.vrf_sign(unsigned_header_hash, ad)
    }

    /// Produce deterministic VRF-like bytes when VRF input construction fails.
    /// Uses the public key point as a valid curve point in the output.
    fn deterministic_vrf_bytes(&self, _data: &[u8]) -> [u8; 96] {
        let mut result = [0u8; 96];
        // Use the public key as a valid output point
        let pk = self.public_key_bytes();
        result[..32].copy_from_slice(&pk);
        result
    }
}

// ---------------------------------------------------------------------------
// SRS / Ring parameters
// ---------------------------------------------------------------------------

/// SRS file path (Zcash BLS12-381 Powers of Tau, 2^11 elements).
const SRS_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/data/bls12-381-srs-2-11-uncompressed-zcash.bin"
);

/// Lazily initialized PCS (KZG) parameters from the SRS file.
fn pcs_params() -> &'static PcsParams {
    static PCS: OnceLock<PcsParams> = OnceLock::new();
    PCS.get_or_init(|| {
        let buf = std::fs::read(SRS_FILE).expect("Failed to read SRS file");
        PcsParams::deserialize_uncompressed_unchecked(&mut &buf[..])
            .expect("Failed to deserialize SRS")
    })
}

/// Create ring proof params for a given ring size.
fn make_ring_params(ring_size: usize) -> RingProofParams {
    RingProofParams::from_pcs_params(ring_size, pcs_params().clone())
        .expect("Failed to create ring params")
}

/// Compute the ring commitment O([k_b | k ← keys]) from a list of
/// Bandersnatch public keys (eq G.4).
///
/// Returns the 144-byte serialized ring commitment (γZ).
pub fn compute_ring_commitment(bandersnatch_keys: &[[u8; 32]]) -> [u8; 144] {
    let params = make_ring_params(bandersnatch_keys.len());

    // Deserialize public keys to affine points, using padding point for invalid keys
    let points: Vec<AffinePoint> = bandersnatch_keys
        .iter()
        .map(|key_bytes| {
            AffinePoint::deserialize_compressed(&key_bytes[..])
                .unwrap_or(RingProofParams::padding_point())
        })
        .collect();

    // Compute verifier key from the ring of public keys
    let verifier_key = params.verifier_key(&points);

    // Extract the commitment and serialize it
    let commitment = verifier_key.commitment();
    let mut buf = Vec::new();
    commitment
        .serialize_compressed(&mut buf)
        .expect("commitment serialization failed");

    let mut result = [0u8; 144];
    result[..buf.len().min(144)].copy_from_slice(&buf[..buf.len().min(144)]);
    result
}

/// Verify a Ring VRF proof and extract the VRF output (ticket ID).
///
/// Parameters:
/// - `ring_size`: Number of validators in the ring
/// - `ring_commitment_bytes`: γZ (144 bytes) — the ring commitment
/// - `vrf_input_data`: The VRF input data (context string ++ entropy ++ attempt)
/// - `ad`: Additional authenticated data (empty for tickets)
/// - `signature`: The 784-byte signature (32-byte output + 752-byte proof)
///
/// Returns the 32-byte VRF output hash (ticket ID) on success, or None on failure.
pub fn ring_vrf_verify(
    ring_size: usize,
    ring_commitment_bytes: &[u8; 144],
    vrf_input_data: &[u8],
    ad: &[u8],
    signature: &[u8],
) -> Option<[u8; 32]> {
    use ark_vrf::ring::Verifier as _;

    if signature.len() < 33 {
        return None;
    }

    let params = make_ring_params(ring_size);

    // Deserialize ring commitment
    let commitment =
        RingCommitment::deserialize_compressed(&mut &ring_commitment_bytes[..]).ok()?;

    // Reconstruct verifier key from commitment
    let verifier_key = params.verifier_key_from_commitment(commitment);
    let verifier = params.verifier(verifier_key);

    // Parse the VRF output from the first 32 bytes
    let output_point = AffinePoint::deserialize_compressed(&mut &signature[..32]).ok()?;
    let output = ark_vrf::Output::<Suite>::from_affine(output_point);

    // Parse the proof from the remaining bytes
    let proof = RingProof::deserialize_compressed(&mut &signature[32..]).ok()?;

    // Construct VRF input from the data
    let input = ark_vrf::Input::<Suite>::new(vrf_input_data)?;

    // Extract VRF output hash before verify (which consumes output)
    let hash = output.hash();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash[..32]);

    // Verify the proof
    ark_vrf::Public::<Suite>::verify(input, output, ad, &proof, &verifier).ok()?;

    Some(result)
}

/// Extract the VRF output hash Y(s) from a Bandersnatch VRF signature.
///
/// The signature's first 32 bytes encode a compressed curve point (the VRF output).
/// Y(s) is the hash of that output point, used for entropy derivation (eq 6.22).
///
/// Returns the 32-byte hash, or None if the first 32 bytes are not a valid point.
pub fn vrf_output_hash(signature: &[u8]) -> Option<[u8; 32]> {
    if signature.len() < 32 {
        return None;
    }
    let output_point = AffinePoint::deserialize_compressed(&mut &signature[..32]).ok()?;
    let output = ark_vrf::Output::<Suite>::from_affine(output_point);
    let hash = output.hash();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash[..32]);
    Some(result)
}

/// Ticket VRF context string (Appendix I.4.5: X_T = $jam_ticket_seal).
pub const TICKET_SEAL_CONTEXT: &[u8] = b"jam_ticket_seal";

/// Verify a ticket Ring VRF proof and return the ticket ID.
///
/// Constructs the VRF input as: X_T ⌢ η₂ ⌢ E₁(attempt) (eq 6.29).
pub fn verify_ticket(
    ring_size: usize,
    ring_commitment: &[u8; 144],
    eta2: &[u8; 32],
    attempt: u8,
    proof: &[u8],
) -> Option<[u8; 32]> {
    let mut vrf_input = Vec::with_capacity(48);
    vrf_input.extend_from_slice(TICKET_SEAL_CONTEXT);
    vrf_input.extend_from_slice(eta2);
    vrf_input.push(attempt);
    ring_vrf_verify(ring_size, ring_commitment, &vrf_input, &[], proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        hex::decode(s.strip_prefix("0x").unwrap_or(s)).unwrap()
    }

    #[test]
    fn test_keypair_generation() {
        let seed = [42u8; 32];
        let kp = BandersnatchKeypair::from_seed(&seed);
        let pk = kp.public_key_bytes();
        assert_ne!(pk, [0u8; 32]);
        // Should be deterministic
        let kp2 = BandersnatchKeypair::from_seed(&seed);
        assert_eq!(pk, kp2.public_key_bytes());
    }

    #[test]
    fn test_keypair_different_seeds() {
        let kp1 = BandersnatchKeypair::from_seed(&[1u8; 32]);
        let kp2 = BandersnatchKeypair::from_seed(&[2u8; 32]);
        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn test_vrf_sign_produces_valid_output() {
        let kp = BandersnatchKeypair::from_seed(&[42u8; 32]);
        let sig = kp.vrf_sign(b"jam_entropy_test", b"");
        let output = vrf_output_hash(&sig);
        assert!(
            output.is_some(),
            "VRF signature should contain valid curve point"
        );
    }

    #[test]
    fn test_ring_commitment() {
        // gamma_k keys from test vector (gamma_z = O([k_b | k <- gamma_k]))
        let keys: Vec<[u8; 32]> = [
            "ff71c6c03ff88adb5ed52c9681de1629a54e702fc14729f6b50d2f0a76f185b3",
            "dee6d555b82024f1ccf8a1e37e60fa60fd40b1958c4bb3006af78647950e1b91",
            "9326edb21e5541717fde24ec085000b28709847b8aab1ac51f84e94b37ca1b66",
            "0746846d17469fb2f95ef365efcab9f4e22fa1feb53111c995376be8019981cc",
            "151e5c8fe2b9d8a606966a79edd2f9e5db47e83947ce368ccba53bf6ba20a40b",
            "2105650944fcd101621fd5bb3124c9fd191d114b7ad936c1d79d734f9f21392e",
        ]
        .iter()
        .map(|h| {
            let bytes = hex::decode(h).unwrap();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        })
        .collect();

        let commitment = compute_ring_commitment(&keys);
        let expected = hex_to_bytes("af39b7de5fcfb9fb8a46b1645310529ce7d08af7301d9758249da4724ec698eb127f489b58e49ae9ab85027509116962a135fc4d97b66fbbed1d3df88cd7bf5cc6e5d7391d261a4b552246648defcb64ad440d61d69ec61b5473506a48d58e1992e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf");
        let mut expected_arr = [0u8; 144];
        expected_arr.copy_from_slice(&expected);

        assert_eq!(
            commitment, expected_arr,
            "Ring commitment mismatch.\nGot:      {}\nExpected: {}",
            hex::encode(commitment),
            hex::encode(expected_arr)
        );
    }
}
