//! BLS12-381 key generation and signing for Beefy distribution (GP Section 18).
//!
//! Public keys are 144 bytes: G1 compressed (48 bytes) || G2 proof-of-possession (96 bytes).
//! Signatures are G2 points (96 bytes compressed).
//!
//! Uses the `blst` library with "minimal-pubkey-size" variant (pk in G1, sig in G2).

use blst::min_pk::{PublicKey, SecretKey, Signature};

/// Domain separation tag for BLS signing in JAM (Beefy commitments).
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Domain separation tag for proof-of-possession.
const DST_POP: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// A BLS12-381 keypair.
pub struct BlsKeypair {
    secret: SecretKey,
}

impl BlsKeypair {
    /// Derive a BLS keypair from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let secret = SecretKey::key_gen(seed, &[])
            .expect("key_gen should not fail with 32-byte seed");
        BlsKeypair { secret }
    }

    /// Get the 144-byte public key: G1 compressed (48) || G2 proof-of-possession (96).
    pub fn public_key_bytes(&self) -> [u8; 144] {
        let pk = self.secret.sk_to_pk();
        let pk_bytes = pk.compress();

        // Proof-of-possession: sign the public key bytes
        let pop = self.secret.sign(&pk_bytes, DST_POP, &[]);
        let pop_bytes = pop.compress();

        let mut result = [0u8; 144];
        result[..48].copy_from_slice(&pk_bytes);
        result[48..144].copy_from_slice(&pop_bytes);
        result
    }

    /// Sign a message, producing a 96-byte G2 signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 96] {
        let sig = self.secret.sign(message, DST, &[]);
        sig.compress()
    }
}

/// Verify a BLS signature against a 144-byte public key and message.
pub fn bls_verify(public_key: &[u8; 144], message: &[u8], signature: &[u8; 96]) -> bool {
    let pk = match PublicKey::uncompress(&public_key[..48]) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let sig = match Signature::uncompress(signature) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    let result = sig.verify(true, message, DST, &[], &pk, true);
    result == blst::BLST_ERROR::BLST_SUCCESS
}

/// Verify a proof-of-possession for a 144-byte public key.
pub fn bls_verify_pop(public_key: &[u8; 144]) -> bool {
    let pk_bytes = &public_key[..48];
    let pop_bytes = &public_key[48..144];

    let pk = match PublicKey::uncompress(pk_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let pop = match Signature::uncompress(pop_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    let result = pop.verify(true, pk_bytes, DST_POP, &[], &pk, true);
    result == blst::BLST_ERROR::BLST_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bls_keygen_and_sign() {
        let seed = [42u8; 32];
        let keypair = BlsKeypair::from_seed(&seed);
        let pk = keypair.public_key_bytes();

        // Verify proof-of-possession
        assert!(bls_verify_pop(&pk), "PoP should be valid");

        // Sign and verify a message
        let message = b"jam_beefy";
        let sig = keypair.sign(message);
        assert!(bls_verify(&pk, message, &sig), "signature should be valid");

        // Wrong message should fail
        assert!(!bls_verify(&pk, b"wrong", &sig), "wrong message should fail");
    }

    #[test]
    fn test_bls_deterministic() {
        let seed = [7u8; 32];
        let kp1 = BlsKeypair::from_seed(&seed);
        let kp2 = BlsKeypair::from_seed(&seed);
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }
}
