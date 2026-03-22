//! Ed25519 signature operations (Section 3.8).
//!
//! Provides signing and verification using Ed25519 keys.

use ed25519_dalek::{Signer, Verifier};
use grey_types::{Ed25519PublicKey, Ed25519Signature};

/// An Ed25519 signing keypair.
pub struct Ed25519Keypair(ed25519_dalek::SigningKey);

impl Ed25519Keypair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        Self(ed25519_dalek::SigningKey::generate(&mut rng))
    }

    /// Create a keypair from a 32-byte secret seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// Get the public key.
    pub fn public_key(&self) -> Ed25519PublicKey {
        let vk = self.0.verifying_key();
        Ed25519PublicKey(vk.to_bytes())
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let sig = self.0.sign(message);
        Ed25519Signature(sig.to_bytes())
    }
}

/// Verify an Ed25519 signature.
///
/// Returns `true` if the signature is valid for the given message and public key.
pub fn ed25519_verify(
    public_key: &Ed25519PublicKey,
    message: &[u8],
    signature: &Ed25519Signature,
) -> bool {
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&public_key.0) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
    vk.verify(message, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let keypair = Ed25519Keypair::generate();
        let message = b"jam protocol test message";
        let signature = keypair.sign(message);
        let public_key = keypair.public_key();

        assert!(ed25519_verify(&public_key, message, &signature));
    }

    #[test]
    fn test_verify_wrong_message() {
        let keypair = Ed25519Keypair::generate();
        let signature = keypair.sign(b"correct message");
        let public_key = keypair.public_key();

        assert!(!ed25519_verify(&public_key, b"wrong message", &signature));
    }

    #[test]
    fn test_verify_wrong_key() {
        let keypair1 = Ed25519Keypair::generate();
        let keypair2 = Ed25519Keypair::generate();
        let message = b"test message";
        let signature = keypair1.sign(message);

        assert!(!ed25519_verify(&keypair2.public_key(), message, &signature));
    }

    #[test]
    fn test_deterministic_from_seed() {
        let seed = [42u8; 32];
        let kp1 = Ed25519Keypair::from_seed(&seed);
        let kp2 = Ed25519Keypair::from_seed(&seed);
        assert_eq!(kp1.public_key(), kp2.public_key());

        let msg = b"deterministic";
        assert_eq!(kp1.sign(msg).0, kp2.sign(msg).0);
    }

    #[test]
    fn test_invalid_public_key() {
        // 0xff repeated is not a valid Ed25519 point (not on curve)
        let bad_key = Ed25519PublicKey([0xff; 32]);
        let sig = Ed25519Signature([0u8; 64]);
        assert!(!ed25519_verify(&bad_key, b"msg", &sig));
    }
}
