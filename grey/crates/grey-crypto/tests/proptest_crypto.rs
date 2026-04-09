//! Property-based tests for cryptographic primitives.
//!
//! Tests fundamental properties: determinism, collision resistance (weak),
//! and Ed25519 sign-then-verify correctness.

use grey_crypto::{blake2b_256, ed25519, keccak_256};
use proptest::prelude::*;

/// Arbitrary message data (0-256 bytes).
fn arb_message() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=256)
}

/// Arbitrary 32-byte seed for Ed25519 key generation.
fn arb_seed() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

proptest! {
    // ========================================================================
    // Blake2b-256 properties
    // ========================================================================

    /// Hashing the same message twice produces the same result.
    #[test]
    fn blake2b_deterministic(msg in arb_message()) {
        let h1 = blake2b_256(&msg);
        let h2 = blake2b_256(&msg);
        prop_assert_eq!(h1, h2);
    }

    /// Different messages (that differ) produce different hashes.
    /// This is a weak collision-resistance check — not a proof, but
    /// a sanity check that the hash function isn't degenerate.
    #[test]
    fn blake2b_different_inputs_different_outputs(
        msg1 in arb_message(),
        msg2 in arb_message(),
    ) {
        prop_assume!(msg1 != msg2);
        let h1 = blake2b_256(&msg1);
        let h2 = blake2b_256(&msg2);
        prop_assert_ne!(h1, h2, "hash collision on different inputs");
    }

    /// Appending a byte changes the hash.
    #[test]
    fn blake2b_append_changes_hash(msg in arb_message()) {
        let h_original = blake2b_256(&msg);
        let mut extended = msg.clone();
        extended.push(0x00);
        let h_extended = blake2b_256(&extended);
        prop_assert_ne!(h_original, h_extended);
    }

    // ========================================================================
    // Keccak-256 properties
    // ========================================================================

    /// Hashing the same message twice produces the same result.
    #[test]
    fn keccak_deterministic(msg in arb_message()) {
        let h1 = keccak_256(&msg);
        let h2 = keccak_256(&msg);
        prop_assert_eq!(h1, h2);
    }

    /// Different messages produce different hashes.
    #[test]
    fn keccak_different_inputs_different_outputs(
        msg1 in arb_message(),
        msg2 in arb_message(),
    ) {
        prop_assume!(msg1 != msg2);
        let h1 = keccak_256(&msg1);
        let h2 = keccak_256(&msg2);
        prop_assert_ne!(h1, h2, "hash collision on different inputs");
    }

    /// Blake2b and Keccak produce different outputs for the same input
    /// (they are different hash functions).
    #[test]
    fn blake2b_and_keccak_differ(msg in arb_message()) {
        let h_blake = blake2b_256(&msg);
        let h_keccak = keccak_256(&msg);
        prop_assert_ne!(h_blake, h_keccak, "blake2b and keccak should differ");
    }

    // ========================================================================
    // Ed25519 properties
    // ========================================================================

    /// Sign then verify succeeds for the signing key's public key.
    #[test]
    fn ed25519_sign_verify_roundtrip(seed in arb_seed(), msg in arb_message()) {
        let keypair = ed25519::Ed25519Keypair::from_seed(&seed);
        let signature = keypair.sign(&msg);
        let public_key = keypair.public_key();
        prop_assert!(
            ed25519::ed25519_verify(&public_key, &msg, &signature),
            "valid signature should verify"
        );
    }

    /// Signature verification fails for a wrong message.
    #[test]
    fn ed25519_wrong_message_fails(
        seed in arb_seed(),
        msg in arb_message(),
        wrong_msg in arb_message(),
    ) {
        prop_assume!(msg != wrong_msg);
        let keypair = ed25519::Ed25519Keypair::from_seed(&seed);
        let signature = keypair.sign(&msg);
        let public_key = keypair.public_key();
        prop_assert!(
            !ed25519::ed25519_verify(&public_key, &wrong_msg, &signature),
            "signature should not verify with wrong message"
        );
    }

    /// Signature verification fails with a different key.
    #[test]
    fn ed25519_wrong_key_fails(
        seed1 in arb_seed(),
        seed2 in arb_seed(),
        msg in arb_message(),
    ) {
        prop_assume!(seed1 != seed2);
        let keypair1 = ed25519::Ed25519Keypair::from_seed(&seed1);
        let keypair2 = ed25519::Ed25519Keypair::from_seed(&seed2);
        let signature = keypair1.sign(&msg);
        let wrong_public_key = keypair2.public_key();
        prop_assert!(
            !ed25519::ed25519_verify(&wrong_public_key, &msg, &signature),
            "signature should not verify with wrong public key"
        );
    }

    /// Same seed produces same keypair (deterministic).
    #[test]
    fn ed25519_deterministic_keygen(seed in arb_seed()) {
        let kp1 = ed25519::Ed25519Keypair::from_seed(&seed);
        let kp2 = ed25519::Ed25519Keypair::from_seed(&seed);
        prop_assert_eq!(kp1.public_key(), kp2.public_key());
    }

    /// Different seeds produce different public keys.
    #[test]
    fn ed25519_different_seeds_different_keys(seed1 in arb_seed(), seed2 in arb_seed()) {
        prop_assume!(seed1 != seed2);
        let kp1 = ed25519::Ed25519Keypair::from_seed(&seed1);
        let kp2 = ed25519::Ed25519Keypair::from_seed(&seed2);
        prop_assert_ne!(
            kp1.public_key(),
            kp2.public_key(),
            "different seeds should produce different keys"
        );
    }

    /// Signing the same message with the same key is deterministic.
    #[test]
    fn ed25519_signing_deterministic(seed in arb_seed(), msg in arb_message()) {
        let keypair = ed25519::Ed25519Keypair::from_seed(&seed);
        let sig1 = keypair.sign(&msg);
        let sig2 = keypair.sign(&msg);
        prop_assert_eq!(sig1, sig2);
    }
}
