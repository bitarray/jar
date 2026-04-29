//! Cryptographic primitives for jar-kernel.
//!
//! Two surfaces:
//! - `blake2b_256` — used for state-root hashing, container hashes, code-cache keys.
//! - `ed25519` — `KeyPair`, `sign`, `verify` for AttestationCap (Direct + Sealing).
//!
//! These are leaf primitives. The kernel-static facade lives in
//! `jar_kernel::crypto`; userspace never sees the bytes typed.
//!
//! BLS aggregate is stubbed; `AttestationAggregateCap` returns `false`.

#![forbid(unsafe_code)]

use blake2::digest::{Update, VariableOutput};
use jar_types::{Hash, KeyId, Signature};

/// 32-byte Blake2b digest of `data`.
pub fn blake2b_256(data: &[u8]) -> Hash {
    let mut hasher = blake2::Blake2bVar::new(32).expect("32 ≤ Blake2b max output");
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).expect("32-byte buffer");
    Hash(out)
}

/// Ed25519 key + signature operations.
pub mod ed25519 {
    use super::*;
    use ed25519_dalek::{Signature as DalekSig, Signer, SigningKey, Verifier, VerifyingKey};
    use rand::rngs::OsRng;

    /// A key pair holding the secret key. Used by nodes that hold validator
    /// keys; the `KeyId` derived from the verifying key is the public name.
    #[derive(Clone)]
    pub struct KeyPair {
        signing: SigningKey,
    }

    impl KeyPair {
        /// Generate a fresh keypair from OS randomness. Tests only — production
        /// keys come from outside the kernel.
        pub fn generate() -> Self {
            let mut csprng = OsRng;
            let signing = SigningKey::generate(&mut csprng);
            KeyPair { signing }
        }

        /// Build a keypair from a 32-byte secret seed.
        pub fn from_seed(seed: &[u8; 32]) -> Self {
            KeyPair {
                signing: SigningKey::from_bytes(seed),
            }
        }

        /// Public KeyId is the 32-byte ed25519 verifying-key bytes.
        pub fn key_id(&self) -> KeyId {
            KeyId(self.signing.verifying_key().to_bytes().to_vec())
        }

        pub fn sign(&self, msg: &[u8]) -> Signature {
            let sig: DalekSig = self.signing.sign(msg);
            Signature(sig.to_bytes().to_vec())
        }
    }

    /// Verify a signature against the verifying-key bytes embedded in `key`.
    /// Returns false on any decode failure (wrong key width, malformed sig).
    pub fn verify(key: &KeyId, msg: &[u8], sig: &Signature) -> bool {
        let key_bytes: &[u8; 32] = match key.0.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let Ok(vk) = VerifyingKey::from_bytes(key_bytes) else {
            return false;
        };
        let dalek = match DalekSig::try_from(sig.0.as_slice()) {
            Ok(s) => s,
            Err(_) => return false,
        };
        vk.verify(msg, &dalek).is_ok()
    }
}

/// BLS / threshold aggregate. Stubbed — returns `false` until BLS lands.
pub fn aggregate_verify(_key: &KeyId, _msg: &[u8]) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake2_is_deterministic() {
        assert_eq!(blake2b_256(b"abc"), blake2b_256(b"abc"));
        assert_ne!(blake2b_256(b"abc"), blake2b_256(b"abd"));
    }

    #[test]
    fn ed25519_roundtrip() {
        let kp = ed25519::KeyPair::from_seed(&[42u8; 32]);
        let key = kp.key_id();
        let msg = b"hello";
        let sig = kp.sign(msg);
        assert!(ed25519::verify(&key, msg, &sig));
        assert!(!ed25519::verify(&key, b"goodbye", &sig));
    }
}
