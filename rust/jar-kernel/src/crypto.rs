//! Kernel-static crypto.
//!
//! Two surfaces, both kernel-static (every Hardware shares the same impl):
//! - `blake2b_256` and the kernel-canonical `hash` — used for state-root,
//!   container hashes, code-cache keys.
//! - `ed25519` (`KeyPair`, `sign`, `verify`) for AttestationCap (Direct +
//!   Sealing scope). `AttestationAggregateCap` (BLS) is stubbed.
//!
//! Userspace never sees these functions directly. Vault code that wants to
//! verify a signature uses `attest()` against an `AttestationCap`, which
//! the kernel routes through `verify` here. Vault code that wants to hash
//! data goes through a host call.
//!
//! Block hashing (`block_hash`) lives here too: the kernel must be able to
//! canonically encode a block whenever a Sealing-scope AttestationCap
//! exercises against it.

#![forbid(unsafe_code)]

use crate::types::{Block, Hash, KeyId, Signature};
use blake2::digest::{Update, VariableOutput};

// -----------------------------------------------------------------------------
// Hashing
// -----------------------------------------------------------------------------

/// 32-byte Blake2b digest of `data`.
pub fn blake2b_256(data: &[u8]) -> Hash {
    let mut hasher = blake2::Blake2bVar::new(32).expect("32 ≤ Blake2b max output");
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).expect("32-byte buffer");
    Hash(out)
}

/// Kernel-canonical hash. Always blake2b-256 in v1.
pub fn hash(blob: &[u8]) -> Hash {
    blake2b_256(blob)
}

// -----------------------------------------------------------------------------
// Ed25519
// -----------------------------------------------------------------------------

/// Verify `sig` against `(key, msg)`. Returns false on any malformed input
/// (wrong key width, malformed signature, etc.). Curve is determined by
/// the key/sig widths — Ed25519 today; future BLS impl would dispatch
/// internally.
pub fn verify(key: &KeyId, msg: &[u8], sig: &Signature) -> bool {
    ed25519::verify(key, msg, sig)
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
        /// Generate a fresh keypair from OS randomness. Tests only —
        /// production keys come from outside the kernel.
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

// -----------------------------------------------------------------------------
// Block hashing
// -----------------------------------------------------------------------------

/// Canonical hash of a `Block`. Used by the chain's block-sealing
/// AttestationCap (Sealing scope) and by hardware to index blocks in its
/// fork tree / aux store.
///
/// Encoding: parent hash bytes followed by the body's canonical encoding.
/// Body encoding mirrors `state_root::state_root`'s shape — flat,
/// length-prefixed, BTreeMap-iterated. Stub-but-canonical.
pub fn block_hash(block: &Block) -> Hash {
    let mut buf = Vec::with_capacity(4096);
    buf.extend_from_slice(block.parent.as_ref());
    encode_body(&mut buf, &block.body);
    hash(&buf)
}

fn encode_body(buf: &mut Vec<u8>, body: &crate::types::Body) {
    push_u64(buf, body.events.len() as u64);
    for (vid, group) in &body.events {
        push_u64(buf, vid.0);
        push_u64(buf, group.len() as u64);
        for ev in group {
            push_bytes(buf, &ev.payload);
            push_bytes(buf, &ev.caps);
            push_u64(buf, ev.attestation_trace.len() as u64);
            for a in &ev.attestation_trace {
                push_bytes(buf, &a.key.0);
                buf.extend_from_slice(a.blob_hash.as_ref());
                push_bytes(buf, &a.signature.0);
            }
            push_u64(buf, ev.result_trace.len() as u64);
            for r in &ev.result_trace {
                push_bytes(buf, &r.blob);
            }
        }
    }
    push_u64(buf, body.attestation_trace.len() as u64);
    for a in &body.attestation_trace {
        push_bytes(buf, &a.key.0);
        buf.extend_from_slice(a.blob_hash.as_ref());
        push_bytes(buf, &a.signature.0);
    }
    push_u64(buf, body.result_trace.len() as u64);
    for r in &body.result_trace {
        push_bytes(buf, &r.blob);
    }
    push_u64(buf, body.reach_trace.len() as u64);
    for re in &body.reach_trace {
        push_u64(buf, re.entrypoint.0);
        push_u64(buf, re.event_idx as u64);
        push_u64(buf, re.vaults.len() as u64);
        for v in &re.vaults {
            push_u64(buf, v.0);
        }
    }
    push_u64(buf, body.merkle_traces.len() as u64);
    for mp in &body.merkle_traces {
        push_u64(buf, mp.vault.0);
        push_bytes(buf, &mp.key);
        push_bytes(buf, &mp.value);
        push_bytes(buf, &mp.proof);
    }
}

fn push_u64(buf: &mut Vec<u8>, x: u64) {
    buf.extend_from_slice(&x.to_le_bytes());
}

fn push_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    push_u64(buf, b.len() as u64);
    buf.extend_from_slice(b);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Block;

    #[test]
    fn blake2_is_deterministic() {
        assert_eq!(blake2b_256(b"abc"), blake2b_256(b"abc"));
        assert_ne!(blake2b_256(b"abc"), blake2b_256(b"abd"));
    }

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(hash(b"abc"), hash(b"abc"));
        assert_ne!(hash(b"abc"), hash(b"abd"));
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

    #[test]
    fn block_hash_is_deterministic() {
        let b1 = Block::default();
        let b2 = Block::default();
        assert_eq!(block_hash(&b1), block_hash(&b2));
    }
}
