//! Transaction encoding for the simple-chain example.
//!
//! Wire layout (144 bytes):
//!   0..32   from pubkey (ed25519, 32 B)
//!   32..64  to pubkey   (32 B)
//!   64..72  amount      (u64 LE)
//!   72..80  nonce       (u64 LE — must equal sender's next nonce)
//!   80..144 signature   (ed25519, 64 B)
//!
//! Signing message: `from || to || amount_le || nonce_le` (80 bytes).

use jar_kernel::crypto::ed25519::KeyPair;
use jar_kernel::{KeyId, Signature};

/// Total wire length of one transaction.
pub const TXN_LEN: usize = 144;

/// Build a signed transaction blob.
pub fn sign_transfer(from_kp: &KeyPair, to: &KeyId, amount: u64, nonce: u64) -> Vec<u8> {
    assert_eq!(to.0.len(), 32, "to-pubkey must be 32 bytes");

    let from_key = from_kp.key_id();
    let mut msg = [0u8; 80];
    msg[0..32].copy_from_slice(&from_key.0);
    msg[32..64].copy_from_slice(&to.0);
    msg[64..72].copy_from_slice(&amount.to_le_bytes());
    msg[72..80].copy_from_slice(&nonce.to_le_bytes());

    let sig: Signature = from_kp.sign(&msg);

    let mut blob = vec![0u8; TXN_LEN];
    blob[0..32].copy_from_slice(&from_key.0);
    blob[32..64].copy_from_slice(&to.0);
    blob[64..72].copy_from_slice(&amount.to_le_bytes());
    blob[72..80].copy_from_slice(&nonce.to_le_bytes());
    assert_eq!(sig.0.len(), 64, "ed25519 sig must be 64 bytes");
    blob[80..144].copy_from_slice(&sig.0);
    blob
}

/// Decode a single account record (64 bytes) → (pubkey, balance, nonce).
pub fn decode_record(record: &[u8]) -> ([u8; 32], u64, u64) {
    assert_eq!(record.len(), 64);
    let mut key = [0u8; 32];
    key.copy_from_slice(&record[0..32]);
    let balance = u64::from_le_bytes(record[32..40].try_into().unwrap());
    let nonce = u64::from_le_bytes(record[40..48].try_into().unwrap());
    (key, balance, nonce)
}

/// Walk a 4 KiB account map and find the record for `pubkey`.
pub fn lookup(map: &[u8], pubkey: &KeyId) -> Option<(u64, u64)> {
    assert_eq!(pubkey.0.len(), 32);
    for off in (0..4096).step_by(64) {
        if map[off..off + 32] == pubkey.0[..] {
            let balance = u64::from_le_bytes(map[off + 32..off + 40].try_into().unwrap());
            let nonce = u64::from_le_bytes(map[off + 40..off + 48].try_into().unwrap());
            return Some((balance, nonce));
        }
    }
    None
}
