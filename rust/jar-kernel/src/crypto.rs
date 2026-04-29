//! Kernel-static crypto primitives.
//!
//! The kernel commits to a single curve + hash function at the protocol level
//! (Ed25519 + Blake2b-256 in v1; BLS pencilled in for later). These are
//! NOT pluggable per Hardware impl — every Hardware shares the same hash and
//! verify functions. Only `sign` and `holds_key` live on Hardware (they
//! require secret material).
//!
//! Userspace never sees these functions directly. Vault code that wants to
//! verify a signature uses `attest()` against an `AttestationCap`, which the
//! kernel routes through `verify` here. Vault code that wants to hash data
//! goes through a host call that calls `hash`.

use jar_types::{Block, Hash, KeyId, Signature};

/// Hash a byte string. Always blake2b-256 in v1.
pub fn hash(blob: &[u8]) -> Hash {
    jar_crypto::blake2b_256(blob)
}

/// Verify `sig` against `(key, msg)`. Returns false on any malformed input
/// (wrong key width, malformed signature, etc.). Curve is determined by the
/// key/sig widths — Ed25519 today; future BLS impl would dispatch internally.
pub fn verify(key: &KeyId, msg: &[u8], sig: &Signature) -> bool {
    jar_crypto::ed25519::verify(key, msg, sig)
}

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

fn encode_body(buf: &mut Vec<u8>, body: &jar_types::Body) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use jar_types::Block;

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(hash(b"abc"), hash(b"abc"));
        assert_ne!(hash(b"abc"), hash(b"abd"));
    }

    #[test]
    fn block_hash_is_deterministic() {
        let b1 = Block::default();
        let b2 = Block::default();
        assert_eq!(block_hash(&b1), block_hash(&b2));
    }
}
