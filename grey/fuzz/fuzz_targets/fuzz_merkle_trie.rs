//! Fuzz target: random KV pairs into merkle_root and MMR operations.
//!
//! Verifies that computing Merkle trie roots and MMR appends from
//! arbitrary input never panics — only produces valid hashes.

#![no_main]

use grey_merkle::mmr::MerkleMountainRange;
use grey_merkle::trie::merkle_root;
use grey_types::Hash;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Split data into key-value pairs for the trie.
    // Each entry: 32 bytes key, 1 byte value_len, then value_len bytes value.
    let mut kvs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut pos = 0;

    while pos + 33 <= data.len() && kvs.len() < 64 {
        let key = data[pos..pos + 32].to_vec();
        let vlen = data[pos + 32] as usize;
        let vlen = vlen.min(data.len().saturating_sub(pos + 33));
        let value = data[pos + 33..pos + 33 + vlen].to_vec();
        kvs.push((key, value));
        pos += 33 + vlen;
    }

    // Deduplicate keys (merkle_root expects unique keys per the trie spec)
    let mut seen = std::collections::HashSet::new();
    let kvs: Vec<(Vec<u8>, Vec<u8>)> = kvs
        .into_iter()
        .filter(|(k, _)| seen.insert(k.clone()))
        .collect();

    // Fuzz: merkle_root should never panic
    let refs: Vec<(&[u8], &[u8])> = kvs.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect();
    let _root = merkle_root(&refs);

    // Fuzz: MMR append should never panic
    let mut mmr = MerkleMountainRange::new();
    for (i, (_k, _v)) in kvs.iter().enumerate() {
        // Use index-based deterministic hashes for MMR leaves
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&(i as u64).to_le_bytes());
        mmr.append(Hash(h), grey_crypto::blake2b_256);
    }
    let _mmr_root = mmr.root(grey_crypto::blake2b_256);
});
