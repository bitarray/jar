//! State Merklization, Merkle tries, and Merkle Mountain Ranges (Appendices D & E).
//!
//! Implements:
//! - Binary Patricia Merkle Trie with 64-byte nodes
//! - State key construction C
//! - State serialization T(σ)
//! - Well-balanced binary Merkle tree MB
//! - Constant-depth binary Merkle tree M
//! - Merkle Mountain Ranges and Belts

pub mod mmr;
pub mod state_serial;
pub mod trie;

use grey_types::Hash;
use grey_types::config::Config;
use grey_types::state::State;

/// Compute the state Merklization Mσ(σ) — compose T(σ) with merkle_root.
pub fn compute_state_root(state: &State, config: &Config) -> Hash {
    let kvs = state_serial::serialize_state(state, config);
    compute_state_root_from_kvs(&kvs)
}

/// Compute the state root from pre-serialized KV pairs.
pub fn compute_state_root_from_kvs(kvs: &[([u8; 31], Vec<u8>)]) -> Hash {
    let refs: Vec<(&[u8], &[u8])> = kvs
        .iter()
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect();
    trie::merkle_root(&refs)
}

/// GP node function N(v, H) (eq E.1) — returns raw bytes (blob or hash).
///
/// - |v| = 0: H_0 (32 zero bytes)
/// - |v| = 1: v_0 (raw blob, NOT hashed)
/// - |v| > 1: H("node" ⌢ N(left, H) ⌢ N(right, H))
///
/// Note: Reference implementations (Strawberry/Go) use "node" without '$' prefix.
fn merkle_node(leaves: &[&[u8]], hash_fn: fn(&[u8]) -> Hash) -> Vec<u8> {
    match leaves.len() {
        0 => vec![0u8; 32],
        1 => leaves[0].to_vec(),
        n => {
            let mid = n.div_ceil(2); // ceil(n/2)
            let left = merkle_node(&leaves[..mid], hash_fn);
            let right = merkle_node(&leaves[mid..], hash_fn);
            let mut input = Vec::with_capacity(4 + left.len() + right.len());
            input.extend_from_slice(b"node");
            input.extend_from_slice(&left);
            input.extend_from_slice(&right);
            hash_fn(&input).0.to_vec()
        }
    }
}

/// Compute the well-balanced binary Merkle tree root MB (eq E.1).
///
/// - |v| = 1: H(v_0) (hash the single item)
/// - otherwise: N(v, H)
///
/// MB: (⟦B⟧, B → H) → H
pub fn balanced_merkle_root(leaves: &[&[u8]], hash_fn: fn(&[u8]) -> Hash) -> Hash {
    if leaves.len() == 1 {
        return hash_fn(leaves[0]);
    }
    // For 0 or 2+ items, delegate to N
    let result = merkle_node(leaves, hash_fn);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Hash(hash)
}

/// Compute the constant-depth binary Merkle tree root M (eq E.4).
///
/// M(v, H) = N(C(v, H), H) where C is the constancy preprocessor:
/// - Hash each item with "leaf" prefix: H("leaf" ⌢ v_i)
/// - Pad to next power of 2 with zero hashes H_0
///
/// Used for segment-root (exports_root) computation.
pub fn constant_depth_merkle_root(leaves: &[&[u8]], hash_fn: fn(&[u8]) -> Hash) -> Hash {
    // Apply constancy preprocessor C
    let preprocessed = constancy_preprocess(leaves, hash_fn);
    let refs: Vec<&[u8]> = preprocessed.iter().map(|h| h.0.as_ref()).collect();
    // Apply N (merkle_node) and convert to Hash
    let result = merkle_node(&refs, hash_fn);
    let mut hash = [0u8; 32];
    let len = result.len().min(32);
    hash[..len].copy_from_slice(&result[..len]);
    Hash(hash)
}

/// Constancy preprocessor C (eq E.4):
/// Hashes each leaf with "leaf" prefix, pads to next power of 2 with H_0.
fn constancy_preprocess(leaves: &[&[u8]], hash_fn: fn(&[u8]) -> Hash) -> Vec<Hash> {
    if leaves.is_empty() {
        return vec![];
    }
    // Next power of 2
    let n = leaves.len().next_power_of_two();
    let mut result = Vec::with_capacity(n);
    // Hash each leaf with "leaf" prefix — reuse buffer across iterations
    let mut input = Vec::new();
    for leaf in leaves {
        input.clear();
        input.extend_from_slice(b"leaf");
        input.extend_from_slice(leaf);
        result.push(hash_fn(&input));
    }
    // Pad with zero hashes
    while result.len() < n {
        result.push(Hash::ZERO);
    }
    result
}

/// State-key constructor C (eq D.1).
///
/// Maps state component indices (and optionally service IDs) to 31-byte keys.
pub fn state_key_from_index(index: u8) -> [u8; 31] {
    let mut key = [0u8; 31];
    key[0] = index;
    key
}

/// State-key constructor C for service account components (eq D.1).
pub fn state_key_for_service(index: u8, service_id: u32) -> [u8; 31] {
    let mut key = [0u8; 31];
    let s = service_id.to_le_bytes();
    key[0] = index;
    key[1] = s[0];
    key[2] = 0;
    key[3] = s[1];
    key[4] = 0;
    key[5] = s[2];
    key[6] = 0;
    key[7] = s[3];
    key
}

/// Interleave service_id LE bytes with blake2b hash bytes into a 31-byte key (eq D.1).
///
/// Used by both `state_key_for_storage` and `state_serial::key_for_service_data`.
pub fn interleave_service_key(service_id: u32, a: &Hash) -> [u8; 31] {
    let s = service_id.to_le_bytes();
    let mut key = [0u8; 31];
    key[0] = s[0];
    key[1] = a.0[0];
    key[2] = s[1];
    key[3] = a.0[1];
    key[4] = s[2];
    key[5] = a.0[2];
    key[6] = s[3];
    key[7] = a.0[3];
    key[8..31].copy_from_slice(&a.0[4..27]);
    key
}

/// State-key constructor C for service storage items (eq D.1).
pub fn state_key_for_storage(service_id: u32, hash: &Hash) -> [u8; 31] {
    interleave_service_key(service_id, &grey_crypto::blake2b_256(&hash.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_key_from_index() {
        let key = state_key_from_index(6);
        assert_eq!(key[0], 6);
        assert!(key[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_balanced_merkle_root_single() {
        let leaf = b"hello";
        let root = balanced_merkle_root(&[leaf.as_ref()], grey_crypto::blake2b_256);
        assert_ne!(root, Hash::ZERO);
    }

    #[test]
    fn test_balanced_merkle_root_empty() {
        let root = balanced_merkle_root(&[], grey_crypto::blake2b_256);
        assert_eq!(root, Hash::ZERO);
    }

    #[test]
    fn test_constant_depth_merkle_root_empty() {
        // Empty tree: M([], H) = N(C([], H), H) = N([], H) = H_0
        let root = constant_depth_merkle_root(&[], grey_crypto::blake2b_256);
        assert_eq!(root, Hash::ZERO);
    }

    #[test]
    fn test_constant_depth_merkle_root_single() {
        // Single leaf: C preprocesses to [H("leaf" ⌢ v_0)]
        // N of single item = raw bytes (no hash)
        // So M = Hash from the preprocessed single leaf hash
        let leaf = b"segment_data";
        let root = constant_depth_merkle_root(&[leaf.as_ref()], grey_crypto::blake2b_256);

        // Expected: C([leaf]) = [H("leaf" ⌢ leaf)], padded to 1 (already power of 2)
        // N of single = raw bytes of that hash
        let expected = grey_crypto::blake2b_256(b"leafsegment_data");
        assert_eq!(root, expected);
    }

    #[test]
    fn test_constant_depth_merkle_root_two() {
        let a = b"seg_a";
        let b_data = b"seg_b";
        let root =
            constant_depth_merkle_root(&[a.as_ref(), b_data.as_ref()], grey_crypto::blake2b_256);

        // C([a,b]) = [H("leaf"⌢a), H("leaf"⌢b)] (already power of 2)
        // N of 2 items = H("node" ⌢ N([left]) ⌢ N([right]))
        // = H("node" ⌢ H("leaf"⌢a).bytes ⌢ H("leaf"⌢b).bytes)
        let ha = grey_crypto::blake2b_256(b"leafseg_a");
        let hb = grey_crypto::blake2b_256(b"leafseg_b");
        let mut input = Vec::new();
        input.extend_from_slice(b"node");
        input.extend_from_slice(&ha.0);
        input.extend_from_slice(&hb.0);
        let expected = grey_crypto::blake2b_256(&input);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_constant_depth_merkle_root_three_pads_to_four() {
        // 3 leaves → padded to 4 (next power of 2)
        let a = b"a";
        let b_data = b"b";
        let c = b"c";
        let root = constant_depth_merkle_root(
            &[a.as_ref(), b_data.as_ref(), c.as_ref()],
            grey_crypto::blake2b_256,
        );
        assert_ne!(root, Hash::ZERO);

        // Manually compute: C([a,b,c]) = [H("leaf"⌢a), H("leaf"⌢b), H("leaf"⌢c), H_0]
        // N splits 4 items: ceil(4/2)=2, left=[0..2], right=[2..4]
        let ha = grey_crypto::blake2b_256(b"leafa");
        let hb = grey_crypto::blake2b_256(b"leafb");
        let hc = grey_crypto::blake2b_256(b"leafc");
        let h0 = Hash::ZERO;

        // N([ha, hb]) = H("node" ⌢ ha.bytes ⌢ hb.bytes)
        let mut left_input = Vec::new();
        left_input.extend_from_slice(b"node");
        left_input.extend_from_slice(&ha.0);
        left_input.extend_from_slice(&hb.0);
        let left = grey_crypto::blake2b_256(&left_input);

        // N([hc, h0]) = H("node" ⌢ hc.bytes ⌢ h0.bytes)
        let mut right_input = Vec::new();
        right_input.extend_from_slice(b"node");
        right_input.extend_from_slice(&hc.0);
        right_input.extend_from_slice(&h0.0);
        let right = grey_crypto::blake2b_256(&right_input);

        // N([left_node, right_node]) = H("node" ⌢ left_hash ⌢ right_hash)
        let mut root_input = Vec::new();
        root_input.extend_from_slice(b"node");
        root_input.extend_from_slice(&left.0);
        root_input.extend_from_slice(&right.0);
        let expected = grey_crypto::blake2b_256(&root_input);
        assert_eq!(root, expected);
    }
}
