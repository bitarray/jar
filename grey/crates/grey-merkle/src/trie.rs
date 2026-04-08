//! Binary Patricia Merkle Trie (Appendix D.2).
//!
//! 64-byte nodes, either branches or leaves.
//! Branch: 1-bit discriminator + two child hashes (255 + 256 bits).
//! Leaf: embedded-value or regular (with value hash).

use grey_crypto::blake2b_256;
use grey_types::Hash;

/// A node in the binary Patricia Merkle Trie.
#[derive(Clone, Debug)]
pub enum TrieNode {
    /// Empty sub-trie, identified by H₀.
    Empty,

    /// Branch node: left and right child hashes.
    Branch { left: Hash, right: Hash },

    /// Leaf node with embedded value (≤ 32 bytes).
    EmbeddedLeaf { key: [u8; 31], value: Vec<u8> },

    /// Leaf node with hashed value (> 32 bytes).
    HashedLeaf { key: [u8; 31], value_hash: Hash },
}

impl TrieNode {
    /// Encode this node as 64 bytes (eq D.3-D.5).
    pub fn encode(&self) -> [u8; 64] {
        let mut node = [0u8; 64];
        match self {
            TrieNode::Empty => {} // All zeros = H₀

            TrieNode::Branch { left, right } => {
                // First bit = 0 (branch)
                // Remaining 255 bits of left, then 256 bits of right
                // left: bits 1..256 → bytes 0..31 (skipping first bit)
                // right: bits 256..512 → bytes 32..64
                node[0] = 0; // First bit = 0
                // Left child: use last 255 bits (skip MSB of first byte)
                node[0] |= left.0[0] & 0x7F; // 7 bits from left[0]
                node[1..32].copy_from_slice(&left.0[1..32]);
                node[32..64].copy_from_slice(&right.0);
            }

            TrieNode::EmbeddedLeaf { key, value } => {
                // Bits: 10xxxxxx where xxxxxx = value length (eq D.5)
                let len = value.len().min(32) as u8;
                node[0] = 0x80 | (len & 0x3F);
                node[1..32].copy_from_slice(key);
                node[32..32 + value.len().min(32)].copy_from_slice(&value[..value.len().min(32)]);
            }

            TrieNode::HashedLeaf { key, value_hash } => {
                // Bits: 11000000 (eq D.4)
                node[0] = 0xC0;
                node[1..32].copy_from_slice(key);
                node[32..64].copy_from_slice(&value_hash.0);
            }
        }
        node
    }

    /// Compute the hash (identity) of this node.
    pub fn hash(&self) -> Hash {
        match self {
            TrieNode::Empty => Hash::ZERO,
            _ => grey_crypto::blake2b_256(&self.encode()),
        }
    }
}

/// Extract bit `i` from a key (MSB-first within each byte).
fn bit(key: &[u8], i: usize) -> bool {
    (key[i >> 3] & (1 << (7 - (i & 7)))) != 0
}

/// Compute the Merkle root hash for a set of key-value pairs (eq D.6).
///
/// Keys are 32 bytes, values are arbitrary length byte slices.
pub fn merkle_root(kvs: &[(&[u8], &[u8])]) -> Hash {
    merkle_recursive(kvs, 0)
}

fn merkle_recursive(kvs: &[(&[u8], &[u8])], depth: usize) -> Hash {
    if kvs.is_empty() {
        return Hash::ZERO;
    }
    if kvs.len() == 1 {
        let (k, v) = kvs[0];
        let mut key31 = [0u8; 31];
        key31.copy_from_slice(&k[..31]);
        let node = if v.len() <= 32 {
            TrieNode::EmbeddedLeaf {
                key: key31,
                value: v.to_vec(),
            }
        } else {
            TrieNode::HashedLeaf {
                key: key31,
                value_hash: blake2b_256(v),
            }
        };
        return node.hash();
    }

    // Split by bit at current depth
    let mut left = Vec::new();
    let mut right = Vec::new();
    for &(k, v) in kvs {
        if bit(k, depth) {
            right.push((k, v));
        } else {
            left.push((k, v));
        }
    }

    let left_hash = merkle_recursive(&left, depth + 1);
    let right_hash = merkle_recursive(&right, depth + 1);

    let branch = TrieNode::Branch {
        left: left_hash,
        right: right_hash,
    };
    branch.hash()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_node_is_zero_hash() {
        assert_eq!(TrieNode::Empty.hash(), Hash::ZERO);
    }

    #[test]
    fn test_embedded_leaf_encoding() {
        let node = TrieNode::EmbeddedLeaf {
            key: [0xAB; 31],
            value: vec![1, 2, 3],
        };
        let encoded = node.encode();
        // First byte: 0x80 | 3 = 0x83
        assert_eq!(encoded[0], 0x83);
        assert_eq!(&encoded[1..32], &[0xAB; 31]);
        assert_eq!(&encoded[32..35], &[1, 2, 3]);
    }

    #[test]
    fn test_hashed_leaf_encoding() {
        let node = TrieNode::HashedLeaf {
            key: [0xCD; 31],
            value_hash: Hash([0xFF; 32]),
        };
        let encoded = node.encode();
        assert_eq!(encoded[0], 0xC0);
        assert_eq!(&encoded[1..32], &[0xCD; 31]);
        assert_eq!(&encoded[32..64], &[0xFF; 32]);
    }

    #[test]
    fn test_branch_encoding() {
        let node = TrieNode::Branch {
            left: Hash([0xFF; 32]),
            right: Hash([0xAA; 32]),
        };
        let encoded = node.encode();
        // First bit = 0 (branch), remaining 7 bits from left[0]
        assert_eq!(encoded[0], 0x7F); // MSB cleared (branch discriminator = 0)
        assert_eq!(&encoded[1..32], &[0xFF; 31]);
        assert_eq!(&encoded[32..64], &[0xAA; 32]);
    }

    #[test]
    fn test_branch_encoding_clears_msb() {
        // When left hash has MSB set, branch encoding must clear it
        let mut left_bytes = [0u8; 32];
        left_bytes[0] = 0x80; // only MSB set
        let node = TrieNode::Branch {
            left: Hash(left_bytes),
            right: Hash([0; 32]),
        };
        let encoded = node.encode();
        // MSB must be 0 (branch discriminator)
        assert_eq!(encoded[0] & 0x80, 0);
    }

    #[test]
    fn test_node_hash_empty_is_zero() {
        assert_eq!(TrieNode::Empty.hash(), Hash::ZERO);
        assert_eq!(TrieNode::Empty.encode(), [0u8; 64]);
    }

    #[test]
    fn test_node_hash_non_empty_is_blake2b() {
        let node = TrieNode::EmbeddedLeaf {
            key: [1; 31],
            value: vec![42],
        };
        let encoded = node.encode();
        assert_eq!(node.hash(), grey_crypto::blake2b_256(&encoded));
    }

    #[test]
    fn test_bit_extraction() {
        // 0x80 = 10000000 → bit 0 = true, bits 1-7 = false
        assert!(bit(&[0x80], 0));
        assert!(!bit(&[0x80], 1));
        // 0x01 = 00000001 → bit 7 = true, bits 0-6 = false
        assert!(bit(&[0x01], 7));
        assert!(!bit(&[0x01], 0));
        // Multi-byte: bit 8 is MSB of second byte
        assert!(bit(&[0x00, 0x80], 8));
        assert!(!bit(&[0x00, 0x80], 9));
    }

    #[test]
    fn test_merkle_root_empty() {
        assert_eq!(merkle_root(&[]), Hash::ZERO);
    }

    #[test]
    fn test_merkle_root_single_embedded() {
        let key = [0u8; 32];
        let value = [1u8, 2, 3];
        let root = merkle_root(&[(&key, &value)]);
        // Single embedded leaf
        let mut key31 = [0u8; 31];
        key31.copy_from_slice(&key[..31]);
        let expected = TrieNode::EmbeddedLeaf {
            key: key31,
            value: value.to_vec(),
        }
        .hash();
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_single_hashed() {
        let key = [0u8; 32];
        let value = [0xAA; 64]; // > 32 bytes → hashed leaf
        let root = merkle_root(&[(&key, &value)]);
        let mut key31 = [0u8; 31];
        key31.copy_from_slice(&key[..31]);
        let expected = TrieNode::HashedLeaf {
            key: key31,
            value_hash: grey_crypto::blake2b_256(&value),
        }
        .hash();
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_two_entries_deterministic() {
        let key1 = [0u8; 32]; // bit 0 = 0 → left
        let key2 = {
            let mut k = [0u8; 32];
            k[0] = 0x80; // bit 0 = 1 → right
            k
        };
        let root1 = merkle_root(&[(&key1, b"a"), (&key2, b"b")]);
        let root2 = merkle_root(&[(&key1, b"a"), (&key2, b"b")]);
        assert_eq!(root1, root2);
        assert_ne!(root1, Hash::ZERO);
    }

    #[test]
    fn test_merkle_root_order_independent() {
        // Trie structure depends on key bits, not insertion order
        let key1 = [0u8; 32];
        let key2 = {
            let mut k = [0u8; 32];
            k[0] = 0x80;
            k
        };
        let root_ab = merkle_root(&[(&key1, b"a"), (&key2, b"b")]);
        let root_ba = merkle_root(&[(&key2, b"b"), (&key1, b"a")]);
        assert_eq!(root_ab, root_ba);
    }

    #[test]
    fn test_trie_vectors() {
        use std::collections::BTreeMap;

        #[derive(serde::Deserialize)]
        struct TrieTestCase {
            input: BTreeMap<String, String>,
            output: String,
        }

        let data = include_str!("../../../../spec/tests/vectors/trie/trie.json");
        let cases: Vec<TrieTestCase> =
            serde_json::from_str(data).expect("failed to parse trie test vectors");

        for (i, case) in cases.iter().enumerate() {
            let kvs: Vec<(Vec<u8>, Vec<u8>)> = case
                .input
                .iter()
                .map(|(k, v)| {
                    (
                        hex::decode(k).unwrap_or_else(|e| panic!("case {i}: bad key hex: {e}")),
                        hex::decode(v).unwrap_or_else(|e| panic!("case {i}: bad value hex: {e}")),
                    )
                })
                .collect();

            let kvs_refs: Vec<(&[u8], &[u8])> = kvs
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                .collect();

            let root = merkle_root(&kvs_refs);
            let expected_hex = &case.output;
            let expected_bytes = hex::decode(expected_hex)
                .unwrap_or_else(|e| panic!("case {i}: bad output hex: {e}"));
            let mut expected = [0u8; 32];
            expected.copy_from_slice(&expected_bytes);

            assert_eq!(
                root,
                Hash(expected),
                "case {i}: trie root mismatch (num_keys={})",
                case.input.len()
            );
        }
    }
}
