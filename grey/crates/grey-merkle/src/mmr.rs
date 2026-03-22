//! Merkle Mountain Ranges and Belts (Appendix E.2).
//!
//! MMR is an append-only cryptographic data structure yielding a commitment
//! to a sequence of values.

use grey_types::Hash;

/// Merkle Mountain Range: a sequence of optional peaks.
///
/// Each peak is the root of a Merkle tree containing 2^i items
/// where i is the index in the sequence.
#[derive(Clone, Debug, Default)]
pub struct MerkleMountainRange {
    pub peaks: Vec<Option<Hash>>,
}

impl MerkleMountainRange {
    /// Create a new empty MMR.
    pub fn new() -> Self {
        Self { peaks: Vec::new() }
    }

    /// Append a leaf hash to the MMR (eq E.8).
    ///
    /// A(r, l, H) → ⟦H?⟧
    pub fn append(&mut self, leaf: Hash, hash_fn: fn(&[u8]) -> Hash) {
        self.append_at(leaf, 0, hash_fn);
    }

    fn append_at(&mut self, leaf: Hash, index: usize, hash_fn: fn(&[u8]) -> Hash) {
        // Ensure peaks vector is long enough
        while self.peaks.len() <= index {
            self.peaks.push(None);
        }

        match self.peaks[index] {
            None => {
                self.peaks[index] = Some(leaf);
            }
            Some(existing) => {
                // Combine with existing peak and promote
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&existing.0);
                combined.extend_from_slice(&leaf.0);
                let new_hash = hash_fn(&combined);
                self.peaks[index] = None;
                self.append_at(new_hash, index + 1, hash_fn);
            }
        }
    }

    /// Compute the super-peak (single commitment) MR (eq E.10).
    pub fn root(&self, hash_fn: fn(&[u8]) -> Hash) -> Hash {
        let non_empty: Vec<&Hash> = self.peaks.iter().filter_map(|p| p.as_ref()).collect();

        match non_empty.len() {
            0 => Hash::ZERO,
            1 => *non_empty[0],
            _ => {
                // Bag from right to left with $peak prefix
                let last = non_empty.len() - 1;
                let mut acc = *non_empty[last];
                for i in (0..last).rev() {
                    let mut input = Vec::new();
                    input.extend_from_slice(b"$peak");
                    input.extend_from_slice(&acc.0);
                    input.extend_from_slice(&non_empty[i].0);
                    acc = hash_fn(&input);
                }
                acc
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash(data: &[u8]) -> Hash {
        grey_crypto::blake2b_256(data)
    }

    #[test]
    fn test_mmr_empty() {
        let mmr = MerkleMountainRange::new();
        assert_eq!(mmr.root(test_hash), Hash::ZERO);
    }

    #[test]
    fn test_mmr_single() {
        let mut mmr = MerkleMountainRange::new();
        let leaf = Hash([1u8; 32]);
        mmr.append(leaf, test_hash);
        assert_eq!(mmr.root(test_hash), leaf);
    }

    #[test]
    fn test_mmr_two() {
        let mut mmr = MerkleMountainRange::new();
        mmr.append(Hash([1u8; 32]), test_hash);
        mmr.append(Hash([2u8; 32]), test_hash);
        // After two appends, peaks[0] should be None, peaks[1] should be Some
        assert!(mmr.peaks[0].is_none());
        assert!(mmr.peaks[1].is_some());
    }

    #[test]
    fn test_mmr_three() {
        let mut mmr = MerkleMountainRange::new();
        mmr.append(Hash([1u8; 32]), test_hash);
        mmr.append(Hash([2u8; 32]), test_hash);
        mmr.append(Hash([3u8; 32]), test_hash);
        // Three items: peaks[0] = Some, peaks[1] = Some
        assert!(mmr.peaks[0].is_some());
        assert!(mmr.peaks[1].is_some());
    }
}
