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
                // MR(h) = H_K("peak" || MR(h[..n-1]) || h[n-1]) (eq E.10)
                mr_recursive(&non_empty, hash_fn)
            }
        }
    }
}

/// Recursive super-peak computation matching the spec (eq E.10).
///
/// MR([]) = H_0, MR([h]) = h, MR(h) = H_K("peak" || MR(h[..n-1]) || h[n-1])
fn mr_recursive(peaks: &[&Hash], hash_fn: fn(&[u8]) -> Hash) -> Hash {
    match peaks.len() {
        0 => Hash::ZERO,
        1 => *peaks[0],
        n => {
            let last = *peaks[n - 1];
            let rest = mr_recursive(&peaks[..n - 1], hash_fn);
            let mut data = Vec::with_capacity(4 + 32 + 32);
            data.extend_from_slice(b"peak");
            data.extend_from_slice(&rest.0);
            data.extend_from_slice(&last.0);
            hash_fn(&data)
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

    #[test]
    fn test_mmr_root_uses_peak_prefix() {
        // Verify the super-peak computation uses "peak" (not "$peak")
        // and the correct argument order: H("peak" || MR(rest) || last)
        let mut mmr = MerkleMountainRange::new();
        mmr.append(Hash([1u8; 32]), test_hash);
        mmr.append(Hash([2u8; 32]), test_hash);
        mmr.append(Hash([3u8; 32]), test_hash);
        // Two peaks: peaks[0] = [3u8;32], peaks[1] = H([1;32] || [2;32])
        let peak0 = Hash([3u8; 32]);
        let peak1 = test_hash(&{
            let mut v = Vec::new();
            v.extend_from_slice(&[1u8; 32]);
            v.extend_from_slice(&[2u8; 32]);
            v
        });
        // MR([peak0, peak1]) = H("peak" || peak0 || peak1)
        let expected = test_hash(&{
            let mut v = Vec::new();
            v.extend_from_slice(b"peak");
            v.extend_from_slice(&peak0.0);
            v.extend_from_slice(&peak1.0);
            v
        });
        assert_eq!(mmr.root(test_hash), expected);
    }
}
