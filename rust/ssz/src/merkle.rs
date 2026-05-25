//! SSZ merkleization primitives.
//!
//! All hashes are 32-byte digests, threaded through the [`digest::Digest`]
//! trait with `OutputSize = U32`. No domain bytes or prefixes are mixed in
//! at the node level — concatenation is the only operation.

use alloc::vec::Vec;
use digest::Digest;
use digest::typenum::U32;

use crate::BYTES_PER_CHUNK;

/// Hash two 32-byte children into their parent node.
#[inline]
pub fn hash_pair<D: Digest<OutputSize = U32>>(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = D::new();
    hasher.update(left);
    hasher.update(right);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(out.as_slice());
    arr
}

/// Pack a byte slice into 32-byte chunks, zero-padding the tail.
pub fn pack_bytes(bytes: &[u8]) -> Vec<[u8; 32]> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let n = bytes.len().div_ceil(BYTES_PER_CHUNK);
    let mut out = Vec::with_capacity(n);
    let mut cursor = 0;
    for _ in 0..n {
        let mut chunk = [0u8; 32];
        let take = core::cmp::min(BYTES_PER_CHUNK, bytes.len() - cursor);
        chunk[..take].copy_from_slice(&bytes[cursor..cursor + take]);
        out.push(chunk);
        cursor += take;
    }
    out
}

/// Number of leaves in a balanced tree of `depth` levels.
#[inline]
pub fn leaves_at_depth(depth: usize) -> u64 {
    1u64 << depth
}

/// Returns `ceil(log2(max(1, n)))`.
#[inline]
pub fn ceil_log2(n: u64) -> usize {
    if n <= 1 {
        return 0;
    }
    (64 - (n - 1).leading_zeros()) as usize
}

/// SSZ `merkleize` — pad `chunks` to `max(limit, chunks.len())` rounded up
/// to the next power of two, build a balanced binary tree using
/// `hash(left || right)`, and return the root.
///
/// `limit` is the type-level chunk cap (e.g. `ceil(N * size_of_T / 32)` for
/// `List<T, N>`). When `chunks.len() > limit`, the limit is bumped up to
/// `chunks.len()` (callers should validate the type-level cap separately).
///
/// Empty input with `limit == 0` returns a zero hash (the root of a single
/// zero chunk).
///
/// Complexity: `O(chunks.len() + depth)` hash operations, independent of
/// `limit`. This is achieved by only materialising the "real" prefix at
/// each level; the implicit zero-padded suffix folds into `zero_hash(d)`
/// without iteration.
pub fn merkleize<D: Digest<OutputSize = U32>>(chunks: &[[u8; 32]], limit: usize) -> [u8; 32] {
    let target = core::cmp::max(limit, chunks.len()).max(1);
    let padded_len = target.next_power_of_two();
    let depth = padded_len.trailing_zeros() as usize;

    if padded_len == 1 {
        return chunks.first().copied().unwrap_or([0u8; 32]);
    }

    // Empty input with depth > 0 → entire tree is implicit zero padding.
    if chunks.is_empty() {
        return zero_hash::<D>(depth);
    }

    // Precompute the zero-hash table for this call's `depth`. Each level's
    // zero_hash is `H(prev || prev)`; computing it once up-front turns the
    // per-level lookup from O(d) into O(1) and the total from O(depth²)
    // into O(depth). Without this, a depth-32 merkleize (e.g. a Vec<T> with
    // MAX_VEC_LEN = 1 << 32) burns ~496 redundant SHA-256s per call just
    // recomputing the same zero hashes.
    let mut zero_h_table: Vec<[u8; 32]> = Vec::with_capacity(depth);
    let mut cur_zero = [0u8; 32];
    zero_h_table.push(cur_zero);
    for _ in 1..depth {
        cur_zero = hash_pair::<D>(&cur_zero, &cur_zero);
        zero_h_table.push(cur_zero);
    }

    // Iterative bottom-up reduction. At each level we only iterate over the
    // "real" entries; missing right siblings draw from `zero_h_table[d]`. The
    // implicit padding to `padded_len` is handled by continuing to fold for
    // the full `depth` iterations even after `level.len()` reaches 1.
    let mut level: Vec<[u8; 32]> = Vec::new();
    level.extend_from_slice(chunks);

    for &zero_h in zero_h_table.iter().take(depth) {
        let next_count = level.len().div_ceil(2);
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(next_count);
        for i in 0..next_count {
            let l = level[2 * i];
            let r = level.get(2 * i + 1).copied().unwrap_or(zero_h);
            next.push(hash_pair::<D>(&l, &r));
        }
        level = next;
    }

    level[0]
}

/// `mix_in_length(root, len) = hash(root || u256_le(len))`.
#[inline]
pub fn mix_in_length<D: Digest<OutputSize = U32>>(root: [u8; 32], len: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[..8].copy_from_slice(&len.to_le_bytes());
    hash_pair::<D>(&root, &buf)
}

/// `mix_in_selector(root, sel) = hash(root || u256_le(sel))`.
///
/// Note that the selector is padded to a full 32-byte little-endian u256,
/// matching the spec (not just one byte).
#[inline]
pub fn mix_in_selector<D: Digest<OutputSize = U32>>(root: [u8; 32], selector: u8) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[0] = selector;
    hash_pair::<D>(&root, &buf)
}

/// Cached zero-hash table: `zero_hash(d) = hash(zero_hash(d-1), zero_hash(d-1))`,
/// with `zero_hash(0) == [0u8; 32]`.
pub fn zero_hash<D: Digest<OutputSize = U32>>(depth: usize) -> [u8; 32] {
    // We rebuild the table per call. This is sufficient for jar's tree
    // depths (≤ 64 in practice); a future optimisation could memoize a
    // `OnceLock<[u8; 32]; 64>` per hash type, but no_std forbids
    // unconditional `OnceLock`. Callers that hash hot paths should cache
    // their own zero-hash array.
    let mut current = [0u8; 32];
    for _ in 0..depth {
        current = hash_pair::<D>(&current, &current);
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    #[test]
    fn zero_hash_depth_0_is_zero() {
        assert_eq!(zero_hash::<Sha256>(0), [0u8; 32]);
    }

    #[test]
    fn zero_hash_depth_1_is_h00() {
        let expected = hash_pair::<Sha256>(&[0u8; 32], &[0u8; 32]);
        assert_eq!(zero_hash::<Sha256>(1), expected);
    }

    #[test]
    fn merkleize_single_chunk_returns_chunk() {
        let chunk = [0xAAu8; 32];
        assert_eq!(merkleize::<Sha256>(&[chunk], 1), chunk);
    }

    #[test]
    fn merkleize_two_chunks() {
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];
        let expected = hash_pair::<Sha256>(&a, &b);
        assert_eq!(merkleize::<Sha256>(&[a, b], 2), expected);
    }

    #[test]
    fn merkleize_empty_with_limit_zero_is_zero_chunk() {
        assert_eq!(merkleize::<Sha256>(&[], 0), [0u8; 32]);
    }

    #[test]
    fn merkleize_padded_with_zero_hashes() {
        // 3 chunks → padded to 4. Right-subtree right leaf is zero_hash(0).
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let left = hash_pair::<Sha256>(&a, &b);
        let right = hash_pair::<Sha256>(&c, &[0u8; 32]);
        let root = hash_pair::<Sha256>(&left, &right);
        assert_eq!(merkleize::<Sha256>(&[a, b, c], 4), root);
    }

    #[test]
    fn pack_bytes_pads_tail_with_zeros() {
        let chunks = pack_bytes(&[1, 2, 3]);
        assert_eq!(chunks.len(), 1);
        let mut expected = [0u8; 32];
        expected[0] = 1;
        expected[1] = 2;
        expected[2] = 3;
        assert_eq!(chunks[0], expected);
    }

    #[test]
    fn merkleize_huge_limit_finishes_fast() {
        // Regression: previous algorithm was O(padded_len), so a 4-billion
        // limit would try to allocate a 2-billion-entry Vec. Now O(depth).
        // limit = 1 << 32 → padded_len = 2^32, depth = 32 hash operations
        // after the initial input fold. Should complete in microseconds.
        let chunk = [0xAAu8; 32];
        let root = merkleize::<Sha256>(&[chunk], 1usize << 32);

        // Equivalent: a single real leaf in a depth-32 tree; sibling at
        // each level is zero_hash(d).
        let mut current = chunk;
        for d in 0..32 {
            current = hash_pair::<Sha256>(&current, &zero_hash::<Sha256>(d));
        }
        assert_eq!(root, current);
    }

    #[test]
    fn merkleize_empty_with_large_limit_is_zero_subtree() {
        // Empty input, limit = 1024 → root must be zero_hash(10) without
        // materializing 1024 zero leaves.
        let root = merkleize::<Sha256>(&[], 1024);
        assert_eq!(root, zero_hash::<Sha256>(10));
    }

    #[test]
    fn merkleize_three_chunks_with_large_limit() {
        // 3 chunks, limit = 16 → padded_len = 16, depth = 4.
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let root = merkleize::<Sha256>(&[a, b, c], 16);

        // Compute by hand. Level 0 has [a, b, c]; level 1 has
        // [H(a,b), H(c, zero_h0)]; level 2 has [H(L1[0], L1[1])];
        // level 3 has [H(L2[0], zero_h2)]; level 4 has [H(L3[0], zero_h3)].
        let l1_0 = hash_pair::<Sha256>(&a, &b);
        let l1_1 = hash_pair::<Sha256>(&c, &zero_hash::<Sha256>(0));
        let l2_0 = hash_pair::<Sha256>(&l1_0, &l1_1);
        let l3_0 = hash_pair::<Sha256>(&l2_0, &zero_hash::<Sha256>(2));
        let l4_0 = hash_pair::<Sha256>(&l3_0, &zero_hash::<Sha256>(3));
        assert_eq!(root, l4_0);
    }

    #[test]
    fn ceil_log2_examples() {
        assert_eq!(ceil_log2(0), 0);
        assert_eq!(ceil_log2(1), 0);
        assert_eq!(ceil_log2(2), 1);
        assert_eq!(ceil_log2(3), 2);
        assert_eq!(ceil_log2(4), 2);
        assert_eq!(ceil_log2(5), 3);
        assert_eq!(ceil_log2(8), 3);
        assert_eq!(ceil_log2(9), 4);
    }
}
