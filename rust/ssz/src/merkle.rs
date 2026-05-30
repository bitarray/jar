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

/// Compute `zero_hash(depth)`, where
/// `zero_hash(d) = hash(zero_hash(d-1), zero_hash(d-1))` and
/// `zero_hash(0) == [0u8; 32]`. Recomputed per call (not memoized).
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
