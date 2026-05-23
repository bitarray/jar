//! `SparseList<T, N>` — a list view that may omit materializing parts of
//! the tree, using cached subtree roots or zero-hashes for empty regions.
//!
//! The hash tree root is byte-identical to a fully-materialised
//! `List<T, N>` with the same effective contents. The algorithm walks the
//! implicit balanced binary tree of depth `ceil_log2(N)` iteratively,
//! using a fixed-size stack — never materialising the full `N` leaves.
//!
//! ## Storage
//!
//! Both inner maps are sorted `Vec`s keyed by `u64`, allocated through
//! the caller-provided `A: Allocator + Clone`. Sorted Vec gives us:
//!
//! - **O(log n) lookup** via `binary_search_by_key`.
//! - **O(n) insert/remove** at the sorted position. For the cnode-slot
//!   use case (N ≤ 256, typically very sparse), the linear shift is
//!   trivial.
//! - **O(log n) range queries** via `partition_point`, used by
//!   [`compute_subtree_root`](SparseList::compute_subtree_root) to
//!   short-circuit empty subtrees.
//! - **Iteration in sorted order**, byte-equivalent to `BTreeMap::iter`.
//! - **Allocator-genericity** — `allocator_api2::vec::Vec<T, A>` carries
//!   the allocator handle on every allocation, so a `SparseList<_, N,
//!   TalcAlloc>` keeps no state on the host's `Global` allocator. This
//!   is what makes `Cap::CNode` walkable from the guest's view of the
//!   shared state cache.
//!
//! Previous versions used `alloc::collections::BTreeMap` (stable, but
//! hardwired to `Global`); the switch preserves wire-format and
//! hash-tree-root output byte-identically.

use allocator_api2::alloc::{Allocator, Global};
use allocator_api2::vec::Vec;
use core::fmt;
use digest::Digest;
use digest::typenum::U32;

use crate::merkle::{ceil_log2, hash_pair, mix_in_length, zero_hash};
use crate::missing::MissingOr;
use crate::{BYTES_PER_LENGTH_OFFSET, Decode, DecodeError, Encode, HashTreeRoot};

/// A list with a maximum length of `N` that exposes its tree structure
/// for sparse fill-in: materialized indices, cached subtree roots, or
/// implicit zero-hashes for never-written regions.
///
/// Hash is byte-identical to a fully-materialised `List<T, N>` with the
/// same effective contents.
pub struct SparseList<T, const N: u64, A: Allocator + Clone = Global> {
    len: u64,
    /// Sorted (by `u64` key) entries: leaf index → optional materialized
    /// value (or precomputed hash). Absent indices contribute
    /// `zero_hash(0)` to the root unless covered by
    /// [`cached_subtree_roots`].
    entries: Vec<(u64, MissingOr<T>), A>,
    /// Sorted (by `u64` key) cache of precomputed subtree roots. Key is
    /// a tree coordinate `(depth, index_at_depth)` flattened via
    /// `coord_to_key(depth, idx) = (1u64 << depth) | idx` — the standard
    /// "heap index" of a node in a complete binary tree.
    cached_subtree_roots: Vec<(u64, [u8; 32]), A>,
    alloc: A,
}

impl<T, const N: u64> SparseList<T, N, Global> {
    /// Build an empty `Global`-allocated sparse list.
    pub fn new() -> Self {
        Self::new_in(Global)
    }
}

impl<T, const N: u64> Default for SparseList<T, N, Global> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: u64, A: Allocator + Clone> SparseList<T, N, A> {
    /// Build an empty sparse list with a caller-provided allocator.
    pub fn new_in(alloc: A) -> Self {
        Self {
            len: 0,
            entries: Vec::new_in(alloc.clone()),
            cached_subtree_roots: Vec::new_in(alloc.clone()),
            alloc,
        }
    }

    /// Borrow the captured allocator handle.
    #[inline]
    pub fn allocator(&self) -> &A {
        &self.alloc
    }

    /// Logical length.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// `true` iff no entries are present and `len == 0`.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterator over `(index, MissingOr<T>)` for materialized entries only.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &MissingOr<T>)> {
        self.entries.iter().map(|(k, v)| (*k, v))
    }

    /// Mutable iterator over `(index, &mut MissingOr<T>)` for materialized
    /// entries only. Used by callers that need to rewrite entry values
    /// in place (e.g., resolving `Ref` targets to `Hash` after settle).
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (u64, &mut MissingOr<T>)> {
        self.entries.iter_mut().map(|(k, v)| (*k, v))
    }

    /// Number of materialized entries. Distinct from [`len`](Self::len),
    /// which is the logical length (max index + 1).
    pub fn entries_count(&self) -> usize {
        self.entries.len()
    }

    /// Look up a single entry by leaf index. O(log n).
    pub fn get(&self, idx: u64) -> Option<&MissingOr<T>> {
        match self.entries.binary_search_by_key(&idx, |(k, _)| *k) {
            Ok(pos) => Some(&self.entries[pos].1),
            Err(_) => None,
        }
    }

    /// Insert a materialized entry. Updates `len` to `max(len, idx + 1)`.
    /// O(n) — sorted shift on insert. If `idx` is already present, the
    /// existing value is overwritten (matching `BTreeMap::insert` semantics).
    pub fn insert(&mut self, idx: u64, value: MissingOr<T>) -> Result<(), DecodeError> {
        if idx >= N {
            return Err(DecodeError::BoundExceeded {
                len: idx + 1,
                bound: N,
            });
        }
        self.len = self.len.max(idx + 1);
        match self.entries.binary_search_by_key(&idx, |(k, _)| *k) {
            Ok(pos) => {
                self.entries[pos].1 = value;
            }
            Err(pos) => {
                self.entries.insert(pos, (idx, value));
            }
        }
        Ok(())
    }

    /// Remove the entry at `idx`, returning its previous value if any.
    /// Does **not** decrement `len` — the logical length is independent
    /// of which indices are materialized.
    pub fn remove(&mut self, idx: u64) -> Option<MissingOr<T>> {
        match self.entries.binary_search_by_key(&idx, |(k, _)| *k) {
            Ok(pos) => Some(self.entries.remove(pos).1),
            Err(_) => None,
        }
    }

    /// Set the logical length explicitly (does not affect entries).
    pub fn set_len(&mut self, len: u64) -> Result<(), DecodeError> {
        if len > N {
            return Err(DecodeError::BoundExceeded { len, bound: N });
        }
        self.len = len;
        Ok(())
    }

    /// Cache a precomputed subtree root at tree position `(depth, idx)`.
    /// `depth == 0` corresponds to the root; deeper means closer to leaves.
    /// O(n) — sorted insert into `cached_subtree_roots`.
    pub fn cache_subtree_root(&mut self, depth: usize, idx: u64, root: [u8; 32]) {
        let key = coord_to_key(depth, idx);
        match self
            .cached_subtree_roots
            .binary_search_by_key(&key, |(k, _)| *k)
        {
            Ok(pos) => {
                self.cached_subtree_roots[pos].1 = root;
            }
            Err(pos) => {
                self.cached_subtree_roots.insert(pos, (key, root));
            }
        }
    }

    /// Number of cached subtree roots. Used by [`fmt::Debug`].
    pub fn cached_subtree_roots_count(&self) -> usize {
        self.cached_subtree_roots.len()
    }

    /// Iterator over cached subtree roots in sorted-by-key order.
    pub fn cached_subtree_roots(&self) -> impl Iterator<Item = (u64, &[u8; 32])> {
        self.cached_subtree_roots.iter().map(|(k, v)| (*k, v))
    }

    /// Internal: look up a cached subtree root by its `coord_to_key`-encoded key.
    fn cached_subtree_root(&self, key: u64) -> Option<&[u8; 32]> {
        match self
            .cached_subtree_roots
            .binary_search_by_key(&key, |(k, _)| *k)
        {
            Ok(pos) => Some(&self.cached_subtree_roots[pos].1),
            Err(_) => None,
        }
    }
}

#[inline]
fn coord_to_key(depth: usize, idx: u64) -> u64 {
    (1u64 << depth) | idx
}

impl<T: fmt::Debug, const N: u64, A: Allocator + Clone> fmt::Debug for SparseList<T, N, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SparseList")
            .field("cap", &N)
            .field("len", &self.len)
            .field("materialized", &self.entries.len())
            .field("cached_subtrees", &self.cached_subtree_roots.len())
            .finish()
    }
}

impl<T: Clone, const N: u64, A: Allocator + Clone> Clone for SparseList<T, N, A> {
    fn clone(&self) -> Self {
        let mut entries: Vec<(u64, MissingOr<T>), A> =
            Vec::with_capacity_in(self.entries.len(), self.alloc.clone());
        for (k, v) in self.entries.iter() {
            entries.push((*k, v.clone()));
        }
        let mut cached: Vec<(u64, [u8; 32]), A> =
            Vec::with_capacity_in(self.cached_subtree_roots.len(), self.alloc.clone());
        for (k, v) in self.cached_subtree_roots.iter() {
            cached.push((*k, *v));
        }
        Self {
            len: self.len,
            entries,
            cached_subtree_roots: cached,
            alloc: self.alloc.clone(),
        }
    }
}

impl<T: PartialEq, const N: u64, A: Allocator + Clone> PartialEq for SparseList<T, N, A> {
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len
            || self.entries.len() != other.entries.len()
            || self.cached_subtree_roots.len() != other.cached_subtree_roots.len()
        {
            return false;
        }
        // Both vectors are sorted by key, so element-wise comparison
        // suffices.
        for ((ka, va), (kb, vb)) in self.entries.iter().zip(other.entries.iter()) {
            if ka != kb || va != vb {
                return false;
            }
        }
        for ((ka, va), (kb, vb)) in self
            .cached_subtree_roots
            .iter()
            .zip(other.cached_subtree_roots.iter())
        {
            if ka != kb || va != vb {
                return false;
            }
        }
        true
    }
}

impl<T: Eq, const N: u64, A: Allocator + Clone> Eq for SparseList<T, N, A> {}

// --------------------------------------------------------------------------
// Wire format: (len: u64, List<(u64, MissingOr<T>)>).
// --------------------------------------------------------------------------
//
// The list element is an SSZ Container with a fixed `u64` key plus a
// variable-length `MissingOr<T>` payload. We encode it inline rather than
// going through `List<(u64, MissingOr<T>)>` to keep the wire format
// independent of the workspace `(K, V)` tuple impl (which currently
// doesn't exist; we have only the `BTreeMap<K, V>` impl in collections.rs).

impl<T: Encode, const N: u64, A: Allocator + Clone> Encode for SparseList<T, N, A> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }
    fn ssz_bytes_len(&self) -> usize {
        // 8 (len) + 4 (entries-list offset) + offset table + payloads.
        let n_entries = self.entries.len();
        let entry_var_size: usize = self
            .entries
            .iter()
            .map(|(_, v)| v.ssz_bytes_len())
            .sum::<usize>();
        // Each entry is (u64 key, MissingOr<T> value). u64 is fixed (8B);
        // MissingOr<T> is variable, so each entry has a 4B offset slot.
        // Plus the entries list itself is variable — we wrap it in an
        // offset container with the leading `len: u64`.
        // Layout:
        //   [0..8]   len: u64
        //   [8..12]  entries_offset: u32 (always 12)
        //   [12..]   entries list payload
        //
        // entries list payload (variable list of variable elements):
        //   per-entry: (u64 key, 4B value-offset)  ← 12 bytes each
        //   then concatenated payloads
        12 + n_entries * 12 + entry_var_size
    }
    fn ssz_append<A2: Allocator + Clone>(&self, buf: &mut Vec<u8, A2>) {
        // len
        buf.extend_from_slice(&self.len.to_le_bytes());
        // entries_offset = 12
        buf.extend_from_slice(&12u32.to_le_bytes());
        // Now encode the entries list. SSZ list of container elements
        // where the container is (u64 key, MissingOr<T> value).
        encode_sparse_entries_list(&self.entries, buf);
    }
}

fn encode_sparse_entries_list<T: Encode, A: Allocator + Clone, A2: Allocator + Clone>(
    entries: &Vec<(u64, MissingOr<T>), A>,
    buf: &mut Vec<u8, A2>,
) {
    let n = entries.len();
    // Each entry container: (u64 key, MissingOr<T> value).
    // Key is fixed (8B), value is variable. Per-entry container:
    //   [0..8]: key
    //   [8..12]: value-offset (= 12 → payload starts immediately)
    //   [12..]: value payload
    // So per-entry "fixed" portion is 12 bytes; variable portion is the
    // MissingOr payload.
    //
    // To put this inside a list-of-variable-elements, we need a top-level
    // offset table of `n` × 4 bytes pointing at each entry container,
    // followed by the entry containers laid out back-to-back.

    let header_size = n * BYTES_PER_LENGTH_OFFSET;
    let start = buf.len();
    buf.resize(start + header_size, 0u8);

    let mut running = header_size as u32;
    for (i, (key, val)) in entries.iter().enumerate() {
        let off_pos = start + i * BYTES_PER_LENGTH_OFFSET;
        buf[off_pos..off_pos + 4].copy_from_slice(&running.to_le_bytes());

        let entry_start = buf.len();
        // key
        buf.extend_from_slice(&key.to_le_bytes());
        // value-offset within this entry container
        buf.extend_from_slice(&12u32.to_le_bytes());
        // value payload
        val.ssz_append(buf);

        let entry_end = buf.len();
        running = running
            .checked_add((entry_end - entry_start) as u32)
            .expect("ssz offset overflow");
    }
}

impl<T: Decode, const N: u64, A: Allocator + Clone + Default> Decode for SparseList<T, N, A> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }
    fn from_ssz_bytes_in<A2: Allocator + Clone>(
        bytes: &[u8],
        alloc: A2,
    ) -> Result<Self, DecodeError> {
        if bytes.len() < 12 {
            return Err(DecodeError::UnexpectedEof {
                expected: 12,
                actual: bytes.len(),
            });
        }
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&bytes[0..8]);
        let len = u64::from_le_bytes(len_bytes);
        if len > N {
            return Err(DecodeError::BoundExceeded { len, bound: N });
        }
        let entries_offset = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        if entries_offset != 12 {
            return Err(DecodeError::InvalidOffset {
                offset: entries_offset,
                len: bytes.len(),
                fixed: 12,
            });
        }
        let payload = &bytes[12..];
        let entries_in = decode_sparse_entries_list::<T, A2>(payload, alloc)?;
        let target_alloc = A::default();
        let mut entries: Vec<(u64, MissingOr<T>), A> =
            Vec::with_capacity_in(entries_in.len(), target_alloc.clone());
        let mut prev_key: Option<u64> = None;
        for (k, v) in entries_in {
            if k >= N {
                return Err(DecodeError::BoundExceeded {
                    len: k + 1,
                    bound: N,
                });
            }
            if let Some(p) = prev_key
                && k <= p
            {
                return Err(DecodeError::NotSorted);
            }
            prev_key = Some(k);
            entries.push((k, v));
        }
        Ok(Self {
            len,
            entries,
            cached_subtree_roots: Vec::new_in(target_alloc.clone()),
            alloc: target_alloc,
        })
    }
}

fn decode_sparse_entries_list<T: Decode, A: Allocator + Clone>(
    bytes: &[u8],
    alloc: A,
) -> Result<alloc::vec::Vec<(u64, MissingOr<T>)>, DecodeError> {
    if bytes.is_empty() {
        return Ok(alloc::vec::Vec::new());
    }
    if bytes.len() < 4 {
        return Err(DecodeError::UnexpectedEof {
            expected: 4,
            actual: bytes.len(),
        });
    }
    let first = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    if !first.is_multiple_of(BYTES_PER_LENGTH_OFFSET) || first > bytes.len() {
        return Err(DecodeError::InvalidOffset {
            offset: first,
            len: bytes.len(),
            fixed: 0,
        });
    }
    let n = first / BYTES_PER_LENGTH_OFFSET;
    let mut offsets = alloc::vec::Vec::with_capacity(n + 1);
    offsets.push(first);
    for i in 1..n {
        if bytes.len() < (i + 1) * BYTES_PER_LENGTH_OFFSET {
            return Err(DecodeError::UnexpectedEof {
                expected: (i + 1) * BYTES_PER_LENGTH_OFFSET,
                actual: bytes.len(),
            });
        }
        let off = u32::from_le_bytes(
            bytes[i * BYTES_PER_LENGTH_OFFSET..(i + 1) * BYTES_PER_LENGTH_OFFSET]
                .try_into()
                .unwrap(),
        ) as usize;
        if off < *offsets.last().unwrap() {
            return Err(DecodeError::OffsetsNotMonotonic {
                prev: *offsets.last().unwrap(),
                curr: off,
            });
        }
        if off > bytes.len() {
            return Err(DecodeError::InvalidOffset {
                offset: off,
                len: bytes.len(),
                fixed: first,
            });
        }
        offsets.push(off);
    }
    offsets.push(bytes.len());

    let mut out = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let entry_slice = &bytes[offsets[i]..offsets[i + 1]];
        // Each entry: u64 key + value-offset (must be 12) + MissingOr<T> payload.
        if entry_slice.len() < 12 {
            return Err(DecodeError::UnexpectedEof {
                expected: 12,
                actual: entry_slice.len(),
            });
        }
        let mut kbytes = [0u8; 8];
        kbytes.copy_from_slice(&entry_slice[0..8]);
        let key = u64::from_le_bytes(kbytes);
        let value_offset = u32::from_le_bytes(entry_slice[8..12].try_into().unwrap()) as usize;
        if value_offset != 12 {
            return Err(DecodeError::InvalidOffset {
                offset: value_offset,
                len: entry_slice.len(),
                fixed: 12,
            });
        }
        let value = MissingOr::<T>::from_ssz_bytes_in(&entry_slice[12..], alloc.clone())?;
        out.push((key, value));
    }
    Ok(out)
}

// --------------------------------------------------------------------------
// HashTreeRoot
// --------------------------------------------------------------------------

impl<T: HashTreeRoot + Encode, const N: u64, A: Allocator + Clone> HashTreeRoot
    for SparseList<T, N, A>
{
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        // The chunk-tree depth is ceil_log2(N) — the depth at which there
        // are exactly N leaves (one chunk per logical element, since we
        // treat elements as composite types via `HashTreeRoot`).
        // Special-case N <= 1 → depth 0 → root is the (zero or single)
        // chunk.
        let depth = ceil_log2(N);
        let inner = self.compute_subtree_root::<D>(0, 0, depth);
        mix_in_length::<D>(inner, self.len)
    }
}

impl<T: HashTreeRoot, const N: u64, A: Allocator + Clone> SparseList<T, N, A> {
    /// Compute the merkle root of the subtree rooted at coordinate
    /// `(node_depth, node_index_at_depth)` within a balanced binary chunk
    /// tree of total depth `total_depth` (i.e., `2^total_depth` leaves).
    ///
    /// Uses iterative DFS with an explicit stack. Stack depth is bounded
    /// by `total_depth` (≤ 64 for any u64 cap), so the stack is tiny.
    fn compute_subtree_root<D: Digest<OutputSize = U32>>(
        &self,
        node_depth: usize,
        node_index_at_depth: u64,
        total_depth: usize,
    ) -> [u8; 32] {
        // Fast path: explicitly cached subtree root for this coordinate.
        if let Some(cached) =
            self.cached_subtree_root(coord_to_key(node_depth, node_index_at_depth))
        {
            return *cached;
        }

        // Leaf case: we're at the chunk level.
        if node_depth == total_depth {
            // Leaf index is `node_index_at_depth`. Return the chunk root.
            return self
                .get(node_index_at_depth)
                .map(|e| e.hash_tree_root::<D>())
                .unwrap_or([0u8; 32]);
        }

        // Determine the leaf-index range covered by this subtree.
        let levels_below = total_depth - node_depth;
        let leaves_per_subtree = 1u64 << levels_below;
        let lo = node_index_at_depth * leaves_per_subtree;
        let hi = lo + leaves_per_subtree; // exclusive

        // If no materialized entries fall in [lo, hi), this subtree is
        // entirely empty → it's a zero-hash at the appropriate depth.
        // `partition_point` gives us the index of the first entry with
        // key >= lo. If that entry's key is < hi, there's at least one
        // materialized entry in range.
        let pos = self.entries.partition_point(|(k, _)| *k < lo);
        let has_entries = self.entries.get(pos).is_some_and(|(k, _)| *k < hi);
        if !has_entries {
            return zero_hash::<D>(levels_below);
        }

        // Recurse into children.
        let left =
            self.compute_subtree_root::<D>(node_depth + 1, node_index_at_depth * 2, total_depth);
        let right = self.compute_subtree_root::<D>(
            node_depth + 1,
            node_index_at_depth * 2 + 1,
            total_depth,
        );
        hash_pair::<D>(&left, &right)
    }
}
