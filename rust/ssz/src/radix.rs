//! `RadixMap<V, KEY_BYTES>` — a structurally-compressed sparse binary radix
//! merkle key→value map (the "option b" content-addressed map).
//!
//! Keys are fixed-width `[u8; KEY_BYTES]` bit strings (bit 0 = the MSB of
//! byte 0, MSB-first / big-endian), values are any `V: HashTreeRoot`. The
//! root is a **canonical, binding, shallow** commitment to the key→value
//! set: a pure function of the set (insertion-order independent), and a
//! commitment that no two distinct sets can share under collision
//! resistance of the digest `D` alone.
//!
//! This is distinct from [`crate::SparseList`] (the "option a" map): a
//! `SparseList` is a *fixed-depth* sparse Merkle tree whose root is
//! byte-identical to a dense `List<T, N>` (leaves are bare value roots,
//! plus `mix_in_length`). A `RadixMap` is **not** byte-compatible with any
//! SSZ `List`/`Vector` — it is a deliberately different structure (see
//! "Dense ≠ Vector" below).
//!
//! # Structure (EIP-7864-aligned hybrid)
//!
//! The recursion `node(S, depth)` over a set `S` of `(key, value)` entries:
//!
//! - **empty** (`|S| = 0`) → [`EMPTY`] = `[0u8; 32]` (zero hash ops).
//! - **leaf** (`|S| = 1`) → [`leaf_hash`] of that entry's `(key, value_root)`.
//!   A lone key collapses to a single leaf wherever its subtree narrows to
//!   one element — so a lone key is *shallow*, independent of `depth`.
//! - **branch** (`|S| ≥ 2`) → [`branch_hash`] of the two children obtained
//!   by splitting `S` on `bit(key, depth)`.
//!
//! Only **empty** and **singleton** subtrees collapse; a multi-key shared
//! prefix is materialized as a chain of branch nodes each with one
//! [`EMPTY`] sibling (exactly like EIP-7864's outer "minimal InternalNodes"
//! tree, and like `SparseList`'s zero-padding). This is what keeps
//! **non-membership proofs complete**: an absent key always lands on a
//! materialized `EMPTY` sibling (or a diverging leaf) at a well-defined
//! depth — there is no skipped unary run for it to fall into. (A *fully*
//! unary-skip-compressed Patricia trie is shallower for adversarially-close
//! keys but needs an explicit skip-prefix commitment in every node for
//! non-membership completeness; we deliberately avoid that complexity.)
//!
//! Depth is bounded by `KEY_BITS = 8 * KEY_BYTES`. It is shallow in
//! practice: for well-spread keys (e.g. address-derived) the singleton
//! collapse fires at depth ≈ `log2(|S|)`; for the DataCap (group-index
//! keys) `KEY_BYTES` is chosen small enough to bound the depth directly.
//!
//! # Domain separation (binding under collision resistance alone)
//!
//! Leaf and branch nodes are tagged with **distinct** one-byte domain
//! prefixes:
//!
//! ```text
//! EMPTY  = [0u8; 32]
//! leaf   = D( LEAF_TAG(0x00)   || key || value_root )
//! branch = D( BRANCH_TAG(0x01) || left || right )
//! ```
//!
//! Tagging **both** node kinds (not just the leaf) is load-bearing. For
//! `KEY_BYTES ≤ 32`, an SSZ `merkleize(pack_bytes(key), 1)` returns the raw
//! key chunk *un-hashed*, so a bare `hash_pair(key, value_root)` leaf would
//! be byte-identical to a branch `hash_pair(left, right)` — yielding a
//! trivial, collision-free forgery: the one-entry map `{(H_L, Missing(H_R))}`
//! would share a root with the two-entry branch `branch(H_L, H_R)`. The
//! distinct tag bytes make the leaf and branch preimages differ in a fixed
//! position regardless of content, so a collision between the two domains is
//! a collision of `D` itself. This binds the map under collision resistance
//! *alone* (no second-preimage / preimage assumption) and ports cleanly to
//! a future SNARK-friendly sponge (the tag is a structural domain element,
//! not an artifact of byte-hash length padding) — a stronger footing than
//! EIP-7864's asymmetric `stem || 0x00 || …` stem commitment.
//!
//! The leaf commits the **full key** (not just the bits consumed to reach
//! its collapsed depth). This pins each leaf to one logical key — required
//! for canonicality (the shallow placement is uniquely determined by the
//! set) and for sound non-membership proofs (a diverging-leaf exclusion
//! reveals `k' ≠ key`). The value is taken via [`MissingOr`] so an
//! un-materialized leaf (`Missing(h)`) contributes `value_root = h` with no
//! `mix_in_selector` — substitution-transparent, exactly like `SparseList`.
//!
//! Because both node kinds are tagged, a `RadixMap` root also cannot be
//! confused with a `List`/`SparseList` root (bare `hash_pair` + no tag) even
//! absent an enclosing union selector. Note `EMPTY == [0u8;32]` *does* alias
//! the zero summaries `zero_hash(0)` / `PageSlot::Empty` / `MissingOr::Missing([0;32])`;
//! a `RadixMap` root must therefore only ever sit under a domain-separating
//! parent (e.g. the `Cap` SSZ-union selector), never in a position that also
//! admits a raw zero summary.
//!
//! # Canonicality
//!
//! `node(S, depth)` branches only on set membership and `bit(key, depth)`,
//! both intrinsic to the set; the base cases depend only on the (≤ 1)
//! element present and commit the full key. So the root is a pure function
//! of the key→value-**root** set, independent of insertion order or
//! `MissingOr` materialization pattern. Storage is a strictly-ascending
//! sorted `Vec`, so there is exactly one in-memory and one wire form per
//! set; duplicate keys are rejected on decode and overwritten on insert.
//!
//! # Dense ≠ Vector
//!
//! Even a fully-dense `RadixMap` root does **not** coincide with an SSZ
//! `List`/`Vector` root: radix leaves are tagged + key-committed
//! (`D(0x00 || key || value_root)`, not the bare `value_root` a `Vector`
//! leaf carries), branches are tagged, and there is no `mix_in_length`.
//! Standard SSZ merkleization appears **only inside the leaf value** — e.g.
//! the DataCap leaf value is a dense `FixedVector<Page, 512>` merkleized the
//! ordinary SSZ way; that `value_root` is then fed into `leaf_hash`.
//!
//! # Wire format
//!
//! Like [`SparseList`] minus the `len` field (a map has no logical length,
//! only a key set): a single variable field holding a sorted SSZ list of
//! `(key: ByteVector[KEY_BYTES], value: MissingOr<V>)` containers. Decode is
//! strict (loud on any non-canonical encoding): top-level offset must be 4,
//! per-entry value-offset must be `KEY_BYTES + 4`, keys must be strictly
//! ascending (rejecting duplicates and bad order), no trailing bytes.

use alloc::vec::Vec;
use core::fmt;
use digest::Digest;
use digest::typenum::U32;

use crate::missing::MissingOr;
use crate::{BYTES_PER_LENGTH_OFFSET, Decode, DecodeError, Encode, HashTreeRoot};

/// One radix entry: a fixed-width key and its (possibly-elided) value.
type Entry<V, const KEY_BYTES: usize> = ([u8; KEY_BYTES], MissingOr<V>);

/// The empty-subtree hash: the all-zero 32-byte chunk (= `zero_hash(0)`).
pub const EMPTY: [u8; 32] = [0u8; 32];

/// Domain tag prepended to a leaf-node preimage.
pub const LEAF_TAG: u8 = 0x00;

/// Domain tag prepended to a branch-node (internal-node) preimage.
pub const BRANCH_TAG: u8 = 0x01;

/// Extract bit `i` of `key`, MSB-first: bit 0 is the most-significant bit of
/// `key[0]`. Caller must ensure `i < 8 * key.len()`.
#[inline]
pub fn bit(key: &[u8], i: usize) -> u8 {
    (key[i >> 3] >> (7 - (i & 7))) & 1
}

/// Leaf-node hash: `D(LEAF_TAG || key || value_root)`. Commits the full key
/// (canonicality + non-membership) and the value root (via [`MissingOr`]).
#[inline]
pub fn leaf_hash<D: Digest<OutputSize = U32>>(key: &[u8], value_root: &[u8; 32]) -> [u8; 32] {
    let mut hasher = D::new();
    hasher.update([LEAF_TAG]);
    hasher.update(key);
    hasher.update(value_root);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(out.as_slice());
    arr
}

/// Branch-node hash: `D(BRANCH_TAG || left || right)`.
#[inline]
pub fn branch_hash<D: Digest<OutputSize = U32>>(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = D::new();
    hasher.update([BRANCH_TAG]);
    hasher.update(left);
    hasher.update(right);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(out.as_slice());
    arr
}

/// Compute the radix root of the (sorted, distinct-key) entry slice `s`,
/// whose keys all share the first `depth` bits. Recursion depth is bounded
/// by `KEY_BITS = 8 * KEY_BYTES`.
fn radix_node<D, V, const KEY_BYTES: usize>(s: &[Entry<V, KEY_BYTES>], depth: usize) -> [u8; 32]
where
    D: Digest<OutputSize = U32>,
    V: HashTreeRoot,
{
    // EMPTY subtree.
    if s.is_empty() {
        return EMPTY;
    }
    // SINGLETON: collapse to a leaf wherever the subtree narrows to one key.
    if s.len() == 1 {
        return leaf_hash::<D>(&s[0].0, &s[0].1.hash_tree_root::<D>());
    }
    // Distinct keys must diverge before bit KEY_BITS. Reaching the maximum
    // depth with ≥ 2 entries means duplicate keys (a violated invariant);
    // be loud in debug and deterministic (never an out-of-bounds `bit`
    // read) in release.
    if depth >= KEY_BYTES * 8 {
        debug_assert!(false, "RadixMap: duplicate keys at maximum depth");
        return leaf_hash::<D>(&s[0].0, &s[0].1.hash_tree_root::<D>());
    }
    // Within a subtree sharing the first `depth` bits, the strictly-ascending
    // key order makes `bit(depth) == 0` entries a prefix of the slice.
    let mid = s.partition_point(|(k, _)| bit(k, depth) == 0);
    let left = radix_node::<D, V, KEY_BYTES>(&s[..mid], depth + 1);
    let right = radix_node::<D, V, KEY_BYTES>(&s[mid..], depth + 1);
    branch_hash::<D>(&left, &right)
}

/// A structurally-compressed sparse binary radix merkle map (option "b").
///
/// Keys are `[u8; KEY_BYTES]` (MSB-first); values are `V: HashTreeRoot`. The
/// root is canonical and binding (see the module docs). Storage is the
/// strictly-ascending sorted set of `(key, MissingOr<V>)` entries; the tree
/// structure is recomputed on [`HashTreeRoot::hash_tree_root`].
pub struct RadixMap<V, const KEY_BYTES: usize> {
    /// Sorted strictly-ascending by key (lexicographic byte order ==
    /// MSB-first bit order). Sole source of truth.
    entries: Vec<([u8; KEY_BYTES], MissingOr<V>)>,
}

impl<V, const KEY_BYTES: usize> RadixMap<V, KEY_BYTES> {
    /// Compile-time guard: a zero-width key is nonsensical.
    const ASSERT_NONZERO: () = assert!(KEY_BYTES >= 1, "RadixMap KEY_BYTES must be >= 1");

    /// Number of significant key bits (`8 * KEY_BYTES`).
    pub const KEY_BITS: usize = KEY_BYTES * 8;

    /// Build an empty map.
    pub fn new() -> Self {
        let () = Self::ASSERT_NONZERO;
        Self {
            entries: Vec::new(),
        }
    }

    /// Number of entries (the map's "length" is just its key count).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` iff the map holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up an entry by key. O(log n).
    pub fn get(&self, key: &[u8; KEY_BYTES]) -> Option<&MissingOr<V>> {
        match self
            .entries
            .binary_search_by(|(k, _)| k.as_slice().cmp(key.as_slice()))
        {
            Ok(pos) => Some(&self.entries[pos].1),
            Err(_) => None,
        }
    }

    /// Insert (or overwrite) an entry, keeping the sorted invariant.
    /// Returns the previous value at `key`, if any. O(n) (sorted shift).
    pub fn insert(&mut self, key: [u8; KEY_BYTES], value: MissingOr<V>) -> Option<MissingOr<V>> {
        match self
            .entries
            .binary_search_by(|(k, _)| k.as_slice().cmp(key.as_slice()))
        {
            Ok(pos) => Some(core::mem::replace(&mut self.entries[pos].1, value)),
            Err(pos) => {
                self.entries.insert(pos, (key, value));
                None
            }
        }
    }

    /// Remove the entry at `key`, returning its previous value if present.
    pub fn remove(&mut self, key: &[u8; KEY_BYTES]) -> Option<MissingOr<V>> {
        match self
            .entries
            .binary_search_by(|(k, _)| k.as_slice().cmp(key.as_slice()))
        {
            Ok(pos) => Some(self.entries.remove(pos).1),
            Err(_) => None,
        }
    }

    /// Iterate entries in ascending key order.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8; KEY_BYTES], &MissingOr<V>)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }

    /// Mutably iterate entries in ascending key order (e.g. to resolve `Ref`
    /// targets after settle), preserving the key set / order.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&[u8; KEY_BYTES], &mut MissingOr<V>)> {
        self.entries.iter_mut().map(|(k, v)| (&*k, v))
    }
}

impl<V, const KEY_BYTES: usize> Default for RadixMap<V, KEY_BYTES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: fmt::Debug, const KEY_BYTES: usize> fmt::Debug for RadixMap<V, KEY_BYTES> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RadixMap")
            .field("key_bytes", &KEY_BYTES)
            .field("entries", &self.entries.len())
            .finish()
    }
}

impl<V: Clone, const KEY_BYTES: usize> Clone for RadixMap<V, KEY_BYTES> {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
        }
    }
}

impl<V: PartialEq, const KEY_BYTES: usize> PartialEq for RadixMap<V, KEY_BYTES> {
    fn eq(&self, other: &Self) -> bool {
        if self.entries.len() != other.entries.len() {
            return false;
        }
        // Both sorted by key, so element-wise comparison suffices.
        self.entries
            .iter()
            .zip(other.entries.iter())
            .all(|((ka, va), (kb, vb))| ka == kb && va == vb)
    }
}

impl<V: Eq, const KEY_BYTES: usize> Eq for RadixMap<V, KEY_BYTES> {}

impl<V: HashTreeRoot, const KEY_BYTES: usize> HashTreeRoot for RadixMap<V, KEY_BYTES> {
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        radix_node::<D, V, KEY_BYTES>(&self.entries, 0)
    }
}

// --------------------------------------------------------------------------
// Compact membership / non-membership proofs.
//
// A proof is for a single queried key `q`. The verifier folds `q`'s path
// from the terminal up to the root using the (RLE-compressed) co-path
// siblings; EMPTY siblings are omitted and spliced back as the public
// constant. Both membership and non-membership are supported and complete:
// every absent key reaches either an EMPTY terminal or a diverging leaf at a
// well-defined depth (no unary-skip gap). Proofs are NOT unique — for some
// absent keys both an EMPTY and a diverging-leaf terminal can be produced —
// but every accepted proof is sound under collision resistance.
// --------------------------------------------------------------------------

/// The node `q`'s walk terminates on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RadixTerminal<V, const KEY_BYTES: usize> {
    /// Membership: a leaf whose key is the queried key, carrying its value.
    Leaf { value: MissingOr<V> },
    /// Non-membership: `q`'s path reaches an empty subtree.
    Empty,
    /// Non-membership: `q`'s path reaches a leaf for a *different* key that
    /// shares `q`'s consumed prefix.
    DivergingLeaf {
        other_key: [u8; KEY_BYTES],
        other_value_root: [u8; 32],
    },
}

/// A compact proof of (non-)membership of a single key in a [`RadixMap`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadixProof<V, const KEY_BYTES: usize> {
    /// Depth of the terminal node = number of branch levels on `q`'s path.
    pub term_depth: u32,
    /// Non-empty co-path siblings, `(level, hash)`, strictly ascending by
    /// `level`, all `< term_depth`. Absent levels are the EMPTY constant.
    pub siblings: Vec<(u32, [u8; 32])>,
    /// The node `q`'s walk terminates on.
    pub terminal: RadixTerminal<V, KEY_BYTES>,
}

/// Outcome of a verified proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadixVerdict {
    /// The queried key is present (its value is in the proof's terminal).
    Present,
    /// The queried key is absent.
    Absent,
}

/// Count of leading equal bits (MSB-first) shared by `a` and `b`.
fn shared_prefix_bits(a: &[u8], b: &[u8]) -> usize {
    let mut n = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        let d = x ^ y;
        if d == 0 {
            n += 8;
        } else {
            n += d.leading_zeros() as usize;
            break;
        }
    }
    n
}

impl<V: HashTreeRoot + Clone, const KEY_BYTES: usize> RadixMap<V, KEY_BYTES> {
    /// Produce a compact (non-)membership proof for `key`.
    pub fn prove<D: Digest<OutputSize = U32>>(
        &self,
        key: &[u8; KEY_BYTES],
    ) -> RadixProof<V, KEY_BYTES> {
        let mut siblings = Vec::new();
        let (terminal, term_depth) =
            prove_walk::<D, V, KEY_BYTES>(&self.entries, key, 0, &mut siblings);
        RadixProof {
            term_depth: term_depth as u32,
            siblings,
            terminal,
        }
    }
}

/// Walk `q`'s path through the (sorted) entry slice, collecting non-empty
/// co-path siblings; returns the terminal and its depth.
fn prove_walk<D, V, const KEY_BYTES: usize>(
    s: &[Entry<V, KEY_BYTES>],
    q: &[u8; KEY_BYTES],
    depth: usize,
    siblings: &mut Vec<(u32, [u8; 32])>,
) -> (RadixTerminal<V, KEY_BYTES>, usize)
where
    D: Digest<OutputSize = U32>,
    V: HashTreeRoot + Clone,
{
    if s.is_empty() {
        return (RadixTerminal::Empty, depth);
    }
    if s.len() == 1 || depth >= KEY_BYTES * 8 {
        let (k, v) = &s[0];
        return if k.as_slice() == q.as_slice() {
            (RadixTerminal::Leaf { value: v.clone() }, depth)
        } else {
            (
                RadixTerminal::DivergingLeaf {
                    other_key: *k,
                    other_value_root: v.hash_tree_root::<D>(),
                },
                depth,
            )
        };
    }
    let mid = s.partition_point(|(k, _)| bit(k, depth) == 0);
    let (left, right) = s.split_at(mid);
    let (chosen, sibling_slice) = if bit(q, depth) == 0 {
        (left, right)
    } else {
        (right, left)
    };
    let sib_root = radix_node::<D, V, KEY_BYTES>(sibling_slice, depth + 1);
    if sib_root != EMPTY {
        siblings.push((depth as u32, sib_root));
    }
    prove_walk::<D, V, KEY_BYTES>(chosen, q, depth + 1, siblings)
}

/// Verify a [`RadixProof`] for `key` against `root`. Returns the verdict, or
/// `None` if the proof is malformed or does not reconstruct `root`.
///
/// Hardening (all enforced before accepting): `term_depth ≤ KEY_BITS`;
/// sibling levels strictly ascending, distinct, and all `< term_depth`; a
/// `DivergingLeaf` must carry `other_key ≠ key` sharing `key`'s
/// `term_depth`-bit prefix. The terminal depth is soft-authenticated by the
/// fold (a wrong depth cannot reconstruct `root` without a collision).
pub fn verify<D: Digest<OutputSize = U32>, V: HashTreeRoot, const KEY_BYTES: usize>(
    root: &[u8; 32],
    key: &[u8; KEY_BYTES],
    proof: &RadixProof<V, KEY_BYTES>,
) -> Option<RadixVerdict> {
    let td = proof.term_depth as usize;
    if td > KEY_BYTES * 8 {
        return None;
    }
    // Sibling levels: strictly ascending, distinct, all < term_depth.
    let mut prev: Option<u32> = None;
    for (lvl, _) in &proof.siblings {
        if (*lvl as usize) >= td {
            return None;
        }
        if let Some(p) = prev
            && *lvl <= p
        {
            return None;
        }
        prev = Some(*lvl);
    }
    // Terminal node hash + verdict.
    let (mut cur, verdict) = match &proof.terminal {
        RadixTerminal::Leaf { value } => (
            leaf_hash::<D>(key, &value.hash_tree_root::<D>()),
            RadixVerdict::Present,
        ),
        RadixTerminal::Empty => (EMPTY, RadixVerdict::Absent),
        RadixTerminal::DivergingLeaf {
            other_key,
            other_value_root,
        } => {
            if other_key.as_slice() == key.as_slice() {
                return None;
            }
            if shared_prefix_bits(other_key, key) < td {
                return None;
            }
            (
                leaf_hash::<D>(other_key, other_value_root),
                RadixVerdict::Absent,
            )
        }
    };
    // Fold leaf-ward → root-ward, splicing EMPTY for absent sibling levels.
    for level in (0..td).rev() {
        let sib = proof
            .siblings
            .iter()
            .find(|(l, _)| *l as usize == level)
            .map(|(_, h)| *h)
            .unwrap_or(EMPTY);
        cur = if bit(key, level) == 0 {
            branch_hash::<D>(&cur, &sib)
        } else {
            branch_hash::<D>(&sib, &cur)
        };
    }
    if &cur == root { Some(verdict) } else { None }
}

// --------------------------------------------------------------------------
// Wire format: (entries_offset: u32 = 4, List<(ByteVector[KEY_BYTES], MissingOr<V>)>).
//
// Mirrors `SparseList`'s entry-list encoding with the u64 key replaced by a
// fixed KEY_BYTES key and the per-entry inner value-offset = KEY_BYTES + 4.
// There is no leading `len` (a map has no logical length).
// --------------------------------------------------------------------------

impl<V: Encode, const KEY_BYTES: usize> Encode for RadixMap<V, KEY_BYTES> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }
    fn ssz_bytes_len(&self) -> usize {
        // 4 (entries_offset) + offset table (n*4) + per-entry (key + 4 + value).
        let n = self.entries.len();
        let var: usize = self.entries.iter().map(|(_, v)| v.ssz_bytes_len()).sum();
        4 + n * (BYTES_PER_LENGTH_OFFSET + KEY_BYTES + BYTES_PER_LENGTH_OFFSET) + var
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // entries_offset = 4.
        buf.extend_from_slice(&4u32.to_le_bytes());
        encode_entries_list::<V, KEY_BYTES>(&self.entries, buf);
    }
}

fn encode_entries_list<V: Encode, const KEY_BYTES: usize>(
    entries: &[Entry<V, KEY_BYTES>],
    buf: &mut Vec<u8>,
) {
    let n = entries.len();
    let header_size = n * BYTES_PER_LENGTH_OFFSET;
    let start = buf.len();
    buf.resize(start + header_size, 0u8);

    let mut running = header_size as u32;
    for (i, (key, val)) in entries.iter().enumerate() {
        let off_pos = start + i * BYTES_PER_LENGTH_OFFSET;
        buf[off_pos..off_pos + 4].copy_from_slice(&running.to_le_bytes());

        let entry_start = buf.len();
        // key (KEY_BYTES fixed)
        buf.extend_from_slice(key);
        // value-offset within this entry container = KEY_BYTES + 4
        buf.extend_from_slice(&((KEY_BYTES + BYTES_PER_LENGTH_OFFSET) as u32).to_le_bytes());
        // value payload
        val.ssz_append(buf);

        let entry_end = buf.len();
        running = running
            .checked_add((entry_end - entry_start) as u32)
            .expect("ssz offset overflow");
    }
}

impl<V: Decode, const KEY_BYTES: usize> Decode for RadixMap<V, KEY_BYTES> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < 4 {
            return Err(DecodeError::UnexpectedEof {
                expected: 4,
                actual: bytes.len(),
            });
        }
        let entries_offset = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        if entries_offset != 4 {
            return Err(DecodeError::InvalidOffset {
                offset: entries_offset,
                len: bytes.len(),
                fixed: 4,
            });
        }
        let entries = decode_entries_list::<V, KEY_BYTES>(&bytes[4..])?;
        // Enforce strictly-ascending keys (rejects duplicates + bad order).
        let mut prev: Option<&[u8; KEY_BYTES]> = None;
        for (k, _) in &entries {
            if let Some(p) = prev
                && k.as_slice() <= p.as_slice()
            {
                return Err(DecodeError::NotSorted);
            }
            prev = Some(k);
        }
        Ok(Self { entries })
    }
}

fn decode_entries_list<V: Decode, const KEY_BYTES: usize>(
    bytes: &[u8],
) -> Result<Vec<Entry<V, KEY_BYTES>>, DecodeError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() < BYTES_PER_LENGTH_OFFSET {
        return Err(DecodeError::UnexpectedEof {
            expected: BYTES_PER_LENGTH_OFFSET,
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
    let mut offsets = Vec::with_capacity(n + 1);
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

    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let entry = &bytes[offsets[i]..offsets[i + 1]];
        // key (KEY_BYTES) + value-offset (4, must be KEY_BYTES+4) + MissingOr payload.
        if entry.len() < KEY_BYTES + BYTES_PER_LENGTH_OFFSET {
            return Err(DecodeError::UnexpectedEof {
                expected: KEY_BYTES + BYTES_PER_LENGTH_OFFSET,
                actual: entry.len(),
            });
        }
        let mut key = [0u8; KEY_BYTES];
        key.copy_from_slice(&entry[0..KEY_BYTES]);
        let value_offset = u32::from_le_bytes(
            entry[KEY_BYTES..KEY_BYTES + BYTES_PER_LENGTH_OFFSET]
                .try_into()
                .unwrap(),
        ) as usize;
        if value_offset != KEY_BYTES + BYTES_PER_LENGTH_OFFSET {
            return Err(DecodeError::InvalidOffset {
                offset: value_offset,
                len: entry.len(),
                fixed: KEY_BYTES + BYTES_PER_LENGTH_OFFSET,
            });
        }
        let value = MissingOr::<V>::from_ssz_bytes(&entry[KEY_BYTES + BYTES_PER_LENGTH_OFFSET..])?;
        out.push((key, value));
    }
    Ok(out)
}

// --------------------------------------------------------------------------
// rkyv: hand-rolled via delegation to `RadixMapRepr` (mirroring
// `SparseListRepr`). On deserialize we re-sort the entries so the in-memory
// canonical (strictly-ascending) order is restored regardless of the
// archived order — a defensive guard against a non-canonical blob.
// --------------------------------------------------------------------------

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct RadixMapRepr<V, const KEY_BYTES: usize>
where
    V: rkyv::Archive,
    MissingOr<V>: rkyv::Archive,
{
    pub entries: Vec<([u8; KEY_BYTES], MissingOr<V>)>,
}

impl<V, const KEY_BYTES: usize> rkyv::Archive for RadixMap<V, KEY_BYTES>
where
    V: rkyv::Archive + Clone,
    MissingOr<V>: rkyv::Archive,
{
    type Archived = <RadixMapRepr<V, KEY_BYTES> as rkyv::Archive>::Archived;
    type Resolver = <RadixMapRepr<V, KEY_BYTES> as rkyv::Archive>::Resolver;

    fn resolve(&self, resolver: Self::Resolver, out: rkyv::Place<Self::Archived>) {
        let repr = RadixMapRepr {
            entries: self.entries.clone(),
        };
        <RadixMapRepr<V, KEY_BYTES> as rkyv::Archive>::resolve(&repr, resolver, out)
    }
}

impl<V, S, const KEY_BYTES: usize> rkyv::Serialize<S> for RadixMap<V, KEY_BYTES>
where
    V: rkyv::Archive + Clone,
    MissingOr<V>: rkyv::Archive,
    RadixMapRepr<V, KEY_BYTES>: rkyv::Serialize<S>,
    S: rkyv::rancor::Fallible + ?Sized,
{
    fn serialize(
        &self,
        serializer: &mut S,
    ) -> Result<Self::Resolver, <S as rkyv::rancor::Fallible>::Error> {
        let repr = RadixMapRepr {
            entries: self.entries.clone(),
        };
        <RadixMapRepr<V, KEY_BYTES> as rkyv::Serialize<S>>::serialize(&repr, serializer)
    }
}

impl<V, D, const KEY_BYTES: usize> rkyv::Deserialize<RadixMap<V, KEY_BYTES>, D>
    for <RadixMapRepr<V, KEY_BYTES> as rkyv::Archive>::Archived
where
    V: rkyv::Archive + Clone,
    MissingOr<V>: rkyv::Archive,
    <RadixMapRepr<V, KEY_BYTES> as rkyv::Archive>::Archived:
        rkyv::Deserialize<RadixMapRepr<V, KEY_BYTES>, D>,
    D: rkyv::rancor::Fallible + ?Sized,
{
    fn deserialize(
        &self,
        deserializer: &mut D,
    ) -> Result<RadixMap<V, KEY_BYTES>, <D as rkyv::rancor::Fallible>::Error> {
        let repr: RadixMapRepr<V, KEY_BYTES> =
            rkyv::Deserialize::<RadixMapRepr<V, KEY_BYTES>, D>::deserialize(self, deserializer)?;
        let mut entries = repr.entries;
        // Restore the canonical strictly-ascending order (defensive against a
        // non-canonically-ordered archived blob). Duplicate keys would be a
        // corrupt blob; `radix_node` handles them deterministically without
        // panicking.
        entries.sort_by(|(a, _), (b, _)| a.as_slice().cmp(b.as_slice()));
        Ok(RadixMap { entries })
    }
}
