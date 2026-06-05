//! `CNodeCap` — CNode cap: a sparse, hash-keyed key→cap map.
//!
//! A CNode is a [`RadixMap`] from `Hasher(k)` to a [`CapHashOrRef`] slot
//! target, where the logical key `k` is a byte string. The structurally-
//! compressed binary radix (EIP-7864 "minimal InternalNodes", no 256-value
//! stem subtree) gives a canonical, shallow commitment to the key→cap set
//! (depth ≈ `log2(entries)` for well-spread digests), with **no fixed
//! capacity bound** — a CNode is bounded by storage quota, not a
//! compile-time slot count, and a single-entry CNode is one leaf at depth 1.
//!
//! A slot is named by a [`Key`] (a short byte string); [`CNodeCap::get`]
//! / [`CNodeCap::set`] / [`CNodeCap::take`] hash the key to its physical
//! radix key. The V1 ABI uses single-byte keys (`Key::from(b)`), but the
//! map admits arbitrary-length keys natively (the same `get`/`set`/`take`
//! surface), so a future ABI can key e.g. `address -> Cap::Instance` with no
//! structural change. The raw `&[u8]` form is exposed via
//! [`CNodeCap::get_key`] / [`CNodeCap::set_key`] / [`CNodeCap::take_key`].
//!
//! The leaf value is **always a cap** ([`CapHashOrRef`]), never raw data —
//! this is what lets a CNode model e.g. `address -> Cap::Instance` for
//! native contracts. A `Missing(h)` placeholder substitutes losslessly for
//! the materialized value whose `hash_tree_root` equals `h`, the
//! load-bearing property for cold-loading a CNode by hash.
//!
//! ## The `O` (owned-payload) parameter
//!
//! `CNodeCap<O>` is generic over the inline `CapHashOrRef::Owned(O)` payload.
//! The default `O = Box<Cap>` is the wire/content-addressed form: the cnode
//! inside a serialised [`Cap`] (`Cap::CNode`, `InstanceCap.root_cnode`) is
//! always `CNodeCap<Box<Cap>>`, so the wire type is unaffected by this
//! parameter. An engine that needs to attach engine-private state to a
//! resident instance instantiates the *running frame's* cnode with a richer
//! payload (e.g. `Box<CachedCap>` in the recompiler) — that payload is
//! deliberately **not** wire-serialisable, so a cache-carrying cnode cannot
//! cross the host/guest boundary or be content-hashed (a compile error, not
//! a runtime panic). See [`CapHashOrRef`] for the gate.

use alloc::boxed::Box;

use ssz::{MissingOr, RadixMap};

use super::Cap;
use crate::cache::CapHashOrRef;
use crate::error::CapError;
use crate::hash::{Hash, Hasher};
use crate::slot::Key;

/// Physical radix-key width: a 32-byte digest of the logical key.
pub const CNODE_KEY_BYTES: usize = 32;

/// Radix map backing a CNode: `Hasher(k) -> CapHashOrRef<O>`.
pub type CNodeSlots<O = Box<Cap>> = RadixMap<CapHashOrRef<O>, CNODE_KEY_BYTES>;

/// CNode cap: a sparse, hash-keyed `key -> CapHashOrRef<O>` map.
///
/// rkyv (the wire form) is derived; the derive adds a `slots: Archive` field
/// bound, which for the wire payload resolves via `CapHashOrRef<Box<Cap>>:
/// Archive` (gated on `Box<Cap>: WireOwned`, a leaf marker — no recursion into
/// `Cap: Archive`). A non-wire payload such as `Box<CachedCap>` does not
/// satisfy the field bound, so a `CNodeCap<Box<CachedCap>>` has no rkyv impl
/// and cannot cross the wire — non-serialisable by construction. `Clone` /
/// `Debug` / `Default` / `HashTreeRoot` are hand-rolled with payload-specific
/// bounds (a blanket derive would over-constrain `Box<Cap>`, which is not
/// `Default`, and `ssz_derive::HashTreeRoot` adds no bound at all, so it would
/// not compile for a generic field).
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct CNodeCap<O = Box<Cap>> {
    /// Sparse hash-keyed slot table: `Hasher(k) -> CapHashOrRef<O>`. Absent
    /// keys contribute the radix `EMPTY` summary; a `Missing(h)` entry
    /// substitutes losslessly for the value rooting at `h`.
    pub slots: CNodeSlots<O>,
}

impl<O> Default for CNodeCap<O> {
    fn default() -> Self {
        Self::new()
    }
}

impl<O: Clone> Clone for CNodeCap<O> {
    fn clone(&self) -> Self {
        Self {
            slots: self.slots.clone(),
        }
    }
}

impl<O: core::fmt::Debug> core::fmt::Debug for CNodeCap<O> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CNodeCap")
            .field("slots", &self.slots)
            .finish()
    }
}

// Hand-rolled to match the `ssz_derive::HashTreeRoot` output for a single
// named field (`merkleize` over the one field root), but with a
// payload-specific bound: only an archivable `O` (the wire payload) admits a
// content hash, so a cache-carrying cnode is non-hashable at compile time.
impl<O> ssz::HashTreeRoot for CNodeCap<O>
where
    CNodeSlots<O>: ssz::HashTreeRoot,
{
    fn hash_tree_root<D: ssz::digest::Digest<OutputSize = ssz::digest::typenum::U32>>(
        &self,
    ) -> [u8; 32] {
        let roots: [[u8; 32]; 1] = [self.slots.hash_tree_root::<D>()];
        ssz::merkleize::<D>(&roots, 1)
    }
}

impl<O> CNodeCap<O> {
    /// Construct an empty CNode (no slots). A CNode grows on demand and is
    /// bounded by storage quota, not a fixed slot count.
    pub fn new() -> Self {
        Self {
            slots: CNodeSlots::new(),
        }
    }

    /// Physical radix key for a logical byte-string key `k`: `Hasher(k)`.
    #[inline]
    pub fn key_of(k: &[u8]) -> [u8; CNODE_KEY_BYTES] {
        <Hasher as Hash>::hash(k)
    }

    // ---- logical byte-string key API ----

    /// Borrow the cap bound to logical key `k` **without cloning** — the
    /// read-only peek used to inspect an `Owned` cap (e.g. read a callee's
    /// `image_hash` to price a CALL) before deciding whether to
    /// [`take_key`](Self::take_key) it. `None` for an absent key or a
    /// `Missing(_)` placeholder.
    pub fn peek_key(&self, k: &[u8]) -> Option<&CapHashOrRef<O>> {
        match self.slots.get(&Self::key_of(k))? {
            MissingOr::Materialized(t) => Some(t),
            MissingOr::Missing(_) => None,
        }
    }

    /// Bind logical key `k` to `target`, or clear the binding if `target`
    /// is `None`. Returns the prior materialized target, if any —
    /// **moved out**, not cloned, so a `CapHashOrRef::Owned(O)` transfers
    /// with no deep copy (the zero-copy cnode move).
    pub fn set_key(
        &mut self,
        k: &[u8],
        target: Option<CapHashOrRef<O>>,
    ) -> Option<CapHashOrRef<O>> {
        let key = Self::key_of(k);
        // `insert` / `remove` hand back the displaced entry by value — no
        // clone of the prior `CapHashOrRef`.
        let old = match target {
            Some(t) => self.slots.insert(key, MissingOr::Materialized(t)),
            None => self.slots.remove(&key),
        };
        match old {
            Some(MissingOr::Materialized(t)) => Some(t),
            Some(MissingOr::Missing(_)) | None => None,
        }
    }

    /// Take the binding at logical key `k`, leaving it empty. Returns the
    /// prior materialized target (or `None`), **moved out** — the
    /// zero-copy half of an `Owned` cnode-to-cnode (or frame-to-frame)
    /// move.
    pub fn take_key(&mut self, k: &[u8]) -> Option<CapHashOrRef<O>> {
        self.set_key(k, None)
    }

    // ---- Key API ----

    /// Bind `key` to `target`, or clear it if `None`. Returns the prior
    /// materialized target, if any. The radix map is unbounded, so this is
    /// infallible; the `Result` is retained for ABI compatibility with the
    /// pervasive `?`-using call sites.
    pub fn set(
        &mut self,
        key: &Key,
        target: Option<CapHashOrRef<O>>,
    ) -> Result<Option<CapHashOrRef<O>>, CapError> {
        Ok(self.set_key(key.as_slice(), target))
    }

    /// Take the binding at `key`, leaving it empty. Returns the prior
    /// materialized target (or `None`).
    pub fn take(&mut self, key: &Key) -> Result<Option<CapHashOrRef<O>>, CapError> {
        self.set(key, None)
    }
}

impl<O: Clone> CNodeCap<O> {
    /// Look up the cap bound to logical key `k`. Returns `None` for an
    /// absent key or a `Missing(_)` placeholder (callers needing to tell
    /// "absent" from "missing placeholder" apart inspect `self.slots`).
    pub fn get_key(&self, k: &[u8]) -> Option<CapHashOrRef<O>> {
        match self.slots.get(&Self::key_of(k))? {
            MissingOr::Materialized(t) => Some(t.clone()),
            MissingOr::Missing(_) => None,
        }
    }

    /// Look up the slot named by `key`. See [`CNodeCap::get_key`] for the
    /// placeholder semantics.
    pub fn get(&self, key: &Key) -> Option<CapHashOrRef<O>> {
        self.get_key(key.as_slice())
    }
}
