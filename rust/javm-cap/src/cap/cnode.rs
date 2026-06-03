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

use ssz::{MissingOr, RadixMap};

use crate::cache::CapHashOrRef;
use crate::error::CapError;
use crate::hash::{Hash, Hasher};
use crate::slot::Key;

/// Physical radix-key width: a 32-byte digest of the logical key.
pub const CNODE_KEY_BYTES: usize = 32;

/// Radix map backing a CNode: `Hasher(k) -> CapHashOrRef`.
pub type CNodeSlots = RadixMap<CapHashOrRef, CNODE_KEY_BYTES>;

#[derive(
    Clone,
    Debug,
    Default,
    ssz_derive::HashTreeRoot,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct CNodeCap {
    /// Sparse hash-keyed slot table: `Hasher(k) -> CapHashOrRef`. Absent
    /// keys contribute the radix `EMPTY` summary; a `Missing(h)` entry
    /// substitutes losslessly for the value rooting at `h`.
    pub slots: CNodeSlots,
}

impl CNodeCap {
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

    /// Look up the cap bound to logical key `k`. Returns `None` for an
    /// absent key or a `Missing(_)` placeholder (callers needing to tell
    /// "absent" from "missing placeholder" apart inspect `self.slots`).
    pub fn get_key(&self, k: &[u8]) -> Option<CapHashOrRef> {
        match self.slots.get(&Self::key_of(k))? {
            MissingOr::Materialized(t) => Some(t.clone()),
            MissingOr::Missing(_) => None,
        }
    }

    /// Bind logical key `k` to `target`, or clear the binding if `target`
    /// is `None`. Returns the prior materialized target, if any.
    pub fn set_key(&mut self, k: &[u8], target: Option<CapHashOrRef>) -> Option<CapHashOrRef> {
        let key = Self::key_of(k);
        let prior = match self.slots.get(&key) {
            Some(MissingOr::Materialized(t)) => Some(t.clone()),
            Some(MissingOr::Missing(_)) | None => None,
        };
        match target {
            Some(t) => {
                self.slots.insert(key, MissingOr::Materialized(t));
            }
            None => {
                self.slots.remove(&key);
            }
        }
        prior
    }

    /// Take the binding at logical key `k`, leaving it empty. Returns the
    /// prior materialized target (or `None`).
    pub fn take_key(&mut self, k: &[u8]) -> Option<CapHashOrRef> {
        self.set_key(k, None)
    }

    // ---- Key API ----

    /// Look up the slot named by `key`. See [`CNodeCap::get_key`] for the
    /// placeholder semantics.
    pub fn get(&self, key: &Key) -> Option<CapHashOrRef> {
        self.get_key(key.as_slice())
    }

    /// Bind `key` to `target`, or clear it if `None`. Returns the prior
    /// materialized target, if any. The radix map is unbounded, so this is
    /// infallible; the `Result` is retained for ABI compatibility with the
    /// pervasive `?`-using call sites.
    pub fn set(
        &mut self,
        key: &Key,
        target: Option<CapHashOrRef>,
    ) -> Result<Option<CapHashOrRef>, CapError> {
        Ok(self.set_key(key.as_slice(), target))
    }

    /// Take the binding at `key`, leaving it empty. Returns the prior
    /// materialized target (or `None`).
    pub fn take(&mut self, key: &Key) -> Result<Option<CapHashOrRef>, CapError> {
        self.set(key, None)
    }
}
