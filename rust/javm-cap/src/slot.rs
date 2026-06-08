//! Byte-string keys and slot addressing.
//!
//! [`Key`] is the **byte-string key type** used across the cap model: it names
//! one slot in a single cnode (a *slot key*), and it also keys the kernel's
//! resource tables (a *meter key* / *quota key* — same type, unrelated meaning;
//! see the kernel-assisted Gas/Quota handles). A [`SlotPath`] walks from the
//! root cnode through nested `Cap::CNode` slots down to a target slot.
//!
//! A cnode is a sparse direct map keyed by logical byte strings, not an
//! integer-indexed array — so a slot name is a `Key` (a short byte string),
//! and a path is a `SlotPath` (a sequence of `Key`s). There is no fixed slot
//! count: a cnode is bounded by storage quota, not a compile-time capacity.
//! The V1 ABI uses single-byte keys (`Key::from(b)`), but the type admits
//! arbitrary-length keys for future ABI extensions (e.g.
//! `address -> Cap::Instance`).

use crate::cap::MAX_SOURCE_DEPTH;
use crate::error::CapError;
use smallvec::SmallVec;
use ssz_derive::{Decode, Encode};

/// Inline byte capacity of a [`Key`]. Keys longer than this spill to the
/// heap — there is **no hard cap** (unlike a fixed array). The V1 ABI uses
/// 1-byte keys; 8 bytes inline covers an address-sized key without
/// allocating.
pub const MAX_KEY_LEN: usize = 8;

/// The logical key naming one slot in a single cnode.
///
/// A short byte string used directly as a cnode slot key. Backed by a
/// [`SmallVec`] so the common single-byte key stays inline. The SSZ wire/hash
/// form is **identical to `Vec<u8>`** (forwarded via `#[ssz(transparent)]`), so
/// embedding a `Key` is byte-equivalent to embedding the raw key bytes.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    ssz_derive::HashTreeRoot,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq, PartialOrd, Ord))]
pub struct Key(#[ssz(transparent)] pub SmallVec<[u8; MAX_KEY_LEN]>);

impl Key {
    /// The key's bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// True iff this is the empty key (zero bytes). The empty key is a valid
    /// logical key (`[]`), distinct from `Key::from(0u8)` (`[0]`).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// A best-effort numeric id for **diagnostics only** (error messages):
    /// the V1 single-byte ABI value. A multi-byte key folds to its first
    /// byte (0 if empty). Never use this for identity or lookup — the key's
    /// bytes are the identity.
    pub fn diag_id(&self) -> u32 {
        self.0.first().copied().unwrap_or(0) as u32
    }
}

impl From<u8> for Key {
    /// V1 single-byte ABI: a slot index `b` is the 1-byte key `[b]`.
    fn from(b: u8) -> Self {
        Self(smallvec::smallvec![b])
    }
}

impl From<&[u8]> for Key {
    fn from(bytes: &[u8]) -> Self {
        Self(SmallVec::from_slice(bytes))
    }
}

impl core::ops::Deref for Key {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

/// Pack a [`Key`] (≤ [`MAX_KEY_LEN`] bytes) into two registers for storage in a
/// kernel-assisted unit handle (`Gas{meter_key}` / `Quota{quota_key}`): the key
/// bytes little-endian-packed into the first register, the byte length into the
/// second. Inverse of [`key_from_regs`].
///
/// # Panics
///
/// Panics if the key is longer than [`MAX_KEY_LEN`] (8) bytes — the register
/// packing has no room, and silently truncating would alias two distinct keys.
pub fn key_to_regs(key: &Key) -> (u64, u64) {
    let bytes = key.as_slice();
    assert!(
        bytes.len() <= MAX_KEY_LEN,
        "key_to_regs: key length {} exceeds MAX_KEY_LEN {MAX_KEY_LEN}",
        bytes.len()
    );
    let mut packed = [0u8; 8];
    packed[..bytes.len()].copy_from_slice(bytes);
    (u64::from_le_bytes(packed), bytes.len() as u64)
}

/// Reconstruct a [`Key`] from the `(packed, len)` register pair produced by
/// [`key_to_regs`]. A `len > 8` is clamped to 8 (defensive; `key_to_regs`
/// never emits one).
pub fn key_from_regs(packed: u64, len: u64) -> Key {
    let n = (len as usize).min(MAX_KEY_LEN);
    Key::from(&packed.to_le_bytes()[..n])
}

/// Path from the root cnode through nested cnodes to a slot.
///
/// The sequence of [`Key`]s walked through nested `Cap::CNode` slots; the
/// final key is the target. An empty path is invalid (must address some
/// slot). Backed by a [`SmallVec`] sized to [`MAX_SOURCE_DEPTH`] so a typical
/// (shallow) path stays inline; the SSZ wire/hash form is identical to
/// `Vec<Key>` (forwarded via `#[ssz(transparent)]`).
///
/// Example: `SlotPath::root(Key::from(7))` addresses slot 7 of the root
/// cnode; a two-step path addresses a slot of the `Cap::CNode` held in the
/// first step's slot.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Encode,
    Decode,
    ssz_derive::HashTreeRoot,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct SlotPath(#[ssz(transparent)] pub SmallVec<[Key; MAX_SOURCE_DEPTH]>);

impl SlotPath {
    /// Construct from a single root-cnode slot key.
    pub fn root(key: Key) -> Self {
        Self(smallvec::smallvec![key])
    }

    /// Construct from a list of steps. Returns `Err` if empty.
    pub fn new(steps: impl IntoIterator<Item = Key>) -> Result<Self, CapError> {
        let steps: SmallVec<[Key; MAX_SOURCE_DEPTH]> = steps.into_iter().collect();
        if steps.is_empty() {
            // No dedicated "empty path" error variant; reuse SlotOutOfRange.
            Err(CapError::SlotOutOfRange(0, 0))
        } else {
            Ok(Self(steps))
        }
    }

    /// The steps of this path (non-empty by construction).
    pub fn steps(&self) -> &[Key] {
        &self.0
    }

    /// Number of steps.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True iff this path has no steps. A well-formed path is never empty;
    /// this exists for the `clippy::len_without_is_empty` lint and decode
    /// guards.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// True iff this path addresses a slot in the root cnode (one step).
    pub fn is_root_slot(&self) -> bool {
        self.0.len() == 1
    }

    /// The target slot key (the deepest cnode this path addresses).
    ///
    /// Returns `None` only for a malformed empty path (construction forbids
    /// it; the decode/`image_cap` paths reject empty paths eagerly).
    pub fn target(&self) -> Option<&Key> {
        self.0.last()
    }

    /// All steps before the target — the nested-cnode keys to walk.
    pub fn prefix(&self) -> &[Key] {
        let len = self.0.len();
        &self.0[..len.saturating_sub(1)]
    }
}
