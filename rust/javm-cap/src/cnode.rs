//! Capability node ("cnode"): a cap-bearing slot table.
//!
//! v3 specifies two cnode flavors:
//! - The **root cnode** of an Instance: fixed 256 slots.
//! - **Cap::CNode**: variable size `2^k`, mintable via `host_mint_cnode`.
//!
//! Both share the same backend abstraction. The [`CNodeBackend`]
//! trait lets callers swap storage representations:
//! - [`InMemoryCNode`] (default, this crate): all slots materialized
//!   in a `Vec`. Simple; uses 8 KiB at 256 slots, ~32 MiB at 2^20.
//! - Future `MerkleCNode` (not in v0): lazy materialization for
//!   large cnodes, with subtrees stored as hashes until touched.
//!
//! The trait is generic over a slot value type `T`; in practice `T`
//! will be `Cap`, but keeping it generic lets us test the backend
//! independent of the `Cap` enum and lets callers slot in mocks.
//!
//! `hash` is fixed to a 32-byte digest (Blake2b-256-shaped). The
//! `Hash` trait abstraction exists for primitives that callers
//! choose (BMT, image hashes), but at the cnode-backend level we
//! commit to the v3 spec's canonical hash size for dyn-compatibility.

use crate::bmt::Bmt;
use crate::error::CapError;
use crate::hash::{Blake2b256, Hash};
use crate::slot::SlotIdx;

/// 32-byte digest used at the cnode-backend layer. Blake2b-256-shaped.
pub type CnodeHash = [u8; 32];

/// Callback that hashes a single slot value to a 32-byte digest.
/// Provided by the caller; the cnode doesn't know how to hash its
/// element type itself.
pub type SlotHasher<T> = dyn Fn(&T) -> CnodeHash;

/// Trait abstracting cnode storage.
///
/// Constraints `Clone + Debug + 'static` on `T` are at the trait level
/// (not at the method level) so the trait is dyn-compatible.
///
/// Implementations must:
/// - Honor `size_log` in `0..=16` (1 to 65,536 slots).
/// - Reject out-of-range indices with `CapError::SlotOutOfRange`.
/// - Produce a deterministic `hash` of the slot contents.
/// - Provide a `snapshot` that decouples mutations to the original
///   from mutations to the snapshot.
pub trait CNodeBackend<T>: core::fmt::Debug + Send + Sync
where
    T: Clone + core::fmt::Debug + Send + Sync + 'static,
{
    fn size_log(&self) -> u8;

    fn size(&self) -> u32 {
        1u32 << self.size_log()
    }

    fn get(&self, idx: SlotIdx) -> Result<Option<&T>, CapError>;

    fn set(&mut self, idx: SlotIdx, value: Option<T>) -> Result<(), CapError>;

    /// Take the value at `idx`, leaving the slot empty. Returns the
    /// prior value (or `None` if empty).
    fn take(&mut self, idx: SlotIdx) -> Result<Option<T>, CapError>;

    /// Independent copy. Modifications to the copy must not affect
    /// the original.
    fn snapshot(&self) -> Box<dyn CNodeBackend<T>>;

    /// Content hash of the cnode under the caller-supplied per-slot
    /// hasher. Output is 32 bytes (Blake2b-256-shaped).
    fn hash(&self, hasher: &SlotHasher<T>) -> CnodeHash;
}

/// In-memory cnode: all slots materialized in a `Vec<Option<T>>`.
///
/// Initial v3 default. Fine for the root cnode (256 slots) and for
/// modest `Cap::CNode` values. For very large cnodes (size_log > 14
/// ish), use a future `MerkleCNode` backend.
#[derive(Debug, Clone)]
pub struct InMemoryCNode<T: Clone + core::fmt::Debug + Send + Sync + 'static> {
    size_log: u8,
    slots: Vec<Option<T>>,
}

impl<T: Clone + core::fmt::Debug + Send + Sync + 'static> InMemoryCNode<T> {
    /// Construct an empty in-memory cnode with `2^size_log` slots.
    ///
    /// Returns `Err(CapError::InvalidCNodeSize)` if `size_log > 16`.
    pub fn new(size_log: u8) -> Result<Self, CapError> {
        if size_log > 16 {
            return Err(CapError::InvalidCNodeSize(size_log));
        }
        let size = 1usize << size_log;
        let mut slots = Vec::with_capacity(size);
        slots.resize_with(size, || None);
        Ok(Self { size_log, slots })
    }
}

impl<T: Clone + core::fmt::Debug + Send + Sync + 'static> CNodeBackend<T> for InMemoryCNode<T> {
    fn size_log(&self) -> u8 {
        self.size_log
    }

    fn get(&self, idx: SlotIdx) -> Result<Option<&T>, CapError> {
        if !idx.fits(self.size_log) {
            return Err(CapError::SlotOutOfRange(idx.get(), self.size_log));
        }
        Ok(self.slots[idx.as_usize()].as_ref())
    }

    fn set(&mut self, idx: SlotIdx, value: Option<T>) -> Result<(), CapError> {
        if !idx.fits(self.size_log) {
            return Err(CapError::SlotOutOfRange(idx.get(), self.size_log));
        }
        self.slots[idx.as_usize()] = value;
        Ok(())
    }

    fn take(&mut self, idx: SlotIdx) -> Result<Option<T>, CapError> {
        if !idx.fits(self.size_log) {
            return Err(CapError::SlotOutOfRange(idx.get(), self.size_log));
        }
        Ok(self.slots[idx.as_usize()].take())
    }

    fn snapshot(&self) -> Box<dyn CNodeBackend<T>> {
        Box::new(self.clone())
    }

    /// Hash via `Bmt` over per-slot leaf hashes.
    ///
    /// Each slot's leaf is:
    /// - `H(0x00)` for empty (canonical empty-slot tag), or
    /// - `H(0x01 || hasher(value))` for non-empty.
    ///
    /// The leaf-domain tag byte at this layer differs from BMT's
    /// internal-node tag (`0x01`), so leaf vs internal hashes are
    /// distinguishable. The resulting root is the cnode's
    /// content-addressed identity.
    fn hash(&self, hasher: &SlotHasher<T>) -> CnodeHash {
        let mut leaves: Vec<CnodeHash> = Vec::with_capacity(self.slots.len());
        for slot in &self.slots {
            let leaf = match slot {
                None => Blake2b256::hash(&[0x00]),
                Some(v) => {
                    let inner = hasher(v);
                    let mut buf = Vec::with_capacity(1 + inner.len());
                    buf.push(0x01);
                    buf.extend_from_slice(&inner);
                    Blake2b256::hash(&buf)
                }
            };
            leaves.push(leaf);
        }
        Bmt::root::<Blake2b256>(&leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_hasher(t: &u32) -> CnodeHash {
        Blake2b256::hash(&t.to_le_bytes())
    }

    #[test]
    fn size_log_too_large_rejected() {
        assert!(matches!(
            InMemoryCNode::<u32>::new(17),
            Err(CapError::InvalidCNodeSize(17))
        ));
    }

    #[test]
    fn empty_cnode_size_correct() {
        let c: InMemoryCNode<u32> = InMemoryCNode::new(8).unwrap();
        assert_eq!(c.size_log(), 8);
        assert_eq!(c.size(), 256);
    }

    #[test]
    fn get_set_take_round_trip() {
        let mut c: InMemoryCNode<u32> = InMemoryCNode::new(4).unwrap(); // 16 slots
        assert_eq!(c.get(SlotIdx(7)).unwrap(), None);
        c.set(SlotIdx(7), Some(42)).unwrap();
        assert_eq!(c.get(SlotIdx(7)).unwrap(), Some(&42));
        assert_eq!(c.take(SlotIdx(7)).unwrap(), Some(42));
        assert_eq!(c.get(SlotIdx(7)).unwrap(), None);
    }

    #[test]
    fn out_of_range_rejected() {
        let mut c: InMemoryCNode<u32> = InMemoryCNode::new(4).unwrap();
        assert!(matches!(
            c.get(SlotIdx(16)),
            Err(CapError::SlotOutOfRange(16, 4))
        ));
        assert!(matches!(
            c.set(SlotIdx(99), Some(1)),
            Err(CapError::SlotOutOfRange(99, 4))
        ));
    }

    #[test]
    fn snapshot_is_independent() {
        let mut a: InMemoryCNode<u32> = InMemoryCNode::new(4).unwrap();
        a.set(SlotIdx(0), Some(1)).unwrap();
        let mut b = a.snapshot();
        b.set(SlotIdx(0), Some(99)).unwrap();
        assert_eq!(a.get(SlotIdx(0)).unwrap(), Some(&1));
        assert_eq!(b.get(SlotIdx(0)).unwrap(), Some(&99));
    }

    #[test]
    fn hash_is_deterministic() {
        let mut c1: InMemoryCNode<u32> = InMemoryCNode::new(4).unwrap();
        c1.set(SlotIdx(3), Some(7)).unwrap();
        let mut c2: InMemoryCNode<u32> = InMemoryCNode::new(4).unwrap();
        c2.set(SlotIdx(3), Some(7)).unwrap();
        assert_eq!(c1.hash(&dummy_hasher), c2.hash(&dummy_hasher));
    }

    #[test]
    fn hash_changes_with_mutation() {
        let mut c: InMemoryCNode<u32> = InMemoryCNode::new(4).unwrap();
        let h0 = c.hash(&dummy_hasher);
        c.set(SlotIdx(0), Some(1)).unwrap();
        let h1 = c.hash(&dummy_hasher);
        assert_ne!(h0, h1);
    }

    #[test]
    fn hash_distinguishes_empty_from_zero() {
        // A cnode with all slots empty must hash differently from a
        // cnode with slot 0 containing the "zero" value, even though
        // a naive hash that ignored presence/absence would collide.
        let c_empty: InMemoryCNode<u32> = InMemoryCNode::new(2).unwrap();
        let mut c_zero: InMemoryCNode<u32> = InMemoryCNode::new(2).unwrap();
        c_zero.set(SlotIdx(0), Some(0)).unwrap();
        assert_ne!(c_empty.hash(&dummy_hasher), c_zero.hash(&dummy_hasher));
    }
}
