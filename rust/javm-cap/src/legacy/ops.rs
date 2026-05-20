//! Pure-function semantics of MGMT_* operations on cnodes.
//!
//! These functions operate on `&mut dyn CNodeBackend<Cap>` plus a
//! caller-supplied pinned-slot whitelist; they have no notion of
//! execution context (regs, PC, gas). The Vm layer translates ecall
//! invocations into these calls; tests exercise the operations
//! directly without an execution engine.
//!
//! Pinned-slot enforcement is at this layer (not at the backend),
//! because the pinning information is per-Image, not per-cnode.

use super::cap::{CNodeCap, Cap};
use super::cnode::CNodeBackend;
use crate::error::OpError;
use crate::slot::SlotIdx;
use alloc::sync::Arc;

/// Returns true iff `idx` appears in the pinned-slot whitelist.
fn is_pinned(pinned: &[SlotIdx], idx: SlotIdx) -> bool {
    pinned.contains(&idx)
}

/// `MGMT_COPY(src, dst)`: clone the cap at `src` into `dst`.
///
/// - Requires `src` non-empty and `dst` empty.
/// - Neither slot may be pinned.
/// - All five cap kinds are uniformly copyable in v3, so `clone()`
///   suffices; `CNodeCap` shares its `Arc<dyn CNodeBackend>` so the
///   clone is O(1) — mutations to the source or copy require a
///   `snapshot` first (per §9 case (b)).
pub fn mgmt_copy(
    table: &mut dyn CNodeBackend<Cap>,
    pinned: &[SlotIdx],
    src: SlotIdx,
    dst: SlotIdx,
) -> Result<(), OpError> {
    if is_pinned(pinned, src) {
        return Err(OpError::SlotPinned(src.get()));
    }
    if is_pinned(pinned, dst) {
        return Err(OpError::SlotPinned(dst.get()));
    }
    let value = table.get(src)?.ok_or(OpError::SourceEmpty)?.clone();
    if table.get(dst)?.is_some() {
        return Err(OpError::DestinationOccupied);
    }
    table.set(dst, Some(value))?;
    Ok(())
}

/// `MGMT_MOVE(src, dst)`: relocate the cap from `src` to `dst`.
///
/// - Requires `src` non-empty and `dst` empty.
/// - Neither slot may be pinned.
pub fn mgmt_move(
    table: &mut dyn CNodeBackend<Cap>,
    pinned: &[SlotIdx],
    src: SlotIdx,
    dst: SlotIdx,
) -> Result<(), OpError> {
    if is_pinned(pinned, src) {
        return Err(OpError::SlotPinned(src.get()));
    }
    if is_pinned(pinned, dst) {
        return Err(OpError::SlotPinned(dst.get()));
    }
    if table.get(src)?.is_none() {
        return Err(OpError::SourceEmpty);
    }
    if table.get(dst)?.is_some() {
        return Err(OpError::DestinationOccupied);
    }
    let value = table.take(src)?;
    table.set(dst, value)?;
    Ok(())
}

/// `MGMT_DROP(src)`: discard the cap at `src`.
///
/// - Requires `src` non-empty.
/// - Slot may not be pinned.
pub fn mgmt_drop(
    table: &mut dyn CNodeBackend<Cap>,
    pinned: &[SlotIdx],
    src: SlotIdx,
) -> Result<(), OpError> {
    if is_pinned(pinned, src) {
        return Err(OpError::SlotPinned(src.get()));
    }
    if table.get(src)?.is_none() {
        return Err(OpError::SourceEmpty);
    }
    table.take(src)?;
    Ok(())
}

/// `MGMT_CNODE_SWAP(a, b)`: swap the contents of two slots in the
/// same cnode. Either or both slots may be empty.
///
/// - Neither slot may be pinned.
/// - Same-cnode only (the function operates on a single backend).
pub fn mgmt_cnode_swap(
    table: &mut dyn CNodeBackend<Cap>,
    pinned: &[SlotIdx],
    a: SlotIdx,
    b: SlotIdx,
) -> Result<(), OpError> {
    if is_pinned(pinned, a) {
        return Err(OpError::SlotPinned(a.get()));
    }
    if is_pinned(pinned, b) {
        return Err(OpError::SlotPinned(b.get()));
    }
    if a == b {
        // No-op; nothing to swap.
        return Ok(());
    }
    let va = table.take(a)?;
    let vb = table.take(b)?;
    table.set(a, vb)?;
    table.set(b, va)?;
    Ok(())
}

/// `MGMT_CNODE_MINT(dst, size_log)`: mint a fresh empty `Cap::CNode`
/// of `2^size_log` slots and place it at `dst`.
///
/// - `dst` must be empty.
/// - `dst` may not be pinned.
/// - `size_log` constrained by `InMemoryCNode::new` (0..=16).
///
/// In v0 the minted cnode uses the default `InMemoryCNode` backend.
/// A future merkle-backed alternative could be added by passing in
/// a factory function or by parameterizing this op.
pub fn mgmt_cnode_mint(
    table: &mut dyn CNodeBackend<Cap>,
    pinned: &[SlotIdx],
    dst: SlotIdx,
    size_log: u8,
) -> Result<(), OpError> {
    if is_pinned(pinned, dst) {
        return Err(OpError::SlotPinned(dst.get()));
    }
    if table.get(dst)?.is_some() {
        return Err(OpError::DestinationOccupied);
    }
    let fresh = super::cnode::InMemoryCNode::<Cap>::new(size_log)?;
    let cap = Cap::CNode(CNodeCap::new(Arc::new(fresh)));
    table.set(dst, Some(cap))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::cap::{DataCap, ImageCap};
    use super::super::cnode::InMemoryCNode;
    use super::*;

    fn fresh_table() -> InMemoryCNode<Cap> {
        InMemoryCNode::new(4).unwrap() // 16 slots
    }

    fn sample_image_cap(seed: u8) -> Cap {
        Cap::Image(ImageCap {
            content_hash: [seed; 32],
        })
    }

    fn sample_data_cap(seed: u8) -> Cap {
        Cap::Data(DataCap {
            size: 100,
            content_hash: [seed; 32],
        })
    }

    // --- mgmt_copy ---

    #[test]
    fn copy_success() {
        let mut t = fresh_table();
        t.set(SlotIdx(2), Some(sample_image_cap(0xAA))).unwrap();
        mgmt_copy(&mut t, &[], SlotIdx(2), SlotIdx(7)).unwrap();
        assert!(t.get(SlotIdx(2)).unwrap().is_some());
        assert!(t.get(SlotIdx(7)).unwrap().is_some());
        assert_eq!(t.get(SlotIdx(2)).unwrap(), t.get(SlotIdx(7)).unwrap());
    }

    #[test]
    fn copy_source_empty_fails() {
        let mut t = fresh_table();
        assert!(matches!(
            mgmt_copy(&mut t, &[], SlotIdx(2), SlotIdx(7)),
            Err(OpError::SourceEmpty)
        ));
    }

    #[test]
    fn copy_destination_occupied_fails() {
        let mut t = fresh_table();
        t.set(SlotIdx(2), Some(sample_image_cap(0xAA))).unwrap();
        t.set(SlotIdx(7), Some(sample_image_cap(0xBB))).unwrap();
        assert!(matches!(
            mgmt_copy(&mut t, &[], SlotIdx(2), SlotIdx(7)),
            Err(OpError::DestinationOccupied)
        ));
    }

    #[test]
    fn copy_pinned_source_fails() {
        let mut t = fresh_table();
        t.set(SlotIdx(2), Some(sample_image_cap(0xAA))).unwrap();
        assert!(matches!(
            mgmt_copy(&mut t, &[SlotIdx(2)], SlotIdx(2), SlotIdx(7)),
            Err(OpError::SlotPinned(2))
        ));
    }

    #[test]
    fn copy_pinned_destination_fails() {
        let mut t = fresh_table();
        t.set(SlotIdx(2), Some(sample_image_cap(0xAA))).unwrap();
        assert!(matches!(
            mgmt_copy(&mut t, &[SlotIdx(7)], SlotIdx(2), SlotIdx(7)),
            Err(OpError::SlotPinned(7))
        ));
    }

    // --- mgmt_move ---

    #[test]
    fn move_success() {
        let mut t = fresh_table();
        t.set(SlotIdx(2), Some(sample_image_cap(0xAA))).unwrap();
        mgmt_move(&mut t, &[], SlotIdx(2), SlotIdx(7)).unwrap();
        assert!(t.get(SlotIdx(2)).unwrap().is_none());
        assert!(t.get(SlotIdx(7)).unwrap().is_some());
    }

    #[test]
    fn move_source_empty_fails() {
        let mut t = fresh_table();
        assert!(matches!(
            mgmt_move(&mut t, &[], SlotIdx(2), SlotIdx(7)),
            Err(OpError::SourceEmpty)
        ));
    }

    #[test]
    fn move_destination_occupied_fails() {
        let mut t = fresh_table();
        t.set(SlotIdx(2), Some(sample_image_cap(0xAA))).unwrap();
        t.set(SlotIdx(7), Some(sample_image_cap(0xBB))).unwrap();
        assert!(matches!(
            mgmt_move(&mut t, &[], SlotIdx(2), SlotIdx(7)),
            Err(OpError::DestinationOccupied)
        ));
    }

    #[test]
    fn move_pinned_slot_fails() {
        let mut t = fresh_table();
        t.set(SlotIdx(2), Some(sample_image_cap(0xAA))).unwrap();
        assert!(matches!(
            mgmt_move(&mut t, &[SlotIdx(2)], SlotIdx(2), SlotIdx(7)),
            Err(OpError::SlotPinned(2))
        ));
    }

    // --- mgmt_drop ---

    #[test]
    fn drop_success() {
        let mut t = fresh_table();
        t.set(SlotIdx(2), Some(sample_image_cap(0xAA))).unwrap();
        mgmt_drop(&mut t, &[], SlotIdx(2)).unwrap();
        assert!(t.get(SlotIdx(2)).unwrap().is_none());
    }

    #[test]
    fn drop_empty_fails() {
        let mut t = fresh_table();
        assert!(matches!(
            mgmt_drop(&mut t, &[], SlotIdx(2)),
            Err(OpError::SourceEmpty)
        ));
    }

    #[test]
    fn drop_pinned_fails() {
        let mut t = fresh_table();
        t.set(SlotIdx(2), Some(sample_image_cap(0xAA))).unwrap();
        assert!(matches!(
            mgmt_drop(&mut t, &[SlotIdx(2)], SlotIdx(2)),
            Err(OpError::SlotPinned(2))
        ));
    }

    // --- mgmt_cnode_swap ---

    #[test]
    fn swap_two_occupied() {
        let mut t = fresh_table();
        t.set(SlotIdx(2), Some(sample_image_cap(0xAA))).unwrap();
        t.set(SlotIdx(7), Some(sample_data_cap(0xBB))).unwrap();
        mgmt_cnode_swap(&mut t, &[], SlotIdx(2), SlotIdx(7)).unwrap();
        // Now slot 2 holds the data cap; slot 7 holds the image cap.
        assert_eq!(
            t.get(SlotIdx(2)).unwrap().unwrap().kind(),
            super::super::cap::CapKind::Data
        );
        assert_eq!(
            t.get(SlotIdx(7)).unwrap().unwrap().kind(),
            super::super::cap::CapKind::Image
        );
    }

    #[test]
    fn swap_with_empty_left() {
        let mut t = fresh_table();
        t.set(SlotIdx(7), Some(sample_data_cap(0xBB))).unwrap();
        mgmt_cnode_swap(&mut t, &[], SlotIdx(2), SlotIdx(7)).unwrap();
        assert!(t.get(SlotIdx(2)).unwrap().is_some());
        assert!(t.get(SlotIdx(7)).unwrap().is_none());
    }

    #[test]
    fn swap_both_empty_succeeds_as_noop() {
        let mut t = fresh_table();
        mgmt_cnode_swap(&mut t, &[], SlotIdx(2), SlotIdx(7)).unwrap();
        assert!(t.get(SlotIdx(2)).unwrap().is_none());
        assert!(t.get(SlotIdx(7)).unwrap().is_none());
    }

    #[test]
    fn swap_pinned_fails() {
        let mut t = fresh_table();
        t.set(SlotIdx(2), Some(sample_image_cap(0xAA))).unwrap();
        assert!(matches!(
            mgmt_cnode_swap(&mut t, &[SlotIdx(7)], SlotIdx(2), SlotIdx(7)),
            Err(OpError::SlotPinned(7))
        ));
    }

    #[test]
    fn swap_same_slot_noop() {
        let mut t = fresh_table();
        t.set(SlotIdx(2), Some(sample_image_cap(0xAA))).unwrap();
        let before = t.get(SlotIdx(2)).unwrap().cloned();
        mgmt_cnode_swap(&mut t, &[], SlotIdx(2), SlotIdx(2)).unwrap();
        assert_eq!(t.get(SlotIdx(2)).unwrap().cloned(), before);
    }

    // --- mgmt_cnode_mint ---

    #[test]
    fn mint_success() {
        let mut t = fresh_table();
        mgmt_cnode_mint(&mut t, &[], SlotIdx(5), 4).unwrap();
        let cap = t.get(SlotIdx(5)).unwrap().unwrap();
        assert_eq!(cap.kind(), super::super::cap::CapKind::CNode);
    }

    #[test]
    fn mint_destination_occupied_fails() {
        let mut t = fresh_table();
        t.set(SlotIdx(5), Some(sample_image_cap(0xAA))).unwrap();
        assert!(matches!(
            mgmt_cnode_mint(&mut t, &[], SlotIdx(5), 4),
            Err(OpError::DestinationOccupied)
        ));
    }

    #[test]
    fn mint_pinned_fails() {
        let mut t = fresh_table();
        assert!(matches!(
            mgmt_cnode_mint(&mut t, &[SlotIdx(5)], SlotIdx(5), 4),
            Err(OpError::SlotPinned(5))
        ));
    }

    #[test]
    fn mint_too_large_size_log_fails() {
        let mut t = fresh_table();
        assert!(mgmt_cnode_mint(&mut t, &[], SlotIdx(5), 20).is_err());
    }
}
