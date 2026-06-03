//! Integration tests for `javm_cap::cap::image` — the cap-level
//! `ImageCap` / `MemoryMapping`.
//!
//! `MemoryMapping.source` is now a variable-length [`SlotPath`] with a fully
//! derived SSZ codec (was a fixed `[SlotIdx; MAX_SOURCE_DEPTH]` + length with
//! a hand-rolled codec). The eager structural bound on path depth
//! (`≤ MAX_SOURCE_DEPTH`) moved from the `MemoryMapping` wire decode to the
//! `image_cap` deblob — so these tests exercise it there.

use javm_cap::image::{Image, MemoryMapping as WireMapping};
use javm_cap::{ImageConvertError, Key, MAX_SOURCE_DEPTH, MemoryMapping, SlotPath};
use ssz::{Decode as _, Encode as _};
use std::collections::BTreeMap;

#[test]
fn mapping_ssz_roundtrips() {
    let m = MemoryMapping {
        start: 0x1000,
        size: 0x2000,
        source: SlotPath::new([Key::from(7u8), Key::from(&[3u8, 9][..])]).unwrap(),
    };
    let bytes = m.as_ssz_bytes();
    let back = MemoryMapping::from_ssz_bytes(&bytes).unwrap();
    assert_eq!(m, back);
    assert_eq!(back.path().len(), 2);
    assert_eq!(back.path()[0], Key::from(7u8));
}

/// Build a minimal host `Image` with a single mapping whose `source` path has
/// `depth` steps (each a distinct 1-byte key).
fn image_with_source_depth(depth: usize) -> Image {
    let steps: Vec<Key> = (0..depth).map(|i| Key::from(i as u8)).collect();
    let source = SlotPath(steps.into_iter().collect());
    let mut img = Image::empty();
    img.memory_mappings.push(WireMapping {
        start: javm_cap::layout::DATA_BASE as u64,
        size: 0x1000,
        source,
    });
    img
}

#[test]
fn image_cap_rejects_empty_source_path() {
    let mut img = Image::empty();
    img.memory_mappings.push(WireMapping {
        start: javm_cap::layout::DATA_BASE as u64,
        size: 0x1000,
        // Directly construct an empty path (bypassing `SlotPath::new`, which
        // forbids it) to exercise the deblob guard.
        source: SlotPath(Default::default()),
    });
    let err = javm_cap::image_cap(&img, &[], &[]).unwrap_err();
    assert!(matches!(err, ImageConvertError::SourcePathEmpty));
}

#[test]
fn image_cap_rejects_too_deep_source_path() {
    let img = image_with_source_depth(MAX_SOURCE_DEPTH + 1);
    let err = javm_cap::image_cap(&img, &[], &[]).unwrap_err();
    assert!(matches!(err, ImageConvertError::SourcePathTooDeep(d) if d == MAX_SOURCE_DEPTH + 1));
}

#[test]
fn image_cap_accepts_source_path_at_bound() {
    let img = image_with_source_depth(MAX_SOURCE_DEPTH);
    let cap = javm_cap::image_cap(&img, &[], &[]).expect("path at the bound is accepted");
    assert_eq!(cap.mappings.len(), 1);
    assert_eq!(cap.mappings[0].path().len(), MAX_SOURCE_DEPTH);
}

#[test]
fn image_cap_empty_image_has_no_mappings() {
    let img = Image {
        endpoints: BTreeMap::new(),
        ..Image::empty()
    };
    let cap = javm_cap::image_cap(&img, &[], &[]).unwrap();
    assert!(cap.mappings.is_empty());
}
