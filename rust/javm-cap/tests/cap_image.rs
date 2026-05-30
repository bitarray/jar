//! Integration tests for `javm_cap::cap::image` — the cap-level
//! `ImageCap` / `MemoryMapping` (distinct from the SSZ wire-form
//! `javm_cap::image::MemoryMapping` exercised in `tests/image.rs`).
//!
//! Focus: the eager *structural* invariants the deblob must enforce so a
//! malformed Image can neither panic the host nor diverge between engines.

use javm_cap::{MAX_SOURCE_DEPTH, MemoryMapping, SlotIdx};
use ssz::Decode as _;

/// SSZ fixed form of a cap-level `MemoryMapping`:
/// `u64 start || u64 size || MAX_SOURCE_DEPTH×u32 || u8 source_path_len`.
fn mapping_bytes(source_path_len: u8) -> Vec<u8> {
    let mut bytes = vec![0u8; 8 + 8 + MAX_SOURCE_DEPTH * 4 + 1];
    *bytes.last_mut().unwrap() = source_path_len;
    bytes
}

#[test]
fn decode_rejects_oversized_source_path_len() {
    // `source_path_len > MAX_SOURCE_DEPTH` would make `path()` index past
    // the fixed array — reject it at the decode boundary instead.
    let bytes = mapping_bytes((MAX_SOURCE_DEPTH + 1) as u8);
    let err = MemoryMapping::from_ssz_bytes(&bytes).unwrap_err();
    assert!(matches!(err, ssz::DecodeError::BoundExceeded { .. }));

    // The extreme (255) is rejected too, not silently truncated.
    assert!(MemoryMapping::from_ssz_bytes(&mapping_bytes(255)).is_err());
}

#[test]
fn decode_accepts_len_at_the_bound() {
    let m = MemoryMapping::from_ssz_bytes(&mapping_bytes(MAX_SOURCE_DEPTH as u8)).unwrap();
    assert_eq!(m.path().len(), MAX_SOURCE_DEPTH);
}

#[test]
fn path_is_total_for_a_malformed_len() {
    // A hand-built mapping (bypassing decode / `image_cap`) with a bogus
    // length must clamp, never panic the host.
    let m = MemoryMapping {
        start: 0,
        size: 0,
        source_path: [SlotIdx(0); MAX_SOURCE_DEPTH],
        source_path_len: 250,
    };
    assert_eq!(m.path().len(), MAX_SOURCE_DEPTH);
}
