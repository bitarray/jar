//! Encode/decode round-trips and malformed-input rejection.

use nub_program::abi::PAGE_SIZE;
use nub_program::{DecodeError, Endpoint, InvalidProgram, MAGIC, ProgramBlob, Regions};
use std::collections::BTreeMap;

fn sample() -> ProgramBlob {
    let regions = Regions {
        stack_pages: 4,
        ro_pages: 2,
        rw_pages: 1,
        heap_pages: 16,
    };
    let endpoints = BTreeMap::from([
        (
            0,
            Endpoint {
                entry_pc: 0x40,
                arg_registers: 1,
                arg_meta: 2,
                initial_regs: BTreeMap::from([(1, regions.stack_top()), (7, 0xdead_beef)]),
            },
        ),
        (
            255,
            Endpoint {
                entry_pc: 0x80,
                arg_registers: 0,
                arg_meta: 0,
                initial_regs: BTreeMap::from([(1, regions.stack_top())]),
            },
        ),
    ]);
    ProgramBlob::new(
        (0..64u8).collect(),
        regions,
        vec![0xAB; 300],
        vec![0xCD; 17],
        endpoints,
    )
    .expect("valid")
}

#[test]
fn round_trips_exactly() {
    let blob = sample();
    let decoded = ProgramBlob::from_bytes(&blob.to_bytes()).expect("decode");
    assert_eq!(decoded, blob);
}

#[test]
fn round_trips_a_blob_with_only_a_stack() {
    let blob = ProgramBlob::new(
        vec![0x13, 0x00, 0x00, 0x00],
        Regions {
            stack_pages: 1,
            ..Default::default()
        },
        vec![],
        vec![],
        BTreeMap::from([(0, Endpoint::default())]),
    )
    .expect("valid");
    assert_eq!(ProgramBlob::from_bytes(&blob.to_bytes()).unwrap(), blob);
}

/// The whole reason the format trims: a `.bss`-heavy program must not
/// pay for its zeros on disk, yet must decode back to full pages.
#[test]
fn trailing_zero_pages_are_trimmed_on_the_wire_but_restored_on_decode() {
    let regions = Regions {
        stack_pages: 1,
        ro_pages: 0,
        rw_pages: 16, // 64 KiB, all but 4 bytes zero
        heap_pages: 0,
    };
    let mut rw = vec![0u8; 16 * PAGE_SIZE as usize];
    rw[..4].copy_from_slice(&[1, 2, 3, 4]);
    let blob = ProgramBlob::new(
        vec![],
        regions,
        vec![],
        rw,
        BTreeMap::from([(0, Endpoint::default())]),
    )
    .expect("valid");

    let bytes = blob.to_bytes();
    assert!(
        bytes.len() < 128,
        "64 KiB of zeros should not reach the wire, got {} bytes",
        bytes.len()
    );

    let decoded = ProgramBlob::from_bytes(&bytes).expect("decode");
    assert_eq!(decoded.rw_data.len(), 16 * PAGE_SIZE as usize);
    assert_eq!(decoded, blob);
}

#[test]
fn rejects_bad_magic() {
    let mut bytes = sample().to_bytes();
    bytes[0] = b'X';
    assert_eq!(
        ProgramBlob::from_bytes(&bytes).unwrap_err(),
        DecodeError::BadMagic
    );
}

#[test]
fn rejects_an_unsupported_version() {
    let mut bytes = sample().to_bytes();
    bytes[4..6].copy_from_slice(&9999u16.to_le_bytes());
    assert_eq!(
        ProgramBlob::from_bytes(&bytes).unwrap_err(),
        DecodeError::UnsupportedVersion(9999)
    );
}

#[test]
fn rejects_nonzero_reserved_flags() {
    let mut bytes = sample().to_bytes();
    bytes[6..8].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(
        ProgramBlob::from_bytes(&bytes).unwrap_err(),
        DecodeError::ReservedFlags(1)
    );
}

#[test]
fn rejects_truncation_at_every_prefix() {
    let bytes = sample().to_bytes();
    for cut in 0..bytes.len() {
        assert!(
            ProgramBlob::from_bytes(&bytes[..cut]).is_err(),
            "prefix of {cut} bytes decoded, but the blob is {} bytes",
            bytes.len()
        );
    }
    assert!(ProgramBlob::from_bytes(&bytes).is_ok());
}

/// A blob is a whole file; a silently ignored suffix would hide a
/// concatenated or partially-overwritten write.
#[test]
fn rejects_trailing_bytes() {
    let mut bytes = sample().to_bytes();
    bytes.push(0);
    assert_eq!(
        ProgramBlob::from_bytes(&bytes).unwrap_err(),
        DecodeError::TrailingBytes(1)
    );
}

#[test]
fn rejects_a_region_payload_larger_than_its_page_capacity() {
    // ro_pages = 0 but a 1-byte ro payload is declared.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&nub_program::VERSION.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    for v in [1u32, 0, 0, 0] {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    for v in [0u32, 1, 0, 1] {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    bytes.extend_from_slice(&[0, 0, 0, 0]); // endpoint head
    bytes.extend_from_slice(&0u64.to_le_bytes()); // entry_pc
    bytes.push(0xFF); // the over-capacity ro byte
    assert_eq!(
        ProgramBlob::from_bytes(&bytes).unwrap_err(),
        DecodeError::RegionOverflow {
            len: 1,
            capacity: 0
        }
    );
}

#[test]
fn rejects_duplicate_endpoint_indices() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&nub_program::VERSION.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    for v in [1u32, 0, 0, 0] {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    for v in [0u32, 0, 0, 2] {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    for _ in 0..2 {
        bytes.extend_from_slice(&[3, 0, 0, 0]);
        bytes.extend_from_slice(&0u64.to_le_bytes());
    }
    assert_eq!(
        ProgramBlob::from_bytes(&bytes).unwrap_err(),
        DecodeError::DuplicateEndpoint(3)
    );
}

#[test]
fn decode_enforces_blob_invariants() {
    // Well-formed encoding, zero endpoints.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&nub_program::VERSION.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    for v in [1u32, 0, 0, 0] {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    for v in [0u32, 0, 0, 0] {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    assert_eq!(
        ProgramBlob::from_bytes(&bytes).unwrap_err(),
        DecodeError::Invalid(InvalidProgram::NoEndpoints)
    );
}
