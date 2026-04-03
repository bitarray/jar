//! PVM blob emitter — produces JAR v1 program blobs.

use javm::program::{JAR_MAGIC, ProgramHeader};
use scale::Encode;

/// Pack a bitmask array (one byte per bit, 0 or 1) into packed bytes (LSB first).
pub fn pack_bitmask(bitmask: &[u8]) -> Vec<u8> {
    let packed_len = bitmask.len().div_ceil(8);
    let mut packed = vec![0u8; packed_len];
    for (i, &bit) in bitmask.iter().enumerate() {
        if bit != 0 {
            packed[i / 8] |= 1 << (i % 8);
        }
    }
    packed
}

/// Build a complete JAR v1 program blob.
///
/// Layout: header | ro_data | rw_data | jump_table | code | packed_bitmask
pub fn build_standard_program(
    ro_data: &[u8],
    rw_data: &[u8],
    heap_pages: u32,
    max_heap_pages: u32,
    stack_pages: u32,
    code: &[u8],
    bitmask: &[u8],
    jump_table: &[u32],
) -> Vec<u8> {
    assert_eq!(
        code.len(),
        bitmask.len(),
        "code and bitmask must have same length"
    );

    // Determine jump table entry encoding size (z)
    let entry_size: u8 = if jump_table.is_empty() {
        1
    } else {
        let max_val = jump_table.iter().copied().max().unwrap_or(0);
        if max_val <= 0xFF {
            1
        } else if max_val <= 0xFFFF {
            2
        } else if max_val <= 0xFFFFFF {
            3
        } else {
            4
        }
    };

    let header = ProgramHeader {
        magic: JAR_MAGIC,
        ro_size: ro_data.len() as u32,
        rw_size: rw_data.len() as u32,
        heap_pages,
        max_heap_pages,
        stack_pages,
        jump_len: jump_table.len() as u32,
        entry_size,
        code_len: code.len() as u32,
    };

    let mut blob = header.encode();

    // ro_data
    blob.extend_from_slice(ro_data);

    // rw_data
    blob.extend_from_slice(rw_data);

    // jump table entries (entry_size bytes each, LE)
    for &entry in jump_table {
        let bytes = entry.to_le_bytes();
        blob.extend_from_slice(&bytes[..entry_size as usize]);
    }

    // code bytes
    blob.extend_from_slice(code);

    // packed bitmask
    blob.extend_from_slice(&pack_bitmask(bitmask));

    blob
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_bitmask() {
        assert_eq!(pack_bitmask(&[1, 1, 1]), vec![0x07]);
        assert_eq!(pack_bitmask(&[1, 0, 1, 0, 1, 0, 1, 0]), vec![0x55]);
        assert_eq!(pack_bitmask(&[1, 0, 1, 0, 1, 0, 1, 0, 1]), vec![0x55, 0x01]);
    }

    #[test]
    fn test_build_minimal() {
        let code = vec![0, 1, 0]; // trap, fallthrough, trap
        let bitmask = vec![1, 1, 1];
        let blob = build_standard_program(&[], &[], 0, 0, 1, &code, &bitmask, &[]);

        // Should be loadable by PVM
        let pvm = javm::program::initialize_program(&blob, &[], 100_000);
        assert!(pvm.is_some(), "JAR blob should be loadable");
    }

    #[test]
    fn test_round_trip_with_data() {
        let ro = vec![0xDE, 0xAD];
        let rw = vec![0xBE, 0xEF];
        let code = vec![0, 1, 0];
        let bitmask = vec![1, 1, 1];
        let blob = build_standard_program(&ro, &rw, 1, 1, 1, &code, &bitmask, &[]);

        let pvm = javm::program::initialize_program(&blob, &[], 100_000);
        assert!(pvm.is_some());
    }
}
