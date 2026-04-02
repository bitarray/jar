//! PVM blob emitter — produces standard program blobs from PVM code.
//!
//! Implements the standard program format (GP eq A.38) and the
//! inner deblob format (GP eq A.2).

use javm::program::{CodeBlobHeader, ProgramHeader};
use scale::{Encode, U24};

/// Pack a bitmask array (one byte per bit, 0 or 1) into packed bytes (LSB first).
/// GP eq C.9: bit i is at byte i/8, position i%8.
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

/// Build the inner code blob (deblob format, GP eq A.2):
/// `E₄(|j|) ⌢ E₁(z) ⌢ E₄(|c|) ⌢ E_z(j) ⌢ E(c) ⌢ packed_bitmask`
pub fn build_code_blob(code: &[u8], bitmask: &[u8], jump_table: &[u32]) -> Vec<u8> {
    assert_eq!(
        code.len(),
        bitmask.len(),
        "code and bitmask must have same length"
    );

    // Determine jump table entry encoding size (z)
    let z: u8 = if jump_table.is_empty() {
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

    let header = CodeBlobHeader {
        jump_len: jump_table.len() as u32,
        entry_size: z,
        code_len: code.len() as u32,
    };

    let mut blob = header.encode();

    // E_z(j) — jump table entries, z bytes each, LE
    for &entry in jump_table {
        let bytes = entry.to_le_bytes();
        blob.extend_from_slice(&bytes[..z as usize]);
    }

    // E(c) — code bytes
    blob.extend_from_slice(code);

    // packed bitmask
    blob.extend_from_slice(&pack_bitmask(bitmask));

    blob
}

/// Build a complete standard program blob (GP eq A.38):
/// `E₃(|o|) ⌢ E₃(|w|) ⌢ E₂(z) ⌢ E₃(s) ⌢ o ⌢ w ⌢ E₄(|c|) ⌢ code_blob`
pub fn build_standard_program(
    ro_data: &[u8],
    rw_data: &[u8],
    heap_pages: u16,
    stack_size: u32,
    code: &[u8],
    bitmask: &[u8],
    jump_table: &[u32],
) -> Vec<u8> {
    let code_blob = build_code_blob(code, bitmask, jump_table);

    let header = ProgramHeader {
        ro_size: U24::new(ro_data.len() as u32),
        rw_size: U24::new(rw_data.len() as u32),
        heap_pages,
        stack_size: U24::new(stack_size),
    };

    let mut program = header.encode();

    // o — read-only data
    program.extend_from_slice(ro_data);

    // w — read-write data
    program.extend_from_slice(rw_data);

    // E₄(|c|) — code blob length (4 bytes LE)
    (code_blob.len() as u32).encode_to(&mut program);

    // code blob (deblob format)
    program.extend_from_slice(&code_blob);

    program
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_bitmask() {
        // All ones for 3 bits
        assert_eq!(pack_bitmask(&[1, 1, 1]), vec![0x07]);
        // Alternating for 8 bits
        assert_eq!(pack_bitmask(&[1, 0, 1, 0, 1, 0, 1, 0]), vec![0x55]);
        // 9 bits → 2 bytes
        assert_eq!(pack_bitmask(&[1, 0, 1, 0, 1, 0, 1, 0, 1]), vec![0x55, 0x01]);
    }

    #[test]
    fn test_build_code_blob_minimal() {
        // 3 instructions: trap, fallthrough, trap
        let code = vec![0, 1, 0];
        let bitmask = vec![1, 1, 1];
        let jump_table = vec![];

        let blob = build_code_blob(&code, &bitmask, &jump_table);

        // Parse: E₄(0), E₁(1), E₄(3), [no jump entries], code, packed_bitmask
        assert_eq!(&blob[0..4], &[0, 0, 0, 0]); // |j| = 0 as u32 LE
        assert_eq!(blob[4], 1); // z = 1
        assert_eq!(&blob[5..9], &[3, 0, 0, 0]); // |c| = 3 as u32 LE
        assert_eq!(&blob[9..12], &[0, 1, 0]); // code
        assert_eq!(blob[12], 0x07); // bitmask: 111 packed
    }

    #[test]
    fn test_build_standard_program_round_trip() {
        let code = vec![0, 1, 0];
        let bitmask = vec![1, 1, 1];
        let blob = build_standard_program(&[], &[], 0, 4096, &code, &bitmask, &[]);

        // Should be loadable by PVM
        let pvm = javm::program::initialize_program(&blob, &[], 1000);
        assert!(pvm.is_some(), "Standard program blob should be loadable");
    }
}
