//! PVM CODE sub-blob emitter.
//!
//! The transpiler packages translated user code + bitmask + jump
//! table into the [`build_image_code_blob`] format, which is the
//! payload stored in `jar_cap::image::Image::code`. The legacy v1
//! JAR manifest / service-program / data-cap layer was retired with
//! the v3 Image refactor.

/// Determine the minimum byte width needed to encode jump table entries.
fn jump_table_entry_size(jump_table: &[u32]) -> u8 {
    if jump_table.is_empty() {
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
    }
}

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

/// Build the CODE sub-blob for embedding in `Image.code`.
///
/// Layout: `jump_len: u32 LE | entry_size: u8 | code_len: u32 LE |
/// jump_table_entries | code_bytes | packed_bitmask`. This is the
/// same inner format the legacy JAR v1 manifest stored in its
/// CodeCap entry; we expose it directly because v3 Image.code is
/// the new container.
pub fn build_image_code_blob(code: &[u8], bitmask: &[u8], jump_table: &[u32]) -> Vec<u8> {
    assert_eq!(
        code.len(),
        bitmask.len(),
        "code and bitmask must have same length"
    );
    let entry_size = jump_table_entry_size(jump_table);
    let mut blob = Vec::new();
    blob.extend_from_slice(&(jump_table.len() as u32).to_le_bytes());
    blob.push(entry_size);
    blob.extend_from_slice(&(code.len() as u32).to_le_bytes());
    for &entry in jump_table {
        blob.extend_from_slice(&entry.to_le_bytes()[..entry_size as usize]);
    }
    blob.extend_from_slice(code);
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
    fn image_code_blob_layout() {
        let code = vec![0u8, 1, 0];
        let bitmask = vec![1u8, 1, 1];
        let jump_table = vec![0u32];
        let blob = build_image_code_blob(&code, &bitmask, &jump_table);
        // jump_len(4) + entry_size(1) + code_len(4) + 1 jt entry + code + packed bitmask.
        assert_eq!(blob[0..4], 1u32.to_le_bytes());
        assert_eq!(blob[4], 1);
        assert_eq!(blob[5..9], 3u32.to_le_bytes());
    }
}
