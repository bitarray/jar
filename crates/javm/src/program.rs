//! PVM program loading and standard initialization (Appendix A).
//!
//! Includes `deblob` for parsing program blobs (eq A.2) and
//! standard program initialization Y(p, a) (eq A.37).

use crate::memory::{Memory, PageAccess};
use crate::vm::Pvm;
use crate::{Gas, PVM_INIT_INPUT_SIZE, PVM_PAGE_SIZE, PVM_ZONE_SIZE};

/// Parse a program blob into (code, bitmask, jump_table) (eq A.2).
///
/// deblob(p) = (c, k, j) where:
///   p = E(|j|) ⌢ E₁(z) ⌢ E(|c|) ⌢ E_z(j) ⌢ E(c) ⌢ E(k), |k| = |c|
pub fn deblob(blob: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<u32>)> {
    let mut offset = 0;

    // Read |j| (jump table length) as variable-length natural
    let (jt_len, n) = decode_natural(blob, offset)?;
    offset += n;

    // Read z (encoding size for jump table entries) as 1 byte
    if offset >= blob.len() {
        return None;
    }
    let z = blob[offset] as usize;
    offset += 1;

    // Read |c| (code length) as variable-length natural
    let (code_len, n) = decode_natural(blob, offset)?;
    offset += n;

    // Read jump table: jt_len entries, each z bytes LE
    let mut jump_table = Vec::with_capacity(jt_len);
    for _ in 0..jt_len {
        if offset + z > blob.len() {
            return None;
        }
        let mut val: u32 = 0;
        for i in 0..z {
            val |= (blob[offset + i] as u32) << (i * 8);
        }
        jump_table.push(val);
        offset += z;
    }

    // Read code: code_len bytes
    if offset + code_len > blob.len() {
        return None;
    }
    let code = blob[offset..offset + code_len].to_vec();
    offset += code_len;

    // Read bitmask: packed bitfield, ceil(code_len/8) bytes (eq C.9)
    let bitmask_bytes = (code_len + 7) / 8;
    if offset + bitmask_bytes > blob.len() {
        return None;
    }
    let packed_bitmask = &blob[offset..offset + bitmask_bytes];

    // Unpack packed bits to one byte per instruction (LSB first per byte)
    let mut bitmask = vec![0u8; code_len];
    for i in 0..code_len {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        bitmask[i] = (packed_bitmask[byte_idx] >> bit_idx) & 1;
    }

    Some((code, bitmask, jump_table))
}

/// Standard program initialization Y(p, a) (eq A.37-A.43).
///
/// Returns a fully initialized PVM or None if the program blob is invalid.
pub fn initialize_program(program_blob: &[u8], arguments: &[u8], gas: Gas) -> Option<Pvm> {
    let blob = skip_metadata(program_blob);

    // Parse the standard program blob header (eq A.38):
    // E₃(|o|) ⌢ E₃(|w|) ⌢ E₂(z) ⌢ E₃(s) ⌢ o ⌢ w ⌢ E₄(|c|) ⌢ c
    if blob.len() < 15 {
        return None;
    }

    let mut offset = 0;

    let ro_size = read_le_u24(blob, &mut offset)? as u32;
    let rw_size = read_le_u24(blob, &mut offset)? as u32;
    let heap_pages = read_le_u16(blob, &mut offset)? as u32;
    let stack_size = read_le_u24(blob, &mut offset)? as u32;
    tracing::debug!("Program header: ro_size={}, rw_size={}, heap_pages={}, stack_size={}", ro_size, rw_size, heap_pages, stack_size);

    // Read read-only data
    if offset + ro_size as usize > blob.len() {
        return None;
    }
    let ro_data = &blob[offset..offset + ro_size as usize];
    offset += ro_size as usize;

    // Read read-write data
    if offset + rw_size as usize > blob.len() {
        return None;
    }
    let rw_data = &blob[offset..offset + rw_size as usize];
    offset += rw_size as usize;

    // Read E₄(|c|) — 4-byte LE code blob length
    let code_len = read_le_u32(blob, &mut offset)? as usize;
    if offset + code_len > blob.len() {
        return None;
    }
    let program_data = &blob[offset..offset + code_len];
    let (code, bitmask, jump_table) = deblob(program_data)?;

    let zz = PVM_ZONE_SIZE;
    let zi = PVM_INIT_INPUT_SIZE;

    let page_round = |x: u32| -> u32 {
        let ps = PVM_PAGE_SIZE;
        ((x + ps - 1) / ps) * ps
    };

    let zone_round = |x: u32| -> u32 { ((x + zz - 1) / zz) * zz };

    // Check total memory fits in 32-bit address space (eq A.41)
    let ro_zone = zone_round(ro_size);
    let rw_zone = zone_round(rw_size + heap_pages * PVM_PAGE_SIZE);
    let stack_zone = zone_round(stack_size);

    let total = 5u64 * zz as u64 + ro_zone as u64 + rw_zone as u64 + stack_zone as u64 + zi as u64;
    if total > (1u64 << 32) {
        return None;
    }

    // Build memory (eq A.42)
    let mut memory = Memory::new();

    // Read-only data at ZZ
    let ro_base = zz;
    map_region_with_data(&mut memory, ro_base, ro_data, page_round(ro_size), PageAccess::ReadOnly);

    // Read-write data at 2*ZZ + Z(|o|)
    let rw_base = 2 * zz + zone_round(ro_size);
    // GP sbrk h value: beginning of the heap section = 2*Z_Z + Z(|o|) = rw_base
    let heap_base = rw_base;
    map_region_with_data(
        &mut memory,
        rw_base,
        rw_data,
        page_round(rw_size + heap_pages * PVM_PAGE_SIZE),
        PageAccess::ReadWrite,
    );

    // Stack at (2^32 - 2*ZZ - ZI - P(s)) .. (2^32 - 2*ZZ - ZI)
    let stack_top = (1u64 << 32) - 2 * zz as u64 - zi as u64;
    let stack_bottom = stack_top - page_round(stack_size) as u64;
    map_region(&mut memory, stack_bottom as u32, page_round(stack_size), PageAccess::ReadWrite);

    // Arguments at (2^32 - ZZ - ZI)
    let arg_base = (1u64 << 32) - zz as u64 - zi as u64;
    map_region_with_data(
        &mut memory,
        arg_base as u32,
        arguments,
        page_round(arguments.len() as u32),
        PageAccess::ReadOnly,
    );

    // Initialize registers (eq A.43)
    let mut registers = [0u64; 13];
    registers[0] = (1u64 << 32) - (1u64 << 16); // SP initial
    registers[1] = (1u64 << 32) - 2 * zz as u64 - zi as u64; // arg end
    registers[7] = (1u64 << 32) - zz as u64 - zi as u64; // arg base
    registers[8] = arguments.len() as u64; // arg length

    tracing::info!(
        "PVM init: ro={:#x}+{}, rw={:#x}+{}, heap={:#x}, stack={:#x}..{:#x}, args={:#x}+{}, SP={:#x}",
        ro_base, ro_size, rw_base, rw_size, heap_base,
        stack_bottom, stack_top, arg_base, arguments.len(), registers[0]
    );

    let mut pvm = Pvm::new(code, bitmask, jump_table, registers, memory, gas);
    pvm.heap_base = heap_base;
    // heap_top starts at the end of the pre-mapped rw+heap region
    // (heap_base + rw_size + heap_pages * page_size, page-aligned)
    pvm.heap_top = heap_base + page_round(rw_size + heap_pages * PVM_PAGE_SIZE);

    Some(pvm)
}

/// Decode a variable-length natural number (JAM codec format).
/// Returns (value, bytes_consumed) or None.
fn decode_natural(data: &[u8], offset: usize) -> Option<(usize, usize)> {
    if offset >= data.len() {
        return None;
    }

    let first = data[offset];
    if first < 128 {
        // Single byte
        Some((first as usize, 1))
    } else if first < 192 {
        // Two bytes
        if offset + 2 > data.len() {
            return None;
        }
        let val = ((first as usize & 0x3F) << 8) | data[offset + 1] as usize;
        Some((val, 2))
    } else if first < 224 {
        // Three bytes: remaining 2 bytes in LE order
        if offset + 3 > data.len() {
            return None;
        }
        let val = ((first as usize & 0x1F) << 16)
            | ((data[offset + 2] as usize) << 8)
            | data[offset + 1] as usize;
        Some((val, 3))
    } else {
        // Four bytes: remaining 3 bytes in LE order
        if offset + 4 > data.len() {
            return None;
        }
        let val = ((first as usize & 0x0F) << 24)
            | ((data[offset + 3] as usize) << 16)
            | ((data[offset + 2] as usize) << 8)
            | data[offset + 1] as usize;
        Some((val, 4))
    }
}

/// Map a memory region with zero-filled pages.
fn map_region(memory: &mut Memory, base: u32, size: u32, access: PageAccess) {
    if size == 0 {
        return;
    }
    let start_page = base / PVM_PAGE_SIZE;
    let num_pages = (size + PVM_PAGE_SIZE - 1) / PVM_PAGE_SIZE;
    for i in 0..num_pages {
        memory.map_page(start_page + i, access);
    }
}

/// Map a memory region and copy data into it.
fn map_region_with_data(memory: &mut Memory, base: u32, data: &[u8], size: u32, access: PageAccess) {
    if size == 0 {
        return;
    }
    let start_page = base / PVM_PAGE_SIZE;
    let num_pages = (size + PVM_PAGE_SIZE - 1) / PVM_PAGE_SIZE;
    let page_size = PVM_PAGE_SIZE as usize;

    for i in 0..num_pages {
        let data_offset = i as usize * page_size;
        if data_offset < data.len() {
            let end = (data_offset + page_size).min(data.len());
            memory.map_page_with_data(start_page + i, access, &data[data_offset..end]);
        } else {
            memory.map_page(start_page + i, access);
        }
    }
}

fn read_le_u16(data: &[u8], offset: &mut usize) -> Option<u16> {
    if *offset + 2 > data.len() {
        return None;
    }
    let val = u16::from_le_bytes([data[*offset], data[*offset + 1]]);
    *offset += 2;
    Some(val)
}

/// Skip metadata prefix from polkavm-linker output.
/// Detects metadata by checking if the first 3 bytes as E3(ro_size) would be too large.
fn skip_metadata(blob: &[u8]) -> &[u8] {
    if blob.len() < 14 {
        return blob;
    }
    // Try parsing as standard program header (first 3 bytes = E3(ro_size) LE)
    let ro_size = blob[0] as u32 | ((blob[1] as u32) << 8) | ((blob[2] as u32) << 16);
    if (ro_size as usize) + 14 <= blob.len() {
        // Looks like a valid standard program header
        return blob;
    }
    // Assume metadata: varint(length) prefix + metadata bytes
    if let Some((meta_len, consumed)) = decode_natural(blob, 0) {
        let skip = consumed + meta_len;
        if skip < blob.len() {
            return &blob[skip..];
        }
    }
    blob
}

fn read_le_u32(data: &[u8], offset: &mut usize) -> Option<u32> {
    if *offset + 4 > data.len() {
        return None;
    }
    let val = u32::from_le_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
    ]);
    *offset += 4;
    Some(val)
}

fn read_le_u24(data: &[u8], offset: &mut usize) -> Option<u32> {
    if *offset + 3 > data.len() {
        return None;
    }
    let val = data[*offset] as u32 | ((data[*offset + 1] as u32) << 8) | ((data[*offset + 2] as u32) << 16);
    *offset += 3;
    Some(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deblob_simple() {
        // Build a simple blob: |j|=0, z=1, |c|=3, code=[0,1,0], bitmask packed
        let mut blob = Vec::new();
        blob.push(0); // |j| = 0 (single byte natural)
        blob.push(1); // z = 1
        blob.push(3); // |c| = 3
        // no jump table entries
        blob.extend_from_slice(&[0, 1, 0]); // code: trap, fallthrough, trap
        blob.push(0x07); // packed bitmask: bits 0,1,2 set = 0b00000111
        let (code, bitmask, jt) = deblob(&blob).unwrap();
        assert_eq!(code, vec![0, 1, 0]);
        assert_eq!(bitmask, vec![1, 1, 1]);
        assert!(jt.is_empty());
    }

    #[test]
    fn test_deblob_with_jump_table() {
        let mut blob = Vec::new();
        blob.push(2); // |j| = 2
        blob.push(2); // z = 2 (2-byte entries)
        blob.push(2); // |c| = 2
        blob.extend_from_slice(&[0, 0]); // j[0] = 0
        blob.extend_from_slice(&[1, 0]); // j[1] = 1
        blob.extend_from_slice(&[0, 1]); // code: trap, fallthrough
        blob.push(0x03); // packed bitmask: bits 0,1 set = 0b00000011
        let (code, bitmask, jt) = deblob(&blob).unwrap();
        assert_eq!(code, vec![0, 1]);
        assert_eq!(bitmask, vec![1, 1]);
        assert_eq!(jt, vec![0, 1]);
    }

    #[test]
    fn test_invalid_blob() {
        assert!(deblob(&[]).is_none());
        assert!(deblob(&[0]).is_none()); // missing z
    }
}
