//! PVM program loading and initialization (JAR v0.8.0).
//!
//! Includes `deblob` for parsing GP program blobs, `parse_polkavm_blob` for
//! parsing PolkaVM section-based blobs (PVM\x00 format), and linear memory
//! initialization with basic block prevalidation.
//!
//! `initialize_program` auto-detects the format: raw PVM\x00 blobs, .corevm
//! wrapped blobs, and GP Appendix C blobs are all handled transparently.

use alloc::{vec, vec::Vec};

use crate::instruction::Opcode;
use crate::vm::Pvm;
use crate::{Gas, PVM_PAGE_SIZE};
use scale::{Decode as _, U24};

/// Inner code blob header (deblob format, GP eq A.2).
///
/// `E₄(|j|) ⌢ E₁(z) ⌢ E₄(|c|) ⌢ E_z(j) ⌢ code ⌢ packed_bitmask`
///
/// This struct covers the fixed header portion. The variable-length
/// jump table, code, and bitmask follow immediately after.
#[derive(Clone, Debug, scale::Encode, scale::Decode)]
pub struct CodeBlobHeader {
    /// Number of jump table entries.
    pub jump_len: u32,
    /// Bytes per jump table entry (1–4).
    pub entry_size: u8,
    /// Code length in bytes.
    pub code_len: u32,
}

/// Standard program blob header (GP eq A.38).
///
/// `E₃(|o|) ⌢ E₃(|w|) ⌢ E₂(z) ⌢ E₃(s) ⌢ o ⌢ w ⌢ E₄(|c|) ⌢ code_blob`
///
/// This struct covers the fixed 11-byte header. The data sections and
/// code blob follow immediately after.
#[derive(Clone, Debug, scale::Encode, scale::Decode)]
pub struct ProgramHeader {
    /// Read-only data size in bytes.
    pub ro_size: U24,
    /// Read-write data size in bytes.
    pub rw_size: U24,
    /// Additional heap pages.
    pub heap_pages: u16,
    /// Stack size in bytes.
    pub stack_size: U24,
}

/// Parse a program blob into (code, bitmask, jump_table) (eq A.2).
///
/// deblob(p) = (c, k, j) where:
///   p = E₄(|j|) ⌢ E₁(z) ⌢ E₄(|c|) ⌢ E_z(j) ⌢ E(c) ⌢ E(k), |k| = |c|
pub fn deblob(blob: &[u8]) -> Option<(&[u8], Vec<u8>, Vec<u32>)> {
    let (header, mut offset) = CodeBlobHeader::decode(blob).ok()?;
    let jt_len = header.jump_len as usize;
    let z = header.entry_size as usize;
    let code_len = header.code_len as usize;

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
    let code = &blob[offset..offset + code_len];
    offset += code_len;

    // Read bitmask: packed bitfield, ceil(code_len/8) bytes (eq C.9)
    let bitmask_bytes = code_len.div_ceil(8);
    if offset + bitmask_bytes > blob.len() {
        return None;
    }
    let packed_bitmask = &blob[offset..offset + bitmask_bytes];

    // Unpack packed bits to one byte per instruction (LSB first per byte)
    let mut bitmask = vec![0u8; code_len];
    // Process 8 bits at a time for the bulk of the bitmask
    let full_bytes = code_len / 8;
    for i in 0..full_bytes {
        let b = packed_bitmask[i];
        let out = &mut bitmask[i * 8..i * 8 + 8];
        out[0] = b & 1;
        out[1] = (b >> 1) & 1;
        out[2] = (b >> 2) & 1;
        out[3] = (b >> 3) & 1;
        out[4] = (b >> 4) & 1;
        out[5] = (b >> 5) & 1;
        out[6] = (b >> 6) & 1;
        out[7] = (b >> 7) & 1;
    }
    // Handle remaining bits
    for i in full_bytes * 8..code_len {
        bitmask[i] = (packed_bitmask[i / 8] >> (i % 8)) & 1;
    }

    Some((code, bitmask, jump_table))
}

/// Program initialization with JAR v0.8.0 linear memory layout.
///
/// Contiguous layout: [stack | roData | rwData | args | heap | unmapped...]
/// All mapped pages are read-write. No guard zones.
pub fn initialize_program(program_blob: &[u8], arguments: &[u8], gas: Gas) -> Option<Pvm> {
    let blob = program_blob;

    // Parse the standard program blob header:
    // E₃(|o|) ⌢ E₃(|w|) ⌢ E₂(z) ⌢ E₃(s) ⌢ o ⌢ w ⌢ E₄(|c|) ⌢ c
    let (header, mut offset) = ProgramHeader::decode(blob).ok()?;
    let ro_size = header.ro_size.as_u32();
    let rw_size = header.rw_size.as_u32();
    let heap_pages = header.heap_pages as u32;
    let stack_size = header.stack_size.as_u32();

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

    // JAR v0.8.0: basic block prevalidation
    if !validate_basic_blocks(code, &bitmask, &jump_table) {
        return None;
    }

    let page_round = |x: u32| -> u32 { x.div_ceil(PVM_PAGE_SIZE) * PVM_PAGE_SIZE };

    // Linear layout: stack | roData | rwData | args | heap
    let s = page_round(stack_size); // stack: [0, s)
    let ro_start = s;
    let rw_start = ro_start + page_round(ro_size);
    let arg_start = rw_start + page_round(rw_size);
    let heap_start = arg_start + page_round(arguments.len() as u32);
    let heap_end = heap_start + heap_pages * PVM_PAGE_SIZE;
    let mem_size = heap_end;

    // Check total fits in 32-bit address space
    if (mem_size as u64) > (1u64 << 32) {
        return None;
    }

    // Build flat memory buffer
    let mut flat_mem = vec![0u8; mem_size as usize];
    if !ro_data.is_empty() {
        flat_mem[ro_start as usize..ro_start as usize + ro_data.len()].copy_from_slice(ro_data);
    }
    if !rw_data.is_empty() {
        flat_mem[rw_start as usize..rw_start as usize + rw_data.len()].copy_from_slice(rw_data);
    }
    if !arguments.is_empty() {
        flat_mem[arg_start as usize..arg_start as usize + arguments.len()]
            .copy_from_slice(arguments);
    }

    // Registers (JAR v0.8.0 linear)
    let mut registers = [0u64; 13];
    let halt_addr: u64 = (1u64 << 32) - (1u64 << 16); // 0xFFFF0000
    registers[0] = halt_addr; // φ[0]: RA (halt address for top-level return)
    registers[1] = s as u64; // φ[1]: SP (top of stack)
    registers[7] = arg_start as u64; // φ[7]: argument base
    registers[8] = arguments.len() as u64; // φ[8]: argument length

    tracing::info!(
        "PVM init (linear): stack=[0,{:#x}), args={:#x}+{}, ro={:#x}+{}, rw={:#x}+{}, heap={:#x}..{:#x}, SP={:#x}, RA={:#x}",
        s,
        arg_start,
        arguments.len(),
        ro_start,
        ro_size,
        rw_start,
        rw_size,
        heap_start,
        heap_end,
        registers[1],
        registers[0]
    );

    let mut pvm = Pvm::new(code.to_vec(), bitmask, jump_table, registers, flat_mem, gas);
    pvm.heap_base = heap_start;
    pvm.heap_top = heap_end;

    Some(pvm)
}

/// Initialize a program with a specific entry point (PC offset).
///
/// Service blobs have dual entry points:
/// - PC=0: refine (stateless computation)
/// - PC=5: accumulate (stateful effects)
///
/// This is identical to `initialize_program` but sets the initial PC.
pub fn initialize_program_at(
    program_blob: &[u8],
    arguments: &[u8],
    gas: Gas,
    entry_pc: u32,
) -> Option<Pvm> {
    let mut pvm = initialize_program(program_blob, arguments, gas)?;
    pvm.set_pc(entry_pc);
    Some(pvm)
}

/// Memory layout offsets for direct flat-buffer writes.
pub struct DataLayout {
    pub mem_size: u32,
    pub arg_start: u32,
    pub arg_data: Vec<u8>,
    pub ro_start: u32,
    pub ro_data: Vec<u8>,
    pub rw_start: u32,
    pub rw_data: Vec<u8>,
}

/// Parsed program data without interpreter pre-decoding.
/// Code borrows from the program blob to avoid a 110KB copy.
pub struct ParsedProgram<'a> {
    pub code: &'a [u8],
    pub bitmask: Vec<u8>,
    pub jump_table: Vec<u32>,
    pub registers: [u64; crate::PVM_REGISTER_COUNT],
    pub heap_base: u32,
    pub heap_top: u32,
    /// Layout info for direct flat-buffer writes.
    pub layout: Option<DataLayout>,
}

/// Parse a GP Appendix C program blob into raw components without building a full Pvm.
///
/// This function handles GP-format blobs only. For PolkaVM blobs, use
/// `parse_polkavm_blob()` followed by `initialize_from_polkavm()`.
pub fn parse_program_blob<'a>(
    program_blob: &'a [u8],
    arguments: &[u8],
    _gas: Gas,
) -> Option<ParsedProgram<'a>> {
    let (header, mut offset) = ProgramHeader::decode(program_blob).ok()?;
    let ro_size = header.ro_size.as_u32();
    let rw_size = header.rw_size.as_u32();
    let heap_pages = header.heap_pages as u32;
    let stack_size = header.stack_size.as_u32();

    if offset + ro_size as usize > program_blob.len() {
        return None;
    }
    let ro_data = &program_blob[offset..offset + ro_size as usize];
    offset += ro_size as usize;

    if offset + rw_size as usize > program_blob.len() {
        return None;
    }
    let rw_data = &program_blob[offset..offset + rw_size as usize];
    offset += rw_size as usize;

    let code_len = read_le_u32(program_blob, &mut offset)? as usize;
    if offset + code_len > program_blob.len() {
        return None;
    }
    let program_data = &program_blob[offset..offset + code_len];
    let (code, bitmask, jump_table) = deblob(program_data)?;

    if !validate_basic_blocks(code, &bitmask, &jump_table) {
        return None;
    }

    let page_round = |x: u32| -> u32 { x.div_ceil(PVM_PAGE_SIZE) * PVM_PAGE_SIZE };

    // Linear layout: stack | roData | rwData | args | heap
    let s = page_round(stack_size);
    let ro_start = s;
    let rw_start = ro_start + page_round(ro_size);
    let arg_start = rw_start + page_round(rw_size);
    let heap_start = arg_start + page_round(arguments.len() as u32);
    let heap_end = heap_start + heap_pages * PVM_PAGE_SIZE;
    let mem_size = heap_end;

    if (mem_size as u64) > (1u64 << 32) {
        return None;
    }

    let layout = DataLayout {
        mem_size,
        arg_start,
        arg_data: arguments.to_vec(),
        ro_start,
        ro_data: ro_data.to_vec(),
        rw_start,
        rw_data: rw_data.to_vec(),
    };

    let mut registers = [0u64; crate::PVM_REGISTER_COUNT];
    let halt_addr: u64 = (1u64 << 32) - (1u64 << 16); // 0xFFFF0000
    registers[0] = halt_addr; // φ[0]: RA
    registers[1] = s as u64; // φ[1]: SP
    registers[7] = arg_start as u64;
    registers[8] = arguments.len() as u64;

    Some(ParsedProgram {
        code,
        bitmask,
        jump_table,
        registers,
        heap_base: heap_start,
        heap_top: heap_end,
        layout: Some(layout),
    })
}

/// JAR v0.8.0 basic block prevalidation.
/// 1. Last instruction must be a terminator
/// 2. All jump table entries must point to valid instruction boundaries
fn validate_basic_blocks(code: &[u8], bitmask: &[u8], jump_table: &[u32]) -> bool {
    if code.is_empty() {
        return false;
    }
    // Find the last instruction start (scan backwards through bitmask)
    let mut last = code.len() - 1;
    while last > 0 && (last >= bitmask.len() || bitmask[last] != 1) {
        last -= 1;
    }
    // Check it's a valid terminator
    if last >= bitmask.len() || bitmask[last] != 1 {
        return false;
    }
    match Opcode::from_byte(code[last]) {
        Some(op) if op.is_terminator() => {}
        _ => return false,
    }
    // All jump table entries must point to instruction boundaries
    for &target in jump_table {
        let t = target as usize;
        if t != 0 && (t >= bitmask.len() || bitmask[t] != 1) {
            return false;
        }
    }
    true
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

// NOTE: PolkaVM blob format support was removed — Grey uses JAR format only.
// PolkaVM benchmarks (grey-bench) use the polkavm crate's own parser.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deblob_simple() {
        // Build a simple blob: |j|=0, z=1, |c|=3, code=[0,1,0], bitmask packed
        let mut blob = Vec::new();
        blob.extend_from_slice(&0u32.to_le_bytes()); // |j| = 0
        blob.push(1); // z = 1
        blob.extend_from_slice(&3u32.to_le_bytes()); // |c| = 3
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
        blob.extend_from_slice(&2u32.to_le_bytes()); // |j| = 2
        blob.push(2); // z = 2 (2-byte entries)
        blob.extend_from_slice(&2u32.to_le_bytes()); // |c| = 2
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
        assert!(deblob(&[0, 0, 0, 0]).is_none()); // missing z
    }
}
