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

/// Parse a program blob into (code, bitmask, jump_table) (eq A.2).
///
/// deblob(p) = (c, k, j) where:
///   p = E₄(|j|) ⌢ E₁(z) ⌢ E₄(|c|) ⌢ E_z(j) ⌢ E(c) ⌢ E(k), |k| = |c|
pub fn deblob(blob: &[u8]) -> Option<(&[u8], Vec<u8>, Vec<u32>)> {
    let mut offset = 0;

    // Read |j| (jump table length) as u32 LE
    let jt_len = read_le_u32(blob, &mut offset)? as usize;

    // Read z (encoding size for jump table entries) as 1 byte
    if offset >= blob.len() {
        return None;
    }
    let z = blob[offset] as usize;
    offset += 1;

    // Read |c| (code length) as u32 LE
    let code_len = read_le_u32(blob, &mut offset)? as usize;

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
/// Auto-detects the blob format:
///   1. Raw `PVM\x00` → PolkaVM section-based blob
///   2. `.corevm` wrapper → scan for inner `PVM\x00` blob
///   3. Otherwise → GP Appendix C format (with optional metadata prefix)
///
/// Contiguous layout: [stack | args | roData | rwData | heap | unmapped...]
/// All mapped pages are read-write. No guard zones.
pub fn initialize_program(program_blob: &[u8], arguments: &[u8], gas: Gas) -> Option<Pvm> {
    // Auto-detect: raw PVM\x00 blob
    if program_blob.len() >= 4 && program_blob[0..4] == PVM_MAGIC {
        let prog = parse_polkavm_blob(program_blob)?;
        return initialize_from_polkavm(&prog, arguments, gas);
    }

    // Auto-detect: .corevm wrapper (scan all PVM\x00 candidates)
    if let Some(inner) = strip_corevm_wrapper(program_blob) {
        let prog = parse_polkavm_blob(inner)?;
        return initialize_from_polkavm(&prog, arguments, gas);
    }

    // Fall through to GP Appendix C path
    let blob = skip_metadata(program_blob);

    // Parse the standard program blob header:
    // E₃(|o|) ⌢ E₃(|w|) ⌢ E₂(z) ⌢ E₃(s) ⌢ o ⌢ w ⌢ E₄(|c|) ⌢ c
    if blob.len() < 15 {
        return None;
    }

    let mut offset = 0;

    let ro_size = read_le_u24(blob, &mut offset)? as u32;
    let rw_size = read_le_u24(blob, &mut offset)? as u32;
    let heap_pages = read_le_u16(blob, &mut offset)? as u32;
    let stack_size = read_le_u24(blob, &mut offset)? as u32;

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
    let blob = skip_metadata(program_blob);

    if blob.len() < 15 {
        return None;
    }

    let mut offset = 0;
    let ro_size = read_le_u24(blob, &mut offset)? as u32;
    let rw_size = read_le_u24(blob, &mut offset)? as u32;
    let heap_pages = read_le_u16(blob, &mut offset)? as u32;
    let stack_size = read_le_u24(blob, &mut offset)? as u32;

    if offset + ro_size as usize > blob.len() {
        return None;
    }
    let ro_data = &blob[offset..offset + ro_size as usize];
    offset += ro_size as usize;

    if offset + rw_size as usize > blob.len() {
        return None;
    }
    let rw_data = &blob[offset..offset + rw_size as usize];
    offset += rw_size as usize;

    let code_len = read_le_u32(blob, &mut offset)? as usize;
    if offset + code_len > blob.len() {
        return None;
    }
    let program_data = &blob[offset..offset + code_len];
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
    // Assume metadata: u32 LE length prefix + metadata bytes
    let mut off = 0;
    if let Some(meta_len) = read_le_u32(blob, &mut off) {
        let skip = off + meta_len as usize;
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
    let val = data[*offset] as u32
        | ((data[*offset + 1] as u32) << 8)
        | ((data[*offset + 2] as u32) << 16);
    *offset += 3;
    Some(val)
}

// ---------------------------------------------------------------------------
// PolkaVM section-based blob parser (PVM\x00 format)
// ---------------------------------------------------------------------------

/// PolkaVM blob magic header.
const PVM_MAGIC: [u8; 4] = [b'P', b'V', b'M', 0];

/// Section type constants (upstream polkavm-common).
const SECTION_MEMORY_CONFIG: u8 = 1;
const SECTION_RO_DATA: u8 = 2;
const SECTION_RW_DATA: u8 = 3;
const SECTION_IMPORTS: u8 = 4;
const SECTION_EXPORTS: u8 = 5;
const SECTION_CODE_AND_JUMP_TABLE: u8 = 6;
const SECTION_EOF: u8 = 0;
/// Sections with bit 7 set are optional and may be skipped.
const SECTION_OPTIONAL_BIT: u8 = 0x80;

/// Parsed contents of a PolkaVM section-based blob.
#[derive(Debug)]
pub struct PolkaVMProgram {
    /// PolkaVM format version (0-3).
    pub version: u8,
    /// Read-only data segment.
    pub ro_data: Vec<u8>,
    /// Read-write data segment (initial values).
    pub rw_data: Vec<u8>,
    /// Read-write data size (may exceed rw_data.len(); remainder is zero-filled).
    pub rw_data_size: u32,
    /// Stack size in bytes.
    pub stack_size: u32,
    /// Raw code bytes.
    pub code: Vec<u8>,
    /// Instruction bitmask (1 byte per code byte, 1 = instruction start).
    pub bitmask: Vec<u8>,
    /// Jump table entries (PC offsets into code).
    pub jump_table: Vec<u32>,
}

/// Read a PolkaVM-style varint (matches upstream `polkavm-common::varint`).
///
/// The number of leading 1-bits in the first byte determines the extra byte count.
/// Upper data bits from the first byte are placed in the HIGH positions; the
/// remaining bytes are little-endian in the LOW positions.
///
///   - `0xxxxxxx`         → 1 byte,  value = first (0..127)
///   - `10xxxxxx` + 1B    → 2 bytes, value = ((first & 0x7F) << 8)  | b1
///   - `110xxxxx` + 2B    → 3 bytes, value = ((first & 0x3F) << 16) | LE16(b1,b2)
///   - `1110xxxx` + 3B    → 4 bytes, value = ((first & 0x1F) << 24) | LE24(b1,b2,b3)
///   - `11110xxx` + 4B    → 5 bytes, value = (first & 0x0F)         | LE32(b1..b4)
///
/// Returns `(value, bytes_consumed)` or `None` on truncated input.
pub fn read_pvm_varint(data: &[u8], offset: usize) -> Option<(u32, usize)> {
    if offset >= data.len() {
        return None;
    }
    let first = data[offset];

    // Count leading 1-bits → number of extra bytes
    let length = (!first).leading_zeros() as usize; // on u8: 0..8
    let extra = &data[offset + 1..];
    if extra.len() < length {
        return None;
    }

    let upper_mask = 0xFFu32 >> length;
    let upper_bits = (upper_mask & first as u32).wrapping_shl((length * 8) as u32);

    let lower = match length {
        0 => 0,
        1 => extra[0] as u32,
        2 => u16::from_le_bytes([extra[0], extra[1]]) as u32,
        3 => u32::from_le_bytes([extra[0], extra[1], extra[2], 0]),
        4 => u32::from_le_bytes([extra[0], extra[1], extra[2], extra[3]]),
        _ => return None, // 5+ leading 1-bits: invalid
    };

    Some((upper_bits | lower, 1 + length))
}

/// Parse a PolkaVM section-based blob (PVM\x00 format).
///
/// Validates: magic, version (0-3), blob length, section ordering,
/// rejects unknown required sections, skips optional sections (bit 7 set).
///
/// Returns `None` on any parse or validation error.
pub fn parse_polkavm_blob(blob: &[u8]) -> Option<PolkaVMProgram> {
    // Minimum: 4 magic + 1 version + 8 blob_len + 1 EOF section = 14 bytes
    if blob.len() < 14 {
        return None;
    }

    // Magic check
    if blob[0..4] != PVM_MAGIC {
        return None;
    }

    // Version byte
    let version = blob[4];
    if version > 3 {
        return None;
    }

    // Blob length: 8-byte LE u64 at offset 5
    let blob_len = u64::from_le_bytes([
        blob[5], blob[6], blob[7], blob[8], blob[9], blob[10], blob[11], blob[12],
    ]);
    if blob_len as usize != blob.len() {
        return None;
    }

    // Parse sections starting at offset 13
    let mut offset = 13usize;
    let mut last_section_type: u8 = 0; // track ordering (must be ascending)

    let mut ro_data: Vec<u8> = Vec::new();
    let mut rw_data: Vec<u8> = Vec::new();
    let mut rw_data_size: u32 = 0;
    let mut stack_size: u32 = 0;
    let mut code: Vec<u8> = Vec::new();
    let mut bitmask: Vec<u8> = Vec::new();
    let mut jump_table: Vec<u32> = Vec::new();
    let mut seen_sections: u8 = 0; // bitmask of seen required section types

    loop {
        if offset >= blob.len() {
            return None; // truncated — no EOF section
        }

        let section_type = blob[offset];
        offset += 1;

        if section_type == SECTION_EOF {
            break;
        }

        // Read section payload length
        let (section_len, consumed) = read_pvm_varint(blob, offset)?;
        offset += consumed;
        let section_len = section_len as usize;

        if offset + section_len > blob.len() {
            return None; // payload exceeds blob
        }

        let section_data = &blob[offset..offset + section_len];

        // Check ordering: required sections must be strictly ascending.
        // Optional sections (bit 7 set) are skipped but still ordered.
        let ordering_key = section_type & 0x7F;
        if ordering_key != 0 && ordering_key <= last_section_type {
            return None; // out of order or duplicate
        }
        last_section_type = ordering_key;

        if section_type & SECTION_OPTIONAL_BIT != 0 {
            // Optional section — skip
            offset += section_len;
            continue;
        }

        match section_type {
            SECTION_MEMORY_CONFIG => {
                if seen_sections & (1 << SECTION_MEMORY_CONFIG) != 0 {
                    return None; // duplicate
                }
                seen_sections |= 1 << SECTION_MEMORY_CONFIG;
                // memory_config: exactly 3 varint fields (upstream match)
                let mut moff = 0usize;
                let (_ro_sz, n) = read_pvm_varint(section_data, moff)?;
                moff += n;
                let (rw_sz, n) = read_pvm_varint(section_data, moff)?;
                moff += n;
                rw_data_size = rw_sz;
                let (ss, n) = read_pvm_varint(section_data, moff)?;
                moff += n;
                stack_size = ss;
                // Upstream strictly validates: no extra bytes allowed
                if moff != section_data.len() {
                    return None;
                }
                // Note: heap is not stored in the blob; it is computed at
                // runtime as leftover address space (see initialize_from_polkavm).
            }
            SECTION_RO_DATA => {
                if seen_sections & (1 << SECTION_RO_DATA) != 0 {
                    return None;
                }
                seen_sections |= 1 << SECTION_RO_DATA;
                ro_data = section_data.to_vec();
            }
            SECTION_RW_DATA => {
                if seen_sections & (1 << SECTION_RW_DATA) != 0 {
                    return None;
                }
                seen_sections |= 1 << SECTION_RW_DATA;
                rw_data = section_data.to_vec();
            }
            SECTION_IMPORTS => {
                if seen_sections & (1 << SECTION_IMPORTS) != 0 {
                    return None;
                }
                seen_sections |= 1 << SECTION_IMPORTS;
                // Imports section — parsed but not stored (host-call resolution is runtime concern)
            }
            SECTION_EXPORTS => {
                if seen_sections & (1 << SECTION_EXPORTS) != 0 {
                    return None;
                }
                seen_sections |= 1 << SECTION_EXPORTS;
                // Exports section — parsed but not stored
            }
            SECTION_CODE_AND_JUMP_TABLE => {
                if seen_sections & (1 << SECTION_CODE_AND_JUMP_TABLE) != 0 {
                    return None;
                }
                seen_sections |= 1 << SECTION_CODE_AND_JUMP_TABLE;
                // Upstream layout (fixed order):
                //   varint(jt_entry_count) + u8(jt_entry_size) + varint(code_len)
                //   + jt_data + code + bitmask
                let mut coff = 0usize;

                // Jump table entry count
                let (jt_count, n) = read_pvm_varint(section_data, coff)?;
                coff += n;
                let jt_count = jt_count as usize;

                // Jump table entry size — single raw byte (must be 0..=4)
                if coff >= section_data.len() {
                    return None;
                }
                let jt_entry_size = section_data[coff] as usize;
                coff += 1;
                if jt_entry_size > 4 {
                    return None;
                }

                // Code length
                let (code_len, n) = read_pvm_varint(section_data, coff)?;
                coff += n;
                let code_len = code_len as usize;

                // Jump table data
                let jt_bytes = jt_count.checked_mul(jt_entry_size)?;
                if coff + jt_bytes > section_data.len() {
                    return None;
                }
                jump_table = Vec::with_capacity(jt_count);
                for i in 0..jt_count {
                    let base = coff + i * jt_entry_size;
                    let mut val: u32 = 0;
                    for j in 0..jt_entry_size {
                        val |= (section_data[base + j] as u32) << (j * 8);
                    }
                    jump_table.push(val);
                }
                coff += jt_bytes;

                // Code bytes
                if coff + code_len > section_data.len() {
                    return None;
                }
                code = section_data[coff..coff + code_len].to_vec();
                coff += code_len;

                // Remaining bytes are the packed bitmask
                let bitmask_bytes = &section_data[coff..];
                let expected_bitmask_len = code_len.div_ceil(8);
                if bitmask_bytes.len() != expected_bitmask_len {
                    return None;
                }
                bitmask = vec![0u8; code_len];
                let full_bytes = code_len / 8;
                for i in 0..full_bytes.min(bitmask_bytes.len()) {
                    let b = bitmask_bytes[i];
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
                for i in full_bytes * 8..code_len {
                    if i / 8 < bitmask_bytes.len() {
                        bitmask[i] = (bitmask_bytes[i / 8] >> (i % 8)) & 1;
                    }
                }
            }
            _ => {
                // Unknown required section → reject
                return None;
            }
        }

        offset += section_len;
    }

    // Code section is mandatory
    if code.is_empty() && seen_sections & (1 << SECTION_CODE_AND_JUMP_TABLE) == 0 {
        return None;
    }

    Some(PolkaVMProgram {
        version,
        ro_data,
        rw_data,
        rw_data_size,
        stack_size,
        code,
        bitmask,
        jump_table,
    })
}

/// Strip a `.corevm` wrapper by scanning for ALL `PVM\x00` occurrences and
/// returning the suffix at the first candidate that passes full parser validation.
///
/// If the input itself starts with `PVM\x00`, returns it unchanged.
/// Returns `None` if no valid PVM blob is found.
pub fn strip_corevm_wrapper(data: &[u8]) -> Option<&[u8]> {
    // Scan for all PVM\x00 candidates
    let mut pos = 0;
    while pos + 4 <= data.len() {
        if data[pos..pos + 4] == PVM_MAGIC {
            let candidate = &data[pos..];
            if parse_polkavm_blob(candidate).is_some() {
                return Some(candidate);
            }
        }
        pos += 1;
    }
    None
}

/// Initialize a PVM from a parsed PolkaVM program.
///
/// Memory layout follows GP conventions:
///   [stack | args | ro_data | rw_data | heap]
///
/// Register init:
///   RA (r0) = halt_addr, SP (r1) = stack top,
///   A0 (r7) = arg_base, A1 (r8) = arg_len
///
/// `heap_top` starts at `heap_base` (sbrk semantics — no pages allocated until requested).
pub fn initialize_from_polkavm(prog: &PolkaVMProgram, arguments: &[u8], gas: Gas) -> Option<Pvm> {
    let page_round = |x: u32| -> u32 { x.div_ceil(PVM_PAGE_SIZE) * PVM_PAGE_SIZE };

    // Linear layout: stack | roData | rwData | args | heap
    let s = page_round(prog.stack_size);
    let ro_start = s;
    let rw_start = ro_start + page_round(prog.ro_data.len() as u32);
    // rw_data_size may be larger than rw_data payload (zero-filled)
    let rw_region = core::cmp::max(prog.rw_data_size, prog.rw_data.len() as u32);
    let arg_start = rw_start + page_round(rw_region);
    let heap_start = arg_start + page_round(arguments.len() as u32);
    // Heap size is not stored in the blob (upstream computes it as leftover
    // address space).  Default to 32 MB — matches the prototype and gives
    // enough headroom for realistic guests like doom.corevm.
    const DEFAULT_HEAP_BYTES: u32 = 32 * 1024 * 1024;
    let heap_end = heap_start + DEFAULT_HEAP_BYTES;
    let mem_size = heap_end;

    if (mem_size as u64) > (1u64 << 32) {
        return None;
    }

    let mut flat_mem = vec![0u8; mem_size as usize];
    if !prog.ro_data.is_empty() {
        flat_mem[ro_start as usize..ro_start as usize + prog.ro_data.len()]
            .copy_from_slice(&prog.ro_data);
    }
    if !prog.rw_data.is_empty() {
        flat_mem[rw_start as usize..rw_start as usize + prog.rw_data.len()]
            .copy_from_slice(&prog.rw_data);
    }
    if !arguments.is_empty() {
        flat_mem[arg_start as usize..arg_start as usize + arguments.len()]
            .copy_from_slice(arguments);
    }

    let mut registers = [0u64; 13];
    let halt_addr: u64 = (1u64 << 32) - (1u64 << 16); // 0xFFFF0000
    registers[0] = halt_addr; // RA
    registers[1] = s as u64; // SP
    registers[7] = arg_start as u64; // A0: arg base
    registers[8] = arguments.len() as u64; // A1: arg len

    tracing::info!(
        "PVM init (polkavm v{}): stack=[0,{:#x}), args={:#x}+{}, ro={:#x}+{}, rw={:#x}+{}, heap={:#x}..{:#x}",
        prog.version,
        s,
        arg_start,
        arguments.len(),
        ro_start,
        prog.ro_data.len(),
        rw_start,
        prog.rw_data.len(),
        heap_start,
        heap_end,
    );

    let mut pvm = Pvm::new(
        prog.code.clone(),
        prog.bitmask.clone(),
        prog.jump_table.clone(),
        registers,
        flat_mem,
        gas,
    );
    pvm.heap_base = heap_start;
    pvm.heap_top = heap_start; // sbrk: no heap allocated initially

    Some(pvm)
}

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

    // -----------------------------------------------------------------------
    // PolkaVM varint tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_pvm_varint_1_byte() {
        // 0xxxxxxx: value = first byte (0..127)
        assert_eq!(read_pvm_varint(&[0x00], 0), Some((0, 1)));
        assert_eq!(read_pvm_varint(&[0x01], 0), Some((1, 1)));
        assert_eq!(read_pvm_varint(&[0x7F], 0), Some((127, 1)));
    }

    #[test]
    fn test_pvm_varint_2_bytes() {
        // 10xxxxxx + 1B: value = ((first & 0x7F) << 8) | b1
        // 128 = 0x0080 → upper = (0x80 >> 8) = 0 with mask 0x7F → first = 0x80, b1 = 0x80
        assert_eq!(read_pvm_varint(&[0x80, 0x80], 0), Some((128, 2)));
        // 256 = 0x0100 → upper = 1, b1 = 0 → first = 0x81, b1 = 0x00
        assert_eq!(read_pvm_varint(&[0x81, 0x00], 0), Some((256, 2)));
        // Fixture value: stack_size = 8192 = 0x2000 → upper = 0x20, b1 = 0x00
        // first = 0x80 | 0x20 = 0xa0
        assert_eq!(read_pvm_varint(&[0xa0, 0x00], 0), Some((8192, 2)));
    }

    #[test]
    fn test_pvm_varint_3_bytes() {
        // 110xxxxx + 2B LE: value = ((first & 0x3F) << 16) | LE16(b1,b2)
        assert_eq!(read_pvm_varint(&[0xC0, 0x00, 0x00], 0), Some((0, 3)));
        // 0x010000 = 65536 → upper = 1, low = 0 → first = 0xC1
        assert_eq!(read_pvm_varint(&[0xC1, 0x00, 0x00], 0), Some((0x010000, 3)));
    }

    #[test]
    fn test_pvm_varint_4_bytes() {
        // 1110xxxx + 3B LE: value = ((first & 0x1F) << 24) | LE24(b1,b2,b3)
        assert_eq!(read_pvm_varint(&[0xE0, 0x00, 0x00, 0x00], 0), Some((0, 4)));
        // 0x01000000 → upper = 1 → first = 0xE1
        assert_eq!(
            read_pvm_varint(&[0xE1, 0x00, 0x00, 0x00], 0),
            Some((0x01000000, 4))
        );
    }

    #[test]
    fn test_pvm_varint_5_bytes() {
        // 11110xxx + 4B LE: wrapping_shl(32) makes upper_bits stay in low nibble
        assert_eq!(
            read_pvm_varint(&[0xF0, 0x00, 0x00, 0x00, 0x00], 0),
            Some((0, 5))
        );
    }

    #[test]
    fn test_pvm_varint_truncated() {
        assert_eq!(read_pvm_varint(&[0x80], 0), None);
        assert_eq!(read_pvm_varint(&[0xC0, 0x00], 0), None);
        assert_eq!(read_pvm_varint(&[], 0), None);
    }

    #[test]
    fn test_pvm_varint_invalid_prefix() {
        // 11111xxx — 5 leading 1-bits → length=5 → but match falls through
        assert_eq!(read_pvm_varint(&[0xF8, 0, 0, 0, 0, 0], 0), None);
    }

    #[test]
    fn test_pvm_varint_offset() {
        assert_eq!(read_pvm_varint(&[0xFF, 0x05], 1), Some((5, 1)));
    }

    // -----------------------------------------------------------------------
    // Helper: build valid PVM blobs for tests
    // -----------------------------------------------------------------------

    /// Build a minimal PVM blob with given code and packed bitmask.
    fn build_minimal_pvm_blob(code: &[u8], packed_bitmask: &[u8]) -> Vec<u8> {
        build_pvm_blob_with_sections(0, &[], code, packed_bitmask, &[])
    }

    /// Build a PVM blob with full control over sections.
    fn build_pvm_blob_with_sections(
        version: u8,
        memory_config: &[u8], // pre-encoded varint fields (ro_sz, rw_sz, stack_sz)
        code: &[u8],
        packed_bitmask: &[u8],
        extra_sections: &[(u8, &[u8])],
    ) -> Vec<u8> {
        let mut sections = Vec::new();

        // Memory config section (if provided)
        if !memory_config.is_empty() {
            sections.push(SECTION_MEMORY_CONFIG);
            push_pvm_varint(&mut sections, memory_config.len() as u32);
            sections.extend_from_slice(memory_config);
        }

        // Extra sections (e.g. ro_data, rw_data, imports, exports)
        for &(stype, payload) in extra_sections {
            sections.push(stype);
            push_pvm_varint(&mut sections, payload.len() as u32);
            sections.extend_from_slice(payload);
        }

        // Code and jump table section (upstream field order):
        //   varint(jt_count) + u8(jt_entry_size) + varint(code_len)
        //   + jt_data + code + bitmask
        sections.push(SECTION_CODE_AND_JUMP_TABLE);
        let mut code_payload = Vec::new();
        push_pvm_varint(&mut code_payload, 0); // jt_count = 0
        code_payload.push(0); // jt_entry_size = 0 (raw byte)
        push_pvm_varint(&mut code_payload, code.len() as u32);
        // no jt_data (count=0)
        code_payload.extend_from_slice(code);
        code_payload.extend_from_slice(packed_bitmask);
        push_pvm_varint(&mut sections, code_payload.len() as u32);
        sections.extend_from_slice(&code_payload);

        // EOF
        sections.push(SECTION_EOF);

        // Full blob: magic + version + blob_len (8 LE) + sections
        let total_len = 4 + 1 + 8 + sections.len();
        let mut blob = Vec::with_capacity(total_len);
        blob.extend_from_slice(&PVM_MAGIC);
        blob.push(version);
        blob.extend_from_slice(&(total_len as u64).to_le_bytes());
        blob.extend_from_slice(&sections);
        blob
    }

    /// Encode a u32 as a PVM varint (upstream-compatible).
    /// Upper data bits go in the first byte; extra bytes are LE in the low positions.
    fn push_pvm_varint(buf: &mut Vec<u8>, val: u32) {
        if val < 128 {
            buf.push(val as u8);
        } else if val < (1 << 14) {
            // 2 bytes: 10xxxxxx + 1B
            buf.push(0x80 | (val >> 8) as u8);
            buf.push(val as u8);
        } else if val < (1 << 21) {
            // 3 bytes: 110xxxxx + 2B LE
            buf.push(0xC0 | (val >> 16) as u8);
            buf.push(val as u8);
            buf.push((val >> 8) as u8);
        } else if val < (1 << 28) {
            // 4 bytes: 1110xxxx + 3B LE
            buf.push(0xE0 | (val >> 24) as u8);
            buf.push(val as u8);
            buf.push((val >> 8) as u8);
            buf.push((val >> 16) as u8);
        } else {
            // 5 bytes: 11110xxx + 4B LE
            buf.push(0xF0 | (val.wrapping_shr(32)) as u8);
            buf.push(val as u8);
            buf.push((val >> 8) as u8);
            buf.push((val >> 16) as u8);
            buf.push((val >> 24) as u8);
        }
    }

    // -----------------------------------------------------------------------
    // PolkaVM parser tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_polkavm_minimal_valid() {
        let blob = build_minimal_pvm_blob(&[0, 1, 0], &[0x07]);
        let prog = parse_polkavm_blob(&blob).expect("should parse minimal blob");
        assert_eq!(prog.version, 0);
        assert_eq!(prog.code, vec![0, 1, 0]);
        assert_eq!(prog.bitmask, vec![1, 1, 1]);
        assert!(prog.jump_table.is_empty());
    }

    #[test]
    fn test_parse_polkavm_all_versions() {
        for v in 0..=3u8 {
            let blob = build_pvm_blob_with_sections(v, &[], &[0, 1, 0], &[0x07], &[]);
            let prog =
                parse_polkavm_blob(&blob).unwrap_or_else(|| panic!("version {} should parse", v));
            assert_eq!(prog.version, v);
        }
    }

    #[test]
    fn test_parse_polkavm_invalid_magic() {
        let mut blob = build_minimal_pvm_blob(&[0], &[0x01]);
        blob[0] = b'X';
        assert!(parse_polkavm_blob(&blob).is_none());
    }

    #[test]
    fn test_parse_polkavm_invalid_version() {
        let mut blob = build_minimal_pvm_blob(&[0], &[0x01]);
        blob[4] = 4;
        assert!(parse_polkavm_blob(&blob).is_none());
    }

    #[test]
    fn test_parse_polkavm_blob_length_mismatch() {
        let mut blob = build_minimal_pvm_blob(&[0], &[0x01]);
        let wrong_len = (blob.len() + 1) as u64;
        blob[5..13].copy_from_slice(&wrong_len.to_le_bytes());
        assert!(parse_polkavm_blob(&blob).is_none());
    }

    #[test]
    fn test_parse_polkavm_unknown_required_section() {
        let mut sections = Vec::new();
        sections.push(7u8); // unknown required section
        push_pvm_varint(&mut sections, 2);
        sections.extend_from_slice(&[0x00, 0x00]);
        sections.push(SECTION_EOF);

        let total_len = 4 + 1 + 8 + sections.len();
        let mut blob = Vec::with_capacity(total_len);
        blob.extend_from_slice(&PVM_MAGIC);
        blob.push(0);
        blob.extend_from_slice(&(total_len as u64).to_le_bytes());
        blob.extend_from_slice(&sections);
        assert!(parse_polkavm_blob(&blob).is_none());
    }

    #[test]
    fn test_parse_polkavm_duplicate_section() {
        let mut sections = Vec::new();

        // First code section
        sections.push(SECTION_CODE_AND_JUMP_TABLE);
        let mut payload = Vec::new();
        push_pvm_varint(&mut payload, 0); // jt_count
        payload.push(0); // jt_entry_size (raw byte)
        push_pvm_varint(&mut payload, 1); // code_len=1
        payload.push(0); // code: trap
        payload.push(0x01); // bitmask
        push_pvm_varint(&mut sections, payload.len() as u32);
        sections.extend_from_slice(&payload);

        // Duplicate code section
        sections.push(SECTION_CODE_AND_JUMP_TABLE);
        push_pvm_varint(&mut sections, payload.len() as u32);
        sections.extend_from_slice(&payload);

        sections.push(SECTION_EOF);

        let total_len = 4 + 1 + 8 + sections.len();
        let mut blob = Vec::with_capacity(total_len);
        blob.extend_from_slice(&PVM_MAGIC);
        blob.push(0);
        blob.extend_from_slice(&(total_len as u64).to_le_bytes());
        blob.extend_from_slice(&sections);
        assert!(parse_polkavm_blob(&blob).is_none());
    }

    #[test]
    fn test_parse_polkavm_out_of_order_sections() {
        let mut sections = Vec::new();

        // ro_data first (section 2)
        sections.push(SECTION_RO_DATA);
        push_pvm_varint(&mut sections, 2);
        sections.extend_from_slice(&[0xAA, 0xBB]);

        // memory_config second (section 1) → out of order
        sections.push(SECTION_MEMORY_CONFIG);
        let mut mc = Vec::new();
        push_pvm_varint(&mut mc, 0); // ro_data_size
        push_pvm_varint(&mut mc, 0); // rw_data_size
        push_pvm_varint(&mut mc, 0); // stack_size
        push_pvm_varint(&mut sections, mc.len() as u32);
        sections.extend_from_slice(&mc);

        sections.push(SECTION_EOF);

        let total_len = 4 + 1 + 8 + sections.len();
        let mut blob = Vec::with_capacity(total_len);
        blob.extend_from_slice(&PVM_MAGIC);
        blob.push(0);
        blob.extend_from_slice(&(total_len as u64).to_le_bytes());
        blob.extend_from_slice(&sections);
        assert!(parse_polkavm_blob(&blob).is_none());
    }

    #[test]
    fn test_parse_polkavm_optional_section_skipped() {
        let blob = build_pvm_blob_with_sections(
            0,
            &[],
            &[0, 1, 0],
            &[0x07],
            &[(0x80 | 3, &[0xDE, 0xAD])], // optional section 0x83, before code(6)
        );
        let prog = parse_polkavm_blob(&blob).expect("optional section should be skipped");
        assert_eq!(prog.code, vec![0, 1, 0]);
    }

    #[test]
    fn test_parse_polkavm_with_memory_config() {
        // memory_config: ro_data_size=0, rw_data_size=100, stack_size=8192
        // (3 fields only — no heap_pages per upstream spec)
        let mut mc = Vec::new();
        push_pvm_varint(&mut mc, 0); // ro_data_size
        push_pvm_varint(&mut mc, 100); // rw_data_size
        push_pvm_varint(&mut mc, 8192u32); // stack_size (2-byte varint)

        let blob = build_pvm_blob_with_sections(3, &mc, &[0, 1, 0], &[0x07], &[]);
        let prog = parse_polkavm_blob(&blob).expect("should parse with memory config");
        assert_eq!(prog.version, 3);
        assert_eq!(prog.rw_data_size, 100);
        assert_eq!(prog.stack_size, 8192);
    }

    #[test]
    fn test_parse_polkavm_memory_config_extra_bytes_rejected() {
        // memory_config with 4 fields → should fail (upstream: "more data than expected")
        let mut mc = Vec::new();
        push_pvm_varint(&mut mc, 0);
        push_pvm_varint(&mut mc, 0);
        push_pvm_varint(&mut mc, 0);
        push_pvm_varint(&mut mc, 42); // extra field — not allowed

        let blob = build_pvm_blob_with_sections(0, &mc, &[0, 1, 0], &[0x07], &[]);
        assert!(
            parse_polkavm_blob(&blob).is_none(),
            "extra bytes in memory_config must be rejected"
        );
    }

    #[test]
    fn test_parse_polkavm_with_ro_data() {
        let ro = &[0x01, 0x02, 0x03, 0x04];
        let blob =
            build_pvm_blob_with_sections(0, &[], &[0, 1, 0], &[0x07], &[(SECTION_RO_DATA, ro)]);
        let prog = parse_polkavm_blob(&blob).expect("should parse with ro_data");
        assert_eq!(prog.ro_data, ro);
    }

    #[test]
    fn test_parse_polkavm_truncated_payload() {
        let blob = build_minimal_pvm_blob(&[0, 1, 0], &[0x07]);
        let truncated = &blob[..blob.len() - 3];
        let mut trunc = truncated.to_vec();
        let new_len = trunc.len() as u64;
        trunc[5..13].copy_from_slice(&new_len.to_le_bytes());
        assert!(parse_polkavm_blob(&trunc).is_none());
    }

    #[test]
    fn test_parse_polkavm_jt_entry_size_too_large() {
        // jt_entry_size = 5 → must reject (upstream: 0..=4 only)
        let mut sections = Vec::new();
        sections.push(SECTION_CODE_AND_JUMP_TABLE);
        let mut payload = Vec::new();
        push_pvm_varint(&mut payload, 0); // jt_count=0
        payload.push(5); // jt_entry_size=5 → INVALID
        push_pvm_varint(&mut payload, 1); // code_len=1
        payload.push(0); // code: trap
        payload.push(0x01); // bitmask
        push_pvm_varint(&mut sections, payload.len() as u32);
        sections.extend_from_slice(&payload);
        sections.push(SECTION_EOF);

        let total_len = 4 + 1 + 8 + sections.len();
        let mut blob = Vec::with_capacity(total_len);
        blob.extend_from_slice(&PVM_MAGIC);
        blob.push(0);
        blob.extend_from_slice(&(total_len as u64).to_le_bytes());
        blob.extend_from_slice(&sections);
        assert!(parse_polkavm_blob(&blob).is_none());
    }

    #[test]
    fn test_parse_polkavm_bitmask_length_mismatch() {
        // Bitmask too short for code length → reject
        let mut sections = Vec::new();
        sections.push(SECTION_CODE_AND_JUMP_TABLE);
        let mut payload = Vec::new();
        push_pvm_varint(&mut payload, 0); // jt_count=0
        payload.push(0); // jt_entry_size=0
        push_pvm_varint(&mut payload, 9); // code_len=9
        payload.extend_from_slice(&[0u8; 9]); // 9 bytes of code
        payload.push(0x00); // bitmask: only 1 byte, but need ceil(9/8)=2
        push_pvm_varint(&mut sections, payload.len() as u32);
        sections.extend_from_slice(&payload);
        sections.push(SECTION_EOF);

        let total_len = 4 + 1 + 8 + sections.len();
        let mut blob = Vec::with_capacity(total_len);
        blob.extend_from_slice(&PVM_MAGIC);
        blob.push(0);
        blob.extend_from_slice(&(total_len as u64).to_le_bytes());
        blob.extend_from_slice(&sections);
        assert!(parse_polkavm_blob(&blob).is_none());
    }

    // -----------------------------------------------------------------------
    // .corevm wrapper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_strip_corevm_raw_passthrough() {
        let blob = build_minimal_pvm_blob(&[0, 1, 0], &[0x07]);
        let result = strip_corevm_wrapper(&blob);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), &blob[..]);
    }

    #[test]
    fn test_strip_corevm_with_prefix() {
        let blob = build_minimal_pvm_blob(&[0, 1, 0], &[0x07]);
        let mut wrapped = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00];
        wrapped.extend_from_slice(&blob);
        let result = strip_corevm_wrapper(&wrapped);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), &blob[..]);
    }

    #[test]
    fn test_strip_corevm_scan_skips_false_magic() {
        let real_blob = build_minimal_pvm_blob(&[0, 1, 0], &[0x07]);
        let mut wrapped = Vec::new();
        wrapped.extend_from_slice(&PVM_MAGIC); // false magic
        wrapped.extend_from_slice(&[0xFF, 0xFF]); // invalid version/length
        wrapped.extend_from_slice(&real_blob);
        let result = strip_corevm_wrapper(&wrapped);
        assert!(result.is_some());
        let inner = result.unwrap();
        let prog = parse_polkavm_blob(inner).expect("inner should parse");
        assert_eq!(prog.code, vec![0, 1, 0]);
    }

    #[test]
    fn test_strip_corevm_no_magic() {
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04];
        assert!(strip_corevm_wrapper(&data).is_none());
    }

    // -----------------------------------------------------------------------
    // Auto-detection tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_autodetect_pvm_blob() {
        let mut mc = Vec::new();
        push_pvm_varint(&mut mc, 0); // ro_data_size
        push_pvm_varint(&mut mc, 0); // rw_data_size
        push_pvm_varint(&mut mc, 8192u32); // stack_size

        let blob = build_pvm_blob_with_sections(0, &mc, &[0, 1, 0], &[0x07], &[]);
        let pvm = initialize_program(&blob, &[], 1000);
        assert!(pvm.is_some(), "PVM blob should auto-detect and initialize");
        assert_eq!(pvm.unwrap().code, vec![0, 1, 0]);
    }

    #[test]
    fn test_autodetect_gp_blob_unchanged() {
        let mut gp_blob = Vec::new();
        gp_blob.extend_from_slice(&[0, 0, 0]); // ro_size=0
        gp_blob.extend_from_slice(&[0, 0, 0]); // rw_size=0
        gp_blob.extend_from_slice(&[1, 0]); // heap_pages=1
        gp_blob.extend_from_slice(&[0x00, 0x10, 0x00]); // stack_size=4096

        let mut code_blob = Vec::new();
        code_blob.extend_from_slice(&0u32.to_le_bytes()); // |j|=0
        code_blob.push(1); // z=1
        code_blob.extend_from_slice(&2u32.to_le_bytes()); // |c|=2
        code_blob.extend_from_slice(&[0, 1]); // code: trap, fallthrough
        code_blob.push(0x03); // bitmask

        let code_blob_len = code_blob.len() as u32;
        gp_blob.extend_from_slice(&code_blob_len.to_le_bytes());
        gp_blob.extend_from_slice(&code_blob);

        let pvm = initialize_program(&gp_blob, &[], 1000);
        assert!(
            pvm.is_some(),
            "GP blob should still work through auto-detect"
        );
        assert_eq!(pvm.unwrap().code, vec![0, 1]);
    }

    // -----------------------------------------------------------------------
    // initialize_from_polkavm tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_initialize_from_polkavm_registers() {
        let mut mc = Vec::new();
        push_pvm_varint(&mut mc, 0); // ro_data_size
        push_pvm_varint(&mut mc, 0); // rw_data_size
        push_pvm_varint(&mut mc, 8192u32); // stack_size

        let blob = build_pvm_blob_with_sections(0, &mc, &[0, 1, 0], &[0x07], &[]);
        let prog = parse_polkavm_blob(&blob).unwrap();
        let args = b"hello";
        let pvm = initialize_from_polkavm(&prog, args, 5000).unwrap();

        assert_eq!(pvm.registers[0], 0xFFFF0000); // RA
        assert_eq!(pvm.registers[1], 8192); // SP = page_round(8192)
        assert_eq!(pvm.registers[7], 8192); // A0 = arg_start
        assert_eq!(pvm.registers[8], 5); // A1 = arg_len
        assert_eq!(pvm.gas, 5000);
    }

    #[test]
    fn test_initialize_from_polkavm_heap_sbrk() {
        let mut mc = Vec::new();
        push_pvm_varint(&mut mc, 0);
        push_pvm_varint(&mut mc, 0);
        push_pvm_varint(&mut mc, 8192u32);

        let blob = build_pvm_blob_with_sections(0, &mc, &[0, 1, 0], &[0x07], &[]);
        let prog = parse_polkavm_blob(&blob).unwrap();
        let pvm = initialize_from_polkavm(&prog, &[], 100).unwrap();

        // heap_top = heap_base (sbrk semantics)
        assert_eq!(pvm.heap_top, pvm.heap_base);
    }

    // -----------------------------------------------------------------------
    // Real fixture: blc-vm.polkavm
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_blc_vm_fixture() {
        // 94-byte PolkaVM blob built from rotkonetworks/romio blc-vm guest
        let fixture = include_bytes!("../tests/fixtures/blc-vm.polkavm");
        assert_eq!(fixture.len(), 94, "fixture must be 94 bytes");

        // Must parse successfully
        let prog = parse_polkavm_blob(fixture).expect("blc-vm.polkavm must parse");
        assert_eq!(prog.version, 2);
        assert_eq!(prog.stack_size, 8192); // 0x2000 from memory_config
        assert!(!prog.code.is_empty(), "code must be non-empty");
        assert_eq!(
            prog.bitmask.len(),
            prog.code.len(),
            "bitmask must match code length"
        );

        // Must initialize a PVM
        let pvm =
            initialize_from_polkavm(&prog, &[], 10_000).expect("blc-vm.polkavm must initialize");
        assert_eq!(pvm.code.len(), prog.code.len());
        assert_eq!(pvm.registers[0], 0xFFFF0000); // RA
    }

    #[test]
    fn test_autodetect_blc_vm_fixture() {
        // Same fixture through the auto-detect path
        let fixture = include_bytes!("../tests/fixtures/blc-vm.polkavm");
        let pvm = initialize_program(fixture, &[], 10_000)
            .expect("blc-vm fixture must auto-detect as polkavm");
        assert!(!pvm.code.is_empty());
    }
}
