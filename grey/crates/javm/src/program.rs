//! PVM program loading and initialization (JAR v1).
//!
//! Parses JAR program blobs with a unified header, initializes linear memory,
//! and performs basic block prevalidation.

use alloc::{vec, vec::Vec};

use crate::instruction::Opcode;
use crate::vm::Pvm;
use crate::{Gas, PVM_PAGE_SIZE};
use scale::Decode as _;

/// JAR PVM program blob magic + version: 'J','A','R', 0x01.
pub const JAR_MAGIC: u32 = u32::from_le_bytes([b'J', b'A', b'R', 0x01]);

/// Gas cost per page for initial memory allocation and grow_heap.
pub const GAS_PER_PAGE: u64 = 1500;

/// Compute memory tier load/store cycles based on total accessible pages.
pub fn compute_mem_cycles(total_pages: u32) -> u8 {
    match total_pages {
        0..=2048 => 25,     // ≤ 8MB: L2 baseline
        2049..=8192 => 50,  // ≤ 32MB: L3
        8193..=65536 => 75, // ≤ 256MB: DRAM
        _ => 100,           // > 256MB: DRAM saturated
    }
}

/// Unified JAR program blob header.
///
/// Layout:
/// ```text
/// magic(4) | ro_size(4) | rw_size(4) | heap_pages(4) | max_heap_pages(4) |
/// stack_pages(4) | jump_len(4) | entry_size(1) | code_len(4)
/// ```
///
/// Followed by: ro_data | rw_data | jump_table | code | packed_bitmask
#[derive(Clone, Debug, scale::Encode, scale::Decode)]
pub struct ProgramHeader {
    /// Magic + version (must equal JAR_MAGIC).
    pub magic: u32,
    /// Read-only data size in bytes.
    pub ro_size: u32,
    /// Read-write data size in bytes.
    pub rw_size: u32,
    /// Initial heap pages (pre-allocated at init).
    pub heap_pages: u32,
    /// Maximum heap pages (grow_heap limit, determines gas tier).
    pub max_heap_pages: u32,
    /// Stack size in pages.
    pub stack_pages: u32,
    /// Jump table entry count.
    pub jump_len: u32,
    /// Bytes per jump table entry (1–4).
    pub entry_size: u8,
    /// Code (instruction bytes) length.
    pub code_len: u32,
}

/// Unpack a packed bitmask into one byte per code position.
fn unpack_bitmask(packed: &[u8], code_len: usize) -> Vec<u8> {
    let mut bitmask = vec![0u8; code_len];
    let full_bytes = code_len / 8;
    for i in 0..full_bytes {
        let b = packed[i];
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
        bitmask[i] = (packed[i / 8] >> (i % 8)) & 1;
    }
    bitmask
}

/// Parsed blob components (borrows code from the blob).
struct ParsedBlob<'a> {
    header: ProgramHeader,
    ro_data: &'a [u8],
    rw_data: &'a [u8],
    jump_table: Vec<u32>,
    code: &'a [u8],
    bitmask: Vec<u8>,
}

/// Parse a JAR program blob: header + ro + rw + jump_table + code + bitmask.
fn parse_blob(blob: &[u8]) -> Option<ParsedBlob<'_>> {
    let (header, mut offset) = ProgramHeader::decode(blob).ok()?;

    if header.magic != JAR_MAGIC {
        return None;
    }

    let ro_size = header.ro_size as usize;
    let rw_size = header.rw_size as usize;
    let jt_len = header.jump_len as usize;
    let z = header.entry_size as usize;
    let code_len = header.code_len as usize;

    if z == 0 || z > 4 {
        return None;
    }

    // Read ro_data
    if offset + ro_size > blob.len() {
        return None;
    }
    let ro_data = &blob[offset..offset + ro_size];
    offset += ro_size;

    // Read rw_data
    if offset + rw_size > blob.len() {
        return None;
    }
    let rw_data = &blob[offset..offset + rw_size];
    offset += rw_size;

    // Read jump table
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

    // Read code
    if offset + code_len > blob.len() {
        return None;
    }
    let code = &blob[offset..offset + code_len];
    offset += code_len;

    // Read packed bitmask
    let bitmask_bytes = code_len.div_ceil(8);
    if offset + bitmask_bytes > blob.len() {
        return None;
    }
    let bitmask = unpack_bitmask(&blob[offset..offset + bitmask_bytes], code_len);

    Some(ParsedBlob {
        header,
        ro_data,
        rw_data,
        jump_table,
        code,
        bitmask,
    })
}

/// Compute the linear memory layout from header fields and arguments.
struct MemLayout {
    stack_size: u32,
    ro_start: u32,
    rw_start: u32,
    arg_start: u32,
    heap_start: u32,
    heap_end: u32,
    mem_size: u32,
}

fn compute_layout(header: &ProgramHeader, args_len: u32) -> Option<MemLayout> {
    let page_round = |x: u32| -> u32 { x.div_ceil(PVM_PAGE_SIZE) * PVM_PAGE_SIZE };

    let stack_size = header.stack_pages * PVM_PAGE_SIZE;
    let ro_start = stack_size; // stack is already page-aligned
    let rw_start = ro_start + page_round(header.ro_size);
    let arg_start = rw_start + page_round(header.rw_size);
    let heap_start = arg_start + page_round(args_len);
    let heap_end = heap_start + header.heap_pages * PVM_PAGE_SIZE;
    let mem_size = heap_end;

    if (mem_size as u64) > (1u64 << 32) {
        return None;
    }

    Some(MemLayout {
        stack_size,
        ro_start,
        rw_start,
        arg_start,
        heap_start,
        heap_end,
        mem_size,
    })
}

/// Program initialization with JAR v1 linear memory layout.
///
/// Contiguous layout: [stack | roData | rwData | args | heap | unmapped...]
/// All mapped pages are read-write. No guard zones.
pub fn initialize_program(program_blob: &[u8], arguments: &[u8], gas: Gas) -> Option<Pvm> {
    let ParsedBlob {
        header,
        ro_data,
        rw_data,
        jump_table,
        code,
        bitmask,
    } = parse_blob(program_blob)?;

    if !validate_basic_blocks(code, &bitmask, &jump_table) {
        return None;
    }

    let layout = compute_layout(&header, arguments.len() as u32)?;

    // Compute memory tier from max_heap_pages + other sections
    let total_pages = layout.mem_size / PVM_PAGE_SIZE;
    let mem_cycles = compute_mem_cycles(total_pages);

    // Charge per-page allocation gas before execution
    let init_pages = layout.mem_size / PVM_PAGE_SIZE;
    let init_cost = init_pages as u64 * GAS_PER_PAGE;
    if gas < init_cost {
        return None; // OOG before execution starts
    }
    let gas = gas - init_cost;

    // Build flat memory buffer
    let mut flat_mem = vec![0u8; layout.mem_size as usize];
    if !ro_data.is_empty() {
        flat_mem[layout.ro_start as usize..layout.ro_start as usize + ro_data.len()]
            .copy_from_slice(ro_data);
    }
    if !rw_data.is_empty() {
        flat_mem[layout.rw_start as usize..layout.rw_start as usize + rw_data.len()]
            .copy_from_slice(rw_data);
    }
    if !arguments.is_empty() {
        flat_mem[layout.arg_start as usize..layout.arg_start as usize + arguments.len()]
            .copy_from_slice(arguments);
    }

    // Registers (JAR v1 linear)
    let mut registers = [0u64; 13];
    let halt_addr: u64 = (1u64 << 32) - (1u64 << 16); // 0xFFFF0000
    registers[0] = halt_addr;
    registers[1] = layout.stack_size as u64; // SP
    registers[7] = layout.arg_start as u64;
    registers[8] = arguments.len() as u64;

    tracing::info!(
        "PVM init: stack=[0,{:#x}), ro={:#x}+{}, rw={:#x}+{}, args={:#x}+{}, heap={:#x}..{:#x}",
        layout.stack_size,
        layout.ro_start,
        header.ro_size,
        layout.rw_start,
        header.rw_size,
        layout.arg_start,
        arguments.len(),
        layout.heap_start,
        layout.heap_end,
    );

    let mut pvm = Pvm::new(
        code.to_vec(),
        bitmask,
        jump_table,
        registers,
        flat_mem,
        gas,
        mem_cycles,
    );
    pvm.heap_base = layout.heap_start;
    pvm.heap_top = layout.heap_end;
    pvm.max_heap_pages = header.max_heap_pages;

    Some(pvm)
}

/// Initialize a program with a specific entry point (PC offset).
///
/// Service blobs have dual entry points:
/// - PC=0: refine (stateless computation)
/// - PC=5: accumulate (stateful effects)
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
/// Code borrows from the program blob to avoid copying.
pub struct ParsedProgram<'a> {
    pub code: &'a [u8],
    pub bitmask: Vec<u8>,
    pub jump_table: Vec<u32>,
    pub registers: [u64; crate::PVM_REGISTER_COUNT],
    pub heap_base: u32,
    pub heap_top: u32,
    pub max_heap_pages: u32,
    pub mem_cycles: u8,
    pub layout: Option<DataLayout>,
}

/// Parse a JAR program blob into raw components without building a full Pvm.
pub fn parse_program_blob<'a>(
    program_blob: &'a [u8],
    arguments: &[u8],
    _gas: Gas,
) -> Option<ParsedProgram<'a>> {
    let ParsedBlob {
        header,
        ro_data,
        rw_data,
        jump_table,
        code,
        bitmask,
    } = parse_blob(program_blob)?;

    if !validate_basic_blocks(code, &bitmask, &jump_table) {
        return None;
    }

    let mem = compute_layout(&header, arguments.len() as u32)?;

    let layout = DataLayout {
        mem_size: mem.mem_size,
        arg_start: mem.arg_start,
        arg_data: arguments.to_vec(),
        ro_start: mem.ro_start,
        ro_data: ro_data.to_vec(),
        rw_start: mem.rw_start,
        rw_data: rw_data.to_vec(),
    };

    let mut registers = [0u64; crate::PVM_REGISTER_COUNT];
    let halt_addr: u64 = (1u64 << 32) - (1u64 << 16);
    registers[0] = halt_addr;
    registers[1] = mem.stack_size as u64;
    registers[7] = mem.arg_start as u64;
    registers[8] = arguments.len() as u64;

    let total_pages = mem.mem_size / PVM_PAGE_SIZE;
    let mem_cycles = compute_mem_cycles(total_pages);

    Some(ParsedProgram {
        code,
        bitmask,
        jump_table,
        registers,
        heap_base: mem.heap_start,
        heap_top: mem.heap_end,
        max_heap_pages: header.max_heap_pages,
        mem_cycles,
        layout: Some(layout),
    })
}

/// JAR v0.8.0 basic block prevalidation.
fn validate_basic_blocks(code: &[u8], bitmask: &[u8], jump_table: &[u32]) -> bool {
    if code.is_empty() {
        return false;
    }
    let mut last = code.len() - 1;
    while last > 0 && (last >= bitmask.len() || bitmask[last] != 1) {
        last -= 1;
    }
    if last >= bitmask.len() || bitmask[last] != 1 {
        return false;
    }
    match Opcode::from_byte(code[last]) {
        Some(op) if op.is_terminator() => {}
        _ => return false,
    }
    for &target in jump_table {
        let t = target as usize;
        if t != 0 && (t >= bitmask.len() || bitmask[t] != 1) {
            return false;
        }
    }
    true
}

// NOTE: PolkaVM blob format support was removed — Grey uses JAR format only.
// PolkaVM benchmarks (grey-bench) use the polkavm crate's own parser.

/// Convert a v1 (JAR\x01) blob to a v2 (JAR\x02) capability manifest blob.
/// Used by the kernel to accept v1 blobs transparently.
pub fn convert_v1_to_v2(blob: &[u8], _args: &[u8]) -> Option<Vec<u8>> {
    let parsed = parse_blob(blob)?;

    // Build the code sub-blob (header + jump_table + code + packed_bitmask)
    let entry_size = parsed.header.entry_size as usize;
    let mut code_sub = Vec::new();
    // Sub-blob header: jump_len(4) + entry_size(1) + code_len(4)
    code_sub.extend_from_slice(&(parsed.header.jump_len as u32).to_le_bytes());
    code_sub.push(parsed.header.entry_size);
    code_sub.extend_from_slice(&(parsed.header.code_len as u32).to_le_bytes());
    // Jump table entries
    for &entry in &parsed.jump_table {
        code_sub.extend_from_slice(&entry.to_le_bytes()[..entry_size]);
    }
    // Code bytes
    code_sub.extend_from_slice(parsed.code);
    // Packed bitmask (re-pack from unpacked)
    let bitmask_packed_len = parsed.code.len().div_ceil(8);
    let mut packed = vec![0u8; bitmask_packed_len];
    for (i, &b) in parsed.bitmask.iter().enumerate() {
        if b != 0 {
            packed[i / 8] |= 1 << (i % 8);
        }
    }
    code_sub.extend_from_slice(&packed);

    // Build data section: code_sub + ro_data + rw_data
    let mut data_section = Vec::new();
    let code_offset = 0u32;
    let code_len = code_sub.len() as u32;
    data_section.extend_from_slice(&code_sub);

    let ro_offset = data_section.len() as u32;
    let ro_len = parsed.ro_data.len() as u32;
    data_section.extend_from_slice(parsed.ro_data);

    let rw_offset = data_section.len() as u32;
    let rw_len = parsed.rw_data.len() as u32;
    data_section.extend_from_slice(parsed.rw_data);

    // Build cap manifest
    use crate::cap::Access;
    use crate::program_v2::{CapEntryType, CapManifestEntry};

    let stack_pages = parsed.header.stack_pages;
    let mut caps = Vec::new();
    let mut next_page = 0u32;

    // CODE cap at slot 64
    caps.push(CapManifestEntry {
        cap_index: 64,
        cap_type: CapEntryType::Code,
        base_page: 0,
        page_count: 0,
        init_access: Access::RO,
        data_offset: code_offset,
        data_len: code_len,
    });

    // Stack DATA at slot 65
    caps.push(CapManifestEntry {
        cap_index: 65,
        cap_type: CapEntryType::Data,
        base_page: next_page,
        page_count: stack_pages,
        init_access: Access::RW,
        data_offset: 0,
        data_len: 0,
    });
    next_page += stack_pages;

    // RO DATA at slot 66
    if ro_len > 0 {
        let ro_pages = (ro_len as u32).div_ceil(4096);
        caps.push(CapManifestEntry {
            cap_index: 66,
            cap_type: CapEntryType::Data,
            base_page: next_page,
            page_count: ro_pages,
            init_access: Access::RO,
            data_offset: ro_offset,
            data_len: ro_len,
        });
        next_page += ro_pages;
    }

    // RW DATA at slot 67
    if rw_len > 0 {
        let rw_pages = (rw_len as u32).div_ceil(4096);
        caps.push(CapManifestEntry {
            cap_index: 67,
            cap_type: CapEntryType::Data,
            base_page: next_page,
            page_count: rw_pages,
            init_access: Access::RW,
            data_offset: rw_offset,
            data_len: rw_len,
        });
        next_page += rw_pages;
    }

    // Heap DATA at slot 68
    let heap_pages = parsed.header.heap_pages;
    if heap_pages > 0 {
        caps.push(CapManifestEntry {
            cap_index: 68,
            cap_type: CapEntryType::Data,
            base_page: next_page,
            page_count: heap_pages,
            init_access: Access::RW,
            data_offset: 0,
            data_len: 0,
        });
        next_page += heap_pages;
    }

    // Args DATA at slot 69
    if !_args.is_empty() {
        let arg_pages = (_args.len() as u32).div_ceil(4096);
        caps.push(CapManifestEntry {
            cap_index: 69,
            cap_type: CapEntryType::Data,
            base_page: next_page,
            page_count: arg_pages,
            init_access: Access::RW,
            data_offset: 0,
            data_len: 0,
        });
        next_page += arg_pages;
    }
    let args_cap = if !_args.is_empty() { 69 } else { 0xFF };

    let memory_pages = parsed.header.max_heap_pages.max(next_page);
    Some(crate::program_v2::build_v2_blob(
        memory_pages, 64, args_cap, &caps, &data_section,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid JAR blob for testing.
    fn make_blob(
        ro_data: &[u8],
        rw_data: &[u8],
        heap_pages: u32,
        stack_pages: u32,
        code: &[u8],
        bitmask: &[u8],
        jump_table: &[u32],
    ) -> Vec<u8> {
        use scale::Encode;
        let entry_size: u8 = if jump_table.is_empty() {
            1
        } else {
            let max = jump_table.iter().copied().max().unwrap_or(0);
            if max <= 0xFF {
                1
            } else if max <= 0xFFFF {
                2
            } else if max <= 0xFFFFFF {
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
            max_heap_pages: heap_pages,
            stack_pages,
            jump_len: jump_table.len() as u32,
            entry_size,
            code_len: code.len() as u32,
        };
        let mut blob = header.encode();
        blob.extend_from_slice(ro_data);
        blob.extend_from_slice(rw_data);
        for &e in jump_table {
            blob.extend_from_slice(&e.to_le_bytes()[..entry_size as usize]);
        }
        blob.extend_from_slice(code);
        // Pack bitmask
        let packed_len = bitmask.len().div_ceil(8);
        let mut packed = vec![0u8; packed_len];
        for (i, &bit) in bitmask.iter().enumerate() {
            if bit != 0 {
                packed[i / 8] |= 1 << (i % 8);
            }
        }
        blob.extend_from_slice(&packed);
        blob
    }

    #[test]
    fn test_parse_blob_minimal() {
        let blob = make_blob(&[], &[], 0, 1, &[0, 1, 0], &[1, 1, 1], &[]);
        let ParsedBlob {
            header,
            ro_data: ro,
            rw_data: rw,
            jump_table: jt,
            code,
            bitmask: bm,
        } = parse_blob(&blob).unwrap();
        assert_eq!(header.magic, JAR_MAGIC);
        assert_eq!(header.ro_size, 0);
        assert_eq!(header.stack_pages, 1);
        assert_eq!(code, &[0, 1, 0]);
        assert_eq!(bm, vec![1, 1, 1]);
        assert!(jt.is_empty());
        assert!(ro.is_empty());
        assert!(rw.is_empty());
    }

    #[test]
    fn test_parse_blob_with_jump_table() {
        let blob = make_blob(&[], &[], 0, 1, &[0, 1], &[1, 1], &[0, 1]);
        let ParsedBlob {
            jump_table: jt,
            code,
            bitmask: bm,
            ..
        } = parse_blob(&blob).unwrap();
        assert_eq!(code, &[0, 1]);
        assert_eq!(bm, vec![1, 1]);
        assert_eq!(jt, vec![0, 1]);
    }

    #[test]
    fn test_invalid_blob() {
        assert!(parse_blob(&[]).is_none());
        assert!(parse_blob(&[0; 4]).is_none()); // wrong magic
    }

    #[test]
    fn test_round_trip() {
        let blob = make_blob(&[], &[], 0, 1, &[0, 1, 0], &[1, 1, 1], &[]);
        let pvm = initialize_program(&blob, &[], 10000);
        assert!(pvm.is_some(), "JAR blob should be loadable");
    }
}
