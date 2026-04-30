//! PVM blob emitter — produces JAR program blobs.

use scale::Encode;

/// JAR v1 magic: 'J','A','R', 0x01.
const JAR_MAGIC: u32 = u32::from_le_bytes([b'J', b'A', b'R', 0x01]);

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

/// JAR v1 unified header (scale-encoded as sequential LE fields).
#[derive(Clone, Debug, scale::Encode)]
struct ProgramHeader {
    pub magic: u32,
    pub ro_size: u32,
    pub rw_size: u32,
    pub heap_pages: u32,
    pub max_heap_pages: u32,
    pub stack_pages: u32,
    pub jump_len: u32,
    pub entry_size: u8,
    pub code_len: u32,
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

/// Build a complete JAR v1 program blob.
///
/// Layout: header | ro_data | rw_data | jump_table | code | packed_bitmask
#[allow(clippy::too_many_arguments)]
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
    let entry_size = jump_table_entry_size(jump_table);

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

/// Build a JAR capability manifest blob from components.
///
/// Takes raw user code/bitmask/jump_table plus optional ro/rw byte
/// blobs and emits a JAR blob whose CodeCap contains:
/// 1. The init prologue (`ProgramLayout::emit_prologue`): stackless
///    `MGMT_MAP` ecallis for every DATA cap + `load_imm_64 SP, stack_top`.
/// 2. The user's `code` bytes verbatim.
///
/// Jump-table entries are shifted by the prologue's byte length so
/// they continue to point at the correct location in user code.
///
/// The simplest blob has one CODE cap and one DATA cap (stack).
/// More complex blobs have separate ro_data, rw_data, heap DATA caps.
#[allow(clippy::too_many_arguments)]
pub fn build_service_program(
    code: &[u8],
    bitmask: &[u8],
    jump_table: &[u32],
    ro_data: &[u8],
    rw_data: &[u8],
    stack_pages: u32,
    heap_pages: u32,
    memory_pages: u32,
) -> Vec<u8> {
    use crate::layout::{CODE_CAP_INDEX, PVM_PAGE_SIZE, ProgramLayout, emit_prologue};
    use javm::program::{CapEntryType, CapManifestEntry, build_blob};

    // Compute the shared layout so the prologue and the manifest agree
    // on which slot each DATA cap lives at.
    let ro_pages = (ro_data.len() as u32).div_ceil(PVM_PAGE_SIZE);
    let rw_pages = (rw_data.len() as u32).div_ceil(PVM_PAGE_SIZE);
    let layout = ProgramLayout::compute(stack_pages, ro_pages, rw_pages, heap_pages);

    // Emit the init prologue. It must run at PC=0 of the CodeCap; user
    // code follows immediately. Jump-table entries (which encode
    // absolute byte offsets into the resulting code blob) shift by the
    // prologue's length.
    let (prologue_code, prologue_bitmask) = emit_prologue(&layout);
    let prologue_len = prologue_code.len() as u32;

    let mut full_code = prologue_code;
    full_code.extend_from_slice(code);

    let mut full_bitmask = prologue_bitmask;
    full_bitmask.extend_from_slice(bitmask);

    let shifted_jump_table: Vec<u32> = jump_table.iter().map(|&e| e + prologue_len).collect();

    // Build the CODE sub-blob (jump_table + code + packed_bitmask).
    let entry_size = jump_table_entry_size(&shifted_jump_table);
    let mut code_blob = Vec::new();
    code_blob.extend_from_slice(&(shifted_jump_table.len() as u32).to_le_bytes());
    code_blob.push(entry_size);
    code_blob.extend_from_slice(&(full_code.len() as u32).to_le_bytes());
    for &entry in &shifted_jump_table {
        code_blob.extend_from_slice(&entry.to_le_bytes()[..entry_size as usize]);
    }
    code_blob.extend_from_slice(&full_code);
    code_blob.extend_from_slice(&pack_bitmask(&full_bitmask));

    // Build data section: code_blob + ro_data + rw_data.
    let mut data_section = Vec::new();
    let code_offset = 0u32;
    let code_len = code_blob.len() as u32;
    data_section.extend_from_slice(&code_blob);

    let ro_offset = data_section.len() as u32;
    let ro_len = ro_data.len() as u32;
    data_section.extend_from_slice(ro_data);

    let rw_offset = data_section.len() as u32;
    let rw_len = rw_data.len() as u32;
    data_section.extend_from_slice(rw_data);

    // Build the manifest from `layout`. The manifest no longer carries
    // (base_page, init_access); those come from the prologue.
    let mut caps = Vec::new();
    caps.push(CapManifestEntry {
        cap_index: CODE_CAP_INDEX,
        cap_type: CapEntryType::Code,
        page_count: 0,
        data_offset: code_offset,
        data_len: code_len,
    });
    caps.push(CapManifestEntry {
        cap_index: layout.stack.cap_index,
        cap_type: CapEntryType::Data,
        page_count: layout.stack.page_count,
        data_offset: 0,
        data_len: 0,
    });
    if let Some(ro) = layout.ro {
        caps.push(CapManifestEntry {
            cap_index: ro.cap_index,
            cap_type: CapEntryType::Data,
            page_count: ro.page_count,
            data_offset: ro_offset,
            data_len: ro_len,
        });
    }
    if let Some(rw) = layout.rw {
        caps.push(CapManifestEntry {
            cap_index: rw.cap_index,
            cap_type: CapEntryType::Data,
            page_count: rw.page_count,
            data_offset: rw_offset,
            data_len: rw_len,
        });
    }
    if let Some(heap) = layout.heap {
        caps.push(CapManifestEntry {
            cap_index: heap.cap_index,
            cap_type: CapEntryType::Data,
            page_count: heap.page_count,
            data_offset: 0,
            data_len: 0,
        });
    }
    // Args DATA cap (slot 69) — a transpiler-host convention. Hosts
    // populate it via `kernel.write_data_cap_init(ARGS_CAP_INDEX, bytes)`
    // post-init and pass the resulting byte address to the guest in φ[8].
    caps.push(CapManifestEntry {
        cap_index: layout.args.cap_index,
        cap_type: CapEntryType::Data,
        page_count: layout.args.page_count,
        data_offset: 0,
        data_len: 0,
    });

    // Untyped budget: max of the caller's request and the layout's
    // total reserved data pages plus an extra heap headroom (legacy
    // behavior preserved).
    let total = memory_pages.max(layout.total_data_pages() + heap_pages);
    build_blob(total, CODE_CAP_INDEX, &caps, &data_section)
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
    fn test_build_v2_minimal() {
        let blob = javm::program::build_simple_blob(&[0, 1, 0], &[1, 1, 1], &[]);
        let backend = javm::PvmBackend::Default;
        let kernel = javm::kernel::cap_table_from_blob::<u8>(&blob, backend, None)
            .and_then(|a| javm::kernel::InvocationKernel::new_from_artifacts(a, 100_000, backend));
        assert!(
            kernel.is_ok(),
            "blob should be loadable: {:?}",
            kernel.err()
        );
    }

    #[test]
    fn test_build_v2_service_round_trip() {
        let code = vec![0, 1, 0]; // trap, fallthrough, trap
        let bitmask = vec![1, 1, 1];
        let blob = build_service_program(&code, &bitmask, &[], &[], &[], 1, 0, 4);
        let backend = javm::PvmBackend::Default;
        let kernel = javm::kernel::cap_table_from_blob::<u8>(&blob, backend, None)
            .and_then(|a| javm::kernel::InvocationKernel::new_from_artifacts(a, 100_000, backend));
        assert!(
            kernel.is_ok(),
            "service blob should be loadable: {:?}",
            kernel.err()
        );
    }
}
