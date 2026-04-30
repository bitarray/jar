//! JAR program blob format — capability manifest.
//!
//! The blob is a capability manifest: a list of initial capabilities
//! (CODE and DATA) with their contents, plus invocation directives.
//!
//! Layout:
//! ```text
//! Header:
//!   magic: u32              'JAR\x02'
//!   memory_pages: u32       total Untyped budget
//!   cap_count: u8           number of initial capabilities
//!   init_cap: u8            cap_index of the **initialize CODE cap**
//!                            run by Vault.initialize. The init program
//!                            is responsible for placing a callable-shaped
//!                            FrameRef at bare-Frame slot 4 before halting.
//!
//! Capabilities[cap_count]:
//!   cap[i]: {
//!     cap_index: u8         slot in VM's cap table
//!     cap_type: u8          0 = CODE, 1 = DATA
//!     base_page: u32        starting page in address space (DATA only)
//!     page_count: u32       number of pages (DATA only)
//!     init_access: u8       0 = RO, 1 = RW (DATA only)
//!     data_offset: u32      offset into blob's data section
//!     data_len: u32         bytes of initial data (0 = zero-filled)
//!   }
//!
//! Data section:
//!   (variable-length, referenced by capabilities)
//! ```

use alloc::{vec, vec::Vec};

use crate::cap::Access;

/// JAR magic: 'J','A','R', 0x02.
pub const JAR_MAGIC: u32 = u32::from_le_bytes([b'J', b'A', b'R', 0x02]);

/// Header size: magic(4) + memory_pages(4) + cap_count(1) + init_cap(1) = 10.
const HEADER_SIZE: usize = 10;

/// Per-cap entry size: cap_index(1) + cap_type(1) + base_page(4) + page_count(4)
///   + init_access(1) + data_offset(4) + data_len(4) = 19.
const CAP_ENTRY_SIZE: usize = 19;

/// Cap type discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CapEntryType {
    Code = 0,
    Data = 1,
}

/// A single capability entry in the manifest.
#[derive(Debug, Clone)]
pub struct CapManifestEntry {
    /// Slot in the VM's cap table.
    pub cap_index: u8,
    /// Capability type.
    pub cap_type: CapEntryType,
    /// Starting page in address space (DATA only, ignored for CODE).
    pub base_page: u32,
    /// Number of pages (DATA only, ignored for CODE).
    pub page_count: u32,
    /// Initial access mode for MAP at program init (DATA only).
    pub init_access: Access,
    /// Offset into the blob's data section (0 = no data).
    pub data_offset: u32,
    /// Bytes of initial data (0 = zero-filled for DATA, empty for CODE).
    pub data_len: u32,
}

/// Parsed JAR header.
#[derive(Debug, Clone)]
pub struct ProgramHeader {
    /// Total Untyped page budget.
    pub memory_pages: u32,
    /// Number of capabilities in the manifest.
    pub cap_count: u8,
    /// Cap index of the **initialize CODE cap** — the program run by
    /// `Vault.initialize`. The init program decides what becomes the
    /// public Callable (placed at bare-Frame slot 4 before halting).
    pub init_cap: u8,
}

/// Parsed JAR blob.
#[derive(Debug)]
pub struct ParsedBlob<'a> {
    /// Header fields.
    pub header: ProgramHeader,
    /// Capability manifest entries.
    pub caps: Vec<CapManifestEntry>,
    /// Data section (referenced by capabilities via data_offset + data_len).
    pub data_section: &'a [u8],
}

fn read_u8(blob: &[u8], offset: &mut usize) -> Option<u8> {
    if *offset >= blob.len() {
        return None;
    }
    let v = blob[*offset];
    *offset += 1;
    Some(v)
}

fn read_u32_le(blob: &[u8], offset: &mut usize) -> Option<u32> {
    if *offset + 4 > blob.len() {
        return None;
    }
    let v = u32::from_le_bytes([
        blob[*offset],
        blob[*offset + 1],
        blob[*offset + 2],
        blob[*offset + 3],
    ]);
    *offset += 4;
    Some(v)
}

/// Parse a JAR program blob.
pub fn parse_blob(blob: &[u8]) -> Option<ParsedBlob<'_>> {
    if blob.len() < HEADER_SIZE {
        return None;
    }

    let mut offset = 0;

    // Header
    let magic = read_u32_le(blob, &mut offset)?;
    if magic != JAR_MAGIC {
        return None;
    }
    let memory_pages = read_u32_le(blob, &mut offset)?;
    let cap_count = read_u8(blob, &mut offset)?;
    let init_cap = read_u8(blob, &mut offset)?;

    // Capability entries
    let entries_size = cap_count as usize * CAP_ENTRY_SIZE;
    if offset + entries_size > blob.len() {
        return None;
    }

    let mut caps = Vec::with_capacity(cap_count as usize);
    for _ in 0..cap_count {
        let cap_index = read_u8(blob, &mut offset)?;
        let cap_type_raw = read_u8(blob, &mut offset)?;
        let cap_type = match cap_type_raw {
            0 => CapEntryType::Code,
            1 => CapEntryType::Data,
            _ => return None,
        };
        let base_page = read_u32_le(blob, &mut offset)?;
        let page_count = read_u32_le(blob, &mut offset)?;
        let init_access_raw = read_u8(blob, &mut offset)?;
        let init_access = match init_access_raw {
            0 => Access::RO,
            1 => Access::RW,
            _ => return None,
        };
        let data_offset = read_u32_le(blob, &mut offset)?;
        let data_len = read_u32_le(blob, &mut offset)?;

        caps.push(CapManifestEntry {
            cap_index,
            cap_type,
            base_page,
            page_count,
            init_access,
            data_offset,
            data_len,
        });
    }

    // Data section = everything after the cap entries
    let data_section = &blob[offset..];

    // Validate data references
    for cap in &caps {
        if cap.data_len > 0 {
            let end = cap.data_offset as usize + cap.data_len as usize;
            if end > data_section.len() {
                return None;
            }
        }
    }

    Some(ParsedBlob {
        header: ProgramHeader {
            memory_pages,
            cap_count,
            init_cap,
        },
        caps,
        data_section,
    })
}

/// Parsed code sub-blob (within a CODE cap's data section).
#[derive(Debug)]
pub struct ParsedCodeBlob {
    pub jump_table: Vec<u32>,
    pub code: Vec<u8>,
    pub bitmask: Vec<u8>,
}

/// Parse a CODE cap's data section into jump table, code, and bitmask.
/// Format: jump_len(4) + entry_size(1) + code_len(4) + jump_entries + code + packed_bitmask
pub fn parse_code_blob(data: &[u8]) -> Option<ParsedCodeBlob> {
    if data.len() < 9 {
        return None;
    }
    let mut offset = 0;
    let jump_len = read_u32_le(data, &mut offset)? as usize;
    let entry_size = read_u8(data, &mut offset)? as usize;
    let code_len = read_u32_le(data, &mut offset)? as usize;

    if entry_size == 0 || entry_size > 4 {
        return None;
    }

    // Read jump table
    let jt_bytes = jump_len * entry_size;
    if offset + jt_bytes > data.len() {
        return None;
    }
    let mut jump_table = Vec::with_capacity(jump_len);
    for _ in 0..jump_len {
        let mut val: u32 = 0;
        for i in 0..entry_size {
            val |= (data[offset + i] as u32) << (i * 8);
        }
        jump_table.push(val);
        offset += entry_size;
    }

    // Read code
    if offset + code_len > data.len() {
        return None;
    }
    let code = data[offset..offset + code_len].to_vec();
    offset += code_len;

    // Read packed bitmask
    let bitmask_bytes = code_len.div_ceil(8);
    if offset + bitmask_bytes > data.len() {
        return None;
    }
    let bitmask = unpack_bitmask(&data[offset..offset + bitmask_bytes], code_len);

    Some(ParsedCodeBlob {
        jump_table,
        code,
        bitmask,
    })
}

/// Unpack a packed bitmask (1 bit per byte) into one byte per code position.
fn unpack_bitmask(packed: &[u8], code_len: usize) -> Vec<u8> {
    let mut bitmask = vec![0u8; code_len];
    for i in 0..code_len {
        bitmask[i] = (packed[i / 8] >> (i % 8)) & 1;
    }
    bitmask
}

/// Build a minimal JAR blob with a single CODE cap from raw components.
/// Useful for tests — no DATA caps, small memory budget.
pub fn build_simple_blob(code: &[u8], bitmask: &[u8], jump_table: &[u32]) -> Vec<u8> {
    use crate::cap::Access;

    // Build code sub-blob: jump_len(4) + entry_size(1) + code_len(4) + jt + code + packed_bitmask
    let entry_size = if jump_table.is_empty() { 1u8 } else { 4u8 };
    let mut code_data = Vec::new();
    code_data.extend_from_slice(&(jump_table.len() as u32).to_le_bytes());
    code_data.push(entry_size);
    code_data.extend_from_slice(&(code.len() as u32).to_le_bytes());
    for &jt_entry in jump_table {
        code_data.extend_from_slice(&jt_entry.to_le_bytes()[..entry_size as usize]);
    }
    code_data.extend_from_slice(code);
    // Pack bitmask
    let packed_len = code.len().div_ceil(8);
    let mut packed = vec![0u8; packed_len];
    for (i, &b) in bitmask.iter().enumerate() {
        if b != 0 {
            packed[i / 8] |= 1 << (i % 8);
        }
    }
    code_data.extend_from_slice(&packed);

    let caps = vec![CapManifestEntry {
        cap_index: 64,
        cap_type: CapEntryType::Code,
        base_page: 0,
        page_count: 0,
        init_access: Access::RO,
        data_offset: 0,
        data_len: code_data.len() as u32,
    }];
    build_blob(4, 64, &caps, &code_data)
}

/// Build a JAR blob from components.
pub fn build_blob(
    memory_pages: u32,
    init_cap: u8,
    caps: &[CapManifestEntry],
    data_section: &[u8],
) -> Vec<u8> {
    let cap_count = caps.len() as u8;
    let total_size = HEADER_SIZE + caps.len() * CAP_ENTRY_SIZE + data_section.len();
    let mut blob = vec![0u8; total_size];
    let mut offset = 0;

    // Header (10 bytes: magic + memory_pages + cap_count + init_cap)
    write_u32_le(&mut blob, &mut offset, JAR_MAGIC);
    write_u32_le(&mut blob, &mut offset, memory_pages);
    write_u8(&mut blob, &mut offset, cap_count);
    write_u8(&mut blob, &mut offset, init_cap);

    // Cap entries
    for cap in caps {
        write_u8(&mut blob, &mut offset, cap.cap_index);
        write_u8(&mut blob, &mut offset, cap.cap_type as u8);
        write_u32_le(&mut blob, &mut offset, cap.base_page);
        write_u32_le(&mut blob, &mut offset, cap.page_count);
        write_u8(&mut blob, &mut offset, cap.init_access as u8);
        write_u32_le(&mut blob, &mut offset, cap.data_offset);
        write_u32_le(&mut blob, &mut offset, cap.data_len);
    }

    // Data section
    blob[offset..].copy_from_slice(data_section);

    blob
}

fn write_u8(buf: &mut [u8], offset: &mut usize, v: u8) {
    buf[*offset] = v;
    *offset += 1;
}

fn write_u32_le(buf: &mut [u8], offset: &mut usize, v: u32) {
    buf[*offset..*offset + 4].copy_from_slice(&v.to_le_bytes());
    *offset += 4;
}

/// Get the data slice for a capability entry from the data section.
pub fn cap_data<'a>(entry: &CapManifestEntry, data_section: &'a [u8]) -> &'a [u8] {
    if entry.data_len == 0 {
        return &[];
    }
    &data_section[entry.data_offset as usize..entry.data_offset as usize + entry.data_len as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_blob() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        // CODE blob: 4 bytes of PVM code
        let code_data = vec![0x00, 0x01, 0x02, 0x03]; // trap, fallthrough, unlikely, ...
        // RO data: 8 bytes
        let ro_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];

        // Combined data section: code_data + ro_data
        let mut data_section = Vec::new();
        data_section.extend_from_slice(&code_data);
        data_section.extend_from_slice(&ro_data);

        (code_data, ro_data, data_section)
    }

    #[test]
    fn test_roundtrip() {
        let (_code_data, _ro_data, data_section) = make_test_blob();

        let caps = vec![
            CapManifestEntry {
                cap_index: 64,
                cap_type: CapEntryType::Code,
                base_page: 0,
                page_count: 0,
                init_access: Access::RO,
                data_offset: 0,
                data_len: 4, // code blob
            },
            CapManifestEntry {
                cap_index: 65,
                cap_type: CapEntryType::Data,
                base_page: 0,
                page_count: 1,
                init_access: Access::RW,
                data_offset: 0,
                data_len: 0, // zero-filled stack
            },
            CapManifestEntry {
                cap_index: 66,
                cap_type: CapEntryType::Data,
                base_page: 1,
                page_count: 1,
                init_access: Access::RO,
                data_offset: 4,
                data_len: 8, // ro_data
            },
        ];

        let blob = build_blob(10, 64, &caps, &data_section);
        let parsed = parse_blob(&blob).expect("parse failed");

        assert_eq!(parsed.header.memory_pages, 10);
        assert_eq!(parsed.header.cap_count, 3);
        assert_eq!(parsed.header.init_cap, 64);
        assert_eq!(parsed.caps.len(), 3);

        // CODE cap
        assert_eq!(parsed.caps[0].cap_index, 64);
        assert_eq!(parsed.caps[0].cap_type, CapEntryType::Code);
        assert_eq!(parsed.caps[0].data_len, 4);
        let code = cap_data(&parsed.caps[0], parsed.data_section);
        assert_eq!(code, &[0x00, 0x01, 0x02, 0x03]);

        // Stack DATA cap (zero-filled)
        assert_eq!(parsed.caps[1].cap_index, 65);
        assert_eq!(parsed.caps[1].cap_type, CapEntryType::Data);
        assert_eq!(parsed.caps[1].base_page, 0);
        assert_eq!(parsed.caps[1].page_count, 1);
        assert_eq!(parsed.caps[1].init_access, Access::RW);
        assert_eq!(parsed.caps[1].data_len, 0);

        // RO DATA cap
        assert_eq!(parsed.caps[2].cap_index, 66);
        assert_eq!(parsed.caps[2].cap_type, CapEntryType::Data);
        assert_eq!(parsed.caps[2].base_page, 1);
        assert_eq!(parsed.caps[2].page_count, 1);
        assert_eq!(parsed.caps[2].init_access, Access::RO);
        let ro = cap_data(&parsed.caps[2], parsed.data_section);
        assert_eq!(ro, &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
    }

    #[test]
    fn test_bad_magic() {
        let blob = build_blob(10, 64, &[], &[]);
        let mut bad = blob.clone();
        bad[3] = 0x99; // corrupt version byte
        assert!(parse_blob(&bad).is_none());
    }

    #[test]
    fn test_truncated_blob() {
        // Too short for header
        assert!(parse_blob(&[0; 5]).is_none());

        // Header says 1 cap but blob is too short
        let blob = build_blob(10, 64, &[], &[]);
        let mut bad = blob;
        bad[8] = 1; // cap_count = 1 but no cap entries follow
        assert!(parse_blob(&bad).is_none());
    }

    #[test]
    fn test_bad_data_reference() {
        let caps = vec![CapManifestEntry {
            cap_index: 64,
            cap_type: CapEntryType::Code,
            base_page: 0,
            page_count: 0,
            init_access: Access::RO,
            data_offset: 0,
            data_len: 100, // references 100 bytes but data section is empty
        }];
        let blob = build_blob(10, 64, &caps, &[]);
        assert!(parse_blob(&blob).is_none());
    }

    #[test]
    fn test_empty_manifest() {
        let blob = build_blob(0, 0, &[], &[]);
        let parsed = parse_blob(&blob).unwrap();
        assert_eq!(parsed.caps.len(), 0);
        assert_eq!(parsed.data_section.len(), 0);
    }

    #[test]
    fn test_code_sub_blob_with_jump_table() {
        // Build a code sub-blob: jump_len=2, entry_size=4, code=[0,1], bitmask=[1,1], jt=[0,1]
        let mut code_data = Vec::new();
        code_data.extend_from_slice(&2u32.to_le_bytes()); // jump_len
        code_data.push(4); // entry_size
        code_data.extend_from_slice(&2u32.to_le_bytes()); // code_len
        // jump table: 2 entries × 4 bytes
        code_data.extend_from_slice(&0u32.to_le_bytes());
        code_data.extend_from_slice(&1u32.to_le_bytes());
        // code bytes
        code_data.push(0); // trap
        code_data.push(1); // fallthrough
        // packed bitmask: 1 byte for 2 bits = 0b11 = 3
        code_data.push(0x03);

        let blob = parse_code_blob(&code_data);
        assert!(blob.is_some(), "code sub-blob should parse");
        let blob = blob.unwrap();
        assert_eq!(blob.code, vec![0, 1]);
        assert_eq!(blob.bitmask, vec![1, 1]);
        assert_eq!(blob.jump_table, vec![0, 1]);
    }

    #[test]
    fn test_build_simple_blob_roundtrip() {
        let blob = build_simple_blob(&[0, 1, 0], &[1, 1, 1], &[]);
        let parsed = parse_blob(&blob).expect("should parse");
        assert_eq!(parsed.caps.len(), 1); // 1 CODE cap
        let code_cap = &parsed.caps[0];
        assert_eq!(code_cap.cap_type, CapEntryType::Code);
        let code_blob = parse_code_blob(cap_data(code_cap, parsed.data_section)).unwrap();
        assert_eq!(code_blob.code, vec![0, 1, 0]);
        assert_eq!(code_blob.bitmask, vec![1, 1, 1]);
    }
}
