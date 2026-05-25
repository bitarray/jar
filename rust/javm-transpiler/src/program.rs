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
//!     page_count: u32       number of pages (DATA only)
//!     data_offset: u32      offset into blob's data section
//!     data_len: u32         bytes of initial data (0 = zero-filled)
//!   }
//!
//! Data section:
//!   (variable-length, referenced by capabilities)
//! ```
//!
//! In the v3 model the kernel will eventually consume `Image.memory_mappings`
//! to set up DATA-cap mappings declaratively at instance init. Until that
//! lands, transpiled chain Images carry an empty mapping list; the SP
//! value baked into `EndpointDef.initial_regs` makes the metadata
//! correct for when mappings come online.

/// Memory-mapping access mode tracked by [`ProgramLayout`](crate::layout::ProgramLayout) for the
/// stack / ro / rw / heap regions. Persistent mappings (declarative
/// `Image.memory_mappings`) will translate this into the
/// corresponding `MappingSource::Persistent(...)` entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    RO,
    RW,
}

/// JAR magic: 'J','A','R', 0x02.
pub const JAR_MAGIC: u32 = u32::from_le_bytes([b'J', b'A', b'R', 0x02]);

/// Header size: magic(4) + memory_pages(4) + cap_count(1) + init_cap(1) = 10.
const HEADER_SIZE: usize = 10;

/// Per-cap entry size: cap_index(1) + cap_type(1) + page_count(4)
///   + data_offset(4) + data_len(4) = 14.
const CAP_ENTRY_SIZE: usize = 14;

/// Cap type discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CapEntryType {
    Code = 0,
    Data = 1,
}

/// A single capability entry in the manifest. DATA caps carry only
/// `(cap_index, page_count, data_offset, data_len)`; v3 chain Images
/// will eventually express their data regions via
/// `Image.memory_mappings` directly.
#[derive(Debug, Clone)]
pub struct CapManifestEntry {
    /// Slot in the VM's cap table.
    pub cap_index: u8,
    /// Capability type.
    pub cap_type: CapEntryType,
    /// Number of pages (DATA only, ignored for CODE).
    pub page_count: u32,
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
        let page_count = read_u32_le(blob, &mut offset)?;
        let data_offset = read_u32_le(blob, &mut offset)?;
        let data_len = read_u32_le(blob, &mut offset)?;

        caps.push(CapManifestEntry {
            cap_index,
            cap_type,
            page_count,
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
        page_count: 0,
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
        write_u32_le(&mut blob, &mut offset, cap.page_count);
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
