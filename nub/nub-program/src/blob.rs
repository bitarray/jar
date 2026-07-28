//! The [`ProgramBlob`] type and its region geometry.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::abi::{DATA_BASE, PAGE_SIZE};

/// Which of the four fixed data regions a [`Region`] describes.
///
/// The order of the variants is the address order: regions are laid
/// out from [`DATA_BASE`] upward as stack, ro, rw, heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RegionKind {
    /// Guest stack. Always present. Grows downward from
    /// [`Regions::stack_top`].
    Stack,
    /// Read-only data (`.rodata`). Backed by [`ProgramBlob::ro_data`].
    Ro,
    /// Read-write data (`.data` + `.bss`). Backed by
    /// [`ProgramBlob::rw_data`].
    Rw,
    /// Heap. Zero-initialized; the guest's allocator owns it.
    Heap,
}

impl RegionKind {
    /// Whether the runtime must map this region read-only.
    pub const fn is_read_only(self) -> bool {
        matches!(self, RegionKind::Ro)
    }
}

/// One data region's placement in the guest address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub kind: RegionKind,
    /// Page number (address / [`PAGE_SIZE`]), not an offset from
    /// [`DATA_BASE`].
    pub base_page: u32,
    pub page_count: u32,
}

impl Region {
    /// Guest address of the first byte.
    pub const fn start(&self) -> u64 {
        self.base_page as u64 * PAGE_SIZE as u64
    }

    /// Region length in bytes (always a whole number of pages).
    pub const fn size(&self) -> u64 {
        self.page_count as u64 * PAGE_SIZE as u64
    }
}

/// Data-region geometry: the page count of each of the four fixed
/// regions. Placement is derived, not stored — regions stack linearly
/// from [`DATA_BASE`] in the order stack, ro, rw, heap, so the page
/// counts alone determine every base address.
///
/// A region with zero pages is omitted from [`Regions::iter`] entirely
/// and occupies no address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Regions {
    pub stack_pages: u32,
    pub ro_pages: u32,
    pub rw_pages: u32,
    pub heap_pages: u32,
}

impl Regions {
    /// Iterate every non-empty region in address (and [`RegionKind`])
    /// order: stack, ro?, rw?, heap?.
    ///
    /// Consumers that pack a content-addressed arena in insertion
    /// order depend on this order being stable; do not reorder it.
    pub fn iter(&self) -> impl Iterator<Item = Region> + '_ {
        let mut next_page = DATA_BASE / PAGE_SIZE;
        [
            (RegionKind::Stack, self.stack_pages),
            (RegionKind::Ro, self.ro_pages),
            (RegionKind::Rw, self.rw_pages),
            (RegionKind::Heap, self.heap_pages),
        ]
        .into_iter()
        .filter_map(move |(kind, page_count)| {
            if page_count == 0 {
                return None;
            }
            let base_page = next_page;
            next_page += page_count;
            Some(Region {
                kind,
                base_page,
                page_count,
            })
        })
    }

    /// Look up one region by kind, or `None` if it is empty.
    pub fn get(&self, kind: RegionKind) -> Option<Region> {
        self.iter().find(|r| r.kind == kind)
    }

    /// Top-of-stack address (initial SP). RISC-V SP grows downward, so
    /// the first push lands at `stack_top - 8`.
    pub const fn stack_top(&self) -> u64 {
        (DATA_BASE / PAGE_SIZE) as u64 * PAGE_SIZE as u64
            + self.stack_pages as u64 * PAGE_SIZE as u64
    }

    /// Total pages across all regions.
    pub const fn total_pages(&self) -> u32 {
        self.stack_pages + self.ro_pages + self.rw_pages + self.heap_pages
    }

    /// Total data length in bytes, i.e. the size of the flat memory
    /// image a runtime must materialize at [`DATA_BASE`].
    pub const fn data_extent(&self) -> u64 {
        self.total_pages() as u64 * PAGE_SIZE as u64
    }

    /// One past the last data byte, in guest addresses.
    pub const fn data_end(&self) -> u64 {
        DATA_BASE as u64 + self.data_extent()
    }
}

/// One exported entry point.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Endpoint {
    /// Byte offset into [`ProgramBlob::code`]. A runtime seeds
    /// `PC = abi::CODE_BASE + entry_pc`.
    pub entry_pc: u64,
    /// Number of register args the caller supplies.
    pub arg_registers: u8,
    /// Opaque pass-through of the third descriptor metadata byte. nub
    /// does not interpret it; a personality may (JAVM reads it as the
    /// arg-cnode size).
    pub arg_meta: u8,
    /// Register-file overrides applied before entry, keyed by PVM
    /// register index. The linker always seeds
    /// [`abi::SP_REG`](crate::abi::SP_REG) with
    /// [`Regions::stack_top`].
    pub initial_regs: BTreeMap<u8, u64>,
}

/// A self-contained PVM2 program: raw code plus the region geometry and
/// initial contents a runtime needs to build its address space.
///
/// This is the personality-free artifact the linker emits. A
/// capability-based personality may *wrap* it — JAVM's cap `Image` is
/// one such wrapping, adding cnode slots, content hashing and an SSZ
/// encoding — but nothing here knows about capabilities.
///
/// # Invariants
///
/// [`ProgramBlob::new`] establishes and [`ProgramBlob::validate`]
/// re-checks:
///
/// - `ro_data.len() == regions.ro_pages * PAGE_SIZE`
/// - `rw_data.len() == regions.rw_pages * PAGE_SIZE`
/// - `code.len() <= MAX_CODE_SIZE`
/// - `regions.data_end() <= ADDRESS_SPACE_END`
/// - at least one endpoint
///
/// Stack and heap have no backing bytes: they are zero-initialized.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProgramBlob {
    /// PVM2 bytecode, mapped read-only at
    /// [`abi::CODE_BASE`](crate::abi::CODE_BASE).
    pub code: Vec<u8>,
    /// Page counts for the four data regions.
    pub regions: Regions,
    /// Read-only region contents, exactly `ro_pages * PAGE_SIZE` bytes.
    pub ro_data: Vec<u8>,
    /// Read-write region contents, exactly `rw_pages * PAGE_SIZE` bytes.
    pub rw_data: Vec<u8>,
    /// Exported entry points, keyed by endpoint index.
    pub endpoints: BTreeMap<u8, Endpoint>,
}

/// Why a [`ProgramBlob`] is not well-formed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidProgram {
    /// `code.len()` exceeds `MAX_CODE_SIZE` — code would overlap
    /// `DATA_BASE`.
    CodeTooLarge { len: usize },
    /// The data regions run past the 4 GiB guest address space.
    DataOutOfRange { end: u64 },
    /// A region's backing buffer length disagrees with its page count.
    RegionLengthMismatch {
        kind: RegionKind,
        expected: usize,
        actual: usize,
    },
    /// A program with no entry point can never be invoked.
    NoEndpoints,
}

impl core::fmt::Display for InvalidProgram {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InvalidProgram::CodeTooLarge { len } => write!(
                f,
                "code length {len:#x} exceeds MAX_CODE_SIZE {:#x}",
                crate::abi::MAX_CODE_SIZE
            ),
            InvalidProgram::DataOutOfRange { end } => {
                write!(f, "data end {end:#x} exceeds the 4 GiB guest range")
            }
            InvalidProgram::RegionLengthMismatch {
                kind,
                expected,
                actual,
            } => write!(
                f,
                "{kind:?} region backing buffer is {actual} bytes, expected {expected}"
            ),
            InvalidProgram::NoEndpoints => f.write_str("program declares no endpoints"),
        }
    }
}

impl core::error::Error for InvalidProgram {}

impl ProgramBlob {
    /// Build a blob, zero-extending `ro_data`/`rw_data` to their page
    /// counts so the length invariants hold, then validate.
    ///
    /// The linker hands over `.rodata`/`.data`+`.bss` buffers whose
    /// lengths are whatever the ELF sections were; normalizing to whole
    /// pages here is what makes encode/decode round-trip exactly.
    pub fn new(
        code: Vec<u8>,
        regions: Regions,
        mut ro_data: Vec<u8>,
        mut rw_data: Vec<u8>,
        endpoints: BTreeMap<u8, Endpoint>,
    ) -> Result<Self, InvalidProgram> {
        ro_data.resize(regions.ro_pages as usize * PAGE_SIZE as usize, 0);
        rw_data.resize(regions.rw_pages as usize * PAGE_SIZE as usize, 0);
        let blob = ProgramBlob {
            code,
            regions,
            ro_data,
            rw_data,
            endpoints,
        };
        blob.validate()?;
        Ok(blob)
    }

    /// Re-check the documented invariants.
    pub fn validate(&self) -> Result<(), InvalidProgram> {
        if self.code.len() > crate::abi::MAX_CODE_SIZE as usize {
            return Err(InvalidProgram::CodeTooLarge {
                len: self.code.len(),
            });
        }
        if self.regions.data_end() > crate::abi::ADDRESS_SPACE_END {
            return Err(InvalidProgram::DataOutOfRange {
                end: self.regions.data_end(),
            });
        }
        for (kind, data, pages) in [
            (RegionKind::Ro, &self.ro_data, self.regions.ro_pages),
            (RegionKind::Rw, &self.rw_data, self.regions.rw_pages),
        ] {
            let expected = pages as usize * PAGE_SIZE as usize;
            if data.len() != expected {
                return Err(InvalidProgram::RegionLengthMismatch {
                    kind,
                    expected,
                    actual: data.len(),
                });
            }
        }
        if self.endpoints.is_empty() {
            return Err(InvalidProgram::NoEndpoints);
        }
        Ok(())
    }

    /// The backing bytes for `kind`, or `None` for the zero-initialized
    /// stack and heap regions.
    pub fn region_data(&self, kind: RegionKind) -> Option<&[u8]> {
        match kind {
            RegionKind::Ro => Some(&self.ro_data),
            RegionKind::Rw => Some(&self.rw_data),
            RegionKind::Stack | RegionKind::Heap => None,
        }
    }

    /// Materialize the flat data image a runtime maps at
    /// [`DATA_BASE`]: `regions.data_extent()` bytes, with each region's
    /// backing bytes at its offset and everything else zero.
    pub fn memory_image(&self) -> Vec<u8> {
        let mut image = alloc::vec![0u8; self.regions.data_extent() as usize];
        for region in self.regions.iter() {
            let Some(data) = self.region_data(region.kind) else {
                continue;
            };
            let off = (region.start() - DATA_BASE as u64) as usize;
            image[off..off + data.len()].copy_from_slice(data);
        }
        image
    }
}
