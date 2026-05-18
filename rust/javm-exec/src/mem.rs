//! Flat-buffer memory model + the [`Memory`] trait that abstracts
//! over different memory backends (software-copy here, hardware-paged
//! in the bare-metal Hyperlight guest).
//!
//! Matches v2 javm's `flat_mem` layout for perf parity: a single
//! contiguous `Vec<u8>` indexed by 32-bit address. Reads/writes are
//! bounds-checked against `flat_mem.len()`; on out-of-range the
//! caller gets `false`/`None` and translates to `ExitReason::PageFault`.
//!
//! Per-page permissions are tracked separately in `flat_perms` (one
//! byte per page) so the JIT signal handler can detect ro-write
//! faults without involving the interpreter. The interpreter itself
//! relies on the page-protected mmap mapping (Stage 3 / kernel
//! integration) for read-only enforcement; this layer just bounds-
//! checks.
//!
//! The fast-path read/write helpers use `read_unaligned` /
//! `write_unaligned` via raw pointers — single MOV on x86. Same
//! shape as v2 `javm/src/interpreter/mod.rs:198-309`.

use alloc::vec::Vec;

/// PVM page size: 4 KiB.
pub const PAGE_SIZE: u32 = 1 << 12;

/// Per-page permission byte (matches v2's `flat_perms` semantics).
pub mod perm {
    /// Page is inaccessible (read or write faults).
    pub const NONE: u8 = 0;
    /// Page is readable; writes fault.
    pub const RO: u8 = 1;
    /// Page is readable + writable.
    pub const RW: u8 = 2;
}

/// Mapping permission for [`Memory::map_region`]. RO regions back
/// `perm::RO` pages; RW regions back `perm::RW` pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    ReadOnly,
    ReadWrite,
}

/// Outcome of a memory access (slow path; the fast inline helpers
/// return raw `Option` / `bool`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemAccess {
    Ok,
    /// Page not mapped at the page-aligned address.
    PageFault(u32),
    /// Page is read-only and the access is a write.
    WriteProtected(u32),
}

/// Setup-time error for [`Memory::map_region`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    /// `start` is not page-aligned.
    UnalignedStart(u64),
    /// `size` is not a multiple of [`PAGE_SIZE`].
    UnalignedSize(u64),
    /// `start + size` overflows `usize` on this platform, or exceeds
    /// the addressable range supported by `Mem`.
    Overflow,
}

/// Memory backend abstraction.
///
/// The interpreter is generic over `M: Memory` so the same source
/// compiles for two substrates:
///
/// - **Software-copy**: [`CopyingMemory`] (this module) — an owning
///   `Vec<u8>` with per-page permissions. Runs in-process.
/// - **Hardware-paged**: a future bare-metal impl in
///   `nub-arch-x86` that maps PVM pages onto real CPU pages
///   via the in-guest IDT + page tables.
///
/// Hot-path methods (`read_u*`/`write_u*`) return `Option<T>` or
/// `bool` to keep the interpreter loop branch-free. Implementations
/// should mark these `#[inline]` (or `#[inline(always)]`) — the
/// interpreter calls them through trait dispatch, and we want
/// monomorphisation to collapse to direct function calls.
pub trait Memory {
    // ---- Hot-path width-typed reads. ----
    fn read_u8(&self, addr: u32) -> Option<u8>;
    fn read_u16_le(&self, addr: u32) -> Option<u16>;
    fn read_u32_le(&self, addr: u32) -> Option<u32>;
    fn read_u64_le(&self, addr: u32) -> Option<u64>;

    // ---- Hot-path width-typed writes. ----
    fn write_u8(&mut self, addr: u32, val: u8) -> bool;
    fn write_u16_le(&mut self, addr: u32, val: u16) -> bool;
    fn write_u32_le(&mut self, addr: u32, val: u32) -> bool;
    fn write_u64_le(&mut self, addr: u32, val: u64) -> bool;

    // ---- Setup-time + cold-path. ----

    /// Declare a mapped region. See [`CopyingMemory::map_region`] for
    /// the canonical semantics.
    fn map_region(
        &mut self,
        start: u64,
        size: u64,
        access: Access,
        init: Option<&[u8]>,
    ) -> Result<(), MapError>;

    /// Per-page permission byte for the page containing `addr`.
    /// Returns [`perm::NONE`] if `addr` is out of range.
    fn perm_of(&self, addr: u32) -> u8;

    /// Read `dst.len()` bytes starting at `addr` into `dst`.
    fn read(&self, addr: u32, len: usize) -> Result<Vec<u8>, MemAccess>;

    /// Write `data.len()` bytes starting at `addr`. Per-page perm
    /// checks apply; out-of-range or RO-page writes return `Err`.
    fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), MemAccess>;
}

/// Address-space mapping for one execution context.
///
/// Flat-buffer layout matching v2 javm. The buffer's length defines
/// the upper bound of valid addresses; per-page permissions live in
/// `perms`. Implements [`Memory`] via inherent-method delegation so
/// concrete callers don't need to import the trait.
#[derive(Clone, Debug)]
pub struct CopyingMemory {
    /// Contiguous byte buffer covering `0..flat_mem.len()`.
    pub flat_mem: Vec<u8>,
    /// One permission byte per `PAGE_SIZE`-page in `flat_mem`.
    /// `perms.len() == flat_mem.len() / PAGE_SIZE` (rounded up).
    pub perms: Vec<u8>,
    /// Heap base address (for sbrk).
    pub heap_base: u32,
    /// Current heap top.
    pub heap_top: u32,
    /// Maximum heap pages (sbrk refuses beyond this).
    pub max_heap_pages: u32,
}

impl Default for CopyingMemory {
    fn default() -> Self {
        Self::new()
    }
}

/// Compatibility alias for the pre-trait name. Consumers can keep
/// writing `Mem`; new code should prefer `CopyingMemory` (when the
/// concrete impl is wanted) or be generic over `M: Memory`.
pub type Mem = CopyingMemory;

impl CopyingMemory {
    /// Empty memory; no pages allocated.
    pub fn new() -> Self {
        Self {
            flat_mem: Vec::new(),
            perms: Vec::new(),
            heap_base: 0,
            heap_top: 0,
            max_heap_pages: 0,
        }
    }

    /// Construct with a pre-sized flat buffer (zero-initialized).
    /// `n_pages` is the number of `PAGE_SIZE`-pages.
    pub fn with_pages(n_pages: u32, default_perm: u8) -> Self {
        let bytes = (n_pages as usize) * (PAGE_SIZE as usize);
        Self {
            flat_mem: vec![0u8; bytes],
            perms: vec![default_perm; n_pages as usize],
            heap_base: 0,
            heap_top: 0,
            max_heap_pages: 0,
        }
    }

    /// Returns true iff `addr` is within `flat_mem`.
    #[inline(always)]
    pub fn is_in_bounds(&self, addr: u32) -> bool {
        (addr as usize) < self.flat_mem.len()
    }

    /// Per-page permission for the page containing `addr`. Returns
    /// `perm::NONE` if the address is out of range.
    pub fn perm_of(&self, addr: u32) -> u8 {
        let page = (addr / PAGE_SIZE) as usize;
        self.perms.get(page).copied().unwrap_or(perm::NONE)
    }

    // ---- Fast-path read helpers (inline; single bounds check + raw pointer load). ----

    #[inline(always)]
    pub fn read_u8(&self, addr: u32) -> Option<u8> {
        let a = addr as usize;
        if a < self.flat_mem.len() {
            // SAFETY: bounds-checked.
            Some(unsafe { *self.flat_mem.get_unchecked(a) })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn read_u16_le(&self, addr: u32) -> Option<u16> {
        let a = addr as usize;
        if a + 2 <= self.flat_mem.len() {
            Some(unsafe { self.flat_mem.as_ptr().add(a).cast::<u16>().read_unaligned() })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn read_u32_le(&self, addr: u32) -> Option<u32> {
        let a = addr as usize;
        if a + 4 <= self.flat_mem.len() {
            Some(unsafe { self.flat_mem.as_ptr().add(a).cast::<u32>().read_unaligned() })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn read_u64_le(&self, addr: u32) -> Option<u64> {
        let a = addr as usize;
        if a + 8 <= self.flat_mem.len() {
            Some(unsafe { self.flat_mem.as_ptr().add(a).cast::<u64>().read_unaligned() })
        } else {
            None
        }
    }

    // ---- Fast-path write helpers. ----

    #[inline(always)]
    pub fn write_u8(&mut self, addr: u32, val: u8) -> bool {
        let a = addr as usize;
        if a < self.flat_mem.len() {
            unsafe {
                *self.flat_mem.get_unchecked_mut(a) = val;
            }
            true
        } else {
            false
        }
    }

    #[inline(always)]
    pub fn write_u16_le(&mut self, addr: u32, val: u16) -> bool {
        let a = addr as usize;
        if a + 2 <= self.flat_mem.len() {
            unsafe {
                self.flat_mem
                    .as_mut_ptr()
                    .add(a)
                    .cast::<u16>()
                    .write_unaligned(val);
            }
            true
        } else {
            false
        }
    }

    #[inline(always)]
    pub fn write_u32_le(&mut self, addr: u32, val: u32) -> bool {
        let a = addr as usize;
        if a + 4 <= self.flat_mem.len() {
            unsafe {
                self.flat_mem
                    .as_mut_ptr()
                    .add(a)
                    .cast::<u32>()
                    .write_unaligned(val);
            }
            true
        } else {
            false
        }
    }

    #[inline(always)]
    pub fn write_u64_le(&mut self, addr: u32, val: u64) -> bool {
        let a = addr as usize;
        if a + 8 <= self.flat_mem.len() {
            unsafe {
                self.flat_mem
                    .as_mut_ptr()
                    .add(a)
                    .cast::<u64>()
                    .write_unaligned(val);
            }
            true
        } else {
            false
        }
    }

    /// Declare a mapped region at `[start, start + size)` with
    /// per-page permissions `access` and optional initial bytes.
    ///
    /// - `start` and `size` must each be multiples of [`PAGE_SIZE`].
    /// - Grows `flat_mem` to cover `start + size` if necessary
    ///   (newly-grown bytes are zero-initialized; their pages
    ///   default to [`perm::NONE`] before this call sets them).
    /// - Sets pages in `[start / PAGE_SIZE, (start + size) /
    ///   PAGE_SIZE)` to the permission byte for `access`.
    /// - If `init` is `Some(bytes)`, copies `bytes[..bytes.len()
    ///   .min(size)]` into `flat_mem[start..]`; the rest of the
    ///   region remains zero-filled (matches the DataCap canonical
    ///   form: trailing zeros are stripped from `content`, but the
    ///   logical `size` may be larger).
    pub fn map_region(
        &mut self,
        start: u64,
        size: u64,
        access: Access,
        init: Option<&[u8]>,
    ) -> Result<(), MapError> {
        let page = PAGE_SIZE as u64;
        if !start.is_multiple_of(page) {
            return Err(MapError::UnalignedStart(start));
        }
        if !size.is_multiple_of(page) {
            return Err(MapError::UnalignedSize(size));
        }
        let end = start.checked_add(size).ok_or(MapError::Overflow)?;
        let end_usize: usize = end.try_into().map_err(|_| MapError::Overflow)?;

        // Grow flat_mem + perms to cover [0, end).
        if end_usize > self.flat_mem.len() {
            self.flat_mem.resize(end_usize, 0);
            let needed_pages = end_usize.div_ceil(PAGE_SIZE as usize);
            if self.perms.len() < needed_pages {
                self.perms.resize(needed_pages, perm::NONE);
            }
        }

        // Set permissions on the affected pages.
        let perm_byte = match access {
            Access::ReadOnly => perm::RO,
            Access::ReadWrite => perm::RW,
        };
        let first_page = (start / page) as usize;
        let last_page = ((end / page) as usize).saturating_sub(1);
        if size > 0 {
            for p in first_page..=last_page {
                self.perms[p] = perm_byte;
            }
        }

        // Copy initial bytes if any. The destination starts as zero
        // either from initial allocation or the grow above, so any
        // trailing region beyond `init` is implicitly zero.
        if let Some(bytes) = init {
            let n = bytes.len().min(size as usize);
            let s = start as usize;
            self.flat_mem[s..s + n].copy_from_slice(&bytes[..n]);
        }

        Ok(())
    }

    // ---- Slow-path helpers (for tests / non-hot paths). ----

    /// Read `len` bytes from `addr`. Returns `Err` on out-of-range.
    pub fn read(&self, addr: u32, len: usize) -> Result<Vec<u8>, MemAccess> {
        let a = addr as usize;
        let end = a
            .checked_add(len)
            .ok_or(MemAccess::PageFault(addr & !(PAGE_SIZE - 1)))?;
        if end > self.flat_mem.len() {
            return Err(MemAccess::PageFault(addr & !(PAGE_SIZE - 1)));
        }
        Ok(self.flat_mem[a..end].to_vec())
    }

    /// Write `data` starting at `addr`. Returns `Err` on out-of-range
    /// or write-protected page. Writes are NOT rolled back on partial
    /// failure (test-only API).
    pub fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), MemAccess> {
        let a = addr as usize;
        let end = a
            .checked_add(data.len())
            .ok_or(MemAccess::PageFault(addr & !(PAGE_SIZE - 1)))?;
        if end > self.flat_mem.len() {
            return Err(MemAccess::PageFault(addr & !(PAGE_SIZE - 1)));
        }
        // Check perms per page touched.
        let start_page = a / (PAGE_SIZE as usize);
        let last_page = (end - 1) / (PAGE_SIZE as usize);
        for p in start_page..=last_page {
            if self.perms.get(p).copied().unwrap_or(perm::NONE) != perm::RW {
                return Err(MemAccess::WriteProtected((p as u32) * PAGE_SIZE));
            }
        }
        self.flat_mem[a..end].copy_from_slice(data);
        Ok(())
    }
}

// `Memory` impl delegates to inherent methods via UFCS (no name
// clash, no recursion). All bodies are `#[inline(always)]` so trait
// dispatch is zero-cost after monomorphisation.
impl Memory for CopyingMemory {
    #[inline(always)]
    fn read_u8(&self, addr: u32) -> Option<u8> {
        CopyingMemory::read_u8(self, addr)
    }
    #[inline(always)]
    fn read_u16_le(&self, addr: u32) -> Option<u16> {
        CopyingMemory::read_u16_le(self, addr)
    }
    #[inline(always)]
    fn read_u32_le(&self, addr: u32) -> Option<u32> {
        CopyingMemory::read_u32_le(self, addr)
    }
    #[inline(always)]
    fn read_u64_le(&self, addr: u32) -> Option<u64> {
        CopyingMemory::read_u64_le(self, addr)
    }
    #[inline(always)]
    fn write_u8(&mut self, addr: u32, val: u8) -> bool {
        CopyingMemory::write_u8(self, addr, val)
    }
    #[inline(always)]
    fn write_u16_le(&mut self, addr: u32, val: u16) -> bool {
        CopyingMemory::write_u16_le(self, addr, val)
    }
    #[inline(always)]
    fn write_u32_le(&mut self, addr: u32, val: u32) -> bool {
        CopyingMemory::write_u32_le(self, addr, val)
    }
    #[inline(always)]
    fn write_u64_le(&mut self, addr: u32, val: u64) -> bool {
        CopyingMemory::write_u64_le(self, addr, val)
    }
    #[inline]
    fn map_region(
        &mut self,
        start: u64,
        size: u64,
        access: Access,
        init: Option<&[u8]>,
    ) -> Result<(), MapError> {
        CopyingMemory::map_region(self, start, size, access, init)
    }
    #[inline]
    fn perm_of(&self, addr: u32) -> u8 {
        CopyingMemory::perm_of(self, addr)
    }
    #[inline]
    fn read(&self, addr: u32, len: usize) -> Result<Vec<u8>, MemAccess> {
        CopyingMemory::read(self, addr, len)
    }
    #[inline]
    fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), MemAccess> {
        CopyingMemory::write(self, addr, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_u8_in_bounds() {
        let mut m = Mem::with_pages(1, perm::RW);
        m.write_u8(0x100, 0xAB);
        assert_eq!(m.read_u8(0x100), Some(0xAB));
    }

    #[test]
    fn read_u8_out_of_bounds_returns_none() {
        let m = Mem::with_pages(1, perm::RW);
        assert_eq!(m.read_u8(PAGE_SIZE), None);
        assert_eq!(m.read_u8(u32::MAX), None);
    }

    #[test]
    fn read_write_u32_le() {
        let mut m = Mem::with_pages(1, perm::RW);
        m.write_u32_le(0x10, 0xDEAD_BEEF);
        assert_eq!(m.read_u32_le(0x10), Some(0xDEAD_BEEF));
    }

    #[test]
    fn unaligned_access_works() {
        let mut m = Mem::with_pages(1, perm::RW);
        m.write_u32_le(0x103, 0x1234_5678);
        assert_eq!(m.read_u32_le(0x103), Some(0x1234_5678));
    }

    #[test]
    fn read_u32_straddling_end_returns_none() {
        let m = Mem::with_pages(1, perm::RW);
        // PAGE_SIZE - 2 → would read 4 bytes ending at PAGE_SIZE + 2, OOB.
        assert_eq!(m.read_u32_le(PAGE_SIZE - 2), None);
    }

    #[test]
    fn ro_page_write_via_slow_path_faults() {
        let mut m = Mem::with_pages(1, perm::RO);
        let res = m.write(0, &[1]);
        assert!(matches!(res, Err(MemAccess::WriteProtected(_))));
    }

    #[test]
    fn perm_of_page_after_set() {
        let m = Mem::with_pages(2, perm::RW);
        assert_eq!(m.perm_of(0), perm::RW);
        assert_eq!(m.perm_of(PAGE_SIZE), perm::RW);
        // Out of range
        assert_eq!(m.perm_of(2 * PAGE_SIZE), perm::NONE);
    }

    #[test]
    fn slow_path_read_write_round_trip() {
        let mut m = Mem::with_pages(1, perm::RW);
        m.write(0, &[1, 2, 3, 4]).unwrap();
        assert_eq!(m.read(0, 4).unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn map_region_grows_buffer_and_sets_perms() {
        let mut m = Mem::new();
        m.map_region(
            2 * PAGE_SIZE as u64,
            2 * PAGE_SIZE as u64,
            Access::ReadWrite,
            None,
        )
        .unwrap();
        assert_eq!(m.flat_mem.len(), 4 * PAGE_SIZE as usize);
        // Pages 0..2 are unmapped; pages 2..4 are RW.
        assert_eq!(m.perm_of(0), perm::NONE);
        assert_eq!(m.perm_of(PAGE_SIZE), perm::NONE);
        assert_eq!(m.perm_of(2 * PAGE_SIZE), perm::RW);
        assert_eq!(m.perm_of(3 * PAGE_SIZE), perm::RW);
    }

    #[test]
    fn map_region_copies_init_bytes_and_zero_fills_tail() {
        let mut m = Mem::new();
        m.map_region(
            0,
            PAGE_SIZE as u64,
            Access::ReadOnly,
            Some(&[0xAA, 0xBB, 0xCC]),
        )
        .unwrap();
        assert_eq!(m.flat_mem[0], 0xAA);
        assert_eq!(m.flat_mem[1], 0xBB);
        assert_eq!(m.flat_mem[2], 0xCC);
        assert_eq!(m.flat_mem[3], 0x00);
        assert_eq!(m.perm_of(0), perm::RO);
    }

    #[test]
    fn map_region_truncates_oversize_init() {
        let mut m = Mem::new();
        let init = vec![0x77u8; (PAGE_SIZE as usize) * 3];
        // Only one page declared; init is bigger.
        m.map_region(0, PAGE_SIZE as u64, Access::ReadWrite, Some(&init))
            .unwrap();
        assert_eq!(m.flat_mem.len(), PAGE_SIZE as usize);
        assert_eq!(m.flat_mem[PAGE_SIZE as usize - 1], 0x77);
    }

    #[test]
    fn map_region_rejects_unaligned_start() {
        let mut m = Mem::new();
        assert_eq!(
            m.map_region(123, PAGE_SIZE as u64, Access::ReadOnly, None),
            Err(MapError::UnalignedStart(123))
        );
    }

    #[test]
    fn map_region_rejects_unaligned_size() {
        let mut m = Mem::new();
        assert_eq!(
            m.map_region(0, 123, Access::ReadOnly, None),
            Err(MapError::UnalignedSize(123))
        );
    }

    #[test]
    fn map_region_overlapping_overwrites_perms() {
        let mut m = Mem::with_pages(2, perm::RO);
        m.map_region(0, 2 * PAGE_SIZE as u64, Access::ReadWrite, None)
            .unwrap();
        assert_eq!(m.perm_of(0), perm::RW);
        assert_eq!(m.perm_of(PAGE_SIZE), perm::RW);
    }
}
