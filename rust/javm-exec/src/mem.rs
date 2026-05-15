//! Page-based memory model.
//!
//! 4 KiB pages in a 32-bit virtual address space (matches v3 spec /
//! the underlying PVM). Memory is a mapping table: each page is
//! either unmapped (faults on access), readable, or readable+writable.
//! Writable pages may be copy-on-write — the engine doesn't care; it
//! just sees `Ok(())` on write and gets bytes via `read`.
//!
//! v0 implementation: simple `BTreeMap<u32 page, Page>`. Future
//! variant could use a dense vector with sentinels for hot paths or
//! a copy-on-write tree for snapshot cheap-clone.
//!
//! This module deliberately knows nothing about caps: pages are raw
//! bytes that the integration layer materializes (e.g., from a
//! `Cap::Data` of the active Instance's mapped slot).

use std::collections::BTreeMap;

/// PVM page size: 4 KiB.
pub const PAGE_SIZE: u32 = 1 << 12;

/// Page-aligned mask.
const PAGE_MASK: u32 = PAGE_SIZE - 1;

/// Permission bits for a mapped page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Perm {
    /// Readable only. Writes fault.
    Ro,
    /// Readable + writable.
    Rw,
}

/// A single page: 4 KiB of bytes + permissions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub bytes: Box<[u8; PAGE_SIZE as usize]>,
    pub perm: Perm,
}

impl Page {
    /// All-zero page with the given permission.
    pub fn zeroed(perm: Perm) -> Self {
        Self {
            bytes: Box::new([0u8; PAGE_SIZE as usize]),
            perm,
        }
    }
}

/// Address-space mapping for one execution context.
///
/// Pages are keyed by page-aligned address (`addr >> 12`). Reads
/// of unmapped pages or writes to read-only pages produce `Err`.
#[derive(Clone, Debug, Default)]
pub struct Mem {
    pages: BTreeMap<u32, Page>,
}

/// Outcome of a memory access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemAccess {
    Ok,
    /// Page not mapped at the page-aligned address.
    PageFault(u32),
    /// Page is read-only and the access is a write.
    WriteProtected(u32),
}

impl Mem {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install (or replace) a mapping at the page containing `addr`.
    pub fn map(&mut self, addr: u32, page: Page) {
        let key = addr & !PAGE_MASK;
        self.pages.insert(key, page);
    }

    /// Remove the mapping at `addr`. Returns the previously mapped
    /// page if any.
    pub fn unmap(&mut self, addr: u32) -> Option<Page> {
        let key = addr & !PAGE_MASK;
        self.pages.remove(&key)
    }

    /// True iff the address is in a mapped page.
    pub fn is_mapped(&self, addr: u32) -> bool {
        let key = addr & !PAGE_MASK;
        self.pages.contains_key(&key)
    }

    /// Read `len` bytes from `addr`. Slow path — for testing /
    /// non-hot-loop use. Hot-loop reads go through the interpreter's
    /// faster per-byte / per-word paths.
    pub fn read(&self, addr: u32, len: usize) -> Result<Vec<u8>, MemAccess> {
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            let a = addr.wrapping_add(i as u32);
            let key = a & !PAGE_MASK;
            let off = (a & PAGE_MASK) as usize;
            match self.pages.get(&key) {
                None => return Err(MemAccess::PageFault(key)),
                Some(page) => out.push(page.bytes[off]),
            }
        }
        Ok(out)
    }

    /// Write `data` starting at `addr`. Slow path (testing /
    /// non-hot-loop). Returns the first faulting page if any access
    /// fails; the partial write is rolled back to maintain the
    /// "no observable effect on fault" invariant.
    pub fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), MemAccess> {
        // First, validate all accesses without mutating.
        for i in 0..data.len() {
            let a = addr.wrapping_add(i as u32);
            let key = a & !PAGE_MASK;
            match self.pages.get(&key) {
                None => return Err(MemAccess::PageFault(key)),
                Some(p) if p.perm == Perm::Ro => return Err(MemAccess::WriteProtected(key)),
                _ => {}
            }
        }
        // All accesses valid — now do the write.
        for (i, &b) in data.iter().enumerate() {
            let a = addr.wrapping_add(i as u32);
            let key = a & !PAGE_MASK;
            let off = (a & PAGE_MASK) as usize;
            if let Some(page) = self.pages.get_mut(&key) {
                page.bytes[off] = b;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmapped_read_faults() {
        let m = Mem::new();
        assert!(matches!(m.read(0, 4), Err(MemAccess::PageFault(0))));
        assert!(matches!(
            m.read(0x10000, 1),
            Err(MemAccess::PageFault(0x10000))
        ));
    }

    #[test]
    fn mapped_read_write_round_trip() {
        let mut m = Mem::new();
        m.map(0, Page::zeroed(Perm::Rw));
        m.write(0, &[1, 2, 3, 4]).unwrap();
        assert_eq!(m.read(0, 4).unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn write_to_ro_page_faults() {
        let mut m = Mem::new();
        m.map(0, Page::zeroed(Perm::Ro));
        assert!(matches!(
            m.write(0, &[1]),
            Err(MemAccess::WriteProtected(0))
        ));
    }

    #[test]
    fn fault_does_not_partially_apply() {
        // First page (addr 0) RW; second page (addr PAGE_SIZE) unmapped.
        let mut m = Mem::new();
        m.map(0, Page::zeroed(Perm::Rw));
        // Write that straddles the page boundary into the unmapped page.
        let start = PAGE_SIZE - 2;
        let data = [1u8, 2, 3, 4];
        let res = m.write(start, &data);
        assert!(matches!(res, Err(MemAccess::PageFault(_))));
        // First page's bytes still zero (no partial write).
        assert_eq!(m.read(start, 2).unwrap(), vec![0, 0]);
    }

    #[test]
    fn unmap_removes_mapping() {
        let mut m = Mem::new();
        m.map(0, Page::zeroed(Perm::Rw));
        assert!(m.is_mapped(0));
        m.unmap(0);
        assert!(!m.is_mapped(0));
    }

    #[test]
    fn is_mapped_works_for_any_addr_in_page() {
        let mut m = Mem::new();
        m.map(0x4000, Page::zeroed(Perm::Rw));
        assert!(m.is_mapped(0x4000));
        assert!(m.is_mapped(0x4000 + 100));
        assert!(m.is_mapped(0x4FFF));
        assert!(!m.is_mapped(0x5000));
    }
}
