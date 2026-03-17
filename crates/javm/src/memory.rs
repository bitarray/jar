//! PVM memory model (Appendix A, eq 4.24).
//!
//! Memory is a 32-bit addressable space organized into pages of ZP = 4096 bytes.
//! Each page has an access mode: Read-only, Read-Write, or Inaccessible.

use crate::PVM_PAGE_SIZE;
use std::collections::BTreeMap;

/// Page access mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageAccess {
    /// Inaccessible (∅) — reading or writing causes a page fault.
    Inaccessible,
    /// Read-only (R) — writing causes a page fault.
    ReadOnly,
    /// Read-write (W) — fully accessible.
    ReadWrite,
}

/// PVM memory: pageable 32-bit address space (set M, eq 4.24).
///
/// Consists of:
/// - µv: The value of each byte (µ_i ∈ N_256)
/// - µa: The access mode of each page
#[derive(Clone, Debug)]
pub struct Memory {
    /// Page data storage. Only allocated pages are stored.
    pages: BTreeMap<u32, PageData>,
}

/// Data for a single memory page.
#[derive(Clone, Debug)]
struct PageData {
    /// Access mode for this page.
    access: PageAccess,
    /// Page contents (ZP bytes).
    data: Vec<u8>,
}

/// Result of a memory access attempt.
#[derive(Debug)]
pub enum MemoryAccess {
    Ok,
    PageFault(u32),
}

impl Memory {
    /// Create a new empty memory.
    pub fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
        }
    }

    /// Get the page index for a given address.
    fn page_index(addr: u32) -> u32 {
        addr / PVM_PAGE_SIZE
    }

    /// Get the offset within a page for a given address.
    fn page_offset(addr: u32) -> usize {
        (addr % PVM_PAGE_SIZE) as usize
    }

    /// Map a page with the given access mode, filling with zeros.
    pub fn map_page(&mut self, page: u32, access: PageAccess) {
        self.pages.insert(
            page,
            PageData {
                access,
                data: vec![0u8; PVM_PAGE_SIZE as usize],
            },
        );
    }

    /// Map a page and fill it with data.
    pub fn map_page_with_data(&mut self, page: u32, access: PageAccess, data: &[u8]) {
        let mut page_data = vec![0u8; PVM_PAGE_SIZE as usize];
        let copy_len = data.len().min(PVM_PAGE_SIZE as usize);
        page_data[..copy_len].copy_from_slice(&data[..copy_len]);
        self.pages.insert(
            page,
            PageData {
                access,
                data: page_data,
            },
        );
    }

    /// Return the page indices of all mapped pages.
    pub fn page_indices(&self) -> Vec<u32> {
        self.pages.keys().copied().collect()
    }

    /// Check if a page is mapped (has any access mode, even Inaccessible).
    pub fn is_page_mapped(&self, page: u32) -> bool {
        self.pages.contains_key(&page)
    }

    /// Find the first unmapped page starting from `start_page`.
    /// Returns None if all pages from start_page to max are mapped (unlikely).
    pub fn first_unmapped_page_from(&self, start_page: u32) -> Option<u32> {
        let mut page = start_page;
        // Use the BTreeMap ordering to efficiently skip mapped pages
        for (&mapped_page, _) in self.pages.range(start_page..) {
            if mapped_page != page {
                // Found a gap: page is unmapped
                return Some(page);
            }
            page = page.checked_add(1)?;
        }
        // All pages from start_page to the last mapped page are mapped,
        // so the next unmapped page is right after the last mapped one
        Some(page)
    }

    /// Read a full page's data (4096 bytes). Returns None if page is not mapped.
    pub fn read_page(&self, page: u32) -> Option<&[u8]> {
        self.pages.get(&page).map(|pd| pd.data.as_slice())
    }

    /// Check if an address range is readable (Vµ).
    pub fn is_readable(&self, addr: u32, len: u32) -> bool {
        if len == 0 {
            return true;
        }
        let end = match addr.checked_add(len) {
            Some(e) => e,
            None => return false,
        };
        let start_page = Self::page_index(addr);
        let end_page = Self::page_index(end.saturating_sub(1));
        for page in start_page..=end_page {
            match self.pages.get(&page) {
                Some(pd) if pd.access != PageAccess::Inaccessible => {}
                _ => return false,
            }
        }
        true
    }

    /// Check if an address range is writable (V*µ).
    pub fn is_writable(&self, addr: u32, len: u32) -> bool {
        if len == 0 {
            return true;
        }
        let end = match addr.checked_add(len) {
            Some(e) => e,
            None => return false,
        };
        let start_page = Self::page_index(addr);
        let end_page = Self::page_index(end.saturating_sub(1));
        for page in start_page..=end_page {
            match self.pages.get(&page) {
                Some(pd) if pd.access == PageAccess::ReadWrite => {}
                _ => return false,
            }
        }
        true
    }

    /// Read a single byte. Returns None on page fault.
    pub fn read_u8(&self, addr: u32) -> Option<u8> {
        let page = Self::page_index(addr);
        let offset = Self::page_offset(addr);
        match self.pages.get(&page) {
            Some(pd) if pd.access != PageAccess::Inaccessible => Some(pd.data[offset]),
            _ => None,
        }
    }

    /// Read a slice of bytes. Returns None on any page fault.
    pub fn read_bytes(&self, addr: u32, len: u32) -> Option<Vec<u8>> {
        let mut result = Vec::with_capacity(len as usize);
        for i in 0..len {
            result.push(self.read_u8(addr.wrapping_add(i))?);
        }
        Some(result)
    }

    /// Read a little-endian u16.
    pub fn read_u16_le(&self, addr: u32) -> Option<u16> {
        let bytes = self.read_bytes(addr, 2)?;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Read a little-endian u32.
    pub fn read_u32_le(&self, addr: u32) -> Option<u32> {
        let bytes = self.read_bytes(addr, 4)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a little-endian u64.
    pub fn read_u64_le(&self, addr: u32) -> Option<u64> {
        let bytes = self.read_bytes(addr, 8)?;
        Some(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Write a single byte. Returns error on page fault or read-only.
    pub fn write_u8(&mut self, addr: u32, value: u8) -> MemoryAccess {
        let page = Self::page_index(addr);
        let offset = Self::page_offset(addr);
        match self.pages.get_mut(&page) {
            Some(pd) if pd.access == PageAccess::ReadWrite => {
                pd.data[offset] = value;
                MemoryAccess::Ok
            }
            _ => MemoryAccess::PageFault(addr),
        }
    }

    /// Write a slice of bytes.
    pub fn write_bytes(&mut self, addr: u32, data: &[u8]) -> MemoryAccess {
        for (i, &byte) in data.iter().enumerate() {
            match self.write_u8(addr.wrapping_add(i as u32), byte) {
                MemoryAccess::Ok => {}
                fault => return fault,
            }
        }
        MemoryAccess::Ok
    }

    /// Write a little-endian u16.
    pub fn write_u16_le(&mut self, addr: u32, value: u16) -> MemoryAccess {
        self.write_bytes(addr, &value.to_le_bytes())
    }

    /// Write a little-endian u32.
    pub fn write_u32_le(&mut self, addr: u32, value: u32) -> MemoryAccess {
        self.write_bytes(addr, &value.to_le_bytes())
    }

    /// Write a little-endian u64.
    pub fn write_u64_le(&mut self, addr: u32, value: u64) -> MemoryAccess {
        self.write_bytes(addr, &value.to_le_bytes())
    }

    /// Iterate over all mapped pages: yields (page_index, access, data_slice).
    pub fn pages_iter(&self) -> impl Iterator<Item = (u32, PageAccess, &[u8])> {
        self.pages.iter().map(|(&idx, pd)| (idx, pd.access, pd.data.as_slice()))
    }

    /// Get page data mutably by page index.
    pub fn page_data_mut(&mut self, page: u32) -> Option<&mut [u8]> {
        self.pages.get_mut(&page).map(|pd| pd.data.as_mut_slice())
    }

    /// Get the access mode for a page.
    pub fn page_access(&self, page: u32) -> PageAccess {
        self.pages.get(&page).map_or(PageAccess::Inaccessible, |pd| pd.access)
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_mapping() {
        let mut mem = Memory::new();
        assert!(!mem.is_readable(0, 1));

        mem.map_page(0, PageAccess::ReadOnly);
        assert!(mem.is_readable(0, 1));
        assert!(!mem.is_writable(0, 1));

        mem.map_page(0, PageAccess::ReadWrite);
        assert!(mem.is_readable(0, 1));
        assert!(mem.is_writable(0, 1));
    }

    #[test]
    fn test_read_write_u8() {
        let mut mem = Memory::new();
        mem.map_page(0, PageAccess::ReadWrite);

        assert!(matches!(mem.write_u8(0, 42), MemoryAccess::Ok));
        assert_eq!(mem.read_u8(0), Some(42));
    }

    #[test]
    fn test_read_write_u64() {
        let mut mem = Memory::new();
        mem.map_page(0, PageAccess::ReadWrite);

        let value: u64 = 0x0123456789ABCDEF;
        assert!(matches!(mem.write_u64_le(0, value), MemoryAccess::Ok));
        assert_eq!(mem.read_u64_le(0), Some(value));
    }

    #[test]
    fn test_page_fault_on_unmapped() {
        let mem = Memory::new();
        assert_eq!(mem.read_u8(0), None);
    }

    #[test]
    fn test_page_fault_on_readonly_write() {
        let mut mem = Memory::new();
        mem.map_page(0, PageAccess::ReadOnly);
        assert!(matches!(mem.write_u8(0, 42), MemoryAccess::PageFault(_)));
    }
}
