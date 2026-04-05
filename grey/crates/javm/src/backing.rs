//! memfd-backed physical memory pool for the capability-based JAVM.
//!
//! A `BackingStore` wraps a `memfd_create` file descriptor and provides:
//! - Bump allocation (RETYPE): carve pages from the pool
//! - MAP: `mmap(MAP_SHARED|MAP_FIXED)` pages into a CODE cap's 4GB window
//! - UNMAP: replace mapped region with `PROT_NONE` anonymous pages
//!
//! All VMs in an invocation share the same backing store. DATA caps
//! reference offsets into this store. Zero-copy: grant/revoke just
//! moves the offset metadata, no data is copied.

use crate::PVM_PAGE_SIZE;
use crate::cap::Access;

/// 4GB virtual address space per CODE cap window.
pub const CODE_WINDOW_SIZE: usize = 1 << 32;

/// A memfd-backed physical memory pool.
pub struct BackingStore {
    /// File descriptor from `memfd_create`.
    fd: i32,
    /// Total pages in the pool.
    total_pages: u32,
}

impl BackingStore {
    /// Create a new backing store with `total_pages` of capacity.
    ///
    /// Calls `memfd_create` + `ftruncate`. Physical pages are allocated
    /// lazily by the kernel on first write.
    pub fn new(total_pages: u32) -> Option<Self> {
        let name = b"pvm_untyped\0";
        // SAFETY: memfd_create with a valid null-terminated name.
        let fd = unsafe { libc::memfd_create(name.as_ptr() as *const libc::c_char, 0) };
        if fd < 0 {
            return None;
        }
        let size = total_pages as libc::off_t * PVM_PAGE_SIZE as libc::off_t;
        // SAFETY: fd is valid from memfd_create; size is non-negative.
        let ret = unsafe { libc::ftruncate(fd, size) };
        if ret < 0 {
            // SAFETY: fd is valid.
            unsafe { libc::close(fd) };
            return None;
        }
        Some(Self { fd, total_pages })
    }

    /// Total pages in the pool.
    pub fn total_pages(&self) -> u32 {
        self.total_pages
    }

    /// The raw file descriptor (for mmap calls).
    pub fn fd(&self) -> i32 {
        self.fd
    }

    /// Map pages from the backing store into a CODE cap's window.
    ///
    /// `window_base`: start of the 4GB window (from CodeWindow).
    /// `base_page`: guest page number within the window.
    /// `backing_offset`: page offset into the memfd.
    /// `page_count`: number of pages to map.
    /// `access`: RO or RW.
    ///
    /// # Safety
    /// `window_base` must point to a valid 4GB mmap region.
    pub unsafe fn map_pages(
        &self,
        window_base: *mut u8,
        base_page: u32,
        backing_offset: u32,
        page_count: u32,
        access: Access,
    ) -> bool {
        // SAFETY: caller guarantees window_base is a valid 4GB mmap region.
        unsafe {
            let addr = window_base.add(base_page as usize * PVM_PAGE_SIZE as usize);
            let len = page_count as usize * PVM_PAGE_SIZE as usize;
            let prot = match access {
                Access::RO => libc::PROT_READ,
                Access::RW => libc::PROT_READ | libc::PROT_WRITE,
            };
            let offset = backing_offset as libc::off_t * PVM_PAGE_SIZE as libc::off_t;

            let result = libc::mmap(
                addr as *mut libc::c_void,
                len,
                prot,
                libc::MAP_SHARED | libc::MAP_FIXED,
                self.fd,
                offset,
            );
            result != libc::MAP_FAILED
        }
    }

    /// Unmap pages from a CODE cap's window (replace with PROT_NONE).
    ///
    /// # Safety
    /// `window_base` must point to a valid 4GB mmap region.
    pub unsafe fn unmap_pages(window_base: *mut u8, base_page: u32, page_count: u32) -> bool {
        // SAFETY: caller guarantees window_base is a valid 4GB mmap region.
        unsafe {
            let addr = window_base.add(base_page as usize * PVM_PAGE_SIZE as usize);
            let len = page_count as usize * PVM_PAGE_SIZE as usize;

            let result = libc::mmap(
                addr as *mut libc::c_void,
                len,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED | libc::MAP_NORESERVE,
                -1,
                0,
            );
            result != libc::MAP_FAILED
        }
    }

    /// Write initial data into the backing store at a given page offset.
    ///
    /// This writes directly to the memfd via a temporary mmap, then unmaps.
    /// Used during program init to load DATA cap contents from the blob.
    pub fn write_init_data(&self, backing_offset: u32, data: &[u8]) -> bool {
        if data.is_empty() {
            return true;
        }
        let offset = backing_offset as libc::off_t * PVM_PAGE_SIZE as libc::off_t;
        let len = data.len();
        // Map a temporary window to write data
        // SAFETY: fd is valid, offset is within ftruncate'd range (caller ensures).
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_WRITE,
                libc::MAP_SHARED,
                self.fd,
                offset,
            )
        };
        if ptr == libc::MAP_FAILED {
            return false;
        }
        // SAFETY: ptr is a valid mmap'd region of `len` bytes; data.len() == len.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, len);
            libc::munmap(ptr, len);
        }
        true
    }
}

impl Drop for BackingStore {
    fn drop(&mut self) {
        // SAFETY: fd is valid from memfd_create in new().
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Size of the JitContext page placed before the guest memory base.
const CTX_PAGE: usize = 4096;

/// A 4GB virtual address space window for a CODE cap.
///
/// Layout:
/// ```text
/// [CTX page (4KB, RW)] [guest memory (4GB, PROT_NONE initially)]
/// ^                     ^
/// region                base (R15 in JIT code)
/// ```
///
/// DATA caps are mapped into the guest memory region via `BackingStore::map_pages`.
/// JitContext is placed at `base - CTX_PAGE` (same layout as FlatMemory).
pub struct CodeWindow {
    /// Base of the entire mmap'd region (CTX page).
    region: *mut u8,
    /// Total region size (CTX_PAGE + CODE_WINDOW_SIZE).
    region_size: usize,
    /// Guest memory base (region + CTX_PAGE). This is R15 in JIT code.
    base: *mut u8,
}

impl CodeWindow {
    /// Allocate a new 4GB window with CTX page.
    pub fn new() -> Option<Self> {
        let region_size = CTX_PAGE + CODE_WINDOW_SIZE;
        // SAFETY: MAP_ANONYMOUS | MAP_NORESERVE allocates virtual address space only.
        let region = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                region_size,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if region == libc::MAP_FAILED {
            return None;
        }
        let region = region as *mut u8;

        // Make CTX page writable (for JitContext)
        // SAFETY: region points to the start of the mmap, CTX_PAGE is within bounds.
        unsafe {
            if libc::mprotect(
                region as *mut libc::c_void,
                CTX_PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
            ) != 0
            {
                libc::munmap(region as *mut libc::c_void, region_size);
                return None;
            }
        }

        // SAFETY: CTX_PAGE < region_size, so add is in-bounds.
        let base = unsafe { region.add(CTX_PAGE) };

        Some(Self {
            region,
            region_size,
            base,
        })
    }

    /// Guest memory base pointer (R15 in JIT code).
    pub fn base(&self) -> *mut u8 {
        self.base
    }

    /// Pointer to the JitContext page (base - CTX_PAGE).
    pub fn ctx_ptr(&self) -> *mut u8 {
        self.region
    }
}

impl Drop for CodeWindow {
    fn drop(&mut self) {
        // SAFETY: region/region_size from mmap in new().
        unsafe {
            libc::munmap(self.region as *mut libc::c_void, self.region_size);
        }
    }
}

// Send/Sync: CodeWindow holds a raw pointer but we only use it from
// the thread that created it (cooperative scheduling, single-threaded kernel).
unsafe impl Send for CodeWindow {}
unsafe impl Sync for CodeWindow {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backing_store_create() {
        let store = BackingStore::new(10).expect("memfd_create failed");
        assert_eq!(store.total_pages(), 10);
    }

    #[test]
    fn test_code_window_create() {
        let window = CodeWindow::new().expect("mmap failed");
        assert!(!window.base().is_null());
    }

    #[test]
    fn test_map_write_read() {
        let store = BackingStore::new(4).expect("memfd_create failed");
        let window = CodeWindow::new().expect("mmap failed");

        // Map 2 pages at base_page=0 as RW
        unsafe {
            assert!(store.map_pages(window.base(), 0, 0, 2, Access::RW));
        }

        // Write some data
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), window.base(), 4);
        }

        // Read it back
        let mut buf = [0u8; 4];
        unsafe {
            std::ptr::copy_nonoverlapping(window.base(), buf.as_mut_ptr(), 4);
        }
        assert_eq!(buf, [0xDE, 0xAD, 0xBE, 0xEF]);

        // Unmap
        unsafe {
            assert!(BackingStore::unmap_pages(window.base(), 0, 2));
        }
    }

    #[test]
    fn test_map_remap_different_address() {
        let store = BackingStore::new(4).expect("memfd_create failed");
        let window = CodeWindow::new().expect("mmap failed");

        // Map at base_page=0, write data
        unsafe {
            assert!(store.map_pages(window.base(), 0, 0, 1, Access::RW));
            let ptr = window.base();
            *ptr = 0x42;
        }

        // Unmap from page 0
        unsafe {
            assert!(BackingStore::unmap_pages(window.base(), 0, 1));
        }

        // Remap same backing page at base_page=5
        unsafe {
            assert!(store.map_pages(window.base(), 5, 0, 1, Access::RW));
            let ptr = window.base().add(5 * PVM_PAGE_SIZE as usize);
            assert_eq!(*ptr, 0x42); // Same physical data!
        }

        unsafe {
            assert!(BackingStore::unmap_pages(window.base(), 5, 1));
        }
    }

    #[test]
    fn test_write_init_data() {
        let store = BackingStore::new(2).expect("memfd_create failed");
        let window = CodeWindow::new().expect("mmap failed");

        // Write init data to backing page 0
        let init_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        assert!(store.write_init_data(0, &init_data));

        // Map and verify
        unsafe {
            assert!(store.map_pages(window.base(), 0, 0, 1, Access::RO));
            let mut buf = [0u8; 8];
            std::ptr::copy_nonoverlapping(window.base(), buf.as_mut_ptr(), 8);
            assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8]);
            assert!(BackingStore::unmap_pages(window.base(), 0, 1));
        }
    }

    #[test]
    fn test_two_windows_same_backing() {
        let store = BackingStore::new(2).expect("memfd_create failed");
        let win_a = CodeWindow::new().expect("mmap failed");
        let win_b = CodeWindow::new().expect("mmap failed");

        // Map same backing page into both windows at different addresses
        unsafe {
            assert!(store.map_pages(win_a.base(), 0, 0, 1, Access::RW));
            assert!(store.map_pages(win_b.base(), 3, 0, 1, Access::RW));

            // Write via window A
            *win_a.base() = 0xAB;

            // Read via window B — same physical page
            let val = *win_b.base().add(3 * PVM_PAGE_SIZE as usize);
            assert_eq!(val, 0xAB);

            assert!(BackingStore::unmap_pages(win_a.base(), 0, 1));
            assert!(BackingStore::unmap_pages(win_b.base(), 3, 1));
        }
    }
}
