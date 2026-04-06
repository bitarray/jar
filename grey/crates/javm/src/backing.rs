//! Physical memory pool for the capability-based JAVM.
//!
//! On Linux x86-64 a `memfd_create` file descriptor backs the pool:
//! - MAP: `mmap(MAP_SHARED|MAP_FIXED)` pages into a CODE cap's 4GB window
//! - UNMAP: replace mapped region with `PROT_NONE` anonymous pages
//!
//! On other platforms (e.g. macOS ARM64) the pool uses a heap-allocated
//! `Vec<u8>`. MAP/UNMAP copy data in/out rather than remapping shared
//! physical pages. Zero-copy grant/revoke is not available, but all
//! interpreter-based tests pass correctly.
//!
//! All VMs in an invocation share the same backing store. DATA caps
//! reference offsets into this store.

use crate::PVM_PAGE_SIZE;
use crate::cap::Access;

/// 4GB virtual address space per CODE cap window.
pub const CODE_WINDOW_SIZE: usize = 1 << 32;

// ─── Linux x86-64: memfd + mmap ───────────────────────────────────────────

/// A memfd-backed physical memory pool.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub struct BackingStore {
    /// File descriptor from `memfd_create`.
    fd: i32,
    /// Total pages in the pool.
    total_pages: u32,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
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

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl Drop for BackingStore {
    fn drop(&mut self) {
        // SAFETY: fd is valid from memfd_create in new().
        unsafe { libc::close(self.fd) };
    }
}

// ─── Non-Linux: heap-backed fallback ──────────────────────────────────────

/// On non-Linux platforms the pool lives in a `Vec<u8>`.
/// MAP copies pages from the pool into the `CodeWindow` buffer;
/// UNMAP zeroes them out. No shared-physical-page trick available,
/// but the interpreter path works correctly.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub struct BackingStore {
    data: Vec<u8>,
    total_pages: u32,
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
impl BackingStore {
    pub fn new(total_pages: u32) -> Option<Self> {
        let size = total_pages as usize * PVM_PAGE_SIZE as usize;
        Some(Self {
            data: vec![0u8; size],
            total_pages,
        })
    }

    pub fn total_pages(&self) -> u32 {
        self.total_pages
    }

    /// Copy pages from the pool into the CodeWindow buffer.
    ///
    /// # Safety
    /// `window_base` must point to a buffer of at least
    /// `(base_page + page_count) * PVM_PAGE_SIZE` bytes.
    pub unsafe fn map_pages(
        &self,
        window_base: *mut u8,
        base_page: u32,
        backing_offset: u32,
        page_count: u32,
        _access: Access,
    ) -> bool {
        let src_start = backing_offset as usize * PVM_PAGE_SIZE as usize;
        let dst_start = base_page as usize * PVM_PAGE_SIZE as usize;
        let len = page_count as usize * PVM_PAGE_SIZE as usize;
        if src_start + len > self.data.len() {
            return false;
        }
        // SAFETY: caller ensures window_base has sufficient capacity.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.data.as_ptr().add(src_start),
                window_base.add(dst_start),
                len,
            );
        }
        true
    }

    /// Zero out pages in the CodeWindow buffer.
    ///
    /// # Safety
    /// `window_base` must point to a buffer of at least
    /// `(base_page + page_count) * PVM_PAGE_SIZE` bytes.
    pub unsafe fn unmap_pages(window_base: *mut u8, base_page: u32, page_count: u32) -> bool {
        let dst_start = base_page as usize * PVM_PAGE_SIZE as usize;
        let len = page_count as usize * PVM_PAGE_SIZE as usize;
        // SAFETY: caller ensures window_base is valid.
        unsafe {
            std::ptr::write_bytes(window_base.add(dst_start), 0, len);
        }
        true
    }

    /// Write initial data directly into the pool.
    pub fn write_init_data(&self, backing_offset: u32, data: &[u8]) -> bool {
        if data.is_empty() {
            return true;
        }
        let start = backing_offset as usize * PVM_PAGE_SIZE as usize;
        if start + data.len() > self.data.len() {
            return false;
        }
        // SAFETY: bounds checked above; cast away the shared ref to write init data.
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.data.as_ptr().add(start) as *mut u8,
                data.len(),
            );
        }
        true
    }
}

// ─── CodeWindow ───────────────────────────────────────────────────────────

/// Size of the JitContext page placed before the guest memory base.
const CTX_PAGE: usize = 4096;

/// A virtual address space window for a CODE cap.
///
/// On Linux x86-64: a full 4GB mmap region with a CTX page prefix.
/// On other platforms: a heap-allocated buffer sized to `total_pages`.
///
/// Layout (both platforms):
/// ```text
/// [CTX page (4KB, RW)] [guest memory region]
/// ^                     ^
/// ctx_ptr()             base()  ← R15 in JIT code
/// ```
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub struct CodeWindow {
    /// Base of the entire mmap'd region (CTX page).
    region: *mut u8,
    /// Total region size (CTX_PAGE + CODE_WINDOW_SIZE).
    region_size: usize,
    /// Guest memory base (region + CTX_PAGE). This is R15 in JIT code.
    base: *mut u8,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl CodeWindow {
    /// Allocate a new 4GB window with CTX page.
    pub fn new(_total_pages: u32) -> Option<Self> {
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

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl Drop for CodeWindow {
    fn drop(&mut self) {
        // SAFETY: region/region_size from mmap in new().
        unsafe { libc::munmap(self.region as *mut libc::c_void, self.region_size) };
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe impl Send for CodeWindow {}
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe impl Sync for CodeWindow {}

/// Heap-backed window for non-Linux platforms.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub struct CodeWindow {
    buf: Vec<u8>,
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
impl CodeWindow {
    /// Allocate a buffer large enough for `total_pages` guest pages
    /// plus one CTX page prefix.
    pub fn new(total_pages: u32) -> Option<Self> {
        let size = CTX_PAGE + total_pages as usize * PVM_PAGE_SIZE as usize;
        Some(Self {
            buf: vec![0u8; size],
        })
    }

    /// Guest memory base pointer (after the CTX page prefix).
    pub fn base(&self) -> *mut u8 {
        // SAFETY: buf has at least CTX_PAGE bytes.
        unsafe { self.buf.as_ptr().add(CTX_PAGE) as *mut u8 }
    }

    /// Pointer to the CTX page (base - CTX_PAGE).
    pub fn ctx_ptr(&self) -> *mut u8 {
        self.buf.as_ptr() as *mut u8
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
unsafe impl Send for CodeWindow {}
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
unsafe impl Sync for CodeWindow {}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backing_store_create() {
        let store = BackingStore::new(10).expect("BackingStore::new failed");
        assert_eq!(store.total_pages(), 10);
    }

    #[test]
    fn test_code_window_create() {
        let window = CodeWindow::new(16).expect("CodeWindow::new failed");
        assert!(!window.base().is_null());
    }

    #[test]
    fn test_map_write_read() {
        let store = BackingStore::new(4).expect("BackingStore::new failed");
        let window = CodeWindow::new(4).expect("CodeWindow::new failed");

        unsafe { assert!(store.map_pages(window.base(), 0, 0, 2, Access::RW)) };

        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), window.base(), 4) };

        let mut buf = [0u8; 4];
        unsafe { std::ptr::copy_nonoverlapping(window.base(), buf.as_mut_ptr(), 4) };
        assert_eq!(buf, [0xDE, 0xAD, 0xBE, 0xEF]);

        unsafe { assert!(BackingStore::unmap_pages(window.base(), 0, 2)) };
    }

    #[test]
    fn test_write_init_data() {
        let store = BackingStore::new(2).expect("BackingStore::new failed");
        let window = CodeWindow::new(2).expect("CodeWindow::new failed");

        let init_data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        assert!(store.write_init_data(0, &init_data));

        unsafe {
            assert!(store.map_pages(window.base(), 0, 0, 1, Access::RO));
            let mut buf = [0u8; 8];
            std::ptr::copy_nonoverlapping(window.base(), buf.as_mut_ptr(), 8);
            assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8]);
            assert!(BackingStore::unmap_pages(window.base(), 0, 1));
        }
    }
}
