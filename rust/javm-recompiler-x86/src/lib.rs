//! PVM recompiler — compiles PVM bytecode to native x86-64 machine code.
//!
//! This provides the same semantics as the interpreter but with significantly
//! better performance by eliminating decode overhead and keeping PVM registers
//! in native CPU registers.
//!
//! # JIT Memory Model
//!
//! **Compilation** (`Compiler` in `codegen.rs`):
//! - Emits x86-64 bytes into an `Assembler` buffer (`asm.rs`)
//! - Buffer is either a `Vec<u8>` (tests) or an mmap'd region (production)
//! - Production path: mmap with PROT_READ|PROT_WRITE during compilation,
//!   then mremap + mprotect to PROT_READ|PROT_EXEC before execution
//!
//! **Execution context** (`JitContext`):
//! - `#[repr(C)]` struct at fixed offsets, passed to JIT code via R15
//! - Owned by the caller (kernel or standalone harness); JIT code reads/writes
//!   fields at known offsets via `[r15 + OFFSET]` addressing
//! - `regs[0..13]`: PVM registers, synced to/from `VmInstance` on context switch
//! - `gas`: signed i64; JIT subtracts per-basic-block costs and exits on negative
//! - `flat_buf` / `flat_perms`: pointers into the backing store's mmap'd 4GB
//!   CODE window (Harvard architecture, shared across VMs using the same CODE cap)
//!
//! **Native code** (`NativeCode`):
//! - Mmap'd executable region; one per CODE cap (shared across all VMs)
//! - Compiled once on first use, then reused via `dispatch_table` (PVM PC → native offset)
//! - Dropped when the CODE cap is dropped (munmap in `Drop` impl)
//!
//! **Signal handler** (`signal.rs`):
//! - Installs a SIGSEGV handler that catches faults from JIT guest memory access
//! - Uses the `trap_table` (sorted native PC → PVM PC pairs) to map faulting
//!   address back to PVM state for page fault reporting

pub mod asm;
pub mod codegen;
pub mod predecode;
pub mod signal;

use codegen::{Compiler, HelperFns};
use javm_exec::ExitReason;
use javm_exec::{Gas, REG_COUNT as PVM_REGISTER_COUNT};

/// No-op tracing shim. v2 javm uses the `tracing` crate for diagnostic
/// logs; javm-exec doesn't pull that in. Diagnostic logs in the JIT
/// driver are pure diagnostics, so we no-op them here.
mod tracing {
    macro_rules! debug {
        ($($tt:tt)*) => {{}};
    }
    pub(super) use debug;
}

/// JIT execution context passed to compiled code via R15.
/// Must be #[repr(C)] with exact field ordering matching codegen offsets.
#[repr(C)]
pub struct JitContext {
    /// PVM registers (offset 0, 13 × 8 = 104 bytes).
    pub regs: [u64; 13],
    /// Gas counter (offset 104). Signed to detect underflow.
    pub gas: i64,
    /// Exit reason code (offset 112).
    pub exit_reason: u32,
    /// Exit argument (offset 116) — host call ID, page fault addr, etc.
    pub exit_arg: u32,
    /// Heap base address (offset 120).
    pub heap_base: u32,
    /// Current heap top (offset 124).
    pub heap_top: u32,
    /// Jump table pointer (offset 128).
    pub jt_ptr: *const u32,
    /// Jump table length (offset 136).
    pub jt_len: u32,
    pub _pad0: u32,
    /// Basic block starts pointer (offset 144).
    pub bb_starts: *const u8,
    /// Basic block starts length (offset 152).
    pub bb_len: u32,
    pub _pad1: u32,
    /// Entry PC for re-entry after host calls (offset 160).
    pub entry_pc: u32,
    /// Current PC when execution stopped (offset 164).
    pub pc: u32,
    /// Dispatch table: PVM PC → native code offset (offset 168).
    pub dispatch_table: *const i32,
    /// Base address of native code (offset 176).
    pub code_base: u64,
    /// Flat guest memory buffer base pointer (offset 184).
    pub flat_buf: *mut u8,
    /// Permission table base pointer (offset 192).
    pub flat_perms: *const u8,
    /// Fast re-entry flag (offset 200).
    pub fast_reentry: u32,
    pub _pad2: u32,
    /// Maximum heap pages — grow_heap refuses beyond this (offset 208).
    pub max_heap_pages: u32,
    pub _pad3: u32,
}

/// Compiled native code buffer (mmap'd as executable).
///
/// The allocation includes a trailing PROT_NONE guard page that catches
/// wild forward jumps or buffer overruns past the end of the JIT code.
pub struct NativeCode {
    pub ptr: *mut u8,
    pub len: usize,
    /// Total mmap size including the trailing guard page.
    pub mmap_cap: usize,
}

const PAGE_SIZE: usize = 4096;

/// Round `n` up to the next multiple of `PAGE_SIZE`.
fn page_align(n: usize) -> usize {
    (n + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

impl NativeCode {
    /// Allocate an executable code buffer and copy machine code into it.
    /// This is the fallback path; the mmap-direct path skips the copy.
    /// A trailing PROT_NONE guard page is placed after the code.
    fn new(code: &[u8]) -> Result<Self, String> {
        if code.is_empty() {
            return Err("empty code buffer".into());
        }
        let len = code.len();
        let code_pages = page_align(len);
        let total = code_pages + PAGE_SIZE; // + trailing guard page
        // SAFETY: mmap with MAP_ANONYMOUS|MAP_PRIVATE allocates fresh pages. MAP_FAILED checked below.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                total,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err("mmap failed".into());
        }
        let ptr = ptr as *mut u8;
        // SAFETY: ptr is a valid mmap'd region of `total` bytes; copy_nonoverlapping is in-bounds.
        // mprotect/munmap operate on the same valid mmap region.
        unsafe {
            std::ptr::copy_nonoverlapping(code.as_ptr(), ptr, len);
            // Make code pages executable (and read-only).
            if libc::mprotect(
                ptr as *mut libc::c_void,
                code_pages,
                libc::PROT_READ | libc::PROT_EXEC,
            ) != 0
            {
                libc::munmap(ptr as *mut libc::c_void, total);
                return Err("mprotect RX failed".into());
            }
            // Trailing guard page: PROT_NONE catches wild forward jumps.
            // SAFETY: ptr + code_pages is within the mmap'd region (total = code_pages + PAGE_SIZE).
            if libc::mprotect(
                ptr.add(code_pages) as *mut libc::c_void,
                PAGE_SIZE,
                libc::PROT_NONE,
            ) != 0
            {
                libc::munmap(ptr as *mut libc::c_void, total);
                return Err("mprotect guard failed".into());
            }
        }
        Ok(Self {
            ptr,
            len,
            mmap_cap: total,
        })
    }

    /// Get the function pointer for the compiled code entry.
    pub fn entry(&self) -> unsafe extern "sysv64" fn(*mut JitContext) {
        // SAFETY: ptr contains valid x86-64 machine code from the assembler, and was
        // mprotected to PROT_READ|PROT_EXEC. Transmute to fn pointer is valid.
        unsafe { std::mem::transmute(self.ptr) }
    }
}

impl Drop for NativeCode {
    fn drop(&mut self) {
        // SAFETY: ptr and mmap_cap correspond to a valid mmap allocation from new().
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.mmap_cap);
        }
    }
}

/// Result of standalone code compilation (no execution context).
pub struct CompiledCode {
    pub native_code: NativeCode,
    pub dispatch_table: Vec<i32>,
    pub trap_table: Vec<(u32, u32)>,
    pub exit_label_offset: u32,
}

/// Compile PVM code to native x86-64 without creating an execution context.
/// Returns the compiled artifacts that can be stored in a CodeCap.
pub fn compile_code(
    code: &[u8],
    bitmask: &[u8],
    jump_table: &[u32],
    mem_cycles: u8,
) -> Result<CompiledCode, String> {
    let helpers = HelperFns {
        mem_read_u8: mem_read_u8 as *const () as u64,
        mem_read_u16: mem_read_u16 as *const () as u64,
        mem_read_u32: mem_read_u32 as *const () as u64,
        mem_read_u64: mem_read_u64_fn as *const () as u64,
        mem_write_u8: mem_write_u8 as *const () as u64,
        mem_write_u16: mem_write_u16 as *const () as u64,
        mem_write_u32: mem_write_u32 as *const () as u64,
        mem_write_u64: mem_write_u64_fn as *const () as u64,
        sbrk_helper: sbrk_helper as *const () as u64,
    };

    let compiler = Compiler::new(bitmask, jump_table, helpers, code.len(), true, mem_cycles);
    let result = compiler.compile(code, bitmask);
    let dispatch_table = result.dispatch_table;

    let native_code = if let Some(mmap_ptr) = result.mmap_ptr {
        NativeCode {
            ptr: mmap_ptr,
            len: result.mmap_len,
            mmap_cap: result.mmap_cap,
        }
    } else {
        NativeCode::new(&result.native_code)?
    };

    Ok(CompiledCode {
        native_code,
        dispatch_table,
        trap_table: result.trap_table,
        exit_label_offset: result.exit_label_offset,
    })
}

// SAFETY: NativeCode holds a raw pointer to mmap'd memory. It's only accessed from
// the thread that owns the kernel (cooperative scheduling).
unsafe impl Send for NativeCode {}
unsafe impl Sync for NativeCode {}

/// Flat memory backing buffer for inline JIT memory access.
///
/// Contiguous mmap layout (R15 = guest memory base = region + HEADER_SIZE):
///   [perm table, 1MB] [JitContext page, 4KB] [guest memory, 4GB]
///   ^                  ^                      ^
///   region             ctx_ptr                 R15 (buf)
///
/// R15-relative offsets:
///   perms:  R15 - CTX_PAGE - NUM_PAGES  = R15 - PERMS_OFFSET
///   ctx:    R15 - CTX_PAGE              = R15 - CTX_OFFSET
///   guest:  R15 + 0 .. R15 + 4GB
/// Memory layout offsets for direct flat-buffer writes (standalone recompiler path).
pub struct DataLayout {
    pub mem_size: u32,
    pub arg_start: u32,
    pub arg_data: Vec<u8>,
    pub ro_start: u32,
    pub ro_data: Vec<u8>,
    pub rw_start: u32,
    pub rw_data: Vec<u8>,
}

pub struct FlatMemory {
    /// Base of the entire mmap'd region.
    region: *mut u8,
    /// Total mmap size.
    region_size: usize,
    /// Pointer to the guest memory base (= region + HEADER_SIZE).
    buf: *mut u8,
    /// Pointer to the permission table (= region).
    perms: *mut u8,
    /// Largest valid guest-address bound: bytes in `[0, mem_size)`
    /// are considered in-range for `Memory` accesses. The underlying
    /// mmap actually covers 4 GiB, but the practical PVM program
    /// uses far less; we cap reads/writes here so the interpreter
    /// path's `Option<T>` / `bool` returns behave sensibly.
    mem_size: u32,
}

// SAFETY: FlatMemory holds raw pointers to its own mmap'd region; the
// region is owned by FlatMemory itself (no external aliasing) and
// access is single-threaded (driven by the kernel's cooperative
// scheduler).
unsafe impl Send for FlatMemory {}
unsafe impl Sync for FlatMemory {}

/// Guest address-space size. Reduced from 4 GiB to 64 MiB so many
/// concurrent JIT instances (e.g. `cargo test` running with default
/// parallelism) can each grab a low-VA reservation under MAP_32BIT.
/// PVM programs in the current bench/test corpus all use << 64 MiB.
/// When a guest needs more we'll switch FlatMemory to
/// `MAP_FIXED_NOREPLACE` at a chosen low address and reserve a
/// single process-wide pool.
const FLAT_BUF_SIZE: usize = 1 << 24; // 16 MiB virtual
/// Perm-table size, one byte per 4 KiB page covering FLAT_BUF_SIZE.
const NUM_PAGES: usize = FLAT_BUF_SIZE / 4096;
const CTX_PAGE: usize = 4096; // JitContext page
const HEADER_SIZE: usize = NUM_PAGES + CTX_PAGE; // perms + ctx page before guest mem

impl FlatMemory {
    /// Allocate a fresh 4 GiB virtual address space (anonymous,
    /// `MAP_NORESERVE`) plus the leading perm-table + CTX_PAGE.
    ///
    /// `mem_size` sets the practical guest-address upper bound for
    /// the `Memory` trait's bounds checks. Pages in `[0, mem_size)`
    /// are pre-marked RW in the perm table so `populate_memory` can
    /// overwrite them with the proper RO/RW classification.
    pub fn new(mem_size: u32) -> Option<Self> {
        let region_size = HEADER_SIZE + FLAT_BUF_SIZE;
        // `MAP_32BIT` forces the kernel to pick an address in [0, 2 GiB).
        // Combined with FLAT_BUF_SIZE = 1 GiB, the entire reservation
        // ends below 2^32, satisfying the `NativeMemory` low-4 GiB
        // invariant (guest 32-bit addresses == host pointers via
        // zero-extension).
        //
        // SAFETY: mmap with MAP_ANONYMOUS|MAP_PRIVATE|MAP_NORESERVE allocates virtual pages.
        // MAP_FAILED checked below.
        let region = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                region_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_NORESERVE | libc::MAP_32BIT,
                -1,
                0,
            )
        };
        if region == libc::MAP_FAILED {
            return None;
        }
        let region = region as *mut u8;
        let perms = region;
        // SAFETY: HEADER_SIZE < region_size, so region + HEADER_SIZE is within the mmap.
        let buf = unsafe { region.add(HEADER_SIZE) };

        // Pre-mark `[0, mem_size)` pages RW so `populate_memory` can
        // refine per region. (The native ABI's read/write helpers
        // check this table; perms here gate the cold-path API. JIT'd
        // code path-bounds via mmap guard pages, not this table.)
        let num_pages = mem_size.div_ceil(4096) as usize;
        unsafe {
            std::ptr::write_bytes(perms, javm_exec::perm::RW, num_pages.min(NUM_PAGES));
        }

        Some(Self {
            region,
            region_size,
            buf,
            perms,
            mem_size,
        })
    }

    /// Get the pointer where JitContext should be placed (buf - CTX_PAGE).
    fn ctx_ptr(&self) -> *mut u8 {
        // SAFETY: buf = region + HEADER_SIZE and HEADER_SIZE >= CTX_PAGE, so sub is in-bounds.
        unsafe { self.buf.sub(CTX_PAGE) }
    }
}

/// Populate `memory` from a `DataLayout` by writing arg/ro/rw
/// regions in place. The caller is responsible for ensuring the
/// memory backing covers `layout.mem_size`.
pub fn populate_memory<M: javm_exec::Memory>(memory: &mut M, layout: &DataLayout) {
    if !layout.arg_data.is_empty() {
        // Best-effort: ignore errors for the test/bench path (which
        // pre-validates layout). Errors here would indicate a layout
        // bug, not a runtime fault.
        let _ = memory.write(layout.arg_start, &layout.arg_data);
    }
    if !layout.ro_data.is_empty() {
        let _ = memory.write(layout.ro_start, &layout.ro_data);
    }
    if !layout.rw_data.is_empty() {
        let _ = memory.write(layout.rw_start, &layout.rw_data);
    }
}

impl Drop for FlatMemory {
    fn drop(&mut self) {
        // SAFETY: region and region_size correspond to a valid mmap allocation from new().
        unsafe {
            libc::munmap(self.region as *mut libc::c_void, self.region_size);
        }
    }
}

/// Extension of [`javm_exec::Memory`] for backends suitable as the
/// recompiler's address space.
///
/// **Invariant** (to be enforced by `RecompiledPvm::new` once the
/// recompiler stops owning its own mmap in commit 5):
/// `host_buf_ptr() as usize + host_buf_len() <= 1 << 32` — i.e. the
/// backing buffer lives in the host's low 4 GiB so guest 32-bit
/// addresses equal host pointers via zero-extension and the JIT can
/// emit `[rdx]`-style absolute addressing without a base register.
///
/// Today's [`FlatMemory`] satisfies the trait but mmaps anywhere the
/// kernel picks; the low-VA invariant lands in commit 5 alongside
/// the codegen change.
pub trait NativeMemory: javm_exec::Memory {
    /// Base pointer of the guest's address space.
    fn host_buf_ptr(&self) -> *mut u8;
    /// Length of the addressable guest region in bytes (≤ 2^32).
    fn host_buf_len(&self) -> usize;
    /// Per-page permission table base pointer. The SIGSEGV handler
    /// reads it to classify faults (RO-write vs unmapped).
    fn host_perms_ptr(&self) -> *mut u8;
    /// Pointer to a scratch region (≥ 4 KiB) where the recompiler
    /// places its per-invocation `JitContext`. The layout invariant
    /// is that the JIT'd code can reach this region via
    /// `R15 - CTX_OFFSET`, i.e. `host_ctx_ptr() == host_buf_ptr() - CTX_PAGE`.
    /// Today's [`FlatMemory`] satisfies this by reserving the page
    /// immediately below the guest buffer.
    fn host_ctx_ptr(&self) -> *mut u8;
}

impl javm_exec::Memory for FlatMemory {
    #[inline]
    fn read_u8(&self, addr: u32) -> Option<u8> {
        if addr >= self.mem_size {
            return None;
        }
        // SAFETY: addr < mem_size <= NUM_PAGES * 4096; buf covers the
        // full 4 GiB anonymous mapping.
        Some(unsafe { *self.buf.add(addr as usize) })
    }
    #[inline]
    fn read_u16_le(&self, addr: u32) -> Option<u16> {
        if (addr as u64).saturating_add(2) > self.mem_size as u64 {
            return None;
        }
        // SAFETY: bounds-checked above.
        Some(unsafe { self.buf.add(addr as usize).cast::<u16>().read_unaligned() })
    }
    #[inline]
    fn read_u32_le(&self, addr: u32) -> Option<u32> {
        if (addr as u64).saturating_add(4) > self.mem_size as u64 {
            return None;
        }
        Some(unsafe { self.buf.add(addr as usize).cast::<u32>().read_unaligned() })
    }
    #[inline]
    fn read_u64_le(&self, addr: u32) -> Option<u64> {
        if (addr as u64).saturating_add(8) > self.mem_size as u64 {
            return None;
        }
        Some(unsafe { self.buf.add(addr as usize).cast::<u64>().read_unaligned() })
    }
    #[inline]
    fn write_u8(&mut self, addr: u32, val: u8) -> bool {
        if addr >= self.mem_size {
            return false;
        }
        unsafe {
            *self.buf.add(addr as usize) = val;
        }
        true
    }
    #[inline]
    fn write_u16_le(&mut self, addr: u32, val: u16) -> bool {
        if (addr as u64).saturating_add(2) > self.mem_size as u64 {
            return false;
        }
        unsafe {
            self.buf
                .add(addr as usize)
                .cast::<u16>()
                .write_unaligned(val);
        }
        true
    }
    #[inline]
    fn write_u32_le(&mut self, addr: u32, val: u32) -> bool {
        if (addr as u64).saturating_add(4) > self.mem_size as u64 {
            return false;
        }
        unsafe {
            self.buf
                .add(addr as usize)
                .cast::<u32>()
                .write_unaligned(val);
        }
        true
    }
    #[inline]
    fn write_u64_le(&mut self, addr: u32, val: u64) -> bool {
        if (addr as u64).saturating_add(8) > self.mem_size as u64 {
            return false;
        }
        unsafe {
            self.buf
                .add(addr as usize)
                .cast::<u64>()
                .write_unaligned(val);
        }
        true
    }

    fn map_region(
        &mut self,
        start: u64,
        size: u64,
        access: javm_exec::Access,
        init: Option<&[u8]>,
    ) -> Result<(), javm_exec::MapError> {
        let page = javm_exec::PAGE_SIZE as u64;
        if !start.is_multiple_of(page) {
            return Err(javm_exec::MapError::UnalignedStart(start));
        }
        if !size.is_multiple_of(page) {
            return Err(javm_exec::MapError::UnalignedSize(size));
        }
        let end = start
            .checked_add(size)
            .ok_or(javm_exec::MapError::Overflow)?;
        if end > self.mem_size as u64 {
            // Grow the effective bound. The underlying mmap already covers 4 GiB.
            let end_u32: u32 = end.try_into().map_err(|_| javm_exec::MapError::Overflow)?;
            self.mem_size = end_u32;
        }

        let perm_byte = match access {
            javm_exec::Access::ReadOnly => javm_exec::perm::RO,
            javm_exec::Access::ReadWrite => javm_exec::perm::RW,
        };
        let first_page = (start / page) as usize;
        let last_page = ((end / page) as usize).saturating_sub(1);
        if size > 0 {
            // SAFETY: page indices are clamped by mem_size <= NUM_PAGES*4096.
            unsafe {
                for p in first_page..=last_page {
                    *self.perms.add(p) = perm_byte;
                }
            }
        }

        if let Some(bytes) = init {
            let n = bytes.len().min(size as usize);
            // SAFETY: start..start+n is within mem_size (bounds-checked above).
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.buf.add(start as usize), n);
            }
        }
        Ok(())
    }

    fn perm_of(&self, addr: u32) -> u8 {
        let page = (addr / javm_exec::PAGE_SIZE) as usize;
        if page >= NUM_PAGES {
            return javm_exec::perm::NONE;
        }
        // SAFETY: page < NUM_PAGES (size of the perm table).
        unsafe { *self.perms.add(page) }
    }

    fn read(&self, addr: u32, len: usize) -> Result<Vec<u8>, javm_exec::MemAccess> {
        let end = (addr as u64)
            .checked_add(len as u64)
            .ok_or(javm_exec::MemAccess::PageFault(
                addr & !(javm_exec::PAGE_SIZE - 1),
            ))?;
        if end > self.mem_size as u64 {
            return Err(javm_exec::MemAccess::PageFault(
                addr & !(javm_exec::PAGE_SIZE - 1),
            ));
        }
        let mut out = vec![0u8; len];
        // SAFETY: addr..addr+len within mem_size (checked).
        unsafe {
            core::ptr::copy_nonoverlapping(self.buf.add(addr as usize), out.as_mut_ptr(), len);
        }
        Ok(out)
    }

    fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), javm_exec::MemAccess> {
        let end =
            (addr as u64)
                .checked_add(data.len() as u64)
                .ok_or(javm_exec::MemAccess::PageFault(
                    addr & !(javm_exec::PAGE_SIZE - 1),
                ))?;
        if end > self.mem_size as u64 {
            return Err(javm_exec::MemAccess::PageFault(
                addr & !(javm_exec::PAGE_SIZE - 1),
            ));
        }
        // Per-page perm check.
        let start_page = (addr as usize) / (javm_exec::PAGE_SIZE as usize);
        let last_page = (end as usize - 1) / (javm_exec::PAGE_SIZE as usize);
        for p in start_page..=last_page {
            let perm = unsafe { *self.perms.add(p) };
            if perm != javm_exec::perm::RW {
                return Err(javm_exec::MemAccess::WriteProtected(
                    (p as u32) * javm_exec::PAGE_SIZE,
                ));
            }
        }
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), self.buf.add(addr as usize), data.len());
        }
        Ok(())
    }
}

impl NativeMemory for FlatMemory {
    #[inline]
    fn host_buf_ptr(&self) -> *mut u8 {
        self.buf
    }
    #[inline]
    fn host_buf_len(&self) -> usize {
        FLAT_BUF_SIZE
    }
    #[inline]
    fn host_perms_ptr(&self) -> *mut u8 {
        self.perms
    }
    #[inline]
    fn host_ctx_ptr(&self) -> *mut u8 {
        self.ctx_ptr()
    }
}

// Memory helper functions called from compiled code.
// For reads: returns the value. On fault, sets ctx fields (ctx obtained from the caller).
// We pass memory pointer directly, and handle faults via a global context.
// Actually, let's pass ctx as first arg for writes so we can set fault info.

// Reads: fn(ctx: *mut JitContext, addr: u32) -> u64
// On fault, the caller checks ctx.exit_reason after the call.
// But the helper doesn't have ctx... Let's restructure.
// Pass ctx as first arg to everything.

/// Check flat buffer permission for a byte range. Returns true if all bytes are accessible.
fn flat_check_perm(ctx: &JitContext, addr: u32, len: u32, min_perm: u8) -> bool {
    if ctx.flat_perms.is_null() {
        return false;
    }
    let start_page = addr as usize / 4096;
    let end_page = (addr as usize + len as usize - 1) / 4096;
    for p in start_page..=end_page {
        if p >= NUM_PAGES {
            return false;
        }
        // SAFETY: p is bounds-checked against NUM_PAGES above; flat_perms is valid for NUM_PAGES.
        let perm = unsafe { *ctx.flat_perms.add(p) };
        if perm < min_perm {
            return false;
        }
    }
    true
}

/// Read from flat buffer. Caller must have checked permissions.
unsafe fn flat_read(ctx: &JitContext, addr: u32, len: usize) -> u64 {
    // SAFETY: caller verified permissions via flat_check_perm; addr..+len is within flat_buf.
    unsafe {
        let ptr = ctx.flat_buf.add(addr as usize);
        match len {
            1 => *ptr as u64,
            2 => u16::from_le_bytes([*ptr, *ptr.add(1)]) as u64,
            4 => u32::from_le_bytes([*ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3)]) as u64,
            8 => u64::from_le_bytes(std::ptr::read_unaligned(ptr as *const [u8; 8])),
            _ => 0,
        }
    }
}

/// Write to flat buffer. Caller must have checked permissions.
unsafe fn flat_write(ctx: &JitContext, addr: u32, bytes: &[u8]) {
    // SAFETY: caller verified permissions via flat_check_perm; addr..+len is within flat_buf.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ctx.flat_buf.add(addr as usize), bytes.len());
    }
}

/// Memory read helpers — read from flat buffer.
///
/// All extern "sysv64" helpers below are called from JIT-generated code with a valid
/// JitContext pointer passed as the first argument via the sysv64 calling convention.
/// The pointer is valid for the duration of JIT execution because JitContext lives in
/// the FlatMemory mmap region which outlives the JIT call.
extern "sysv64" fn mem_read_u8(ctx: *mut JitContext, addr: u32) -> u64 {
    // SAFETY: ctx is a valid JitContext pointer from JIT code; see group comment above.
    let ctx = unsafe { &mut *ctx };
    if flat_check_perm(ctx, addr, 1, 1) {
        // SAFETY: flat_check_perm confirmed the page is readable.
        return unsafe { flat_read(ctx, addr, 1) };
    }
    ctx.exit_reason = 3;
    ctx.exit_arg = addr;
    0
}

extern "sysv64" fn mem_read_u16(ctx: *mut JitContext, addr: u32) -> u64 {
    // SAFETY: valid JitContext pointer from JIT code; see group comment on mem_read_u8.
    let ctx = unsafe { &mut *ctx };
    if flat_check_perm(ctx, addr, 2, 1) {
        // SAFETY: flat_check_perm confirmed the pages are readable.
        return unsafe { flat_read(ctx, addr, 2) };
    }
    ctx.exit_reason = 3;
    ctx.exit_arg = addr;
    0
}

extern "sysv64" fn mem_read_u32(ctx: *mut JitContext, addr: u32) -> u64 {
    // SAFETY: valid JitContext pointer from JIT code; see group comment on mem_read_u8.
    let ctx = unsafe { &mut *ctx };
    if flat_check_perm(ctx, addr, 4, 1) {
        // SAFETY: flat_check_perm confirmed the pages are readable.
        return unsafe { flat_read(ctx, addr, 4) };
    }
    ctx.exit_reason = 3;
    ctx.exit_arg = addr;
    0
}

extern "sysv64" fn mem_read_u64_fn(ctx: *mut JitContext, addr: u32) -> u64 {
    // SAFETY: valid JitContext pointer from JIT code; see group comment on mem_read_u8.
    let ctx = unsafe { &mut *ctx };
    if flat_check_perm(ctx, addr, 8, 1) {
        // SAFETY: flat_check_perm confirmed the pages are readable.
        return unsafe { flat_read(ctx, addr, 8) };
    }
    ctx.exit_reason = 3;
    ctx.exit_arg = addr;
    0
}

/// Memory write helpers — write to flat buffer.
extern "sysv64" fn mem_write_u8(ctx: *mut JitContext, addr: u32, value: u64) -> u64 {
    // SAFETY: valid JitContext pointer from JIT code; see group comment on mem_read_u8.
    let ctx = unsafe { &mut *ctx };
    if flat_check_perm(ctx, addr, 1, 2) {
        // SAFETY: flat_check_perm confirmed the page is writable.
        unsafe {
            flat_write(ctx, addr, &[value as u8]);
        }
        return 0;
    }
    ctx.exit_reason = 3;
    ctx.exit_arg = addr;
    1
}

extern "sysv64" fn mem_write_u16(ctx: *mut JitContext, addr: u32, value: u64) -> u64 {
    // SAFETY: valid JitContext pointer from JIT code; see group comment on mem_read_u8.
    let ctx = unsafe { &mut *ctx };
    if flat_check_perm(ctx, addr, 2, 2) {
        // SAFETY: flat_check_perm confirmed the pages are writable.
        unsafe {
            flat_write(ctx, addr, &(value as u16).to_le_bytes());
        }
        return 0;
    }
    ctx.exit_reason = 3;
    ctx.exit_arg = addr;
    1
}

extern "sysv64" fn mem_write_u32(ctx: *mut JitContext, addr: u32, value: u64) -> u64 {
    // SAFETY: valid JitContext pointer from JIT code; see group comment on mem_read_u8.
    let ctx = unsafe { &mut *ctx };
    if flat_check_perm(ctx, addr, 4, 2) {
        // SAFETY: flat_check_perm confirmed the pages are writable.
        unsafe {
            flat_write(ctx, addr, &(value as u32).to_le_bytes());
        }
        return 0;
    }
    ctx.exit_reason = 3;
    ctx.exit_arg = addr;
    1
}

extern "sysv64" fn mem_write_u64_fn(ctx: *mut JitContext, addr: u32, value: u64) -> u64 {
    // SAFETY: valid JitContext pointer from JIT code; see group comment on mem_read_u8.
    let ctx = unsafe { &mut *ctx };
    if flat_check_perm(ctx, addr, 8, 2) {
        // SAFETY: flat_check_perm confirmed the pages are writable.
        unsafe {
            flat_write(ctx, addr, &value.to_le_bytes());
        }
        return 0;
    }
    ctx.exit_reason = 3;
    ctx.exit_arg = addr;
    1
}

/// Sbrk helper. ctx: *mut JitContext, size: u64 → result in return.
extern "sysv64" fn sbrk_helper(ctx: *mut JitContext, size: u64) -> u64 {
    // SAFETY: valid JitContext pointer from JIT code; see group comment on mem_read_u8.
    let ctx = unsafe { &mut *ctx };
    let ps = javm_exec::PAGE_SIZE;

    if size > u32::MAX as u64 {
        return 0;
    }
    if size == 0 {
        // Query: return current heap top
        return ctx.heap_top as u64;
    }

    let size_u32 = size as u32;
    let old_top = ctx.heap_top;
    let new_top = (old_top as u64) + (size_u32 as u64);

    if new_top > (u32::MAX as u64) + 1 {
        return 0;
    }

    let new_top_u32 = new_top as u32;

    // Check max_heap_pages limit
    if ctx.max_heap_pages > 0 {
        let max_top = ctx.heap_base as u64 + (ctx.max_heap_pages as u64) * (ps as u64);
        if new_top > max_top {
            return 0;
        }
    }

    // Map any pages in [old_top, new_top) that aren't mapped yet
    let start_page = old_top / ps;
    let end_page = if new_top_u32 == 0 {
        u32::MAX / ps
    } else {
        (new_top_u32 - 1) / ps
    };
    let perms = ctx.flat_perms as *mut u8;
    for p in start_page..=end_page {
        // SAFETY: p is a valid page index within the permission table (bounded by address space).
        unsafe {
            if *perms.add(p as usize) == 0 {
                *perms.add(p as usize) = 2; // read-write
            }
        }
    }

    // Make newly accessible pages PROT_READ|PROT_WRITE.
    if !ctx.flat_buf.is_null() {
        let old_page = (old_top as usize).div_ceil(4096);
        let new_page = (new_top_u32 as usize).div_ceil(4096);
        if new_page > old_page {
            // SAFETY: flat_buf points to guest memory base; page range is within the mmap region.
            unsafe {
                let start = ctx.flat_buf.add(old_page * 4096);
                let len = (new_page - old_page) * 4096;
                libc::mprotect(
                    start as *mut libc::c_void,
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                );
            }
        }
    }

    ctx.heap_top = new_top_u32;
    old_top as u64
}

/// Recompiled PVM instance, borrowed against a `NativeMemory`
/// owned by the caller. The lifetime parameter ties the recompiler's
/// internal ctx pointer (which lives inside the memory's reserved
/// CTX_PAGE slot) to the borrow.
pub struct RecompiledPvm<'mem> {
    /// Native code buffer.
    native_code: NativeCode,
    /// JIT context — lives inside the memory's reserved CTX_PAGE
    /// slot (at `memory.host_ctx_ptr()`). Valid for the duration of
    /// the `'mem` borrow.
    ctx: *mut JitContext,
    /// Bitmask.
    bitmask: Vec<u8>,
    /// Jump table.
    jump_table: Vec<u32>,
    /// Initial gas.
    _initial_gas: Gas,
    /// Dispatch table: PVM PC → native code offset (-1 = invalid).
    dispatch_table: Vec<i32>,
    /// Cached debug flag.
    debug: bool,
    /// Signal-based bounds checking state.
    signal_state: Option<Box<signal::SignalState>>,
    /// Trap table (owned, referenced by signal_state via raw pointer).
    _trap_table: Vec<(u32, u32)>,
    /// Tie this struct's lifetime to the borrowed memory.
    _memory: core::marker::PhantomData<&'mem mut ()>,
}

impl<'mem> RecompiledPvm<'mem> {
    /// Create a new recompiled PVM from parsed program components.
    ///
    /// The `memory` must already be populated (e.g. via
    /// [`populate_memory`]) — this function just wires the JIT
    /// against its buffer and perm pointers.
    pub fn new<M: NativeMemory>(
        memory: &'mem mut M,
        code: &[u8],
        bitmask: Vec<u8>,
        jump_table: Vec<u32>,
        registers: [u64; PVM_REGISTER_COUNT],
        gas: Gas,
        mem_cycles: u8,
    ) -> Result<Self, String> {
        let debug = {
            use std::sync::atomic::{AtomicU8, Ordering};
            static CACHED: AtomicU8 = AtomicU8::new(0); // 0=unchecked, 1=false, 2=true
            match CACHED.load(Ordering::Relaxed) {
                2 => true,
                1 => false,
                _ => {
                    let val = std::env::var("GREY_PVM_DEBUG").is_ok();
                    CACHED.store(if val { 2 } else { 1 }, Ordering::Relaxed);
                    val
                }
            }
        };

        // Gas blocks and validation are now computed inline during the compile loop.
        // No separate pre-passes needed.

        // The caller owns the memory; we just wire ctx + JIT pointers
        // against it. The ctx lives in the memory's reserved CTX_PAGE
        // slot (see NativeMemory::host_ctx_ptr).
        let ctx_raw = memory.host_ctx_ptr() as *mut JitContext;
        let host_buf = memory.host_buf_ptr();
        let host_perms = memory.host_perms_ptr();

        // Enforce the NativeMemory low-4 GiB invariant: the entire
        // guest backing must sit at host VA < 2^32 so guest 32-bit
        // addresses equal host pointers via zero-extension. The
        // planned R15-drop in codegen relies on this; even with R15
        // base addressing today, keeping the invariant tight
        // ensures the substrate doesn't drift.
        debug_assert!(
            (host_buf as usize)
                .checked_add(memory.host_buf_len())
                .is_some_and(|end| end <= 1usize << 32),
            "NativeMemory backing must end below 2^32 (host_buf_ptr=0x{:x}, len=0x{:x})",
            host_buf as usize,
            memory.host_buf_len(),
        );
        // SAFETY: ctx_raw points to a properly aligned CTX_PAGE region within the mmap.
        // Writing the JitContext initializes the memory that JIT code will access via R15.
        unsafe {
            ctx_raw.write(JitContext {
                regs: registers,
                gas: gas as i64,

                exit_reason: 0,
                exit_arg: 0,
                heap_base: 0,
                heap_top: 0,
                jt_ptr: std::ptr::null(),
                jt_len: jump_table.len() as u32,
                _pad0: 0,
                bb_starts: std::ptr::null(),
                bb_len: bitmask.len() as u32,
                _pad1: 0,
                entry_pc: 0,
                pc: 0,
                dispatch_table: std::ptr::null(),
                code_base: 0,
                flat_buf: host_buf,
                flat_perms: host_perms,
                fast_reentry: 0,
                _pad2: 0,
                max_heap_pages: 0,
                _pad3: 0,
            });
        }
        // SAFETY: ctx_raw was just initialized above; valid for the lifetime of flat_memory.
        let ctx = unsafe { &mut *ctx_raw };

        // Set up pointers
        ctx.jt_ptr = jump_table.as_ptr();
        ctx.bb_starts = bitmask.as_ptr();

        if debug {
            tracing::debug!(
                write_u8 = format_args!("0x{:x}", mem_write_u8 as *const () as usize),
                write_u32 = format_args!("0x{:x}", mem_write_u32 as *const () as usize),
                read_u8 = format_args!("0x{:x}", mem_read_u8 as *const () as usize),
                "recompiler helper function pointers"
            );
        }

        // Compile
        let helpers = HelperFns {
            mem_read_u8: mem_read_u8 as *const () as u64,
            mem_read_u16: mem_read_u16 as *const () as u64,
            mem_read_u32: mem_read_u32 as *const () as u64,
            mem_read_u64: mem_read_u64_fn as *const () as u64,
            mem_write_u8: mem_write_u8 as *const () as u64,
            mem_write_u16: mem_write_u16 as *const () as u64,
            mem_write_u32: mem_write_u32 as *const () as u64,
            mem_write_u64: mem_write_u64_fn as *const () as u64,
            sbrk_helper: sbrk_helper as *const () as u64,
        };

        let _t2 = std::time::Instant::now();
        let compiler = Compiler::new(
            &bitmask,
            &jump_table,
            helpers,
            code.len(),
            true, // use mmap-backed assembler
            mem_cycles,
        );
        let compile_result = compiler.compile(code, &bitmask);
        let _t_compile = _t2.elapsed();
        let dispatch_table = compile_result.dispatch_table;

        let _t3 = std::time::Instant::now();
        let native_code = if let Some(mmap_ptr) = compile_result.mmap_ptr {
            // Code is already mmap'd and PROT_READ|PROT_EXEC — no copy needed.
            let nc = NativeCode {
                ptr: mmap_ptr,
                len: compile_result.mmap_len,
                mmap_cap: compile_result.mmap_cap,
            };
            if debug {
                // SAFETY: mmap_ptr and mmap_len come from a valid mmap allocation in the assembler.
                let code_slice =
                    unsafe { std::slice::from_raw_parts(mmap_ptr, compile_result.mmap_len) };
                let _ = std::fs::write("/tmp/pvm_native.bin", code_slice);
                tracing::debug!(
                    native_bytes = compile_result.mmap_len,
                    "wrote native code to /tmp/pvm_native.bin (mmap path)"
                );
            }
            nc
        } else {
            let native = compile_result.native_code;
            if debug {
                let _ = std::fs::write("/tmp/pvm_native.bin", &native);
                tracing::debug!(
                    native_bytes = native.len(),
                    "wrote native code to /tmp/pvm_native.bin (copy path)"
                );
            }
            NativeCode::new(&native)?
        };
        let _t_native = _t3.elapsed();

        // Signal-based bounds checking: build trap table and install guard pages.
        let trap_table = compile_result.trap_table;
        let signal_state = {
            signal::ensure_installed();
            let ss = Box::new(signal::SignalState {
                code_start: native_code.ptr as usize,
                code_end: native_code.ptr as usize + native_code.len,
                exit_label_addr: native_code.ptr as usize
                    + compile_result.exit_label_offset as usize,
                ctx_ptr: ctx_raw,
                trap_table_ptr: trap_table.as_ptr(),
                trap_table_len: trap_table.len(),
            });
            Some(ss)
        };

        tracing::debug!(
            compile_us = _t_compile.as_micros() as u64,
            native_us = _t_native.as_micros() as u64,
            code_len = code.len(),
            native_len = native_code.len,
            "recompiler::new() timing"
        );

        // Set dispatch table pointer and code base in context
        ctx.code_base = native_code.ptr as u64;

        let mut result = Self {
            native_code,
            ctx: ctx_raw,
            bitmask,
            jump_table,
            _initial_gas: gas,
            dispatch_table,
            debug,
            signal_state,
            _trap_table: trap_table,
            _memory: core::marker::PhantomData,
        };

        // Set dispatch_table pointer (must point to the Vec's data in Self)
        result.ctx_mut().dispatch_table = result.dispatch_table.as_ptr();

        Ok(result)
    }

    #[inline(always)]
    fn ctx(&self) -> &JitContext {
        // SAFETY: self.ctx points into the FlatMemory mmap region, valid for Self's lifetime.
        unsafe { &*self.ctx }
    }
    #[inline(always)]
    fn ctx_mut(&mut self) -> &mut JitContext {
        // SAFETY: self.ctx points into the FlatMemory mmap region, valid for Self's lifetime.
        unsafe { &mut *self.ctx }
    }

    /// Run the compiled code until exit (halt, panic, OOG, page fault, or host call).
    /// Returns the exit reason. For host calls, the caller should handle the call,
    /// modify registers/memory as needed, then call run() again (entry_pc is set
    /// automatically for re-entry).
    pub fn run(&mut self) -> ExitReason {
        loop {
            if self.debug {
                tracing::debug!(
                    entry_pc = self.ctx().entry_pc,
                    gas = self.ctx().gas,
                    heap_base = format_args!("0x{:08x}", self.ctx().heap_base),
                    heap_top = format_args!("0x{:08x}", self.ctx().heap_top),
                    regs = ?&self.ctx().regs,
                    "recompiler::run() entry"
                );
                self.ctx_mut().exit_reason = 0xDEAD;
            }

            // Execute native code — set up signal state for SIGSEGV handler
            if let Some(ref mut ss) = self.signal_state {
                signal::SIGNAL_STATE.with(|cell| cell.set(&mut **ss as *mut _));
            }

            let entry = self.native_code.entry();
            // SAFETY: entry points to valid JIT-compiled x86-64 code; self.ctx is a valid
            // JitContext pointer. The native code follows the sysv64 calling convention.
            unsafe {
                entry(self.ctx);
            }

            signal::SIGNAL_STATE.with(|cell| cell.set(std::ptr::null_mut()));

            if self.debug {
                tracing::debug!(
                    exit_reason = self.ctx().exit_reason,
                    exit_arg = self.ctx().exit_arg,
                    gas = self.ctx().gas,
                    pc = self.ctx().pc,
                    regs = ?&self.ctx().regs,
                    "recompiler::run() exit"
                );
            }

            // Read exit reason from context.
            // Hot path (case 4 = HostCall) is kept minimal. Cold paths
            // (OOG fallback, gas correction) are in separate methods to
            // avoid bloating the function and hurting instruction cache.
            match self.ctx().exit_reason {
                4 => {
                    self.ctx_mut().entry_pc = self.ctx().pc;
                    return ExitReason::HostCall(self.ctx().exit_arg);
                }
                0 => return self.handle_halt_exit(),
                1 => return self.handle_panic_exit(),
                2 => return self.handle_oog_exit(),
                3 => return self.handle_page_fault_exit(),
                5 => {
                    // Dynamic jump — resolve and re-enter
                    let idx = self.ctx().exit_arg;
                    if let Some(target) = self.resolve_djump(idx) {
                        self.ctx_mut().entry_pc = target;
                        continue;
                    } else {
                        return ExitReason::Panic;
                    }
                }
                6 => {
                    // EXIT_ECALL (PVM opcode 3, plain `ecall`). Mirror
                    // the EXIT_HOST_CALL path: set entry_pc so caller
                    // can re-enter after handling the MGMT op.
                    self.ctx_mut().entry_pc = self.ctx().pc;
                    return ExitReason::Ecall;
                }
                _ => return ExitReason::Panic,
            }
        }
    }

    /// Resolve a dynamic jump target from jump table index.
    fn resolve_djump(&self, idx: u32) -> Option<u32> {
        if idx as usize >= self.jump_table.len() {
            return None;
        }
        let target = self.jump_table[idx as usize];
        if (target as usize) < self.bitmask.len() && self.bitmask[target as usize] == 1 {
            Some(target)
        } else {
            None
        }
    }

    // --- Cold exit handlers (kept out of run() to avoid bloating the hot path) ---

    #[cold]
    fn handle_halt_exit(&mut self) -> ExitReason {
        ExitReason::Halt
    }

    #[cold]
    fn handle_panic_exit(&mut self) -> ExitReason {
        ExitReason::Panic
    }

    #[cold]
    fn handle_page_fault_exit(&mut self) -> ExitReason {
        ExitReason::PageFault(self.ctx().exit_arg)
    }

    #[cold]
    fn handle_oog_exit(&mut self) -> ExitReason {
        // JAR v0.8.0 pipeline gas: the full block cost is always the correct
        // charge. The gas subtraction already happened in the JIT code —
        // just return OOG. No interpreter fallback needed.
        self.ctx_mut().entry_pc = self.ctx().pc;
        ExitReason::OutOfGas
    }

    /// Access the PVM registers.
    pub fn registers(&self) -> &[u64; 13] {
        &self.ctx().regs
    }

    pub fn registers_mut(&mut self) -> &mut [u64; 13] {
        &mut self.ctx_mut().regs
    }

    /// Access remaining gas.
    pub fn gas(&self) -> u64 {
        self.ctx().gas.max(0) as u64
    }

    /// Get the program counter (last known PC on exit).
    pub fn pc(&self) -> u32 {
        self.ctx().pc
    }

    /// Set the program counter for re-entry.
    pub fn set_pc(&mut self, pc: u32) {
        self.ctx_mut().entry_pc = pc;
        self.ctx_mut().pc = pc;
    }

    /// Set gas.
    pub fn set_gas(&mut self, gas: Gas) {
        self.ctx_mut().gas = gas as i64;
    }

    /// Set a single PVM register.
    pub fn set_register(&mut self, idx: usize, val: u64) {
        self.ctx_mut().regs[idx] = val;
    }

    /// Get heap top.
    pub fn heap_top(&self) -> u32 {
        self.ctx().heap_top
    }
    /// Set heap top.
    pub fn set_heap_top(&mut self, top: u32) {
        self.ctx_mut().heap_top = top;
    }

    /// Get the native code bytes (for disassembly / debugging).
    pub fn native_code_bytes(&self) -> &[u8] {
        // SAFETY: ptr and len describe a valid mmap allocation from NativeCode::new().
        unsafe { std::slice::from_raw_parts(self.native_code.ptr, self.native_code.len) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codegen::{
        CTX_CODE_BASE, CTX_DISPATCH_TABLE, CTX_ENTRY_PC, CTX_EXIT_ARG, CTX_EXIT_REASON, CTX_GAS,
        CTX_OFFSET, CTX_PC, CTX_REGS,
    };

    #[test]
    fn test_jit_context_layout() {
        // Verify field offsets match codegen constants.
        // Codegen offsets are negative from R15 (guest memory base).
        // JitContext is at R15 - CTX_OFFSET. So field offset from R15 =
        // -CTX_OFFSET + field_offset_in_struct.
        let ctx = JitContext {
            regs: [0; 13],
            gas: 0,
            exit_reason: 0,
            exit_arg: 0,
            heap_base: 0,
            heap_top: 0,
            jt_ptr: std::ptr::null(),
            jt_len: 0,
            _pad0: 0,
            bb_starts: std::ptr::null(),
            bb_len: 0,
            _pad1: 0,
            entry_pc: 0,
            pc: 0,
            dispatch_table: std::ptr::null(),
            code_base: 0,
            flat_buf: std::ptr::null_mut(),
            flat_perms: std::ptr::null(),
            fast_reentry: 0,
            _pad2: 0,
            max_heap_pages: 0,
            _pad3: 0,
        };
        let base = &ctx as *const JitContext as usize;
        // Convert codegen offset (negative from R15) to struct offset:
        // struct_offset = codegen_offset - (-CTX_OFFSET) = codegen_offset + CTX_OFFSET
        let so = |codegen_off: i32| -> usize { (codegen_off + CTX_OFFSET) as usize };

        assert_eq!(&ctx.regs as *const _ as usize - base, so(CTX_REGS));
        assert_eq!(&ctx.gas as *const _ as usize - base, so(CTX_GAS));
        assert_eq!(
            &ctx.exit_reason as *const _ as usize - base,
            so(CTX_EXIT_REASON)
        );
        assert_eq!(&ctx.exit_arg as *const _ as usize - base, so(CTX_EXIT_ARG));
        assert_eq!(&ctx.entry_pc as *const _ as usize - base, so(CTX_ENTRY_PC));
        assert_eq!(&ctx.pc as *const _ as usize - base, so(CTX_PC));
        assert_eq!(
            &ctx.dispatch_table as *const _ as usize - base,
            so(CTX_DISPATCH_TABLE)
        );
        assert_eq!(
            &ctx.code_base as *const _ as usize - base,
            so(CTX_CODE_BASE)
        );
    }

    // (`test_layout` was the pre-refactor helper; tests now construct
    // FlatMemory directly with a 4096-byte capacity since they don't
    // need to seed any data.)

    #[test]
    fn test_recompile_trap() {
        let code = vec![0u8]; // trap
        let bitmask = vec![1u8];
        let registers = [0u64; 13];

        let mut memory = FlatMemory::new(4096).expect("memory");
        let mut pvm = RecompiledPvm::new(
            &mut memory,
            &code,
            bitmask,
            vec![],
            registers,
            1000,
            javm_exec::gas_cost::DEFAULT_MEM_CYCLES,
        )
        .expect("compilation should succeed");
        let exit = pvm.run();
        assert_eq!(exit, ExitReason::Panic);
    }

    #[test]
    fn test_recompile_ecalli() {
        let code = vec![10, 42]; // ecalli 42
        let bitmask = vec![1, 0];
        let registers = [0u64; 13];

        let mut memory = FlatMemory::new(4096).expect("memory");
        let mut pvm = RecompiledPvm::new(
            &mut memory,
            &code,
            bitmask,
            vec![],
            registers,
            1000,
            javm_exec::gas_cost::DEFAULT_MEM_CYCLES,
        )
        .expect("compilation should succeed");
        let exit = pvm.run();
        assert_eq!(exit, ExitReason::HostCall(42));
    }

    #[test]
    fn test_recompile_load_imm() {
        let code = vec![51, 0, 123, 0]; // load_imm φ[0], 123; then trap
        let bitmask = vec![1, 0, 0, 1];
        let registers = [0u64; 13];

        let mut memory = FlatMemory::new(4096).expect("memory");
        let mut pvm = RecompiledPvm::new(
            &mut memory,
            &code,
            bitmask,
            vec![],
            registers,
            1000,
            javm_exec::gas_cost::DEFAULT_MEM_CYCLES,
        )
        .expect("compilation should succeed");
        let exit = pvm.run();
        assert_eq!(pvm.registers()[0], 123);
        assert_eq!(exit, ExitReason::Panic);
    }

    #[test]
    fn test_recompile_add64() {
        let code = vec![
            51, 0, 10, // load_imm φ[0], 10
            51, 1, 20, // load_imm φ[1], 20
            200, 0x10, 2, // add64 φ[2] = φ[0] + φ[1]
            10, 0, // ecalli 0
        ];
        let bitmask = vec![1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0];
        let registers = [0u64; 13];

        let mut memory = FlatMemory::new(4096).expect("memory");
        let mut pvm = RecompiledPvm::new(
            &mut memory,
            &code,
            bitmask,
            vec![],
            registers,
            1000,
            javm_exec::gas_cost::DEFAULT_MEM_CYCLES,
        )
        .expect("compilation should succeed");
        let exit = pvm.run();
        assert_eq!(pvm.registers()[2], 30);
        assert_eq!(exit, ExitReason::HostCall(0));
    }

    #[test]
    fn test_recompile_out_of_gas() {
        let code = vec![51, 0, 42];
        let bitmask = vec![1, 0, 0];
        let registers = [0u64; 13];

        let mut memory = FlatMemory::new(4096).expect("memory");
        let mut pvm = RecompiledPvm::new(
            &mut memory,
            &code,
            bitmask,
            vec![],
            registers,
            0,
            javm_exec::gas_cost::DEFAULT_MEM_CYCLES,
        )
        .expect("compilation should succeed");
        let exit = pvm.run();
        assert_eq!(exit, ExitReason::OutOfGas);
    }

    #[test]
    fn test_carry_flag_fusion() {
        // Test: add64 + setLtU carry detection (overflow case)
        // r2 = r0 + r1 (overflow: u64::MAX + 1 = 0)
        // r3 = (r2 < r1) ? 1 : 0  (should be 1 because of overflow)
        // Then ecalli 0 to exit
        let code = vec![
            200, 0x01, 2, // add64: rd=2, ra=0, rb=1 (r2 = r0 + r1)
            216, 0x12, 3, // setLtU: rd=3, ra=2, rb=1 (r3 = r2 < r1)
            10, 0, // ecalli 0
        ];
        let mk_bitmask = || vec![1u8, 0, 0, 1, 0, 0, 1, 0];
        let mut registers = [0u64; 13];
        registers[0] = u64::MAX; // r0 = MAX
        registers[1] = 1; // r1 = 1

        let mut memory = FlatMemory::new(4096).expect("memory");
        let mut pvm = RecompiledPvm::new(
            &mut memory,
            &code,
            mk_bitmask(),
            vec![],
            registers,
            10000,
            javm_exec::gas_cost::DEFAULT_MEM_CYCLES,
        )
        .expect("compilation should succeed");
        let exit = pvm.run();
        assert_eq!(exit, ExitReason::HostCall(0));
        assert_eq!(pvm.registers()[2], 0); // MAX + 1 = 0 (overflow)
        assert_eq!(pvm.registers()[3], 1); // carry = 1 (overflow detected)

        // Test non-overflow case: 5 + 3 = 8, no overflow
        let mut registers2 = [0u64; 13];
        registers2[0] = 5;
        registers2[1] = 3;
        let mut memory2 = FlatMemory::new(4096).expect("memory");
        let mut pvm2 = RecompiledPvm::new(
            &mut memory2,
            &code,
            mk_bitmask(),
            vec![],
            registers2,
            10000,
            javm_exec::gas_cost::DEFAULT_MEM_CYCLES,
        )
        .expect("compilation should succeed");
        let exit2 = pvm2.run();
        assert_eq!(exit2, ExitReason::HostCall(0));
        assert_eq!(pvm2.registers()[2], 8); // 5 + 3 = 8
        assert_eq!(pvm2.registers()[3], 0); // carry = 0 (no overflow)
    }

    #[test]
    fn test_recompile_shlo_l_imm_64() {
        // ShloLImm64 (opcode 151): φ[rd] = φ[rb] << imm
        // TwoRegOneImm: [151, rd|(rb<<4), imm0, imm1, imm2, imm3]
        let code = vec![
            51, 0, 5, // load_imm φ[0], 5
            151, 0x00, 3, 0, 0, 0, // shlo_l_imm_64 φ[0] = φ[0] << 3  (= 40)
            10, 0, // ecalli 0
        ];
        let bitmask = vec![1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0];
        let registers = [0u64; 13];

        let mut memory = FlatMemory::new(4096).expect("memory");
        let mut pvm = RecompiledPvm::new(
            &mut memory,
            &code,
            bitmask,
            vec![],
            registers,
            10000,
            javm_exec::gas_cost::DEFAULT_MEM_CYCLES,
        )
        .expect("compilation should succeed");
        let exit = pvm.run();
        assert_eq!(exit, ExitReason::HostCall(0));
        assert_eq!(pvm.registers()[0], 40); // 5 << 3 = 40
    }

    #[test]
    fn test_recompile_shlo_l_imm_64_different_regs() {
        // ShloLImm64: φ[rd] = φ[rb] << imm where rd != rb
        // rd=2 (T0), rb=0 (RA): [151, 2|(0<<4), 1, 0, 0, 0]
        let code = vec![
            51, 0, 10, // load_imm φ[0], 10
            151, 0x02, 1, 0, 0, 0, // shlo_l_imm_64 φ[2] = φ[0] << 1  (= 20)
            10, 0, // ecalli 0
        ];
        let bitmask = vec![1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0];
        let registers = [0u64; 13];

        let mut memory = FlatMemory::new(4096).expect("memory");
        let mut pvm = RecompiledPvm::new(
            &mut memory,
            &code,
            bitmask,
            vec![],
            registers,
            10000,
            javm_exec::gas_cost::DEFAULT_MEM_CYCLES,
        )
        .expect("compilation should succeed");
        let exit = pvm.run();
        assert_eq!(exit, ExitReason::HostCall(0));
        assert_eq!(pvm.registers()[2], 20); // 10 << 1 = 20
        assert_eq!(pvm.registers()[0], 10); // source unchanged
    }

    #[test]
    fn test_recompile_shlo_l_imm_64_as_address() {
        // Test shift result used as memory address (the bench bug scenario).
        // Compute addr = base << 2, then store/load via that address.
        // DataLayout: rw_start=0, rw_data has 256 bytes.
        let layout = DataLayout {
            mem_size: 4096,
            arg_start: 0,
            arg_data: vec![],
            ro_start: 0,
            ro_data: vec![],
            rw_start: 0,
            rw_data: vec![0u8; 256],
        };

        let code = vec![
            51, 0, 4, // load_imm φ[0], 4 (base index)
            151, 0x00, 2, 0, 0, 0, // shlo_l_imm_64 φ[0] = φ[0] << 2  (= 16, byte offset)
            // store_ind_u32 [φ[0] + 0] ← φ[1] (value 0xDEAD)
            // opcode 122, rd=1|(ra=0<<4), imm=0
            122, 0x01, 0, 0, 0, 0,
            // load_ind_u32 φ[2] = [φ[0] + 0]
            // opcode 128, rd=2|(ra=0<<4), imm=0
            128, 0x02, 0, 0, 0, 0, 10, 0, // ecalli 0
        ];
        let bitmask = vec![
            1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0,
        ];
        let mut registers = [0u64; 13];
        registers[1] = 0xDEAD; // value to store

        let mut memory = FlatMemory::new(layout.mem_size).expect("memory");
        populate_memory(&mut memory, &layout);
        let mut pvm = RecompiledPvm::new(
            &mut memory,
            &code,
            bitmask,
            vec![],
            registers,
            10000,
            javm_exec::gas_cost::DEFAULT_MEM_CYCLES,
        )
        .expect("compilation should succeed");
        let exit = pvm.run();
        assert_eq!(exit, ExitReason::HostCall(0));
        assert_eq!(pvm.registers()[0], 16); // 4 << 2 = 16
        assert_eq!(pvm.registers()[2], 0xDEAD); // loaded back the stored value
    }

    #[test]
    fn test_recompile_shlo_l_imm_64_then_add() {
        // Shift then add — verifies the shift result persists across basic blocks.
        let code = vec![
            51, 0, 4, // load_imm φ[0], 4
            151, 0x00, 2, 0, 0, 0, // shlo_l_imm_64 φ[0] = φ[0] << 2  (= 16)
            149, 0x02, 1, 0, 0, 0, // add_imm_64 φ[2] = φ[0] + 1  (= 17)
            10, 0, // ecalli 0
        ];
        let bitmask = vec![1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0];
        let registers = [0u64; 13];

        let mut memory = FlatMemory::new(4096).expect("memory");
        let mut pvm = RecompiledPvm::new(
            &mut memory,
            &code,
            bitmask,
            vec![],
            registers,
            10000,
            javm_exec::gas_cost::DEFAULT_MEM_CYCLES,
        )
        .expect("compilation should succeed");
        let exit = pvm.run();
        assert_eq!(exit, ExitReason::HostCall(0));
        assert_eq!(pvm.registers()[0], 16, "φ[0] should be 4 << 2 = 16");
        assert_eq!(pvm.registers()[2], 17, "φ[2] should be 16 + 1 = 17");
    }

    /// Helper: build a program that loads 64-bit values into r0 and r1 via LoadImm64,
    /// applies a ThreeReg instruction (opcode) with ra=0, rb=1, rd=2, then ecalli 0.
    fn run_three_reg_op(opcode: u8, a: u64, b: u64) -> u64 {
        let code = vec![
            20,
            0, // LoadImm64 φ[0]
            a as u8,
            (a >> 8) as u8,
            (a >> 16) as u8,
            (a >> 24) as u8,
            (a >> 32) as u8,
            (a >> 40) as u8,
            (a >> 48) as u8,
            (a >> 56) as u8,
            20,
            1, // LoadImm64 φ[1]
            b as u8,
            (b >> 8) as u8,
            (b >> 16) as u8,
            (b >> 24) as u8,
            (b >> 32) as u8,
            (b >> 40) as u8,
            (b >> 48) as u8,
            (b >> 56) as u8,
            opcode,
            0x10,
            2, // ThreeReg: ra=0, rb=1, rd=2
            10,
            0, // ecalli 0
        ];
        let bitmask = vec![
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0,
        ];
        let registers = [0u64; 13];

        let mut memory = FlatMemory::new(4096).expect("memory");
        let mut pvm = RecompiledPvm::new(
            &mut memory,
            &code,
            bitmask,
            vec![],
            registers,
            100_000,
            javm_exec::gas_cost::DEFAULT_MEM_CYCLES,
        )
        .expect("compilation should succeed");
        let exit = pvm.run();
        assert_eq!(exit, ExitReason::HostCall(0));
        pvm.registers()[2]
    }

    /// Helper: build a program that loads a 64-bit value into r0 via LoadImm64,
    /// applies a TwoReg instruction (opcode) with rd=1, ra=0, then ecalli 0.
    fn run_two_reg_op(opcode: u8, input: u64) -> u64 {
        let code = vec![
            20,
            0, // LoadImm64 φ[0], <8 bytes follow>
            input as u8,
            (input >> 8) as u8,
            (input >> 16) as u8,
            (input >> 24) as u8,
            (input >> 32) as u8,
            (input >> 40) as u8,
            (input >> 48) as u8,
            (input >> 56) as u8,
            opcode,
            0x01, // TwoReg: rd=1, ra=0
            10,
            0, // ecalli 0
        ];
        let bitmask = vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0];
        let registers = [0u64; 13];

        let mut memory = FlatMemory::new(4096).expect("memory");
        let mut pvm = RecompiledPvm::new(
            &mut memory,
            &code,
            bitmask,
            vec![],
            registers,
            10000,
            javm_exec::gas_cost::DEFAULT_MEM_CYCLES,
        )
        .expect("compilation should succeed");
        let exit = pvm.run();
        assert_eq!(exit, ExitReason::HostCall(0));
        pvm.registers()[1]
    }

    // === Division tests ===

    #[test]
    fn test_recompile_div_u64() {
        assert_eq!(run_three_reg_op(203, 100, 7), 14);
        assert_eq!(run_three_reg_op(203, 42, 0), u64::MAX);
        assert_eq!(run_three_reg_op(203, 0, 5), 0);
        assert_eq!(run_three_reg_op(203, u64::MAX, 2), u64::MAX / 2);
    }

    #[test]
    fn test_recompile_div_s64() {
        assert_eq!(run_three_reg_op(204, 100, 7), 14);
        let neg100 = (-100i64) as u64;
        let neg14 = (-14i64) as u64;
        assert_eq!(run_three_reg_op(204, neg100, 7), neg14);
        assert_eq!(run_three_reg_op(204, 42, 0), u64::MAX);
    }

    #[test]
    fn test_recompile_rem_u64() {
        assert_eq!(run_three_reg_op(205, 100, 7), 2);
        assert_eq!(run_three_reg_op(205, 42, 0), 42);
        assert_eq!(run_three_reg_op(205, 0, 5), 0);
    }

    #[test]
    fn test_recompile_rem_s64() {
        assert_eq!(run_three_reg_op(206, 100, 7), 2);
        let neg100 = (-100i64) as u64;
        let neg2 = (-2i64) as u64;
        assert_eq!(run_three_reg_op(206, neg100, 7), neg2);
        assert_eq!(run_three_reg_op(206, 42, 0), 42);
    }

    #[test]
    fn test_recompile_mul64() {
        assert_eq!(run_three_reg_op(202, 6, 7), 42);
        assert_eq!(run_three_reg_op(202, 0, 1000), 0);
        assert_eq!(run_three_reg_op(202, u64::MAX, 2), u64::MAX.wrapping_mul(2));
    }

    #[test]
    fn test_recompile_mul_upper_uu() {
        assert_eq!(run_three_reg_op(214, 1u64 << 63, 2), 1);
        assert_eq!(run_three_reg_op(214, 100, 200), 0);
        assert_eq!(run_three_reg_op(214, u64::MAX, u64::MAX), u64::MAX - 1);
    }

    #[test]
    fn test_recompile_mul_upper_ss() {
        assert_eq!(run_three_reg_op(213, u64::MAX, u64::MAX), 0);
        assert_eq!(run_three_reg_op(213, u64::MAX, 1), u64::MAX);
        assert_eq!(run_three_reg_op(213, 100, 200), 0);
    }

    #[test]
    fn test_recompile_add32() {
        assert_eq!(run_three_reg_op(190, 0x7FFFFFFF, 1), 0xFFFFFFFF80000000u64);
        assert_eq!(run_three_reg_op(190, 5, 3), 8);
    }

    #[test]
    fn test_recompile_sub32() {
        assert_eq!(run_three_reg_op(191, 0, 1), 0xFFFFFFFFFFFFFFFFu64);
        assert_eq!(run_three_reg_op(191, 10, 3), 7);
    }

    #[test]
    fn test_recompile_mul32() {
        assert_eq!(run_three_reg_op(192, 6, 7), 42);
        assert_eq!(run_three_reg_op(192, 0x10000, 0x10000), 0);
        assert_eq!(run_three_reg_op(192, 0xFFFF, 0xFFFF), 0xFFFFFFFFFFFE0001u64);
    }

    #[test]
    fn test_recompile_sign_extend_8() {
        assert_eq!(run_two_reg_op(108, 0x7F), 0x7F);
        assert_eq!(run_two_reg_op(108, 0x80), 0xFFFFFFFFFFFFFF80u64);
        assert_eq!(run_two_reg_op(108, 0xFF), 0xFFFFFFFFFFFFFFFFu64);
        assert_eq!(run_two_reg_op(108, 0x100), 0);
    }

    #[test]
    fn test_recompile_sign_extend_16() {
        assert_eq!(run_two_reg_op(109, 0x7FFF), 0x7FFF);
        assert_eq!(run_two_reg_op(109, 0x8000), 0xFFFFFFFFFFFF8000u64);
        assert_eq!(run_two_reg_op(109, 0xFFFF), 0xFFFFFFFFFFFFFFFFu64);
    }
}
