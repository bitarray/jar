//! PVM recompiler — compiles PVM bytecode to native x86-64 machine code.
//!
//! This provides the same semantics as the interpreter in `vm.rs` but with
//! significantly better performance by eliminating decode overhead and keeping
//! PVM registers in native CPU registers.
//!
//! Usage:
//! ```ignore
//! let pvm = RecompiledPvm::new(code, bitmask, jump_table, registers, gas, Some(layout));
//! let (exit, gas_used) = pvm.run();
//! ```

pub mod asm;
pub mod codegen;
pub mod predecode;
pub mod signal;

use crate::ExitReason;
use crate::{Gas, PVM_REGISTER_COUNT};
use codegen::{Compiler, HelperFns};

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
    /// Original cap bitmap from the active VM's CapTable (offset 216, 32 bytes).
    /// Bit N is set if cap slot N holds its original kernel-populated protocol cap.
    /// Used by codegen to inline protocol cap handlers (e.g., GAS) on the fast path.
    pub original_bitmap: [u8; 32],
}

/// Compiled native code buffer (mmap'd as executable).
pub struct NativeCode {
    pub ptr: *mut u8,
    pub len: usize,
    /// The mmap region capacity (may be > len due to pre-allocation).
    pub mmap_cap: usize,
}

impl NativeCode {
    /// Allocate an executable code buffer and copy machine code into it.
    /// This is the fallback path; the mmap-direct path skips the copy.
    fn new(code: &[u8]) -> Result<Self, String> {
        if code.is_empty() {
            return Err("empty code buffer".into());
        }
        let len = code.len();
        // SAFETY: mmap with MAP_ANONYMOUS|MAP_PRIVATE allocates fresh pages. MAP_FAILED checked below.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
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
        // SAFETY: ptr is a valid mmap'd region of `len` bytes; copy_nonoverlapping is in-bounds.
        // mprotect/munmap operate on the same valid mmap region.
        unsafe {
            std::ptr::copy_nonoverlapping(code.as_ptr(), ptr, len);
            // Make executable (and read-only)
            if libc::mprotect(
                ptr as *mut libc::c_void,
                len,
                libc::PROT_READ | libc::PROT_EXEC,
            ) != 0
            {
                libc::munmap(ptr as *mut libc::c_void, len);
                return Err("mprotect failed".into());
            }
        }
        Ok(Self {
            ptr,
            len,
            mmap_cap: len,
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

struct FlatMemory {
    /// Base of the entire mmap'd region.
    region: *mut u8,
    /// Total mmap size.
    region_size: usize,
    /// Pointer to the guest memory base (= region + HEADER_SIZE).
    buf: *mut u8,
    /// Pointer to the permission table (= region).
    perms: *mut u8,
}

const FLAT_BUF_SIZE: usize = 1 << 32; // 4GB virtual
const NUM_PAGES: usize = 1 << 20; // 2^20 = 1M pages
const CTX_PAGE: usize = 4096; // JitContext page
const HEADER_SIZE: usize = NUM_PAGES + CTX_PAGE; // perms + ctx page before guest mem

impl FlatMemory {
    /// Create a flat memory from a data layout.
    fn new(layout: &DataLayout) -> Option<Self> {
        let region_size = HEADER_SIZE + FLAT_BUF_SIZE;
        // SAFETY: mmap with MAP_ANONYMOUS|MAP_PRIVATE|MAP_NORESERVE allocates virtual pages.
        // MAP_FAILED checked below.
        let region = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                region_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_NORESERVE,
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

        // Set all pages in [0, mem_size) as read-write in the permission table.
        // Reserved for future software bounds checking path
        // AND for write_bytes/read_bytes which always check the permission table.
        {
            let num_pages = layout.mem_size.div_ceil(4096) as usize;
            // SAFETY: perms points to the start of the mmap region; num_pages is clamped to NUM_PAGES.
            unsafe {
                std::ptr::write_bytes(perms, 2u8, num_pages.min(NUM_PAGES));
            }
        }
        // SAFETY: buf points to guest memory base within the mmap. Data layout offsets and
        // lengths are validated by parse_program_blob to fit within the allocated region.
        unsafe {
            if !layout.arg_data.is_empty() {
                std::ptr::copy_nonoverlapping(
                    layout.arg_data.as_ptr(),
                    buf.add(layout.arg_start as usize),
                    layout.arg_data.len(),
                );
            }
            if !layout.ro_data.is_empty() {
                std::ptr::copy_nonoverlapping(
                    layout.ro_data.as_ptr(),
                    buf.add(layout.ro_start as usize),
                    layout.ro_data.len(),
                );
            }
            if !layout.rw_data.is_empty() {
                std::ptr::copy_nonoverlapping(
                    layout.rw_data.as_ptr(),
                    buf.add(layout.rw_start as usize),
                    layout.rw_data.len(),
                );
            }
        }

        Some(Self {
            region,
            region_size,
            buf,
            perms,
        })
    }

    /// Get the pointer where JitContext should be placed (buf - CTX_PAGE).
    fn ctx_ptr(&self) -> *mut u8 {
        // SAFETY: buf = region + HEADER_SIZE and HEADER_SIZE >= CTX_PAGE, so sub is in-bounds.
        unsafe { self.buf.sub(CTX_PAGE) }
    }

    /// Mark pages beyond heap_top as PROT_NONE (guard pages).
    /// Pages [0, heap_top) remain PROT_READ|PROT_WRITE.
    #[allow(dead_code)]
    fn install_guard_pages(&self, heap_top: u32) {
        let heap_top_page = (heap_top as usize).div_ceil(4096);
        // SAFETY: buf points to guest memory base; heap_top_page * 4096 <= FLAT_BUF_SIZE.
        let guard_start = unsafe { self.buf.add(heap_top_page * 4096) };
        let guard_len = FLAT_BUF_SIZE - heap_top_page * 4096;
        if guard_len > 0 {
            // SAFETY: guard_start..+guard_len is within the mmap'd guest memory region.
            unsafe {
                libc::mprotect(guard_start as *mut libc::c_void, guard_len, libc::PROT_NONE);
            }
        }
    }

    /// Make pages in [old_top, new_top) accessible after heap growth.
    fn update_guard_pages(&self, old_top: u32, new_top: u32) {
        let old_page = (old_top as usize).div_ceil(4096);
        let new_page = (new_top as usize).div_ceil(4096);
        if new_page > old_page {
            // SAFETY: buf + old_page..new_page page range is within the mmap'd guest region.
            let start = unsafe { self.buf.add(old_page * 4096) };
            let len = (new_page - old_page) * 4096;
            // SAFETY: start..+len is within the mmap'd guest memory region.
            unsafe {
                libc::mprotect(
                    start as *mut libc::c_void,
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                );
            }
        }
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
    let ps = crate::PVM_PAGE_SIZE;

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

/// Recompiled PVM instance.
pub struct RecompiledPvm {
    /// Native code buffer.
    native_code: NativeCode,
    /// JIT context — lives inside the flat_memory mmap region, NOT heap-allocated.
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
    /// Flat memory for inline JIT access.
    flat_memory: Option<FlatMemory>,
    /// Signal-based bounds checking state.
    signal_state: Option<Box<signal::SignalState>>,
    /// Trap table (owned, referenced by signal_state via raw pointer).
    _trap_table: Vec<(u32, u32)>,
}

impl RecompiledPvm {
    /// Create a new recompiled PVM from parsed program components.
    pub fn new(
        code: &[u8],
        bitmask: Vec<u8>,
        jump_table: Vec<u32>,
        registers: [u64; PVM_REGISTER_COUNT],
        gas: Gas,
        data_layout: Option<DataLayout>,
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

        let layout = data_layout.ok_or("data_layout required for recompiler")?;

        // Initialize flat memory — JitContext will live inside this region
        let _t1 = std::time::Instant::now();
        let flat_memory = FlatMemory::new(&layout).ok_or("failed to mmap flat memory region")?;
        let _t_flat = _t1.elapsed();

        // Place JitContext inside the flat memory region (at buf - CTX_PAGE)
        let ctx_raw = flat_memory.ctx_ptr() as *mut JitContext;
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
                flat_buf: flat_memory.buf,
                flat_perms: flat_memory.perms,
                fast_reentry: 0,
                _pad2: 0,
                max_heap_pages: 0,
                _pad3: 0,
                original_bitmap: [0u8; 32],
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
            flat_mem_us = _t_flat.as_micros() as u64,
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
            flat_memory: Some(flat_memory),
            signal_state,
            _trap_table: trap_table,
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

    /// Read a byte directly from the flat buffer.
    /// Returns None on inaccessible page.
    pub fn read_byte(&self, addr: u32) -> Option<u8> {
        let fm = self.flat_memory.as_ref()?;
        let page = addr as usize / 4096;
        if page < NUM_PAGES {
            // SAFETY: page is bounds-checked against NUM_PAGES above; perms is valid for NUM_PAGES.
            let perm = unsafe { *fm.perms.add(page) };
            if perm >= 1 {
                // SAFETY: permission check passed; addr is within the mmap'd guest memory.
                return Some(unsafe { *fm.buf.add(addr as usize) });
            }
        }
        None
    }

    /// Write a byte directly to the flat buffer.
    /// Returns true on success, false on page fault.
    pub fn write_byte(&mut self, addr: u32, value: u8) -> bool {
        let fm = match self.flat_memory.as_ref() {
            Some(f) => f,
            None => return false,
        };
        let page = addr as usize / 4096;
        if page < NUM_PAGES {
            // SAFETY: page is bounds-checked against NUM_PAGES above; perms is valid for NUM_PAGES.
            let perm = unsafe { *fm.perms.add(page) };
            if perm >= 2 {
                // SAFETY: permission check passed; addr is within the mmap'd guest memory.
                unsafe {
                    *fm.buf.add(addr as usize) = value;
                }
                return true;
            }
        }
        false
    }

    /// Read bytes directly from flat buffer. Returns None on page fault.
    pub fn read_bytes(&self, addr: u32, len: u32) -> Option<Vec<u8>> {
        let fm = self.flat_memory.as_ref()?;
        let mut result = Vec::with_capacity(len as usize);
        for i in 0..len {
            let a = addr.wrapping_add(i);
            let page = a as usize / 4096;
            if page >= NUM_PAGES {
                return None;
            }
            // SAFETY: page is bounds-checked against NUM_PAGES above.
            let perm = unsafe { *fm.perms.add(page) };
            if perm < 1 {
                return None;
            }
            // SAFETY: permission check passed; a is within the mmap'd guest memory.
            result.push(unsafe { *fm.buf.add(a as usize) });
        }
        Some(result)
    }

    /// Write bytes directly to flat buffer. Returns false on page fault.
    pub fn write_bytes(&mut self, addr: u32, data: &[u8]) -> bool {
        let fm = match self.flat_memory.as_ref() {
            Some(f) => f,
            None => return false,
        };
        for (i, &byte) in data.iter().enumerate() {
            let a = addr.wrapping_add(i as u32);
            let page = a as usize / 4096;
            if page >= NUM_PAGES {
                return false;
            }
            // SAFETY: page is bounds-checked against NUM_PAGES above.
            let perm = unsafe { *fm.perms.add(page) };
            if perm < 2 {
                return false;
            }
            // SAFETY: permission check passed; a is within the mmap'd guest memory.
            unsafe {
                *fm.buf.add(a as usize) = byte;
            }
        }
        true
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
        if let Some(ref fm) = self.flat_memory {
            let old = self.ctx().heap_top;
            fm.update_guard_pages(old, top);
        }
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
        CTX_BITMAP, CTX_CODE_BASE, CTX_DISPATCH_TABLE, CTX_ENTRY_PC, CTX_EXIT_ARG, CTX_EXIT_REASON,
        CTX_GAS, CTX_OFFSET, CTX_PC, CTX_REGS,
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
            original_bitmap: [0u8; 32],
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
        assert_eq!(
            &ctx.original_bitmap as *const _ as usize - base,
            so(CTX_BITMAP)
        );
    }

    fn test_layout() -> DataLayout {
        DataLayout {
            mem_size: 4096,
            arg_start: 0,
            arg_data: vec![],
            ro_start: 0,
            ro_data: vec![],
            rw_start: 0,
            rw_data: vec![],
        }
    }

    #[test]
    fn test_recompile_trap() {
        let code = vec![0u8]; // trap
        let bitmask = vec![1u8];
        let registers = [0u64; 13];

        let mut pvm = RecompiledPvm::new(
            &code,
            bitmask,
            vec![],
            registers,
            1000,
            Some(test_layout()),
            crate::gas_cost::DEFAULT_MEM_CYCLES,
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

        let mut pvm = RecompiledPvm::new(
            &code,
            bitmask,
            vec![],
            registers,
            1000,
            Some(test_layout()),
            crate::gas_cost::DEFAULT_MEM_CYCLES,
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

        let mut pvm = RecompiledPvm::new(
            &code,
            bitmask,
            vec![],
            registers,
            1000,
            Some(test_layout()),
            crate::gas_cost::DEFAULT_MEM_CYCLES,
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

        let mut pvm = RecompiledPvm::new(
            &code,
            bitmask,
            vec![],
            registers,
            1000,
            Some(test_layout()),
            crate::gas_cost::DEFAULT_MEM_CYCLES,
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

        let mut pvm = RecompiledPvm::new(
            &code,
            bitmask,
            vec![],
            registers,
            0,
            Some(test_layout()),
            crate::gas_cost::DEFAULT_MEM_CYCLES,
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

        let mut pvm = RecompiledPvm::new(
            &code,
            mk_bitmask(),
            vec![],
            registers,
            10000,
            Some(test_layout()),
            crate::gas_cost::DEFAULT_MEM_CYCLES,
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
        let mut pvm2 = RecompiledPvm::new(
            &code,
            mk_bitmask(),
            vec![],
            registers2,
            10000,
            Some(test_layout()),
            crate::gas_cost::DEFAULT_MEM_CYCLES,
        )
        .expect("compilation should succeed");
        let exit2 = pvm2.run();
        assert_eq!(exit2, ExitReason::HostCall(0));
        assert_eq!(pvm2.registers()[2], 8); // 5 + 3 = 8
        assert_eq!(pvm2.registers()[3], 0); // carry = 0 (no overflow)
    }
}
