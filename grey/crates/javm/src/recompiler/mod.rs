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
#[cfg(feature = "signals")]
pub mod signal;

use crate::vm::ExitReason;
use codegen::{Compiler, HelperFns};
use crate::{Gas, PVM_REGISTER_COUNT};

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
    _pad0: u32,
    /// Basic block starts pointer (offset 144).
    pub bb_starts: *const u8,
    /// Basic block starts length (offset 152).
    pub bb_len: u32,
    _pad1: u32,
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
    _pad2: u32,
}

/// Compiled native code buffer (mmap'd as executable).
struct NativeCode {
    ptr: *mut u8,
    len: usize,
}

impl NativeCode {
    /// Allocate an executable code buffer and copy machine code into it.
    fn new(code: &[u8]) -> Result<Self, String> {
        if code.is_empty() {
            return Err("empty code buffer".into());
        }
        let len = code.len();
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
        unsafe {
            std::ptr::copy_nonoverlapping(code.as_ptr(), ptr, len);
            // Make executable (and read-only)
            if libc::mprotect(ptr as *mut libc::c_void, len, libc::PROT_READ | libc::PROT_EXEC) != 0 {
                libc::munmap(ptr as *mut libc::c_void, len);
                return Err("mprotect failed".into());
            }
        }
        Ok(Self { ptr, len })
    }

    /// Get the function pointer for the compiled code entry.
    fn entry(&self) -> unsafe extern "sysv64" fn(*mut JitContext) {
        unsafe { std::mem::transmute(self.ptr) }
    }
}

impl Drop for NativeCode {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
    }
}

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
const NUM_PAGES: usize = 1 << 20;     // 2^20 = 1M pages
const CTX_PAGE: usize = 4096;         // JitContext page
const HEADER_SIZE: usize = NUM_PAGES + CTX_PAGE; // perms + ctx page before guest mem

impl FlatMemory {
    /// Create a flat memory from a data layout.
    fn new(layout: &crate::program::DataLayout) -> Option<Self> {
        let region_size = HEADER_SIZE + FLAT_BUF_SIZE;
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
        let buf = unsafe { region.add(HEADER_SIZE) };

        // Set all pages in [0, mem_size) as read-write
        let num_pages = (layout.mem_size as usize + 4095) / 4096;
        unsafe {
            std::ptr::write_bytes(perms, 2u8, num_pages.min(NUM_PAGES));
        }
        // Copy data directly into flat buffer
        unsafe {
            if !layout.arg_data.is_empty() {
                std::ptr::copy_nonoverlapping(layout.arg_data.as_ptr(), buf.add(layout.arg_start as usize), layout.arg_data.len());
            }
            if !layout.ro_data.is_empty() {
                std::ptr::copy_nonoverlapping(layout.ro_data.as_ptr(), buf.add(layout.ro_start as usize), layout.ro_data.len());
            }
            if !layout.rw_data.is_empty() {
                std::ptr::copy_nonoverlapping(layout.rw_data.as_ptr(), buf.add(layout.rw_start as usize), layout.rw_data.len());
            }
        }

        Some(Self { region, region_size, buf, perms })
    }

    /// Get the pointer where JitContext should be placed (buf - CTX_PAGE).
    fn ctx_ptr(&self) -> *mut u8 {
        unsafe { self.buf.sub(CTX_PAGE) }
    }

/// Mark pages beyond heap_top as PROT_NONE (guard pages).
    /// Pages [0, heap_top) remain PROT_READ|PROT_WRITE.
    #[cfg(feature = "signals")]
    fn install_guard_pages(&self, heap_top: u32) {
        let heap_top_page = (heap_top as usize + 4095) / 4096;
        let guard_start = unsafe { self.buf.add(heap_top_page * 4096) };
        let guard_len = FLAT_BUF_SIZE - heap_top_page * 4096;
        if guard_len > 0 {
            unsafe {
                libc::mprotect(
                    guard_start as *mut libc::c_void,
                    guard_len,
                    libc::PROT_NONE,
                );
            }
        }
    }

    /// Make pages in [old_top, new_top) accessible after heap growth.
    #[cfg(feature = "signals")]
    fn update_guard_pages(&self, old_top: u32, new_top: u32) {
        let old_page = (old_top as usize + 4095) / 4096;
        let new_page = (new_top as usize + 4095) / 4096;
        if new_page > old_page {
            let start = unsafe { self.buf.add(old_page * 4096) };
            let len = (new_page - old_page) * 4096;
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
        let perm = unsafe { *ctx.flat_perms.add(p) };
        if perm < min_perm {
            return false;
        }
    }
    true
}

/// Read from flat buffer. Caller must have checked permissions.
unsafe fn flat_read(ctx: &JitContext, addr: u32, len: usize) -> u64 {
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
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ctx.flat_buf.add(addr as usize), bytes.len());
    }
}

/// Memory read helpers — read from flat buffer.
extern "sysv64" fn mem_read_u8(ctx: *mut JitContext, addr: u32) -> u64 {
    let ctx = unsafe { &mut *ctx };
    if flat_check_perm(ctx, addr, 1, 1) {
        return unsafe { flat_read(ctx, addr, 1) };
    }
    ctx.exit_reason = 3; ctx.exit_arg = addr; 0
}

extern "sysv64" fn mem_read_u16(ctx: *mut JitContext, addr: u32) -> u64 {
    let ctx = unsafe { &mut *ctx };
    if flat_check_perm(ctx, addr, 2, 1) {
        return unsafe { flat_read(ctx, addr, 2) };
    }
    ctx.exit_reason = 3; ctx.exit_arg = addr; 0
}

extern "sysv64" fn mem_read_u32(ctx: *mut JitContext, addr: u32) -> u64 {
    let ctx = unsafe { &mut *ctx };
    if flat_check_perm(ctx, addr, 4, 1) {
        return unsafe { flat_read(ctx, addr, 4) };
    }
    ctx.exit_reason = 3; ctx.exit_arg = addr; 0
}

extern "sysv64" fn mem_read_u64_fn(ctx: *mut JitContext, addr: u32) -> u64 {
    let ctx = unsafe { &mut *ctx };
    if flat_check_perm(ctx, addr, 8, 1) {
        return unsafe { flat_read(ctx, addr, 8) };
    }
    ctx.exit_reason = 3; ctx.exit_arg = addr; 0
}

/// Memory write helpers — write to flat buffer.
extern "sysv64" fn mem_write_u8(ctx: *mut JitContext, addr: u32, value: u64) -> u64 {
    let ctx = unsafe { &mut *ctx };
    if flat_check_perm(ctx, addr, 1, 2) {
        unsafe { flat_write(ctx, addr, &[value as u8]); }
        return 0;
    }
    ctx.exit_reason = 3; ctx.exit_arg = addr; 1
}

extern "sysv64" fn mem_write_u16(ctx: *mut JitContext, addr: u32, value: u64) -> u64 {
    let ctx = unsafe { &mut *ctx };
    if flat_check_perm(ctx, addr, 2, 2) {
        unsafe { flat_write(ctx, addr, &(value as u16).to_le_bytes()); }
        return 0;
    }
    ctx.exit_reason = 3; ctx.exit_arg = addr; 1
}

extern "sysv64" fn mem_write_u32(ctx: *mut JitContext, addr: u32, value: u64) -> u64 {
    let ctx = unsafe { &mut *ctx };
    if flat_check_perm(ctx, addr, 4, 2) {
        unsafe { flat_write(ctx, addr, &(value as u32).to_le_bytes()); }
        return 0;
    }
    ctx.exit_reason = 3; ctx.exit_arg = addr; 1
}

extern "sysv64" fn mem_write_u64_fn(ctx: *mut JitContext, addr: u32, value: u64) -> u64 {
    let ctx = unsafe { &mut *ctx };
    if flat_check_perm(ctx, addr, 8, 2) {
        unsafe { flat_write(ctx, addr, &value.to_le_bytes()); }
        return 0;
    }
    ctx.exit_reason = 3; ctx.exit_arg = addr; 1
}

/// Sbrk helper. ctx: *mut JitContext, size: u64 → result in return.
extern "sysv64" fn sbrk_helper(ctx: *mut JitContext, size: u64) -> u64 {
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
    // Map any pages in [old_top, new_top) that aren't mapped yet
    let start_page = old_top / ps;
    let end_page = if new_top_u32 == 0 { u32::MAX / ps } else { (new_top_u32 - 1) / ps };
    let perms = ctx.flat_perms as *mut u8;
    for p in start_page..=end_page {
        unsafe {
            if *perms.add(p as usize) == 0 {
                *perms.add(p as usize) = 2; // read-write
            }
        }
    }

    // With signals feature, make newly accessible pages PROT_READ|PROT_WRITE.
    #[cfg(feature = "signals")]
    if !ctx.flat_buf.is_null() {
        let old_page = (old_top as usize + 4095) / 4096;
        let new_page = (new_top_u32 as usize + 4095) / 4096;
        if new_page > old_page {
            unsafe {
                let start = ctx.flat_buf.add(old_page * 4096);
                let len = (new_page - old_page) * 4096;
                libc::mprotect(start as *mut libc::c_void, len, libc::PROT_READ | libc::PROT_WRITE);
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
    /// PVM code (for fallback/debugging).
    code: Vec<u8>,
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
    #[cfg(feature = "signals")]
    signal_state: Option<Box<signal::SignalState>>,
}

impl RecompiledPvm {
    /// Create a new recompiled PVM from parsed program components.
    pub fn new(
        code: Vec<u8>,
        bitmask: Vec<u8>,
        jump_table: Vec<u32>,
        registers: [u64; PVM_REGISTER_COUNT],
        gas: Gas,
        data_layout: Option<crate::program::DataLayout>,
    ) -> Result<Self, String> {
        let debug = std::env::var("GREY_PVM_DEBUG").is_ok();

        // Gas blocks and validation are now computed inline during the compile loop.
        // No separate pre-passes needed.

        let layout = data_layout.ok_or("data_layout required for recompiler")?;

        // Initialize flat memory — JitContext will live inside this region
        let _t1 = std::time::Instant::now();
        let flat_memory = FlatMemory::new(&layout)
            .ok_or("failed to mmap flat memory region")?;
        let _t_flat = _t1.elapsed();

        // Place JitContext inside the flat memory region (at buf - CTX_PAGE)
        let ctx_raw = flat_memory.ctx_ptr() as *mut JitContext;
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
            });
        }
        let ctx = unsafe { &mut *ctx_raw };

        // Set up pointers
        ctx.jt_ptr = jump_table.as_ptr();
        ctx.bb_starts = bitmask.as_ptr() as *const u8;

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
            jump_table.clone(),
            helpers,
            code.len(),
        );
        let compile_result = compiler.compile(&code, &bitmask);
        let _t_compile = _t2.elapsed();
        let native = compile_result.native_code;
        let dispatch_table = compile_result.dispatch_table;

        if debug {
            let _ = std::fs::write("/tmp/pvm_native.bin", &native);
            tracing::debug!(
                native_bytes = native.len(),
                basic_blocks = bitmask.iter().filter(|&&b| b == 1).count(),
                "wrote native code to /tmp/pvm_native.bin"
            );
        }

        let _t3 = std::time::Instant::now();
        let native_code = NativeCode::new(&native)?;
        let _t_native = _t3.elapsed();

        // Signal-based bounds checking: build trap table and install guard pages.
        #[cfg(feature = "signals")]
        let signal_state = {
            signal::ensure_installed();
            let ss = Box::new(signal::SignalState {
                code_start: native_code.ptr as usize,
                code_end: native_code.ptr as usize + native_code.len,
                exit_label_addr: native_code.ptr as usize + compile_result.exit_label_offset as usize,
                ctx_ptr: ctx_raw,
                trap_table: compile_result.trap_table,
            });
            // Guard pages installed later by initialize_program_recompiled
            // after heap_top is set to its correct value.
            Some(ss)
        };

        tracing::debug!(
            flat_mem_us = _t_flat.as_micros() as u64,
            compile_us = _t_compile.as_micros() as u64,
            native_us = _t_native.as_micros() as u64,
            code_len = code.len(),
            native_len = native.len(),
            "recompiler::new() timing"
        );

        // Set dispatch table pointer and code base in context
        ctx.code_base = native_code.ptr as u64;

        let mut result = Self {
            native_code,
            ctx: ctx_raw,
            code,
            bitmask,
            jump_table,
            _initial_gas: gas,
            dispatch_table,
            debug,
            flat_memory: Some(flat_memory),
            #[cfg(feature = "signals")]
            signal_state,
        };

        // Set dispatch_table pointer (must point to the Vec's data in Self)
        result.ctx_mut().dispatch_table = result.dispatch_table.as_ptr();

        Ok(result)
    }

    #[inline(always)]
    fn ctx(&self) -> &JitContext {
        unsafe { &*self.ctx }
    }
    #[inline(always)]
    fn ctx_mut(&mut self) -> &mut JitContext {
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

            // Execute native code
            #[cfg(feature = "signals")]
            if let Some(ref mut ss) = self.signal_state {
                signal::SIGNAL_STATE.with(|cell| cell.set(&mut **ss as *mut _));
            }

            let entry = self.native_code.entry();
            unsafe { entry(self.ctx); }

            #[cfg(feature = "signals")]
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
        if (target as usize) < self.bitmask.len()
            && self.bitmask[target as usize] == 1
        {
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
            let perm = unsafe { *fm.perms.add(page) };
            if perm >= 1 {
                return Some(unsafe { *fm.buf.add(addr as usize) });
            }
        }
        None
    }

    /// Write a byte directly to the flat buffer.
    /// Returns true on success, false on page fault.
    pub fn write_byte(&mut self, addr: u32, value: u8) -> bool {
        let fm = match self.flat_memory.as_ref() { Some(f) => f, None => return false };
        let page = addr as usize / 4096;
        if page < NUM_PAGES {
            let perm = unsafe { *fm.perms.add(page) };
            if perm >= 2 {
                unsafe { *fm.buf.add(addr as usize) = value; }
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
            if page >= NUM_PAGES { return None; }
            let perm = unsafe { *fm.perms.add(page) };
            if perm < 1 { return None; }
            result.push(unsafe { *fm.buf.add(a as usize) });
        }
        Some(result)
    }

    /// Write bytes directly to flat buffer. Returns false on page fault.
    pub fn write_bytes(&mut self, addr: u32, data: &[u8]) -> bool {
        let fm = match self.flat_memory.as_ref() { Some(f) => f, None => return false };
        for (i, &byte) in data.iter().enumerate() {
            let a = addr.wrapping_add(i as u32);
            let page = a as usize / 4096;
            if page >= NUM_PAGES { return false; }
            let perm = unsafe { *fm.perms.add(page) };
            if perm < 2 { return false; }
            unsafe { *fm.buf.add(a as usize) = byte; }
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
        #[cfg(feature = "signals")]
        if let Some(ref fm) = self.flat_memory {
            let old = self.ctx().heap_top;
            fm.update_guard_pages(old, top);
        }
        self.ctx_mut().heap_top = top;
    }

    /// Get the native code bytes (for disassembly / debugging).
    pub fn native_code_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.native_code.ptr, self.native_code.len) }
    }
}


/// Initialize a recompiled PVM from a standard program blob.
pub fn initialize_program_recompiled(
    blob: &[u8],
    arguments: &[u8],
    gas: Gas,
) -> Option<RecompiledPvm> {
    let parsed = crate::program::parse_program_blob(blob, arguments, gas)?;

    let mut rpvm = RecompiledPvm::new(
        parsed.code,
        parsed.bitmask,
        parsed.jump_table,
        parsed.registers,
        gas,
        parsed.layout,
    ).ok()?;

    rpvm.ctx_mut().heap_base = parsed.heap_base;
    rpvm.ctx_mut().heap_top = parsed.heap_top;

    #[cfg(feature = "signals")]
    if let Some(ref fm) = rpvm.flat_memory {
        fm.install_guard_pages(parsed.heap_top);
    }

    Some(rpvm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use codegen::{CTX_REGS, CTX_GAS, CTX_EXIT_REASON, CTX_EXIT_ARG, CTX_ENTRY_PC, CTX_PC,
                  CTX_DISPATCH_TABLE, CTX_CODE_BASE, CTX_OFFSET};

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
        };
        let base = &ctx as *const JitContext as usize;
        // Convert codegen offset (negative from R15) to struct offset:
        // struct_offset = codegen_offset - (-CTX_OFFSET) = codegen_offset + CTX_OFFSET
        let so = |codegen_off: i32| -> usize { (codegen_off + CTX_OFFSET) as usize };

        assert_eq!(&ctx.regs as *const _ as usize - base, so(CTX_REGS));
        assert_eq!(&ctx.gas as *const _ as usize - base, so(CTX_GAS));
        assert_eq!(&ctx.exit_reason as *const _ as usize - base, so(CTX_EXIT_REASON));
        assert_eq!(&ctx.exit_arg as *const _ as usize - base, so(CTX_EXIT_ARG));
        assert_eq!(&ctx.entry_pc as *const _ as usize - base, so(CTX_ENTRY_PC));
        assert_eq!(&ctx.pc as *const _ as usize - base, so(CTX_PC));
        assert_eq!(&ctx.dispatch_table as *const _ as usize - base, so(CTX_DISPATCH_TABLE));
        assert_eq!(&ctx.code_base as *const _ as usize - base, so(CTX_CODE_BASE));
    }

    fn test_layout() -> crate::program::DataLayout {
        crate::program::DataLayout {
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

        let mut pvm = RecompiledPvm::new(code, bitmask, vec![], registers, 1000, Some(test_layout()))
            .expect("compilation should succeed");
        let exit = pvm.run();
        assert_eq!(exit, ExitReason::Panic);
    }

    #[test]
    fn test_recompile_ecalli() {
        let code = vec![10, 42]; // ecalli 42
        let bitmask = vec![1, 0];
        let registers = [0u64; 13];

        let mut pvm = RecompiledPvm::new(code, bitmask, vec![], registers, 1000, Some(test_layout()))
            .expect("compilation should succeed");
        let exit = pvm.run();
        assert_eq!(exit, ExitReason::HostCall(42));
    }

    #[test]
    fn test_recompile_load_imm() {
        let code = vec![51, 0, 123, 0]; // load_imm φ[0], 123; then trap
        let bitmask = vec![1, 0, 0, 1];
        let registers = [0u64; 13];

        let mut pvm = RecompiledPvm::new(code, bitmask, vec![], registers, 1000, Some(test_layout()))
            .expect("compilation should succeed");
        let exit = pvm.run();
        assert_eq!(pvm.registers()[0], 123);
        assert_eq!(exit, ExitReason::Panic);
    }

    #[test]
    fn test_recompile_add64() {
        let code = vec![
            51, 0, 10,     // load_imm φ[0], 10
            51, 1, 20,     // load_imm φ[1], 20
            200, 0x10, 2,  // add64 φ[2] = φ[0] + φ[1]
            10, 0,         // ecalli 0
        ];
        let bitmask = vec![1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0];
        let registers = [0u64; 13];

        let mut pvm = RecompiledPvm::new(code, bitmask, vec![], registers, 1000, Some(test_layout()))
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

        let mut pvm = RecompiledPvm::new(code, bitmask, vec![], registers, 0, Some(test_layout()))
            .expect("compilation should succeed");
        let exit = pvm.run();
        assert_eq!(exit, ExitReason::OutOfGas);
    }

    #[test]
    #[ignore] // Requires /tmp/test_code_blob.bin — used for manual debugging only
    fn test_compare_interpreter_recompiler() {
        // Load the test code blob
        let blob = match std::fs::read("/tmp/test_code_blob.bin") {
            Ok(b) => b,
            Err(_) => {
                eprintln!("Skipping comparison test: /tmp/test_code_blob.bin not found");
                return;
            }
        };
        let args = &[0u8, 0, 0, 0]; // 4-byte dummy args
        let gas = 900_000u64;

        // Initialize interpreter
        let mut interp = crate::program::initialize_program(&blob, args, gas)
            .expect("interpreter init failed");
        interp.pc = 5;

        // Initialize recompiler
        let mut recomp = initialize_program_recompiled(&blob, args, gas)
            .expect("recompiler init failed");
        recomp.set_pc(5);

        // Run both until first host call and compare
        let mut step = 0;
        loop {
            step += 1;
            let interp_exit = interp.run();
            let recomp_exit = recomp.run();

            let interp_exit_clone = interp_exit.0.clone();
            let recomp_gas = recomp.gas();
            let interp_gas = interp.gas;

            eprintln!("Step {}: interp_exit={:?} recomp_exit={:?}", step, interp_exit_clone, recomp_exit);
            eprintln!("  interp: gas={} pc={} regs={:?}", interp_gas, interp.pc, &interp.registers);
            eprintln!("  recomp: gas={} pc={} regs={:?}", recomp_gas, recomp.pc(), recomp.registers());

            // Check for mismatch and print trace if found
            let gas_match = interp_gas == recomp_gas;
            let exit_match = interp_exit_clone == recomp_exit;
            let reg_match = (0..13).all(|i| interp.registers[i] == recomp.registers()[i]);

            if !gas_match || !exit_match || !reg_match {
                // Print interpreter trace before panicking
                let trace = &interp.pc_trace;
                eprintln!("Interpreter trace (first 100 PCs from tracing start):");
                for (i, &(pc, op)) in trace.iter().take(165).enumerate() {
                    let opname = crate::instruction::Opcode::from_byte(op)
                        .map(|o| format!("{:?}", o))
                        .unwrap_or_else(|| format!("?{}", op));
                    eprintln!("  [{:3}] pc={:5} op={}", i, pc, opname);
                }
                if !gas_match {
                    panic!("Gas mismatch at step {}: interp={} recomp={}", step, interp_gas, recomp_gas);
                }
                if !exit_match {
                    panic!("Exit mismatch at step {}: interp={:?} recomp={:?}", step, interp_exit_clone, recomp_exit);
                }
                for i in 0..13 {
                    if interp.registers[i] != recomp.registers()[i] {
                        panic!("Register φ[{}] mismatch at step {}: interp=0x{:x} recomp=0x{:x}",
                            i, step, interp.registers[i], recomp.registers()[i]);
                    }
                }
            }

            // After step 2, print interpreter trace
            if step == 3 {
                let trace = &interp.pc_trace;
                eprintln!("Interpreter trace (first 50 PCs after step 2):");
                for (i, &(pc, op)) in trace.iter().take(50).enumerate() {
                    let opname = crate::instruction::Opcode::from_byte(op)
                        .map(|o| format!("{:?}", o))
                        .unwrap_or_else(|| format!("?{}", op));
                    eprintln!("  [{:3}] pc={:5} op={}", i, pc, opname);
                }
            }

            match interp_exit_clone {
                ExitReason::Halt | ExitReason::Panic | ExitReason::OutOfGas | ExitReason::PageFault(_) => {
                    eprintln!("Both exited with {:?} after {} steps", interp_exit_clone, step);
                    break;
                }
                ExitReason::HostCall(id) => {
                    // Simulate a simple host call: just set ω7 = WHAT (error)
                    // and continue
                    let what = u64::MAX - 2;
                    interp.registers[7] = what;
                    recomp.registers_mut()[7] = what;
                    if id == 0 {
                        // gas host call — return remaining gas
                        interp.registers[7] = interp.gas;
                        recomp.registers_mut()[7] = recomp.gas();
                    }
                    // Enable tracing to help debug divergences
                    interp.tracing_enabled = true;
                }
            }

            if step > 100 {
                eprintln!("Reached 100 steps, stopping comparison");
                break;
            }
        }
    }
}
