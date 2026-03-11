//! PVM recompiler — compiles PVM bytecode to native x86-64 machine code.
//!
//! This provides the same semantics as the interpreter in `vm.rs` but with
//! significantly better performance by eliminating decode overhead and keeping
//! PVM registers in native CPU registers.
//!
//! Usage:
//! ```ignore
//! let pvm = RecompiledPvm::new(code, bitmask, jump_table, registers, memory, gas);
//! let (exit, gas_used) = pvm.run();
//! ```

pub mod asm;
pub mod codegen;

use crate::memory::Memory;
use crate::vm::ExitReason;
use codegen::{Compiler, HelperFns};
use grey_types::constants::PVM_REGISTER_COUNT;
use grey_types::Gas;

/// JIT execution context passed to compiled code via R15.
/// Must be #[repr(C)] with exact field ordering matching codegen offsets.
#[repr(C)]
pub struct JitContext {
    /// PVM registers (offset 0, 13 × 8 = 104 bytes).
    pub regs: [u64; 13],
    /// Gas counter (offset 104). Signed to detect underflow.
    pub gas: i64,
    /// Pointer to Memory (offset 112).
    pub memory: *mut Memory,
    /// Exit reason code (offset 120).
    pub exit_reason: u32,
    /// Exit argument (offset 124) — host call ID, page fault addr, etc.
    pub exit_arg: u32,
    /// Heap base address (offset 128).
    pub heap_base: u32,
    /// Current heap top (offset 132).
    pub heap_top: u32,
    /// Jump table pointer (offset 136).
    pub jt_ptr: *const u32,
    /// Jump table length (offset 144).
    pub jt_len: u32,
    _pad0: u32,
    /// Basic block starts pointer (offset 152).
    pub bb_starts: *const u8,
    /// Basic block starts length (offset 160).
    pub bb_len: u32,
    _pad1: u32,
    /// Entry PC for re-entry after host calls (offset 168).
    /// 0 = start from beginning, otherwise jump to this basic block.
    pub entry_pc: u32,
    /// Current PC when execution stopped (offset 172).
    /// Updated on ecalli/djump exits.
    pub pc: u32,
    /// Dispatch table: PVM PC → native code offset (offset 176).
    /// Array of i32 offsets indexed by PVM PC. -1 = invalid PC.
    pub dispatch_table: *const i32,
    /// Base address of native code (offset 184).
    pub code_base: u64,
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

// Memory helper functions called from compiled code.
// Signature: extern "sysv64" fn(mem: *mut Memory, addr: u32, [value: u64]) -> u64
// For reads: returns the value. On fault, sets ctx fields (ctx obtained from the caller).
// We pass memory pointer directly, and handle faults via a global context.
// Actually, let's pass ctx as first arg for writes so we can set fault info.

// Reads: fn(memory: *const Memory, addr: u32) -> u64
// On fault, the caller checks ctx.exit_reason after the call.
// But the helper doesn't have ctx... Let's restructure.
// Pass ctx as first arg to everything.

/// Memory read helper — reads u8 via ctx. Sets exit_reason on page fault.
extern "sysv64" fn mem_read_u8(ctx: *mut JitContext, addr: u32) -> u64 {
    let ctx = unsafe { &mut *ctx };
    let mem = unsafe { &*ctx.memory };
    if std::env::var("GREY_PVM_DEBUG").is_ok() {
        eprintln!("  mem_read_u8: addr=0x{:08x}", addr);
    }
    match mem.read_u8(addr) {
        Some(v) => v as u64,
        None => {
            if std::env::var("GREY_PVM_DEBUG").is_ok() {
                eprintln!("  mem_read_u8: PAGE FAULT at 0x{:08x}", addr);
            }
            ctx.exit_reason = 3; // EXIT_PAGE_FAULT
            ctx.exit_arg = addr;
            0
        }
    }
}

extern "sysv64" fn mem_read_u16(ctx: *mut JitContext, addr: u32) -> u64 {
    let ctx = unsafe { &mut *ctx };
    let mem = unsafe { &*ctx.memory };
    if std::env::var("GREY_PVM_DEBUG").is_ok() {
        eprintln!("  mem_read_u16: addr=0x{:08x}", addr);
    }
    match mem.read_u16_le(addr) {
        Some(v) => v as u64,
        None => {
            if std::env::var("GREY_PVM_DEBUG").is_ok() {
                eprintln!("  mem_read_u16: PAGE FAULT at 0x{:08x}", addr);
            }
            ctx.exit_reason = 3;
            ctx.exit_arg = addr;
            0
        }
    }
}

extern "sysv64" fn mem_read_u32(ctx: *mut JitContext, addr: u32) -> u64 {
    let ctx = unsafe { &mut *ctx };
    let mem = unsafe { &*ctx.memory };
    if std::env::var("GREY_PVM_DEBUG").is_ok() {
        eprintln!("  mem_read_u32: addr=0x{:08x}", addr);
    }
    match mem.read_u32_le(addr) {
        Some(v) => v as u64,
        None => {
            if std::env::var("GREY_PVM_DEBUG").is_ok() {
                eprintln!("  mem_read_u32: PAGE FAULT at 0x{:08x}", addr);
            }
            ctx.exit_reason = 3;
            ctx.exit_arg = addr;
            0
        }
    }
}

extern "sysv64" fn mem_read_u64_fn(ctx: *mut JitContext, addr: u32) -> u64 {
    let ctx = unsafe { &mut *ctx };
    let mem = unsafe { &*ctx.memory };
    if std::env::var("GREY_PVM_DEBUG").is_ok() {
        eprintln!("  mem_read_u64: addr=0x{:08x}", addr);
    }
    match mem.read_u64_le(addr) {
        Some(v) => v,
        None => {
            if std::env::var("GREY_PVM_DEBUG").is_ok() {
                eprintln!("  mem_read_u64: PAGE FAULT at 0x{:08x}", addr);
            }
            ctx.exit_reason = 3;
            ctx.exit_arg = addr;
            0
        }
    }
}

/// Memory write helper — writes value via ctx. Sets exit_reason on page fault.
extern "sysv64" fn mem_write_u8(ctx: *mut JitContext, addr: u32, value: u64) -> u64 {
    let ctx = unsafe { &mut *ctx };
    let mem = unsafe { &mut *ctx.memory };
    match mem.write_u8(addr, value as u8) {
        crate::memory::MemoryAccess::Ok => 0,
        crate::memory::MemoryAccess::PageFault(a) => {
            ctx.exit_reason = 3;
            ctx.exit_arg = a;
            1
        }
    }
}

extern "sysv64" fn mem_write_u16(ctx: *mut JitContext, addr: u32, value: u64) -> u64 {
    if std::env::var("GREY_PVM_DEBUG").is_ok() {
        eprintln!("  mem_write_u16: addr=0x{:08x}", addr);
    }
    let ctx = unsafe { &mut *ctx };
    let mem = unsafe { &mut *ctx.memory };
    match mem.write_u16_le(addr, value as u16) {
        crate::memory::MemoryAccess::Ok => 0,
        crate::memory::MemoryAccess::PageFault(a) => {
            ctx.exit_reason = 3;
            ctx.exit_arg = a;
            1
        }
    }
}

extern "sysv64" fn mem_write_u32(ctx: *mut JitContext, addr: u32, value: u64) -> u64 {
    if std::env::var("GREY_PVM_DEBUG").is_ok() {
        eprintln!("  mem_write_u32: addr=0x{:08x}", addr);
    }
    let ctx = unsafe { &mut *ctx };
    let mem = unsafe { &mut *ctx.memory };
    match mem.write_u32_le(addr, value as u32) {
        crate::memory::MemoryAccess::Ok => 0,
        crate::memory::MemoryAccess::PageFault(a) => {
            ctx.exit_reason = 3;
            ctx.exit_arg = a;
            1
        }
    }
}

extern "sysv64" fn mem_write_u64_fn(ctx: *mut JitContext, addr: u32, value: u64) -> u64 {
    if std::env::var("GREY_PVM_DEBUG").is_ok() {
        eprintln!("  mem_write_u64: addr=0x{:08x}", addr);
    }
    let ctx = unsafe { &mut *ctx };
    let mem = unsafe { &mut *ctx.memory };
    match mem.write_u64_le(addr, value) {
        crate::memory::MemoryAccess::Ok => 0,
        crate::memory::MemoryAccess::PageFault(a) => {
            ctx.exit_reason = 3;
            ctx.exit_arg = a;
            1
        }
    }
}

/// Sbrk helper. ctx: *mut JitContext, size: u64 → result in return.
extern "sysv64" fn sbrk_helper(ctx: *mut JitContext, size: u64) -> u64 {
    let ctx = unsafe { &mut *ctx };
    let mem = unsafe { &mut *ctx.memory };
    let ps = grey_types::constants::PVM_PAGE_SIZE;

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
    for p in start_page..=end_page {
        if !mem.is_page_mapped(p) {
            mem.map_page(p, crate::memory::PageAccess::ReadWrite);
        }
    }

    ctx.heap_top = new_top_u32;
    old_top as u64
}

/// Recompiled PVM instance.
pub struct RecompiledPvm {
    /// Native code buffer.
    native_code: NativeCode,
    /// JIT context.
    ctx: Box<JitContext>,
    /// PVM code (for fallback/debugging).
    code: Vec<u8>,
    /// Bitmask.
    bitmask: Vec<u8>,
    /// Jump table.
    jump_table: Vec<u32>,
    /// Basic block starts.
    basic_block_starts: Vec<bool>,
    /// Initial gas.
    initial_gas: Gas,
    /// Dispatch table: PVM PC → native code offset (-1 = invalid).
    dispatch_table: Vec<i32>,
    /// Cached debug flag.
    debug: bool,
}

impl RecompiledPvm {
    /// Create a new recompiled PVM from parsed program components.
    pub fn new(
        code: Vec<u8>,
        bitmask: Vec<u8>,
        jump_table: Vec<u32>,
        registers: [u64; PVM_REGISTER_COUNT],
        memory: Memory,
        gas: Gas,
    ) -> Result<Self, String> {
        let debug = std::env::var("GREY_PVM_DEBUG").is_ok();

        // For the recompiler, treat every instruction start as a basic block start.
        // This allows re-entry at any PC (e.g., PC=5 for accumulate, PC=10 for on-transfer).
        // The cost is slightly more frequent gas checks (per-instruction rather than per-block).
        let basic_block_starts: Vec<bool> = bitmask.iter().map(|&b| b == 1).collect();

        // Allocate memory on the heap so we have a stable pointer
        let memory = Box::new(memory);
        let memory_ptr = Box::into_raw(memory);

        let mut ctx = Box::new(JitContext {
            regs: registers,
            gas: gas as i64,
            memory: memory_ptr,
            exit_reason: 0,
            exit_arg: 0,
            heap_base: 0,
            heap_top: 0,
            jt_ptr: std::ptr::null(),
            jt_len: jump_table.len() as u32,
            _pad0: 0,
            bb_starts: std::ptr::null(),
            bb_len: basic_block_starts.len() as u32,
            _pad1: 0,
            entry_pc: 0,
            pc: 0,
            dispatch_table: std::ptr::null(),
            code_base: 0,
        });

        // Set up pointers (will be updated after Box stabilizes)
        ctx.jt_ptr = jump_table.as_ptr();
        ctx.bb_starts = basic_block_starts.as_ptr() as *const u8;

        if debug {
            eprintln!("  write_u8 fn=0x{:x}", mem_write_u8 as *const () as usize);
            eprintln!("  write_u32 fn=0x{:x}", mem_write_u32 as *const () as usize);
            eprintln!("  read_u8 fn=0x{:x}", mem_read_u8 as *const () as usize);
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

        let compiler = Compiler::new(
            basic_block_starts.clone(),
            jump_table.clone(),
            helpers,
        );
        let (native, dispatch_table) = compiler.compile(&code, &bitmask);

        if debug {
            let _ = std::fs::write("/tmp/pvm_native.bin", &native);
            eprintln!("Wrote {} bytes of native code to /tmp/pvm_native.bin", native.len());
            eprintln!("  basic_block_starts count: {}", basic_block_starts.iter().filter(|&&b| b).count());
        }

        let native_code = NativeCode::new(&native)?;

        // Set dispatch table pointer and code base in context
        ctx.code_base = native_code.ptr as u64;

        let mut result = Self {
            native_code,
            ctx,
            code,
            bitmask,
            jump_table,
            basic_block_starts,
            initial_gas: gas,
            dispatch_table,
            debug,
        };

        // Set dispatch_table pointer (must point to the Vec's data in Self)
        result.ctx.dispatch_table = result.dispatch_table.as_ptr();

        Ok(result)
    }

    /// Run the compiled code until exit (halt, panic, OOG, page fault, or host call).
    /// Returns the exit reason. For host calls, the caller should handle the call,
    /// modify registers/memory as needed, then call run() again (entry_pc is set
    /// automatically for re-entry).
    pub fn run(&mut self) -> ExitReason {
        loop {
            if self.debug {
                eprintln!("recompiler::run() entry_pc={} gas={} heap_base=0x{:08x} heap_top=0x{:08x}",
                    self.ctx.entry_pc, self.ctx.gas, self.ctx.heap_base, self.ctx.heap_top);
                eprintln!("  initial regs: {:?}", &self.ctx.regs);
                self.ctx.exit_reason = 0xDEAD;
            }

            // Execute native code
            let entry = self.native_code.entry();
            let ctx_ptr = &mut *self.ctx as *mut JitContext;
            unsafe { entry(ctx_ptr); }

            if self.debug {
                eprintln!("recompiler::run() exit_reason={} exit_arg={} gas={} pc={}",
                    self.ctx.exit_reason, self.ctx.exit_arg, self.ctx.gas, self.ctx.pc);
                eprintln!("  regs: {:?}", &self.ctx.regs);
            }

            // Read exit reason from context
            match self.ctx.exit_reason {
                0 => return ExitReason::Halt,
                1 => return ExitReason::Panic,
                2 => {
                    self.ctx.entry_pc = self.ctx.pc;
                    return ExitReason::OutOfGas;
                }
                3 => return ExitReason::PageFault(self.ctx.exit_arg),
                4 => {
                    // Host call — set entry_pc for re-entry at the next instruction
                    self.ctx.entry_pc = self.ctx.pc;
                    return ExitReason::HostCall(self.ctx.exit_arg);
                }
                5 => {
                    // Dynamic jump — resolve and re-enter
                    let idx = self.ctx.exit_arg;
                    if let Some(target) = self.resolve_djump(idx) {
                        self.ctx.entry_pc = target;
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
        if (target as usize) < self.basic_block_starts.len()
            && self.basic_block_starts[target as usize]
        {
            Some(target)
        } else {
            None
        }
    }

    /// Access the PVM registers.
    pub fn registers(&self) -> &[u64; 13] {
        &self.ctx.regs
    }

    pub fn registers_mut(&mut self) -> &mut [u64; 13] {
        &mut self.ctx.regs
    }

    /// Access remaining gas.
    pub fn gas(&self) -> u64 {
        self.ctx.gas.max(0) as u64
    }

    /// Access memory.
    pub fn memory(&self) -> &Memory {
        unsafe { &*self.ctx.memory }
    }

    pub fn memory_mut(&mut self) -> &mut Memory {
        unsafe { &mut *self.ctx.memory }
    }

    /// Get the program counter (last known PC on exit).
    pub fn pc(&self) -> u32 {
        self.ctx.pc
    }

    /// Set the program counter for re-entry.
    pub fn set_pc(&mut self, pc: u32) {
        self.ctx.entry_pc = pc;
        self.ctx.pc = pc;
    }

    /// Set gas.
    pub fn set_gas(&mut self, gas: Gas) {
        self.ctx.gas = gas as i64;
    }
}

impl Drop for RecompiledPvm {
    fn drop(&mut self) {
        // Re-take ownership of the memory
        unsafe {
            let _ = Box::from_raw(self.ctx.memory);
        }
    }
}

/// Initialize a recompiled PVM from a standard program blob.
pub fn initialize_program_recompiled(
    blob: &[u8],
    arguments: &[u8],
    gas: Gas,
) -> Option<RecompiledPvm> {
    // Use the same parsing as the interpreter
    let pvm = crate::program::initialize_program(blob, arguments, gas)?;

    // Create recompiled version from the interpreter's parsed state
    let mut rpvm = RecompiledPvm::new(
        pvm.code.clone(),
        pvm.bitmask.clone(),
        pvm.jump_table.clone(),
        pvm.registers,
        pvm.memory.clone(),
        pvm.gas,
    ).ok()?;

    // Transfer heap state from interpreter
    rpvm.ctx.heap_base = pvm.heap_base;
    rpvm.ctx.heap_top = pvm.heap_top;

    Some(rpvm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::PageAccess;
    use codegen::{CTX_REGS, CTX_GAS, CTX_EXIT_REASON, CTX_EXIT_ARG, CTX_ENTRY_PC, CTX_PC,
                  CTX_DISPATCH_TABLE, CTX_CODE_BASE};

    #[test]
    fn test_jit_context_layout() {
        // Verify field offsets match codegen constants
        let ctx = JitContext {
            regs: [0; 13],
            gas: 0,
            memory: std::ptr::null_mut(),
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
        };
        let base = &ctx as *const JitContext as usize;

        assert_eq!(&ctx.regs as *const _ as usize - base, CTX_REGS as usize);
        assert_eq!(&ctx.gas as *const _ as usize - base, CTX_GAS as usize);
        assert_eq!(&ctx.exit_reason as *const _ as usize - base, CTX_EXIT_REASON as usize);
        assert_eq!(&ctx.exit_arg as *const _ as usize - base, CTX_EXIT_ARG as usize);
        assert_eq!(&ctx.entry_pc as *const _ as usize - base, CTX_ENTRY_PC as usize);
        assert_eq!(&ctx.pc as *const _ as usize - base, CTX_PC as usize);
        assert_eq!(&ctx.dispatch_table as *const _ as usize - base, CTX_DISPATCH_TABLE as usize);
        assert_eq!(&ctx.code_base as *const _ as usize - base, CTX_CODE_BASE as usize);
    }

    #[test]
    fn test_recompile_trap() {
        let code = vec![0u8]; // trap
        let bitmask = vec![1u8];
        let registers = [0u64; 13];
        let memory = Memory::new();

        let mut pvm = RecompiledPvm::new(code, bitmask, vec![], registers, memory, 1000)
            .expect("compilation should succeed");
        let exit = pvm.run();
        assert_eq!(exit, ExitReason::Panic);
    }

    #[test]
    fn test_recompile_ecalli() {
        let code = vec![10, 42]; // ecalli 42
        let bitmask = vec![1, 0];
        let registers = [0u64; 13];
        let memory = Memory::new();

        let mut pvm = RecompiledPvm::new(code, bitmask, vec![], registers, memory, 1000)
            .expect("compilation should succeed");
        let exit = pvm.run();
        assert_eq!(exit, ExitReason::HostCall(42));
    }

    #[test]
    fn test_recompile_load_imm() {
        let code = vec![51, 0, 123, 0]; // load_imm φ[0], 123; then trap
        let bitmask = vec![1, 0, 0, 1];
        let registers = [0u64; 13];
        let memory = Memory::new();

        let mut pvm = RecompiledPvm::new(code, bitmask, vec![], registers, memory, 1000)
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
        let memory = Memory::new();

        let mut pvm = RecompiledPvm::new(code, bitmask, vec![], registers, memory, 1000)
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
        let memory = Memory::new();

        let mut pvm = RecompiledPvm::new(code, bitmask, vec![], registers, memory, 0)
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
