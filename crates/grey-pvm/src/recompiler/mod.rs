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

/// Memory read helper — reads u8, returns value or sets fault in ctx.
extern "sysv64" fn mem_read_u8(memory: *const Memory, addr: u32) -> u64 {
    let mem = unsafe { &*memory };
    match mem.read_u8(addr) {
        Some(v) => v as u64,
        None => u64::MAX, // sentinel — caller checks
    }
}

extern "sysv64" fn mem_read_u16(memory: *const Memory, addr: u32) -> u64 {
    let mem = unsafe { &*memory };
    match mem.read_u16_le(addr) {
        Some(v) => v as u64,
        None => u64::MAX,
    }
}

extern "sysv64" fn mem_read_u32(memory: *const Memory, addr: u32) -> u64 {
    let mem = unsafe { &*memory };
    match mem.read_u32_le(addr) {
        Some(v) => v as u64,
        None => u64::MAX,
    }
}

extern "sysv64" fn mem_read_u64_fn(memory: *const Memory, addr: u32) -> u64 {
    let mem = unsafe { &*memory };
    match mem.read_u64_le(addr) {
        Some(v) => v,
        None => u64::MAX,
    }
}

/// Memory write helper — writes value, returns 0 on success or fault page addr.
extern "sysv64" fn mem_write_u8(memory: *mut Memory, addr: u32, value: u64) -> u64 {
    let mem = unsafe { &mut *memory };
    match mem.write_u8(addr, value as u8) {
        crate::memory::MemoryAccess::Ok => 0,
        crate::memory::MemoryAccess::PageFault(a) => a as u64,
    }
}

extern "sysv64" fn mem_write_u16(memory: *mut Memory, addr: u32, value: u64) -> u64 {
    let mem = unsafe { &mut *memory };
    match mem.write_u16_le(addr, value as u16) {
        crate::memory::MemoryAccess::Ok => 0,
        crate::memory::MemoryAccess::PageFault(a) => a as u64,
    }
}

extern "sysv64" fn mem_write_u32(memory: *mut Memory, addr: u32, value: u64) -> u64 {
    let mem = unsafe { &mut *memory };
    match mem.write_u32_le(addr, value as u32) {
        crate::memory::MemoryAccess::Ok => 0,
        crate::memory::MemoryAccess::PageFault(a) => a as u64,
    }
}

extern "sysv64" fn mem_write_u64_fn(memory: *mut Memory, addr: u32, value: u64) -> u64 {
    let mem = unsafe { &mut *memory };
    match mem.write_u64_le(addr, value) {
        crate::memory::MemoryAccess::Ok => 0,
        crate::memory::MemoryAccess::PageFault(a) => a as u64,
    }
}

/// Sbrk helper. ctx: *mut JitContext, size: u64 → result in return.
extern "sysv64" fn sbrk_helper(ctx: *mut JitContext, size: u64) -> u64 {
    let ctx = unsafe { &mut *ctx };
    let mem = unsafe { &mut *ctx.memory };

    if size == 0 {
        // Query: return current heap top
        return ctx.heap_top as u64;
    }

    let pages = size as u32;
    let new_top = ctx.heap_top.wrapping_add(pages * grey_types::constants::PVM_PAGE_SIZE);

    // Map pages
    let start_page = ctx.heap_top / grey_types::constants::PVM_PAGE_SIZE;
    for p in 0..pages {
        mem.map_page(start_page + p, crate::memory::PageAccess::ReadWrite);
    }

    let old_top = ctx.heap_top;
    ctx.heap_top = new_top;
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
        let basic_block_starts = crate::vm::compute_basic_block_starts(&code, &bitmask);

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
        });

        // Set up pointers (will be updated after Box stabilizes)
        ctx.jt_ptr = jump_table.as_ptr();
        ctx.bb_starts = basic_block_starts.as_ptr() as *const u8;

        // Compile
        let helpers = HelperFns {
            mem_read_u8: mem_read_u8 as usize as u64,
            mem_read_u16: mem_read_u16 as usize as u64,
            mem_read_u32: mem_read_u32 as usize as u64,
            mem_read_u64: mem_read_u64_fn as usize as u64,
            mem_write_u8: mem_write_u8 as usize as u64,
            mem_write_u16: mem_write_u16 as usize as u64,
            mem_write_u32: mem_write_u32 as usize as u64,
            mem_write_u64: mem_write_u64_fn as usize as u64,
            sbrk_helper: sbrk_helper as usize as u64,
        };

        let compiler = Compiler::new(
            basic_block_starts.clone(),
            jump_table.clone(),
            helpers,
        );
        let native = compiler.compile(&code, &bitmask);
        let native_code = NativeCode::new(&native)?;

        Ok(Self {
            native_code,
            ctx,
            code,
            bitmask,
            jump_table,
            basic_block_starts,
            initial_gas: gas,
        })
    }

    /// Run the compiled code to completion.
    /// Returns (exit_reason, gas_remaining).
    pub fn run(&mut self) -> (ExitReason, u64) {
        // Execute native code
        let entry = self.native_code.entry();
        let ctx_ptr = &mut *self.ctx as *mut JitContext;

        unsafe {
            entry(ctx_ptr);
        }

        // Read exit reason from context
        let exit = match self.ctx.exit_reason {
            0 => ExitReason::Halt,      // EXIT_HALT
            1 => ExitReason::Panic,     // EXIT_PANIC
            2 => ExitReason::OutOfGas,  // EXIT_OOG
            3 => ExitReason::PageFault(self.ctx.exit_arg), // EXIT_PAGE_FAULT
            4 => ExitReason::HostCall(self.ctx.exit_arg),  // EXIT_HOST_CALL
            5 => {
                // Dynamic jump — handle in software
                // exit_arg has the jump table index
                let idx = self.ctx.exit_arg;
                self.handle_djump(idx)
            }
            _ => ExitReason::Panic,
        };

        let gas_remaining = self.ctx.gas.max(0) as u64;
        (exit, gas_remaining)
    }

    /// Handle a dynamic jump that the compiled code couldn't resolve.
    fn handle_djump(&mut self, idx: u32) -> ExitReason {
        // idx = addr/2 - 1 (already computed by codegen)
        if idx as usize >= self.jump_table.len() {
            return ExitReason::Panic;
        }
        let target = self.jump_table[idx as usize];
        if (target as usize) < self.basic_block_starts.len()
            && self.basic_block_starts[target as usize]
        {
            // Valid target — but we can't jump there in native code easily.
            // For now, return Panic. A full implementation would re-enter
            // native code at the target PC.
            // TODO: implement re-entry at target PC
            ExitReason::Panic
        } else {
            ExitReason::Panic
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

    /// Set the program counter (for re-entry after host calls).
    pub fn set_pc(&mut self, _pc: u32) {
        // In the recompiled model, we don't have a PC in the traditional sense.
        // The native code runs from beginning. For host-call re-entry, we'd need
        // to support re-entering at a specific basic block.
        // TODO: implement PC-based re-entry
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
    RecompiledPvm::new(
        pvm.code.clone(),
        pvm.bitmask.clone(),
        pvm.jump_table.clone(),
        pvm.registers,
        pvm.memory.clone(),
        pvm.gas,
    ).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::PageAccess;
    use codegen::{CTX_REGS, CTX_GAS, CTX_EXIT_REASON, CTX_EXIT_ARG};

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
        };
        let base = &ctx as *const JitContext as usize;

        assert_eq!(&ctx.regs as *const _ as usize - base, CTX_REGS as usize);
        assert_eq!(&ctx.gas as *const _ as usize - base, CTX_GAS as usize);
        assert_eq!(&ctx.exit_reason as *const _ as usize - base, CTX_EXIT_REASON as usize);
        assert_eq!(&ctx.exit_arg as *const _ as usize - base, CTX_EXIT_ARG as usize);
    }

    #[test]
    fn test_recompile_trap() {
        // Simple program: trap (opcode 0)
        let code = vec![0u8]; // trap
        let bitmask = vec![1u8];
        let registers = [0u64; 13];
        let memory = Memory::new();

        let mut pvm = RecompiledPvm::new(code, bitmask, vec![], registers, memory, 1000)
            .expect("compilation should succeed");
        let (exit, _gas) = pvm.run();
        assert_eq!(exit, ExitReason::Panic);
    }

    #[test]
    fn test_recompile_ecalli() {
        // Program: ecalli 42
        // ecalli = opcode 10, imm = 42 (1 byte)
        let code = vec![10, 42]; // ecalli 42
        let bitmask = vec![1, 0];
        let registers = [0u64; 13];
        let memory = Memory::new();

        let mut pvm = RecompiledPvm::new(code, bitmask, vec![], registers, memory, 1000)
            .expect("compilation should succeed");
        let (exit, _gas) = pvm.run();
        assert_eq!(exit, ExitReason::HostCall(42));
    }

    #[test]
    fn test_recompile_load_imm() {
        // Program: load_imm φ[0], 123; trap
        // load_imm = opcode 51, reg_byte = 0 (φ[0]), imm = 123
        let code = vec![51, 0, 123, 0]; // load_imm φ[0], 123; then trap
        let bitmask = vec![1, 0, 0, 1]; // two instructions: [51,0,123] and [0]
        let registers = [0u64; 13];
        let memory = Memory::new();

        let mut pvm = RecompiledPvm::new(code, bitmask, vec![], registers, memory, 1000)
            .expect("compilation should succeed");
        let (exit, _gas) = pvm.run();
        // After load_imm, registers[0] should be 123
        assert_eq!(pvm.registers()[0], 123);
        // Then trap
        assert_eq!(exit, ExitReason::Panic);
    }

    #[test]
    fn test_recompile_add64() {
        // load_imm φ[0], 10; load_imm φ[1], 20; add64 φ[2] = φ[0] + φ[1]; ecalli 0
        // add64 = opcode 200, reg_byte = 0|(1<<4) = 0x10, rd = 2
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
        let (exit, _gas) = pvm.run();
        assert_eq!(pvm.registers()[2], 30);
        assert_eq!(exit, ExitReason::HostCall(0));
    }

    #[test]
    fn test_recompile_out_of_gas() {
        // load_imm with only 0 gas
        let code = vec![51, 0, 42];
        let bitmask = vec![1, 0, 0];
        let registers = [0u64; 13];
        let memory = Memory::new();

        let mut pvm = RecompiledPvm::new(code, bitmask, vec![], registers, memory, 0)
            .expect("compilation should succeed");
        let (exit, _gas) = pvm.run();
        assert_eq!(exit, ExitReason::OutOfGas);
    }
}
