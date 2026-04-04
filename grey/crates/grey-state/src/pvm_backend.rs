//! PVM backend — thin wrapper around grey-pvm.
//!
//! Exposes `PvmInstance` and `ExitReason` for use by the accumulate
//! sub-transition, implemented directly from the Gray Paper (Appendix A).
//!
//! Supports three backends selectable via the `GREY_PVM` environment variable:
//! - `interpreter` (default): the standard PVM interpreter
//! - `recompiler`: AOT-compiled native x86-64 execution
//! - `compare`: runs both and compares at each host-call boundary

use javm::Gas;

pub use javm::ExitReason;

/// Check once whether the recompiler backend is requested.
fn pvm_mode() -> &'static str {
    static MODE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    MODE.get_or_init(|| std::env::var("GREY_PVM").unwrap_or_else(|_| "interpreter".to_string()))
}

/// Backend-agnostic PVM instance.
enum Backend {
    Interpreter(Box<javm::vm::Pvm>),
    Recompiler(Box<javm::RecompiledPvm>),
    Compare {
        interp: Box<javm::vm::Pvm>,
        recomp: Box<javm::RecompiledPvm>,
        step: u32,
    },
    /// Capability-based kernel (v2). Manages multi-VM internally.
    /// Only exits to host for protocol cap calls.
    Kernel(Box<javm::kernel::InvocationKernel>),
}

/// PVM instance backed by either the interpreter or recompiler.
pub struct PvmInstance {
    inner: Backend,
}

impl PvmInstance {
    /// Create a capability-based kernel from a JAR v2 blob.
    pub fn initialize_v2(code_blob: &[u8], args: &[u8], gas: Gas) -> Option<Self> {
        match javm::kernel::InvocationKernel::new(code_blob, args, gas) {
            Ok(kernel) => Some(PvmInstance {
                inner: Backend::Kernel(Box::new(kernel)),
            }),
            Err(e) => {
                tracing::warn!("kernel init failed: {e}");
                None
            }
        }
    }

    /// Create a PVM from a code blob, arguments, and gas budget.
    pub fn initialize(code_blob: &[u8], args: &[u8], gas: Gas) -> Option<Self> {
        match pvm_mode() {
            "recompiler" => javm::recompiler::initialize_program_recompiled(code_blob, args, gas)
                .map(|pvm| PvmInstance {
                    inner: Backend::Recompiler(Box::new(pvm)),
                }),
            "compare" => {
                let interp = javm::program::initialize_program(code_blob, args, gas)?;
                let recomp = javm::recompiler::initialize_program_recompiled(code_blob, args, gas)?;
                Some(PvmInstance {
                    inner: Backend::Compare {
                        interp: Box::new(interp),
                        recomp: Box::new(recomp),
                        step: 0,
                    },
                })
            }
            _ => javm::program::initialize_program(code_blob, args, gas).map(|pvm| PvmInstance {
                inner: Backend::Interpreter(Box::new(pvm)),
            }),
        }
    }

    /// Run until exit (halt, panic, OOG, page fault, or host call).
    /// Not supported for Kernel backend — use kernel API directly.
    pub fn run(&mut self) -> ExitReason {
        match &mut self.inner {
            Backend::Interpreter(pvm) => {
                let (reason, _) = pvm.run();
                reason
            }
            Backend::Recompiler(pvm) => pvm.run(),
            Backend::Kernel(_) => unimplemented!("kernel backend: use kernel API"),
            Backend::Compare {
                interp,
                recomp,
                step,
            } => {
                *step += 1;
                let s = *step;

                // Run both with full gas.
                let (ie, _) = interp.run();
                let re = recomp.run();

                // Check for register/PC mismatch
                let mut mismatch = false;
                for i in 0..13 {
                    if interp.registers[i] != recomp.registers()[i] {
                        mismatch = true;
                    }
                }
                if interp.pc != recomp.pc() || ie != re || interp.gas != recomp.gas() {
                    mismatch = true;
                }
                if mismatch {
                    eprintln!(
                        "COMPARE step {}: MISMATCH exit_i={:?} exit_r={:?} pc_i={} pc_r={} gas_i={} gas_r={}",
                        s,
                        ie,
                        re,
                        interp.pc,
                        recomp.pc(),
                        interp.gas,
                        recomp.gas()
                    );
                    for i in 0..13 {
                        if interp.registers[i] != recomp.registers()[i] {
                            eprintln!(
                                "  reg[{:2}]: interp={:#18x} recomp={:#18x}",
                                i,
                                interp.registers[i],
                                recomp.registers()[i]
                            );
                        }
                    }
                    // Print opcode at the recompiler's exit PC to help identify the buggy instruction
                    let rpc = recomp.pc() as usize;
                    if rpc < interp.code.len() {
                        eprintln!("  opcode at recomp_pc={}: {}", rpc, interp.code[rpc]);
                    }
                }
                // Compare memory on host-call exits (when PVM wrote to memory)
                if !mismatch {
                    for (page_idx, chunk) in interp.flat_mem.chunks(4096).enumerate() {
                        let base = (page_idx as u32) * 4096;
                        for (offset, &i_byte) in chunk.iter().enumerate() {
                            let addr = base + offset as u32;
                            let r_byte = recomp.read_byte(addr).unwrap_or(0);
                            if i_byte != r_byte {
                                eprintln!(
                                    "COMPARE step {}: MEMORY MISMATCH at addr=0x{:08x} interp=0x{:02x} recomp=0x{:02x}",
                                    s, addr, i_byte, r_byte
                                );
                                mismatch = true;
                                break;
                            }
                        }
                        if mismatch {
                            break;
                        }
                    }
                }

                if mismatch {
                    // Sync gas and return interpreter's result (correct behavior)
                    recomp.set_gas(interp.gas);
                    // Sync registers and PC from interpreter
                    for i in 0..13 {
                        recomp.set_register(i, interp.registers[i]);
                    }
                    recomp.set_pc(interp.pc);
                }
                // Always return interpreter result (correct), recompiler is just checked
                ie
            }
        }
    }

    /// Check if this is a kernel (v2) backend.
    pub fn is_kernel(&self) -> bool {
        matches!(self.inner, Backend::Kernel(_))
    }

    /// Access the kernel (only for Kernel backend).
    pub fn kernel(&self) -> Option<&javm::kernel::InvocationKernel> {
        match &self.inner {
            Backend::Kernel(k) => Some(k),
            _ => None,
        }
    }

    /// Mutable access to the kernel (only for Kernel backend).
    pub fn kernel_mut(&mut self) -> Option<&mut javm::kernel::InvocationKernel> {
        match &mut self.inner {
            Backend::Kernel(k) => Some(k),
            _ => None,
        }
    }

    pub fn gas(&self) -> Gas {
        match &self.inner {
            Backend::Interpreter(pvm) => pvm.gas,
            Backend::Recompiler(pvm) => pvm.gas(),
            Backend::Compare { recomp, .. } => recomp.gas(),
            Backend::Kernel(k) => k.vms.get(k.active_vm as usize).map(|v| v.gas).unwrap_or(0),
        }
    }
    pub fn set_gas(&mut self, gas: Gas) {
        match &mut self.inner {
            Backend::Interpreter(pvm) => pvm.gas = gas,
            Backend::Recompiler(pvm) => pvm.set_gas(gas),
            Backend::Compare { interp, recomp, .. } => {
                let delta = gas as i64 - recomp.gas() as i64;
                interp.gas = (interp.gas as i64 + delta) as u64;
                recomp.set_gas(gas);
            }
            Backend::Kernel(k) => {
                if let Some(vm) = k.vms.get_mut(k.active_vm as usize) {
                    vm.gas = gas;
                }
            }
        }
    }

    pub fn pc(&self) -> u32 {
        match &self.inner {
            Backend::Interpreter(pvm) => pvm.pc,
            Backend::Recompiler(pvm) => pvm.pc(),
            Backend::Compare { recomp, .. } => recomp.pc(),
            Backend::Kernel(k) => k.vms.get(k.active_vm as usize).map(|v| v.pc).unwrap_or(0),
        }
    }
    pub fn set_pc(&mut self, pc: u32) {
        match &mut self.inner {
            Backend::Interpreter(pvm) => pvm.pc = pc,
            Backend::Recompiler(pvm) => pvm.set_pc(pc),
            Backend::Compare { interp, recomp, .. } => {
                interp.pc = pc;
                recomp.set_pc(pc);
            }
            Backend::Kernel(k) => {
                if let Some(vm) = k.vms.get_mut(k.active_vm as usize) {
                    vm.pc = pc;
                }
            }
        }
    }

    /// Map pages in the given range as ReadWrite (for grow_heap).
    pub fn map_pages_rw(&mut self, start_page: u32, end_page: u32) {
        match &mut self.inner {
            Backend::Interpreter(pvm) => {
                let needed = (end_page as usize) * javm::PVM_PAGE_SIZE as usize;
                if pvm.flat_mem.len() < needed {
                    pvm.flat_mem.resize(needed, 0);
                }
            }
            Backend::Recompiler(pvm) => {
                for p in start_page..end_page {
                    pvm.write_byte(p * javm::PVM_PAGE_SIZE, 0);
                }
            }
            Backend::Compare { interp, recomp, .. } => {
                let needed = (end_page as usize) * javm::PVM_PAGE_SIZE as usize;
                if interp.flat_mem.len() < needed {
                    interp.flat_mem.resize(needed, 0);
                }
                for p in start_page..end_page {
                    recomp.write_byte(p * javm::PVM_PAGE_SIZE, 0);
                }
            }
            Backend::Kernel(_) => {} // kernel uses DATA caps, not flat memory
        }
    }

    pub fn heap_top(&self) -> u32 {
        match &self.inner {
            Backend::Interpreter(pvm) => pvm.heap_top,
            Backend::Recompiler(pvm) => pvm.heap_top(),
            Backend::Compare { recomp, .. } => recomp.heap_top(),
            Backend::Kernel(_) => 0, // kernel uses DATA caps
        }
    }
    pub fn set_heap_top(&mut self, top: u32) {
        match &mut self.inner {
            Backend::Interpreter(pvm) => pvm.heap_top = top,
            Backend::Recompiler(pvm) => pvm.set_heap_top(top),
            Backend::Compare { interp, recomp, .. } => {
                interp.heap_top = top;
                recomp.set_heap_top(top);
            }
            Backend::Kernel(_) => {} // kernel uses DATA caps
        }
    }

    pub fn reg(&self, index: usize) -> u64 {
        match &self.inner {
            Backend::Interpreter(pvm) => pvm.registers[index],
            Backend::Recompiler(pvm) => pvm.registers()[index],
            Backend::Compare { recomp, .. } => recomp.registers()[index],
            Backend::Kernel(k) => {
                k.vms.get(k.active_vm as usize).map(|v| v.registers[index]).unwrap_or(0)
            }
        }
    }
    pub fn set_reg(&mut self, index: usize, value: u64) {
        match &mut self.inner {
            Backend::Interpreter(pvm) => pvm.registers[index] = value,
            Backend::Recompiler(pvm) => pvm.registers_mut()[index] = value,
            Backend::Compare { interp, recomp, .. } => {
                interp.registers[index] = value;
                recomp.registers_mut()[index] = value;
            }
            Backend::Kernel(k) => {
                if let Some(vm) = k.vms.get_mut(k.active_vm as usize) {
                    vm.registers[index] = value;
                }
            }
        }
    }

    pub fn read_byte(&self, addr: u32) -> Option<u8> {
        match &self.inner {
            Backend::Interpreter(pvm) => pvm.read_u8(addr),
            Backend::Recompiler(pvm) => pvm.read_byte(addr),
            Backend::Compare { recomp, .. } => recomp.read_byte(addr),
            Backend::Kernel(_) => None, // kernel uses DATA cap offsets
        }
    }

    pub fn write_byte(&mut self, addr: u32, value: u8) {
        match &mut self.inner {
            Backend::Interpreter(pvm) => {
                pvm.write_u8(addr, value);
            }
            Backend::Recompiler(pvm) => {
                pvm.write_byte(addr, value);
            }
            Backend::Compare { interp, recomp, .. } => {
                interp.write_u8(addr, value);
                recomp.write_byte(addr, value);
            }
            Backend::Kernel(_) => {} // kernel uses DATA cap offsets
        }
    }

    pub fn read_bytes(&self, addr: u32, len: u32) -> Vec<u8> {
        match &self.inner {
            Backend::Interpreter(pvm) => (0..len)
                .map(|i| pvm.read_u8(addr + i).unwrap_or(0))
                .collect(),
            Backend::Recompiler(pvm) => (0..len)
                .map(|i| pvm.read_byte(addr + i).unwrap_or(0))
                .collect(),
            Backend::Compare { recomp, .. } => (0..len)
                .map(|i| recomp.read_byte(addr + i).unwrap_or(0))
                .collect(),
            Backend::Kernel(_) => vec![0; len as usize], // kernel uses DATA cap offsets
        }
    }

    /// Try to read bytes; returns None on page fault (any inaccessible byte).
    pub fn try_read_bytes(&self, addr: u32, len: u32) -> Option<Vec<u8>> {
        match &self.inner {
            Backend::Interpreter(pvm) => {
                let a = addr as usize;
                let end = a + len as usize;
                pvm.flat_mem.get(a..end).map(|s| s.to_vec())
            }
            Backend::Recompiler(pvm) => pvm.read_bytes(addr, len),
            Backend::Compare { recomp, .. } => recomp.read_bytes(addr, len),
            Backend::Kernel(_) => None, // kernel uses DATA cap offsets
        }
    }

    pub fn write_bytes(&mut self, addr: u32, data: &[u8]) {
        match &mut self.inner {
            Backend::Interpreter(pvm) => {
                for (i, &byte) in data.iter().enumerate() {
                    pvm.write_u8(addr + i as u32, byte);
                }
            }
            Backend::Recompiler(pvm) => {
                pvm.write_bytes(addr, data);
            }
            Backend::Compare { interp, recomp, .. } => {
                for (i, &byte) in data.iter().enumerate() {
                    interp.write_u8(addr + i as u32, byte);
                }
                recomp.write_bytes(addr, data);
            }
            Backend::Kernel(_) => {} // kernel uses DATA cap offsets
        }
    }

    /// Try to write bytes; returns None on page fault (any non-writable byte).
    pub fn try_write_bytes(&mut self, addr: u32, data: &[u8]) -> Option<()> {
        match &mut self.inner {
            Backend::Interpreter(pvm) => {
                for (i, &byte) in data.iter().enumerate() {
                    if !pvm.write_u8(addr.wrapping_add(i as u32), byte) {
                        return None;
                    }
                }
                Some(())
            }
            Backend::Recompiler(pvm) => {
                if pvm.write_bytes(addr, data) {
                    Some(())
                } else {
                    None
                }
            }
            Backend::Compare { interp, recomp, .. } => {
                for (i, &byte) in data.iter().enumerate() {
                    if !interp.write_u8(addr.wrapping_add(i as u32), byte) {
                        return None;
                    }
                }
                if !recomp.write_bytes(addr, data) {
                    return None;
                }
                Some(())
            }
            Backend::Kernel(_) => None, // kernel uses DATA cap offsets
        }
    }

    /// Enable instruction trace collection.
    pub fn enable_tracing(&mut self) {
        match &mut self.inner {
            Backend::Interpreter(pvm) => pvm.tracing_enabled = true,
            Backend::Recompiler(_) | Backend::Kernel(_) => {}
            Backend::Compare { interp, .. } => {
                interp.tracing_enabled = true;
            }
        }
    }

    /// Dump code blob and bitmask to files for disassembly.
    pub fn dump_code(&self, code_path: &str, bitmask_path: &str) {
        match &self.inner {
            Backend::Interpreter(pvm) => {
                let _ = std::fs::write(code_path, &pvm.code);
                let _ = std::fs::write(bitmask_path, &pvm.bitmask);
            }
            Backend::Recompiler(_) | Backend::Kernel(_) => {}
            Backend::Compare { interp, .. } => {
                let _ = std::fs::write(code_path, &interp.code);
                let _ = std::fs::write(bitmask_path, &interp.bitmask);
            }
        }
    }

    /// Take the collected instruction trace.
    pub fn take_trace(&mut self) -> Vec<(u32, u8)> {
        match &mut self.inner {
            Backend::Interpreter(pvm) => std::mem::take(&mut pvm.pc_trace),
            Backend::Recompiler(_) | Backend::Kernel(_) => Vec::new(),
            Backend::Compare { interp, .. } => std::mem::take(&mut interp.pc_trace),
        }
    }
}
