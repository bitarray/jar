//! PVM backend — thin wrapper around grey-pvm.
//!
//! Exposes `PvmInstance` and `ExitReason` for use by the accumulate
//! sub-transition, implemented directly from the Gray Paper (Appendix A).
//!
//! Supports three backends selectable via the `GREY_PVM` environment variable:
//! - `interpreter` (default): the standard PVM interpreter
//! - `recompiler`: AOT-compiled native x86-64 execution
//! - `compare`: runs both and compares at each host-call boundary

use grey_types::Gas;

pub use grey_pvm::ExitReason;

/// Check once whether the recompiler backend is requested.
fn pvm_mode() -> &'static str {
    static MODE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    MODE.get_or_init(|| {
        std::env::var("GREY_PVM").unwrap_or_else(|_| "interpreter".to_string())
    })
}

/// Backend-agnostic PVM instance.
enum Backend {
    Interpreter(grey_pvm::vm::Pvm),
    Recompiler(grey_pvm::RecompiledPvm),
    Compare {
        interp: grey_pvm::vm::Pvm,
        recomp: grey_pvm::RecompiledPvm,
        step: u32,
    },
}

/// PVM instance backed by either the interpreter or recompiler.
pub struct PvmInstance {
    inner: Backend,
}

impl PvmInstance {
    /// Create a PVM from a code blob, arguments, and gas budget.
    pub fn initialize(code_blob: &[u8], args: &[u8], gas: Gas) -> Option<Self> {
        match pvm_mode() {
            "recompiler" => {
                grey_pvm::recompiler::initialize_program_recompiled(code_blob, args, gas)
                    .map(|pvm| PvmInstance { inner: Backend::Recompiler(pvm) })
            }
            "compare" => {
                let interp = grey_pvm::program::initialize_program(code_blob, args, gas)?;
                let recomp = grey_pvm::recompiler::initialize_program_recompiled(code_blob, args, gas)?;
                Some(PvmInstance {
                    inner: Backend::Compare { interp, recomp, step: 0 },
                })
            }
            _ => {
                grey_pvm::program::initialize_program(code_blob, args, gas)
                    .map(|pvm| PvmInstance { inner: Backend::Interpreter(pvm) })
            }
        }
    }

    /// Run until exit (halt, panic, OOG, page fault, or host call).
    pub fn run(&mut self) -> ExitReason {
        match &mut self.inner {
            Backend::Interpreter(pvm) => {
                let (reason, _) = pvm.run();
                reason
            }
            Backend::Recompiler(pvm) => pvm.run(),
            Backend::Compare { interp, recomp, step } => {
                *step += 1;
                let s = *step;

                // Per-instruction comparison to find exact divergence point
                let mut instr = 0u32;
                loop {
                    instr += 1;
                    // Save current gas, set to 1 for single instruction
                    let ig = interp.gas;
                    let rg = recomp.gas();
                    interp.gas = 1;
                    recomp.set_gas(1);
                    let (ie, _) = interp.run();
                    let re = recomp.run();
                    // Restore gas: subtract what was consumed (1 - remaining)
                    let ig_after = ig.saturating_sub(1u64.saturating_sub(interp.gas));
                    let rg_after = rg.saturating_sub(1u64.saturating_sub(recomp.gas()));
                    interp.gas = ig_after;
                    recomp.set_gas(rg_after);

                    // Check for register or exit mismatch
                    let mut mismatch = false;
                    for i in 0..13 {
                        if interp.registers[i] != recomp.registers()[i] {
                            tracing::error!(
                                "COMPARE step {} instr {}: REG[{}] MISMATCH interp=0x{:x} recomp=0x{:x} pc_i={} pc_r={}",
                                s, instr, i, interp.registers[i], recomp.registers()[i], interp.pc, recomp.pc()
                            );
                            mismatch = true;
                        }
                    }
                    if interp.pc != recomp.pc() {
                        tracing::error!(
                            "COMPARE step {} instr {}: PC MISMATCH interp={} recomp={}",
                            s, instr, interp.pc, recomp.pc()
                        );
                        mismatch = true;
                    }
                    if ie != re {
                        tracing::error!(
                            "COMPARE step {} instr {}: EXIT MISMATCH interp={:?} recomp={:?} pc_i={} pc_r={}",
                            s, instr, ie, re, interp.pc, recomp.pc()
                        );
                        mismatch = true;
                    }
                    if mismatch {
                        // Return recompiler's result on divergence
                        return re;
                    }
                    // Both exited the same way
                    match ie {
                        ExitReason::OutOfGas => {
                            // Normal: ran one instruction, gas was 1 → 0 → OOG. Continue.
                            continue;
                        }
                        _ => {
                            // Real exit (host call, halt, etc.)
                            return re;
                        }
                    }
                }
            }
        }
    }

    pub fn gas(&self) -> Gas {
        match &self.inner {
            Backend::Interpreter(pvm) => pvm.gas,
            Backend::Recompiler(pvm) => pvm.gas(),
            Backend::Compare { recomp, .. } => recomp.gas(),
        }
    }
    pub fn set_gas(&mut self, gas: Gas) {
        match &mut self.inner {
            Backend::Interpreter(pvm) => pvm.gas = gas,
            Backend::Recompiler(pvm) => pvm.set_gas(gas),
            Backend::Compare { interp, recomp, .. } => {
                // Apply the same delta to both backends to preserve their
                // independent gas tracking (they may differ due to gas metering).
                let delta = gas as i64 - recomp.gas() as i64;
                interp.gas = (interp.gas as i64 + delta) as u64;
                recomp.set_gas(gas);
            }
        }
    }

    pub fn pc(&self) -> u32 {
        match &self.inner {
            Backend::Interpreter(pvm) => pvm.pc,
            Backend::Recompiler(pvm) => pvm.pc(),
            Backend::Compare { recomp, .. } => recomp.pc(),
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
        }
    }

    pub fn reg(&self, index: usize) -> u64 {
        match &self.inner {
            Backend::Interpreter(pvm) => pvm.registers[index],
            Backend::Recompiler(pvm) => pvm.registers()[index],
            Backend::Compare { recomp, .. } => recomp.registers()[index],
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
        }
    }

    pub fn read_byte(&self, addr: u32) -> Option<u8> {
        match &self.inner {
            Backend::Interpreter(pvm) => pvm.memory.read_u8(addr),
            Backend::Recompiler(pvm) => pvm.memory().read_u8(addr),
            Backend::Compare { recomp, .. } => recomp.memory().read_u8(addr),
        }
    }

    pub fn write_byte(&mut self, addr: u32, value: u8) {
        match &mut self.inner {
            Backend::Interpreter(pvm) => { pvm.memory.write_u8(addr, value); }
            Backend::Recompiler(pvm) => { pvm.memory_mut().write_u8(addr, value); }
            Backend::Compare { interp, recomp, .. } => {
                interp.memory.write_u8(addr, value);
                recomp.memory_mut().write_u8(addr, value);
            }
        }
    }

    pub fn read_bytes(&self, addr: u32, len: u32) -> Vec<u8> {
        match &self.inner {
            Backend::Interpreter(pvm) => {
                (0..len)
                    .map(|i| pvm.memory.read_u8(addr + i).unwrap_or(0))
                    .collect()
            }
            Backend::Recompiler(pvm) => {
                (0..len)
                    .map(|i| pvm.memory().read_u8(addr + i).unwrap_or(0))
                    .collect()
            }
            Backend::Compare { recomp, .. } => {
                (0..len)
                    .map(|i| recomp.memory().read_u8(addr + i).unwrap_or(0))
                    .collect()
            }
        }
    }

    /// Try to read bytes; returns None on page fault (any inaccessible byte).
    pub fn try_read_bytes(&self, addr: u32, len: u32) -> Option<Vec<u8>> {
        match &self.inner {
            Backend::Interpreter(pvm) => pvm.memory.read_bytes(addr, len),
            Backend::Recompiler(pvm) => pvm.memory().read_bytes(addr, len),
            Backend::Compare { recomp, .. } => recomp.memory().read_bytes(addr, len),
        }
    }

    pub fn write_bytes(&mut self, addr: u32, data: &[u8]) {
        match &mut self.inner {
            Backend::Interpreter(pvm) => {
                for (i, &byte) in data.iter().enumerate() {
                    pvm.memory.write_u8(addr + i as u32, byte);
                }
            }
            Backend::Recompiler(pvm) => {
                for (i, &byte) in data.iter().enumerate() {
                    pvm.memory_mut().write_u8(addr + i as u32, byte);
                }
            }
            Backend::Compare { interp, recomp, .. } => {
                for (i, &byte) in data.iter().enumerate() {
                    interp.memory.write_u8(addr + i as u32, byte);
                    recomp.memory_mut().write_u8(addr + i as u32, byte);
                }
            }
        }
    }

    /// Try to write bytes; returns None on page fault (any non-writable byte).
    pub fn try_write_bytes(&mut self, addr: u32, data: &[u8]) -> Option<()> {
        use grey_pvm::memory::MemoryAccess;
        match &mut self.inner {
            Backend::Interpreter(pvm) => {
                for (i, &byte) in data.iter().enumerate() {
                    match pvm.memory.write_u8(addr.wrapping_add(i as u32), byte) {
                        MemoryAccess::Ok => {}
                        MemoryAccess::PageFault(_) => return None,
                    }
                }
                Some(())
            }
            Backend::Recompiler(pvm) => {
                for (i, &byte) in data.iter().enumerate() {
                    match pvm.memory_mut().write_u8(addr.wrapping_add(i as u32), byte) {
                        MemoryAccess::Ok => {}
                        MemoryAccess::PageFault(_) => return None,
                    }
                }
                Some(())
            }
            Backend::Compare { interp, recomp, .. } => {
                for (i, &byte) in data.iter().enumerate() {
                    let addr_i = addr.wrapping_add(i as u32);
                    let r1 = interp.memory.write_u8(addr_i, byte);
                    let r2 = recomp.memory_mut().write_u8(addr_i, byte);
                    match (r1, r2) {
                        (MemoryAccess::Ok, MemoryAccess::Ok) => {}
                        (MemoryAccess::PageFault(_), _) | (_, MemoryAccess::PageFault(_)) => return None,
                    }
                }
                Some(())
            }
        }
    }

    /// Enable instruction trace collection.
    pub fn enable_tracing(&mut self) {
        match &mut self.inner {
            Backend::Interpreter(pvm) => pvm.tracing_enabled = true,
            Backend::Recompiler(_) => {
                // Intentional: instruction tracing is interpreter-only.
                // The recompiler compiles basic blocks to native x86-64 code,
                // so per-instruction tracing is not available. Use the
                // interpreter backend or compare mode for trace collection.
            }
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
            Backend::Recompiler(_) => {
                // Not easily accessible in recompiler
            }
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
            Backend::Recompiler(_) => Vec::new(),
            Backend::Compare { interp, .. } => std::mem::take(&mut interp.pc_trace),
        }
    }
}
