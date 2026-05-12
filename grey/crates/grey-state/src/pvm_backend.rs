//! PVM backend — capability-based kernel.
//!
//! All blobs use the JAR capability manifest format.

use javm::Gas;

pub use javm::ExitReason;

/// PVM instance backed by the capability-based kernel.
pub struct PvmInstance {
    kernel: Box<javm::kernel::InvocationKernel>,
}

impl PvmInstance {
    /// Create a PVM from a code blob, arguments, and gas budget.
    pub fn initialize(code_blob: &[u8], args: &[u8], gas: Gas) -> Option<Self> {
        match javm::kernel::InvocationKernel::new(code_blob, args, gas) {
            Ok(kernel) => Some(PvmInstance {
                kernel: Box::new(kernel),
            }),
            Err(e) => {
                tracing::warn!("kernel init failed: {e}");
                None
            }
        }
    }

    /// Check if this is a kernel backend. Always true.
    pub fn is_kernel(&self) -> bool {
        true
    }

    /// Access the kernel.
    pub fn kernel(&self) -> Option<&javm::kernel::InvocationKernel> {
        Some(&self.kernel)
    }

    /// Mutable access to the kernel.
    pub fn kernel_mut(&mut self) -> Option<&mut javm::kernel::InvocationKernel> {
        Some(&mut self.kernel)
    }

    /// Run kernel until protocol call or termination.
    pub fn kernel_run(&mut self) -> javm::kernel::KernelResult {
        self.kernel.run()
    }

    /// Read from a DATA cap in the kernel's active VM.
    pub fn kernel_read_data(&self, cap_idx: u8, offset: u32, len: u32) -> Option<Vec<u8>> {
        self.kernel.read_data_cap(cap_idx, offset, len)
    }

    /// Write to a DATA cap in the kernel's active VM.
    pub fn kernel_write_data(&mut self, cap_idx: u8, offset: u32, data: &[u8]) -> bool {
        self.kernel.write_data_cap(cap_idx, offset, data)
    }

    /// Resume kernel after a protocol call was handled by the host.
    pub fn kernel_resume(&mut self, result0: u64, result1: u64) {
        self.kernel.resume_protocol_call(result0, result1);
    }

    /// Return the active VM's current gas budget.
    pub fn gas(&self) -> Gas {
        self.kernel.active_gas()
    }

    /// Set the active VM's gas budget.
    pub fn set_gas(&mut self, gas: Gas) {
        self.kernel
            .vm_arena
            .vm_mut(self.kernel.active_vm)
            .set_gas(gas);
    }

    /// Read a register. Routes through live_ctx when the recompiler is active,
    /// so it returns the current JitContext value (not stale VmInstance state).
    pub fn reg(&self, index: usize) -> u64 {
        self.kernel.active_reg(index)
    }

    /// Write a register. Routes through live_ctx when the recompiler is active.
    pub fn set_reg(&mut self, index: usize, value: u64) {
        self.kernel.set_active_reg(index, value);
    }
}
