/*
Copyright 2025 The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

use std::fmt::Debug;
use std::sync::OnceLock;

use tracing::{Span, instrument};

use crate::hypervisor::regs::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
use crate::mem::memory_region::MemoryRegion;

/// KVM (Kernel-based Virtual Machine) functionality (linux)
#[cfg(kvm)]
pub(crate) mod kvm;

static AVAILABLE_HYPERVISOR: OnceLock<Option<HypervisorType>> = OnceLock::new();

/// Returns which type of hypervisor is available, if any
pub fn get_available_hypervisor() -> &'static Option<HypervisorType> {
    AVAILABLE_HYPERVISOR.get_or_init(|| {
        #[cfg(kvm)]
        {
            if kvm::is_hypervisor_present() {
                Some(HypervisorType::Kvm)
            } else {
                None
            }
        }
        #[cfg(not(kvm))]
        {
            None
        }
    })
}

/// Returns `true` if a suitable hypervisor is available.
/// If this returns `false`, no hypervisor-backed sandboxes can be created.
#[instrument(skip_all, parent = Span::current())]
pub fn is_hypervisor_present() -> bool {
    get_available_hypervisor().is_some()
}

/// The hypervisor types available for the current platform
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub(crate) enum HypervisorType {
    #[cfg(kvm)]
    Kvm,
}

// Compiler error if the kvm feature is disabled — there is no other hypervisor backend.
#[cfg(not(kvm))]
compile_error!(
    "No hypervisor type is available for the current platform. Please enable the `kvm` cargo feature."
);

/// The various reasons a VM's vCPU can exit
pub(crate) enum VmExit {
    /// The vCPU has halted
    Halt(),
    /// The vCPU has issued a write to the given port with the given value
    IoOut(u16, Vec<u8>),
    /// The vCPU tried to read from the given (unmapped) addr
    MmioRead(u64),
    /// The vCPU tried to write to the given (unmapped) addr
    MmioWrite(u64),
    /// The vCPU execution has been cancelled
    Cancelled(),
    /// The vCPU has exited for a reason that is not handled by Hyperlight
    Unknown(String),
    /// The operation should be retried, for example this can happen on Linux where a call to run the CPU can return EAGAIN
    Retry(),
}

/// Stable index of a vCPU in the VM's fixed vCPU pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct VcpuLane(usize);

impl VcpuLane {
    /// The legacy control lane used by the existing host dispatch path.
    pub(crate) const PRIMARY: Self = Self(0);

    pub(crate) fn new(index: usize) -> Self {
        Self(index)
    }

    pub(crate) fn index(self) -> usize {
        self.0
    }
}

/// VM error
#[derive(Debug, Clone, thiserror::Error)]
pub enum VmError {
    #[error("Failed to create vm: {0}")]
    CreateVm(#[from] CreateVmError),
    #[error("Map memory operation failed: {0}")]
    MapMemory(#[from] MapMemoryError),
    #[error("Register operation failed: {0}")]
    Register(#[from] RegisterError),
    #[error("Failed to run vcpu: {0}")]
    RunVcpu(#[from] RunVcpuError),
    #[error("Unmap memory operation failed: {0}")]
    UnmapMemory(#[from] UnmapMemoryError),
}

/// Create VM error
#[derive(Debug, Clone, thiserror::Error)]
pub enum CreateVmError {
    #[error("VCPU creation failed: {0}")]
    CreateVcpuFd(HypervisorError),
    #[error("VM creation failed: {0}")]
    CreateVmFd(HypervisorError),
    #[error("Hypervisor is not available: {0}")]
    HypervisorNotAvailable(HypervisorError),
    #[error("Initialize VM failed: {0}")]
    InitializeVm(HypervisorError),
    #[error("Set Partition Property failed: {0}")]
    SetPartitionProperty(HypervisorError),
}

/// RunVCPU error
#[derive(Debug, Clone, thiserror::Error)]
pub enum RunVcpuError {
    #[error("Invalid vCPU lane: {0}")]
    InvalidVcpuLane(usize),
    #[error("vCPU lane lock poisoned: {0}")]
    VcpuLanePoisoned(usize),
    #[error("Failed to decode message type: {0}")]
    DecodeIOMessage(u32),
    #[error("Increment RIP failed: {0}")]
    IncrementRip(HypervisorError),
    #[error("Parse GPA access info failed")]
    ParseGpaAccessInfo,
    #[error("Unknown error: {0}")]
    Unknown(HypervisorError),
}

/// Register error
#[derive(Debug, Clone, thiserror::Error)]
pub enum RegisterError {
    #[error("Invalid vCPU lane: {0}")]
    InvalidVcpuLane(usize),
    #[error("vCPU lane lock poisoned: {0}")]
    VcpuLanePoisoned(usize),
    #[error("Failed to get registers: {0}")]
    GetRegs(HypervisorError),
    #[error("Failed to set registers: {0}")]
    SetRegs(HypervisorError),
    #[error("Failed to set FPU registers: {0}")]
    SetFpu(HypervisorError),
    #[error("Failed to set special registers: {0}")]
    SetSregs(HypervisorError),
}

/// Map memory error
#[derive(Debug, Clone, thiserror::Error)]
pub enum MapMemoryError {
    #[error("Hypervisor error: {0}")]
    Hypervisor(HypervisorError),
}

/// Unmap memory error
#[derive(Debug, Clone, thiserror::Error)]
pub enum UnmapMemoryError {
    #[error("Hypervisor error: {0}")]
    Hypervisor(HypervisorError),
}

/// Implementation-specific Hypervisor error
#[derive(Debug, Clone, thiserror::Error)]
pub enum HypervisorError {
    #[cfg(kvm)]
    #[error("KVM error: {0}")]
    KvmError(#[from] kvm_ioctls::Error),
}

/// Common interface for a VM with a fixed vCPU pool.
pub(crate) trait VirtualMachine: Debug + Send + Sync {
    /// Map memory region into this VM
    ///
    /// # Safety
    /// The caller must ensure that the memory region is valid and points to valid memory,
    /// and lives long enough for the VM to use it.
    /// The caller must ensure that the given u32 is not already mapped, otherwise previously mapped
    /// memory regions may be overwritten.
    /// The memory region must not overlap with an existing region, and depending on platform, must be aligned to page boundaries.
    unsafe fn map_memory(
        &mut self,
        region: (u32, &MemoryRegion),
    ) -> std::result::Result<(), MapMemoryError>;

    /// Number of vCPU lanes created for this VM.
    fn vcpu_count(&self) -> usize;

    /// Runs the selected vCPU until it exits.
    /// Note: this function emits traces spans for guests;
    /// the span setup is called right before the KVM run-vcpu ioctl.
    fn run_vcpu_on(&self, lane: VcpuLane) -> std::result::Result<VmExit, RunVcpuError>;

    /// Runs the primary control vCPU until it exits.
    fn run_vcpu(&self) -> std::result::Result<VmExit, RunVcpuError> {
        self.run_vcpu_on(VcpuLane::PRIMARY)
    }

    /// Get regs
    fn regs_on(&self, lane: VcpuLane) -> std::result::Result<CommonRegisters, RegisterError>;

    /// Get regs on the primary control vCPU.
    fn regs(&self) -> std::result::Result<CommonRegisters, RegisterError> {
        self.regs_on(VcpuLane::PRIMARY)
    }

    /// Set regs
    fn set_regs_on(
        &self,
        lane: VcpuLane,
        regs: &CommonRegisters,
    ) -> std::result::Result<(), RegisterError>;

    /// Set regs on the primary control vCPU.
    fn set_regs(&self, regs: &CommonRegisters) -> std::result::Result<(), RegisterError> {
        self.set_regs_on(VcpuLane::PRIMARY, regs)
    }

    /// Set fpu regs
    fn set_fpu_on(&self, lane: VcpuLane, fpu: &CommonFpu)
    -> std::result::Result<(), RegisterError>;

    /// Set fpu regs on the primary control vCPU.
    fn set_fpu(&self, fpu: &CommonFpu) -> std::result::Result<(), RegisterError> {
        self.set_fpu_on(VcpuLane::PRIMARY, fpu)
    }

    /// Set special regs
    fn set_sregs_on(
        &self,
        lane: VcpuLane,
        sregs: &CommonSpecialRegisters,
    ) -> std::result::Result<(), RegisterError>;

    /// Set special regs on the primary control vCPU.
    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> std::result::Result<(), RegisterError> {
        self.set_sregs_on(VcpuLane::PRIMARY, sregs)
    }

    /// Get special regs
    fn sregs_on(
        &self,
        lane: VcpuLane,
    ) -> std::result::Result<CommonSpecialRegisters, RegisterError>;

    /// Get special regs on the primary control vCPU.
    fn sregs(&self) -> std::result::Result<CommonSpecialRegisters, RegisterError> {
        self.sregs_on(VcpuLane::PRIMARY)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(kvm)]
    fn is_hypervisor_present() {
        use std::path::Path;
        assert_eq!(
            Path::new("/dev/kvm").exists(),
            super::is_hypervisor_present()
        );
    }
}
