/*
Copyright 2025  The Hyperlight Authors.

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

use std::sync::LazyLock;

use kvm_bindings::{kvm_fpu, kvm_regs, kvm_sregs, kvm_userspace_memory_region};
use kvm_ioctls::Cap::UserMemory;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use nub_host_common::outb::VmAction;
use tracing::{Span, instrument};

use crate::hypervisor::regs::{
    CommonDebugRegs, CommonFpu, CommonRegisters, CommonSpecialRegisters,
};
use crate::hypervisor::virtual_machine::{
    CreateVmError, MapMemoryError, RegisterError, RunVcpuError, VirtualMachine, VmExit,
};
use crate::mem::memory_region::MemoryRegion;

/// On KVM x86-64 only, we have to set this in order to set the guest
/// physical address width.
///
/// The requirement to set this to configure the guest physical
/// address width for KVM is not well documented, but see e.g. Linux
/// v6.18.6 arch/x86/kvm/cpuid.c:kvm_vcpu_after_set_cpuid()
/// (https://elixir.bootlin.com/linux/v6.18.6/source/arch/x86/kvm/cpuid.c#L444)
/// for how it is processed.
///
/// For the architectural definition and format of the system register:
/// See AMD64 Architecture Programmer's Manual, Volume 3: General-Purpose and
///                                                       System Instructions
///     Appendix E: Obtaining Processor Information Via the CPUID Instruction
///         E.4.7: Function 8000_0008h---Processor Capacity Parameters and
///                Extended Feature Identification, pp. 627--628
const CPUID_FUNCTION_PROCESSOR_CAPACITY_PARAMETERS_AND_EXTENDED_FEATURE_IDENTIFICATION: u32 =
    0x8000_0008;

/// Return `true` if the KVM API is available, version 12, and has UserMemory capability, or `false` otherwise
#[instrument(skip_all, parent = Span::current(), level = "Trace")]
pub(crate) fn is_hypervisor_present() -> bool {
    if let Ok(kvm) = Kvm::new() {
        let api_version = kvm.get_api_version();
        match api_version {
            version if version == 12 && kvm.check_extension(UserMemory) => true,
            12 => {
                tracing::info!("KVM does not have KVM_CAP_USER_MEMORY capability");
                false
            }
            version => {
                tracing::info!("KVM GET_API_VERSION returned {}, expected 12", version);
                false
            }
        }
    } else {
        tracing::info!("KVM is not available on this system");
        false
    }
}

/// A KVM implementation of a single-vcpu VM
#[derive(Debug)]
pub(crate) struct KvmVm {
    vm_fd: VmFd,
    vcpu_fd: VcpuFd,
}

static KVM: LazyLock<std::result::Result<Kvm, CreateVmError>> =
    LazyLock::new(|| Kvm::new().map_err(|e| CreateVmError::HypervisorNotAvailable(e.into())));

impl KvmVm {
    /// Create a new instance of a `KvmVm`
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn new() -> std::result::Result<Self, CreateVmError> {
        let hv = KVM.as_ref().map_err(|e| e.clone())?;

        let vm_fd = hv
            .create_vm_with_type(0)
            .map_err(|e| CreateVmError::CreateVmFd(e.into()))?;

        let vcpu_fd = vm_fd
            .create_vcpu(0)
            .map_err(|e| CreateVmError::CreateVcpuFd(e.into()))?;

        // Set the CPUID leaf for MaxPhysAddr. KVM allows this to
        // easily be overridden by the hypervisor and defaults it very
        // low.
        let mut kvm_cpuid = hv
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .map_err(|e| CreateVmError::InitializeVm(e.into()))?;
        for entry in kvm_cpuid.as_mut_slice().iter_mut() {
            if entry.function
                == CPUID_FUNCTION_PROCESSOR_CAPACITY_PARAMETERS_AND_EXTENDED_FEATURE_IDENTIFICATION
            {
                entry.eax &= !0xff;
                entry.eax |= nub_host_common::layout::MAX_GPA.ilog2() + 1;
            }
        }
        vcpu_fd
            .set_cpuid2(&kvm_cpuid)
            .map_err(|e| CreateVmError::InitializeVm(e.into()))?;

        Ok(Self { vm_fd, vcpu_fd })
    }

    /// Run the vCPU once without hardware interrupt support (default path).
    fn run_vcpu_default(&mut self) -> std::result::Result<VmExit, RunVcpuError> {
        match self.vcpu_fd.run() {
            Ok(VcpuExit::Hlt) => Ok(VmExit::Halt()),
            Ok(VcpuExit::IoOut(port, _)) if port == VmAction::Halt as u16 => Ok(VmExit::Halt()),
            Ok(VcpuExit::IoOut(port, data)) => Ok(VmExit::IoOut(port, data.to_vec())),
            Ok(VcpuExit::MmioRead(addr, _)) => Ok(VmExit::MmioRead(addr)),
            Ok(VcpuExit::MmioWrite(addr, _)) => Ok(VmExit::MmioWrite(addr)),
            Err(e) => match e.errno() {
                // InterruptHandle::kill() sends a signal (SIGRTMIN+offset) to interrupt the vcpu, which causes EINTR
                libc::EINTR => Ok(VmExit::Cancelled()),
                libc::EAGAIN => Ok(VmExit::Retry()),
                _ => Err(RunVcpuError::Unknown(e.into())),
            },
            Ok(other) => Ok(VmExit::Unknown(format!(
                "Unknown KVM VCPU exit: {:?}",
                other
            ))),
        }
    }
}

impl VirtualMachine for KvmVm {
    unsafe fn map_memory(
        &mut self,
        (slot, region): (u32, &MemoryRegion),
    ) -> std::result::Result<(), MapMemoryError> {
        let mut kvm_region: kvm_userspace_memory_region = region.into();
        kvm_region.slot = slot;
        unsafe { self.vm_fd.set_user_memory_region(kvm_region) }
            .map_err(|e| MapMemoryError::Hypervisor(e.into()))
    }

    fn run_vcpu(&mut self) -> std::result::Result<VmExit, RunVcpuError> {
        self.run_vcpu_default()
    }

    fn regs(&self) -> std::result::Result<CommonRegisters, RegisterError> {
        let kvm_regs = self
            .vcpu_fd
            .get_regs()
            .map_err(|e| RegisterError::GetRegs(e.into()))?;
        Ok((&kvm_regs).into())
    }

    fn set_regs(&self, regs: &CommonRegisters) -> std::result::Result<(), RegisterError> {
        let kvm_regs: kvm_regs = regs.into();
        self.vcpu_fd
            .set_regs(&kvm_regs)
            .map_err(|e| RegisterError::SetRegs(e.into()))?;
        Ok(())
    }

    fn fpu(&self) -> std::result::Result<CommonFpu, RegisterError> {
        // Note: On KVM this ignores MXCSR.
        // See https://github.com/torvalds/linux/blob/d358e5254674b70f34c847715ca509e46eb81e6f/arch/x86/kvm/x86.c#L12554-L12599
        let kvm_fpu = self
            .vcpu_fd
            .get_fpu()
            .map_err(|e| RegisterError::GetFpu(e.into()))?;
        Ok((&kvm_fpu).into())
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> std::result::Result<(), RegisterError> {
        let kvm_fpu: kvm_fpu = fpu.into();
        // Note: On KVM this ignores MXCSR.
        // See https://github.com/torvalds/linux/blob/d358e5254674b70f34c847715ca509e46eb81e6f/arch/x86/kvm/x86.c#L12554-L12599
        self.vcpu_fd
            .set_fpu(&kvm_fpu)
            .map_err(|e| RegisterError::SetFpu(e.into()))?;
        Ok(())
    }

    fn sregs(&self) -> std::result::Result<CommonSpecialRegisters, RegisterError> {
        let kvm_sregs = self
            .vcpu_fd
            .get_sregs()
            .map_err(|e| RegisterError::GetSregs(e.into()))?;
        Ok((&kvm_sregs).into())
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> std::result::Result<(), RegisterError> {
        let kvm_sregs: kvm_sregs = sregs.into();
        self.vcpu_fd
            .set_sregs(&kvm_sregs)
            .map_err(|e| RegisterError::SetSregs(e.into()))?;
        Ok(())
    }

    fn debug_regs(&self) -> std::result::Result<CommonDebugRegs, RegisterError> {
        let kvm_debug_regs = self
            .vcpu_fd
            .get_debug_regs()
            .map_err(|e| RegisterError::GetDebugRegs(e.into()))?;
        Ok(kvm_debug_regs.into())
    }

    #[allow(dead_code)]
    fn xsave(&self) -> std::result::Result<Vec<u8>, RegisterError> {
        let xsave = self
            .vcpu_fd
            .get_xsave()
            .map_err(|e| RegisterError::GetXsave(e.into()))?;
        Ok(xsave
            .region
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect())
    }
}
