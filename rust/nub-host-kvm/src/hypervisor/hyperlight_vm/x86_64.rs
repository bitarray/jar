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

use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use tracing::{Span, instrument};
use tracing_core::LevelFilter;

use super::*;
use crate::hypervisor::InterruptHandleImpl;
use crate::hypervisor::LinuxInterruptHandle;
use crate::hypervisor::regs::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
use crate::hypervisor::virtual_machine::VirtualMachine;
use crate::hypervisor::virtual_machine::kvm::KvmVm;
use crate::hypervisor::virtual_machine::{HypervisorType, VmError, get_available_hypervisor};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::RawPtr;
use crate::mem::shared_mem::{GuestSharedMemory, HostSharedMemory};
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::host_funcs::FunctionRegistry;
use crate::sandbox::snapshot::NextAction;

impl HyperlightVm {
    /// Create a new HyperlightVm instance (will not run vm until calling `initialise`)
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        snapshot_mem: SnapshotSharedMemory<GuestSharedMemory>,
        scratch_mem: GuestSharedMemory,
        root_pt_addr: u64,
        entrypoint: NextAction,
        rsp_gva: u64,
        _page_size: usize,
        config: &SandboxConfiguration,
    ) -> std::result::Result<Self, CreateHyperlightVmError> {
        type VmType = Box<dyn VirtualMachine>;

        let vm: VmType = match get_available_hypervisor() {
            Some(HypervisorType::Kvm) => {
                Box::new(KvmVm::new(config.get_vcpu_count()).map_err(VmError::CreateVm)?)
            }
            None => return Err(CreateHyperlightVmError::NoHypervisorFound),
        };

        vm.set_sregs(&CommonSpecialRegisters::standard_64bit_defaults(
            root_pt_addr,
        ))
        .map_err(VmError::Register)?;

        let interrupt_handle: Arc<dyn InterruptHandleImpl> = Arc::new(LinuxInterruptHandle {
            state: AtomicU8::new(0),
            #[cfg(all(
                target_arch = "x86_64",
                target_vendor = "unknown",
                target_os = "linux",
                target_env = "musl"
            ))]
            tid: AtomicU64::new(unsafe { libc::pthread_self() as u64 }),
            #[cfg(not(all(
                target_arch = "x86_64",
                target_vendor = "unknown",
                target_os = "linux",
                target_env = "musl"
            )))]
            tid: AtomicU64::new(unsafe { libc::pthread_self() }),
            retry_delay: config.get_interrupt_retry_delay(),
            sig_rt_min_offset: config.get_interrupt_vcpu_sigrtmin_offset(),
            dropped: AtomicBool::new(false),
        });

        let snapshot_slot = 0u32;
        let scratch_slot = 1u32;
        let mut ret = Self {
            vm,
            entrypoint,
            rsp_gva,
            interrupt_handle,

            snapshot_slot,
            snapshot_memory: None,
            snapshot_fixed_va: None,
            scratch_slot,
            scratch_memory: None,

            mmap_regions: Vec::new(),

            pending_tlb_flush: false,
        };

        ret.install_snapshot_mapping(snapshot_mem)?;
        ret.install_scratch_mapping(scratch_mem)?;

        Ok(ret)
    }

    /// Initialise the internally stored vCPU with the given PEB address and
    /// random number seed, then run it until a HLT instruction.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn initialise(
        &mut self,
        peb_addr: RawPtr,
        seed: u64,
        page_size: u32,
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
        host_funcs: &Arc<Mutex<FunctionRegistry>>,
        guest_max_log_level: Option<LevelFilter>,
    ) -> std::result::Result<(), InitializeError> {
        let NextAction::Initialise(initialise) = self.entrypoint else {
            return Ok(());
        };

        let regs = CommonRegisters {
            rip: initialise,
            // We usually keep the top of the stack 16-byte
            // aligned. However, the ABI requirement is that the stack
            // be aligned _before a call instruction_, which means
            // that the stack needs to actually be ≡ 8 mod 16 at the
            // first instruction (since, on x64, a call instruction
            // automatically pushes a return address).
            rsp: self.rsp_gva - 8,

            // function args
            rdi: peb_addr.into(),
            rsi: seed,
            rdx: page_size.into(),
            rcx: get_guest_log_filter(guest_max_log_level),
            rflags: 1 << 1,

            ..Default::default()
        };
        self.vm.set_regs(&regs)?;

        self.run(mem_mgr, host_funcs)
            .map_err(InitializeError::Run)?;

        let regs = self.vm.regs()?;
        // todo(portability): this is architecture-specific
        if !regs.rsp.is_multiple_of(16) {
            return Err(InitializeError::InvalidStackPointer(regs.rsp));
        }
        self.rsp_gva = regs.rsp;
        self.entrypoint = NextAction::Call(regs.rax);

        Ok(())
    }

    /// Dispatch a call from the host to the guest using the given pointer
    /// to the dispatch function _in the guest's address space_.
    ///
    /// Do this by setting the instruction pointer to `dispatch_func_addr`
    /// and then running the execution loop until a halt instruction.
    ///
    /// Returns `Ok` if the call succeeded, and an `Err` if it failed
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn dispatch_call_from_host(
        &mut self,
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
        host_funcs: &Arc<Mutex<FunctionRegistry>>,
    ) -> std::result::Result<(), DispatchGuestCallError> {
        let NextAction::Call(dispatch_func_addr) = self.entrypoint else {
            return Err(DispatchGuestCallError::Uninitialized);
        };
        let mut rflags = 1 << 1; // RFLAGS.1 is RES1
        if self.pending_tlb_flush {
            rflags |= 1 << 6; // set ZF if we need a tlb flush done before anything else executes
        }
        // set RIP and RSP, reset others
        let regs = CommonRegisters {
            rip: dispatch_func_addr,
            // We usually keep the top of the stack 16-byte
            // aligned. Since the usual ABI requirement is that the
            // stack be aligned _before a call instruction_, one might
            // expect that the stack pointer here needs to actually be
            // ≡ 8 mod 16 at the first instruction (since, on x64, a
            // call instruction automatically pushes a return
            // address).  However, the x64 entry stub in
            // hyperlight_guest::arch::dispatch handles this itself,
            // so we do use the aligned address here.
            rsp: self.rsp_gva,
            rflags,
            ..Default::default()
        };
        self.vm
            .set_regs(&regs)
            .map_err(DispatchGuestCallError::SetupRegs)?;

        // reset fpu
        self.vm
            .set_fpu(&CommonFpu::default())
            .map_err(DispatchGuestCallError::SetupRegs)?;

        let result = self
            .run(mem_mgr, host_funcs)
            .map_err(DispatchGuestCallError::Run);

        // Clear the TLB flush flag only after run() returns. The guest
        // may have been cancelled before it executed the flush.
        self.pending_tlb_flush = false;

        result
    }
}
