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

#[cfg(gdb)]
use std::collections::HashMap;
#[cfg(crashdump)]
use std::path::Path;
#[cfg(any(kvm, mshv3))]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU8;
#[cfg(any(kvm, mshv3))]
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use tracing::{Span, instrument};
use tracing_core::LevelFilter;

use super::*;
use crate::hypervisor::InterruptHandleImpl;
#[cfg(any(kvm, mshv3))]
use crate::hypervisor::LinuxInterruptHandle;
#[cfg(crashdump)]
use crate::hypervisor::crashdump;
#[cfg(gdb)]
use crate::hypervisor::gdb::{
    DebugCommChannel, DebugMsg, DebugResponse, DebuggableVm, VcpuStopReason,
};
#[cfg(gdb)]
use crate::hypervisor::gdb::{DebugError, DebugMemoryAccessError};
use crate::hypervisor::regs::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
#[cfg(not(gdb))]
use crate::hypervisor::virtual_machine::VirtualMachine;
#[cfg(kvm)]
use crate::hypervisor::virtual_machine::kvm::KvmVm;
#[cfg(mshv3)]
use crate::hypervisor::virtual_machine::mshv::MshvVm;
#[cfg(target_os = "windows")]
use crate::hypervisor::virtual_machine::whp::WhpVm;
use crate::hypervisor::virtual_machine::{HypervisorType, VmError, get_available_hypervisor};
#[cfg(target_os = "windows")]
use crate::hypervisor::{PartitionState, WindowsInterruptHandle};
#[cfg(crashdump)]
use crate::mem::memory_region::MemoryRegion;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::RawPtr;
use crate::mem::shared_mem::{GuestSharedMemory, HostSharedMemory};
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::host_funcs::FunctionRegistry;
use crate::sandbox::snapshot::NextAction;
#[cfg(feature = "mem_profile")]
use crate::sandbox::trace::MemTraceInfo;
#[cfg(crashdump)]
use crate::sandbox::uninitialized::SandboxRuntimeConfig;

impl HyperlightVm {
    /// Create a new HyperlightVm instance (will not run vm until calling `initialise`)
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        snapshot_mem: SnapshotSharedMemory<GuestSharedMemory>,
        scratch_mem: GuestSharedMemory,
        _root_pt_addr: u64,
        entrypoint: NextAction,
        rsp_gva: u64,
        _page_size: usize,
        #[cfg_attr(target_os = "windows", allow(unused_variables))] config: &SandboxConfiguration,
        #[cfg(gdb)] gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
        #[cfg(crashdump)] rt_cfg: SandboxRuntimeConfig,
        #[cfg(feature = "mem_profile")] trace_info: MemTraceInfo,
    ) -> std::result::Result<Self, CreateHyperlightVmError> {
        #[cfg(gdb)]
        type VmType = Box<dyn DebuggableVm>;
        #[cfg(not(gdb))]
        type VmType = Box<dyn VirtualMachine>;

        let vm: VmType = match get_available_hypervisor() {
            #[cfg(kvm)]
            Some(HypervisorType::Kvm) => Box::new(KvmVm::new().map_err(VmError::CreateVm)?),
            #[cfg(mshv3)]
            Some(HypervisorType::Mshv) => Box::new(MshvVm::new().map_err(VmError::CreateVm)?),
            #[cfg(target_os = "windows")]
            Some(HypervisorType::Whp) => Box::new(WhpVm::new().map_err(VmError::CreateVm)?),
            None => return Err(CreateHyperlightVmError::NoHypervisorFound),
        };

        #[cfg(not(feature = "i686-guest"))]
        vm.set_sregs(&CommonSpecialRegisters::standard_64bit_defaults(
            _root_pt_addr,
        ))
        .map_err(VmError::Register)?;
        #[cfg(feature = "i686-guest")]
        vm.set_sregs(&CommonSpecialRegisters::standard_32bit_paging_defaults(
            _root_pt_addr,
        ))
        .map_err(VmError::Register)?;

        #[cfg(any(kvm, mshv3))]
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

        #[cfg(target_os = "windows")]
        let interrupt_handle: Arc<dyn InterruptHandleImpl> = Arc::new(WindowsInterruptHandle {
            state: AtomicU8::new(0),
            partition_state: std::sync::RwLock::new(PartitionState {
                handle: vm.partition_handle(),
                dropped: false,
            }),
        });

        let snapshot_slot = 0u32;
        let scratch_slot = 1u32;
        #[cfg_attr(not(gdb), allow(unused_mut))]
        let mut ret = Self {
            vm,
            entrypoint,
            rsp_gva,
            interrupt_handle,

            snapshot_slot,
            snapshot_memory: None,
            scratch_slot,
            scratch_memory: None,

            mmap_regions: Vec::new(),

            pending_tlb_flush: false,

            #[cfg(gdb)]
            gdb_conn,
            #[cfg(gdb)]
            sw_breakpoints: HashMap::new(),
            #[cfg(feature = "mem_profile")]
            trace_info,
            #[cfg(crashdump)]
            rt_cfg,
        };

        ret.install_snapshot_mapping(snapshot_mem)?;
        ret.install_scratch_mapping(scratch_mem)?;

        // Send the interrupt handle to the GDB thread if debugging is enabled
        // This is used to allow the GDB thread to stop the vCPU
        #[cfg(gdb)]
        if ret.gdb_conn.is_some() {
            ret.send_dbg_msg(DebugResponse::InterruptHandle(ret.interrupt_handle.clone()))?;
            // Add breakpoint to the entry point address, if we are going to initialise
            ret.vm.set_debug(true).map_err(VmError::Debug)?;
            if let NextAction::Initialise(initialise) = entrypoint {
                ret.vm
                    .add_hw_breakpoint(initialise)
                    .map_err(CreateHyperlightVmError::AddHwBreakpoint)?;
            }
        }

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
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
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

        self.run(
            mem_mgr,
            host_funcs,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )
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
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
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
            .run(
                mem_mgr,
                host_funcs,
                #[cfg(gdb)]
                dbg_mem_access_fn,
            )
            .map_err(DispatchGuestCallError::Run);

        // Clear the TLB flush flag only after run() returns. The guest
        // may have been cancelled before it executed the flush.
        self.pending_tlb_flush = false;

        result
    }

    // Handle a debug exit
    #[cfg(gdb)]
    pub(super) fn handle_debug(
        &mut self,
        dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
        stop_reason: VcpuStopReason,
    ) -> std::result::Result<(), HandleDebugError> {
        use debug::ProcessDebugRequestError;

        use crate::hypervisor::gdb::DebugMemoryAccess;

        if self.gdb_conn.is_none() {
            return Err(HandleDebugError::DebugNotEnabled);
        }

        let mem_access = DebugMemoryAccess {
            // TODO: dbg_mem_access_fn could be out of sync with the
            // actual snapshot/scratch regions, if a snapshot restore
            // has caused either of those to change.
            dbg_mem_access_fn,
            guest_mmap_regions: self.get_mapped_regions().cloned().collect(),
        };

        match stop_reason {
            // If the vCPU stopped because of a crash, we need to handle it differently
            // We do not want to allow resuming execution or placing breakpoints
            // because the guest has crashed.
            // We only allow reading registers and memory
            VcpuStopReason::Crash => {
                self.send_dbg_msg(DebugResponse::VcpuStopped(stop_reason))?;

                loop {
                    tracing::debug!("Debug wait for event to resume vCPU");
                    // Wait for a message from gdb
                    let req = self.recv_dbg_msg()?;

                    // Flag to store if we should deny continue or step requests
                    let mut deny_continue = false;
                    // Flag to store if we should detach from the gdb session
                    let mut detach = false;

                    let response = match req {
                        // Allow the detach request to disable debugging by continuing resuming
                        // hypervisor crash error reporting
                        DebugMsg::DisableDebug => {
                            detach = true;
                            DebugResponse::DisableDebug
                        }
                        // Do not allow continue or step requests
                        DebugMsg::Continue | DebugMsg::Step => {
                            deny_continue = true;
                            DebugResponse::NotAllowed
                        }
                        // Do not allow adding/removing breakpoints and writing to memory or registers
                        DebugMsg::AddHwBreakpoint(_)
                        | DebugMsg::AddSwBreakpoint(_)
                        | DebugMsg::RemoveHwBreakpoint(_)
                        | DebugMsg::RemoveSwBreakpoint(_)
                        | DebugMsg::WriteAddr(_, _)
                        | DebugMsg::WriteRegisters(_) => DebugResponse::NotAllowed,

                        // For all other requests, we will process them normally
                        _ => {
                            let result = self.process_dbg_request(req, &mem_access);
                            match result {
                                Ok(response) => response,
                                // Treat non-fatal errors separately so the guest doesn't fail
                                Err(ProcessDebugRequestError::ReadMemory(
                                    DebugMemoryAccessError::TranslateGuestAddress(_),
                                ))
                                | Err(ProcessDebugRequestError::Debug(DebugError::TranslateGva(
                                    _,
                                ))) => DebugResponse::ErrorOccurred,
                                Err(e) => {
                                    tracing::error!("Error processing debug request: {:?}", e);
                                    return Err(HandleDebugError::ProcessRequest(e));
                                }
                            }
                        }
                    };

                    // Send the response to the request back to gdb
                    self.send_dbg_msg(response)?;

                    // If we are denying continue or step requests, the debugger assumes the
                    // execution started so we need to report a stop reason as a crash and let
                    // it request to read registers/memory to figure out what happened
                    if deny_continue {
                        self.send_dbg_msg(DebugResponse::VcpuStopped(VcpuStopReason::Crash))?;
                    }

                    // If we are detaching, we will break the loop and the Hypervisor will continue
                    // to handle the Crash reason
                    if detach {
                        break;
                    }
                }
            }
            // If the vCPU stopped because of any other reason except a crash, we can handle it
            // normally
            _ => {
                // Send the stop reason to the gdb thread
                self.send_dbg_msg(DebugResponse::VcpuStopped(stop_reason))?;

                loop {
                    tracing::debug!("Debug wait for event to resume vCPU");
                    // Wait for a message from gdb
                    let req = self.recv_dbg_msg()?;

                    let result = self.process_dbg_request(req, &mem_access);

                    let response = match result {
                        Ok(response) => response,
                        // Treat non-fatal errors separately so the guest doesn't fail
                        Err(ProcessDebugRequestError::ReadMemory(
                            DebugMemoryAccessError::TranslateGuestAddress(_),
                        ))
                        | Err(ProcessDebugRequestError::Debug(DebugError::TranslateGva(_))) => {
                            DebugResponse::ErrorOccurred
                        }
                        Err(e) => {
                            return Err(HandleDebugError::ProcessRequest(e));
                        }
                    };

                    let cont = matches!(
                        response,
                        DebugResponse::Continue | DebugResponse::Step | DebugResponse::DisableDebug
                    );

                    self.send_dbg_msg(response)?;

                    // Check if we should continue execution
                    // We continue if the response is one of the following: Step, Continue, or DisableDebug
                    if cont {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    #[cfg(crashdump)]
    pub(crate) fn crashdump_context(
        &self,
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
    ) -> std::result::Result<Option<crate::hypervisor::crashdump::CrashDumpContext>, CrashDumpError>
    {
        if self.rt_cfg.guest_core_dump {
            let mut regs = [0; 27];

            let vcpu_regs = self.vm.regs()?;
            let sregs = self.vm.sregs()?;
            let xsave = self.vm.xsave()?;

            // Set up the registers for the crash dump
            regs[0] = vcpu_regs.r15; // r15
            regs[1] = vcpu_regs.r14; // r14
            regs[2] = vcpu_regs.r13; // r13
            regs[3] = vcpu_regs.r12; // r12
            regs[4] = vcpu_regs.rbp; // rbp
            regs[5] = vcpu_regs.rbx; // rbx
            regs[6] = vcpu_regs.r11; // r11
            regs[7] = vcpu_regs.r10; // r10
            regs[8] = vcpu_regs.r9; // r9
            regs[9] = vcpu_regs.r8; // r8
            regs[10] = vcpu_regs.rax; // rax
            regs[11] = vcpu_regs.rcx; // rcx
            regs[12] = vcpu_regs.rdx; // rdx
            regs[13] = vcpu_regs.rsi; // rsi
            regs[14] = vcpu_regs.rdi; // rdi
            regs[15] = 0; // orig rax
            regs[16] = vcpu_regs.rip; // rip
            regs[17] = sregs.cs.selector as u64; // cs
            regs[18] = vcpu_regs.rflags; // eflags
            regs[19] = vcpu_regs.rsp; // rsp
            regs[20] = sregs.ss.selector as u64; // ss
            regs[21] = sregs.fs.base; // fs_base
            regs[22] = sregs.gs.base; // gs_base
            regs[23] = sregs.ds.selector as u64; // ds
            regs[24] = sregs.es.selector as u64; // es
            regs[25] = sregs.fs.selector as u64; // fs
            regs[26] = sregs.gs.selector as u64; // gs

            // Get the filename from the binary path
            let filename = self.rt_cfg.binary_path.clone().and_then(|path| {
                Path::new(&path)
                    .file_name()
                    .and_then(|name| name.to_os_string().into_string().ok())
            });

            // Use the stored entry point address from the runtime config.
            // This is the original entry point (load_addr + ELF entry offset)
            // which GDB needs for AT_ENTRY to compute the PIE load offset.
            // We cannot use self.entrypoint here because it transitions from
            // Initialise(addr) to Call(dispatch_addr) after guest init.
            let initialise = self.rt_cfg.entry_point.unwrap_or_else(|| {
                tracing::warn!(
                    "entry_point was never set in SandboxRuntimeConfig; AT_ENTRY will be 0"
                );
                0
            });
            let mmap_regions: Vec<MemoryRegion> = self.get_mapped_regions().cloned().collect();
            let root_pt = self.get_root_pt()?;

            let regions = mem_mgr
                .get_guest_memory_regions(root_pt, &mmap_regions)
                .map_err(|e| CrashDumpError::AccessPageTable(Box::new(e)))?;

            Ok(Some(crashdump::CrashDumpContext::new(
                regions,
                regs,
                xsave.to_vec(),
                initialise,
                self.rt_cfg.binary_path.clone(),
                filename,
            )))
        } else {
            Ok(None)
        }
    }
}

#[cfg(gdb)]
pub(super) mod debug {
    use nub_host_common::mem::PAGE_SIZE;

    use super::HyperlightVm;
    use crate::hypervisor::gdb::arch::{SW_BP, SW_BP_SIZE};
    use crate::hypervisor::gdb::{
        DebugError, DebugMemoryAccess, DebugMemoryAccessError, DebugMsg, DebugResponse,
    };
    use crate::hypervisor::virtual_machine::VmError;

    /// Errors that can occur during GDB debug request processing
    #[derive(Debug, thiserror::Error)]
    pub enum ProcessDebugRequestError {
        #[error("Debug is not enabled")]
        DebugNotEnabled,
        #[error("Failed to acquire lock at {0}:{1}")]
        TryLockError(&'static str, u32),
        #[error("VM operation error: {0}")]
        Vm(#[from] VmError),
        #[error("Debug operation error: {0}")]
        Debug(#[from] DebugError),
        #[error("Address {0:#x} is not a software breakpoint")]
        SwBreakpointNotFound(u64),
        #[error("Failed to read memory: {0}")]
        ReadMemory(#[from] DebugMemoryAccessError),
        #[error("Failed to write memory: {0}")]
        WriteMemory(DebugMemoryAccessError),
    }

    impl HyperlightVm {
        pub(crate) fn process_dbg_request(
            &mut self,
            req: DebugMsg,
            mem_access: &DebugMemoryAccess,
        ) -> std::result::Result<DebugResponse, ProcessDebugRequestError> {
            if self.gdb_conn.is_some() {
                match req {
                    DebugMsg::AddHwBreakpoint(addr) => Ok(DebugResponse::AddHwBreakpoint(
                        self.vm
                            .add_hw_breakpoint(addr)
                            .map_err(|e| {
                                tracing::error!("Failed to add hw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::AddSwBreakpoint(addr) => Ok(DebugResponse::AddSwBreakpoint(
                        self.add_sw_breakpoint(addr, mem_access)
                            .map_err(|e| {
                                tracing::error!("Failed to add sw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::Continue => {
                        self.vm.set_single_step(false).map_err(|e| {
                            tracing::error!("Failed to continue execution: {:?}", e);

                            e
                        })?;

                        Ok(DebugResponse::Continue)
                    }
                    DebugMsg::DisableDebug => {
                        self.vm.set_debug(false).map_err(|e| {
                            tracing::error!("Failed to disable debugging: {:?}", e);
                            e
                        })?;

                        Ok(DebugResponse::DisableDebug)
                    }
                    DebugMsg::GetCodeSectionOffset => {
                        let offset = mem_access
                            .dbg_mem_access_fn
                            .try_lock()
                            .map_err(|_| ProcessDebugRequestError::TryLockError(file!(), line!()))?
                            .layout
                            .get_guest_code_address();

                        Ok(DebugResponse::GetCodeSectionOffset(offset as u64))
                    }
                    DebugMsg::ReadAddr(addr, len) => {
                        let mut data = vec![0u8; len];

                        self.read_addrs(addr, &mut data, mem_access).map_err(|e| {
                            tracing::error!("Failed to read from address: {:?}", e);

                            e
                        })?;

                        Ok(DebugResponse::ReadAddr(data))
                    }
                    DebugMsg::ReadRegisters => {
                        let regs = self.vm.regs().map_err(VmError::Register)?;
                        let fpu = self.vm.fpu().map_err(VmError::Register)?;
                        Ok(DebugResponse::ReadRegisters(Box::new((regs, fpu))))
                    }
                    DebugMsg::RemoveHwBreakpoint(addr) => Ok(DebugResponse::RemoveHwBreakpoint(
                        self.vm
                            .remove_hw_breakpoint(addr)
                            .map_err(|e| {
                                tracing::error!("Failed to remove hw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::RemoveSwBreakpoint(addr) => Ok(DebugResponse::RemoveSwBreakpoint(
                        self.remove_sw_breakpoint(addr, mem_access)
                            .map_err(|e| {
                                tracing::error!("Failed to remove sw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::Step => {
                        self.vm.set_single_step(true).map_err(|e| {
                            tracing::error!("Failed to enable step instruction: {:?}", e);

                            e
                        })?;

                        Ok(DebugResponse::Step)
                    }
                    DebugMsg::WriteAddr(addr, data) => {
                        self.write_addrs(addr, &data, mem_access).map_err(|e| {
                            tracing::error!("Failed to write to address: {:?}", e);

                            e
                        })?;

                        Ok(DebugResponse::WriteAddr)
                    }
                    DebugMsg::WriteRegisters(boxed_regs) => {
                        let (regs, fpu) = boxed_regs.as_ref();
                        self.vm.set_regs(regs).map_err(VmError::Register)?;
                        self.vm.set_fpu(fpu).map_err(VmError::Register)?;

                        Ok(DebugResponse::WriteRegisters)
                    }
                }
            } else {
                Err(ProcessDebugRequestError::DebugNotEnabled)
            }
        }

        pub(crate) fn recv_dbg_msg(
            &mut self,
        ) -> std::result::Result<DebugMsg, super::RecvDbgMsgError> {
            use super::RecvDbgMsgError;

            let gdb_conn = self
                .gdb_conn
                .as_mut()
                .ok_or(RecvDbgMsgError::DebugNotEnabled)?;

            Ok(gdb_conn.recv()?)
        }

        pub(crate) fn send_dbg_msg(
            &mut self,
            cmd: DebugResponse,
        ) -> std::result::Result<(), super::SendDbgMsgError> {
            use super::SendDbgMsgError;

            tracing::debug!("Sending {:?}", cmd);

            let gdb_conn = self
                .gdb_conn
                .as_mut()
                .ok_or(SendDbgMsgError::DebugNotEnabled)?;

            Ok(gdb_conn.send(cmd)?)
        }

        fn read_addrs(
            &mut self,
            mut gva: u64,
            mut data: &mut [u8],
            mem_access: &DebugMemoryAccess,
        ) -> std::result::Result<(), ProcessDebugRequestError> {
            let data_len = data.len();
            tracing::debug!("Read addr: {:X} len: {:X}", gva, data_len);

            while !data.is_empty() {
                let gpa = self.vm.translate_gva(gva)?;

                let read_len = std::cmp::min(
                    data.len(),
                    (PAGE_SIZE - (gpa & (PAGE_SIZE - 1))).try_into().unwrap(),
                );

                mem_access.read(&mut data[..read_len], gpa)?;

                data = &mut data[read_len..];
                gva += read_len as u64;
            }

            Ok(())
        }

        /// Copies the data from the provided slice to the guest memory address
        /// The address is checked to be a valid guest address
        fn write_addrs(
            &mut self,
            mut gva: u64,
            mut data: &[u8],
            mem_access: &DebugMemoryAccess,
        ) -> std::result::Result<(), ProcessDebugRequestError> {
            let data_len = data.len();
            tracing::debug!("Write addr: {:X} len: {:X}", gva, data_len);

            while !data.is_empty() {
                let gpa = self.vm.translate_gva(gva)?;

                let write_len = std::cmp::min(
                    data.len(),
                    (PAGE_SIZE - (gpa & (PAGE_SIZE - 1))).try_into().unwrap(),
                );

                // Use the memory access to write to guest memory
                mem_access
                    .write(&data[..write_len], gpa)
                    .map_err(ProcessDebugRequestError::WriteMemory)?;

                data = &data[write_len..];
                gva += write_len as u64;
            }

            Ok(())
        }

        // Must be idempotent!
        fn add_sw_breakpoint(
            &mut self,
            gva: u64,
            mem_access: &DebugMemoryAccess,
        ) -> std::result::Result<(), ProcessDebugRequestError> {
            // Check if breakpoint already exists
            if self.sw_breakpoints.contains_key(&gva) {
                return Ok(());
            }

            // Write breakpoint OP code to write to guest memory
            let mut save_data = [0; SW_BP_SIZE];
            self.read_addrs(gva, &mut save_data[..], mem_access)?;
            self.write_addrs(gva, &SW_BP, mem_access)?;

            // Save guest memory to restore when breakpoint is removed
            self.sw_breakpoints.insert(gva, save_data[0]);

            Ok(())
        }

        fn remove_sw_breakpoint(
            &mut self,
            gva: u64,
            mem_access: &DebugMemoryAccess,
        ) -> std::result::Result<(), ProcessDebugRequestError> {
            if let Some(saved_data) = self.sw_breakpoints.remove(&gva) {
                // Restore saved data to the guest's memory
                self.write_addrs(gva, &[saved_data], mem_access)?;

                Ok(())
            } else {
                Err(ProcessDebugRequestError::SwBreakpointNotFound(gva))
            }
        }
    }
}
