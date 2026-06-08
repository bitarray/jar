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

mod x86_64;

use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use nub_host_common::log_level::GuestLogFilter;
use tracing_core::LevelFilter;

use crate::HyperlightError;
use crate::hypervisor::virtual_machine::{
    MapMemoryError, RegisterError, RunVcpuError, UnmapMemoryError, VmError, VmExit,
};
use crate::hypervisor::virtual_machine::{VcpuLane, VirtualMachine};
use crate::hypervisor::{InterruptHandle, InterruptHandleImpl, MultiLaneInterruptHandle};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags, MemoryRegionType};
use crate::mem::mgr::{SandboxMemoryManager, SnapshotSharedMemory};
use crate::mem::shared_mem::{GuestSharedMemory, HostSharedMemory, SharedMemory};
use crate::metrics::{METRIC_ERRONEOUS_VCPU_KICKS, METRIC_GUEST_CANCELLATION};
use crate::sandbox::host_funcs::FunctionRegistry;
use crate::sandbox::outb::{HandleOutbError, handle_outb};
use crate::sandbox::snapshot::NextAction;

/// Get the logging level filter to pass to the guest entrypoint
///
/// The guest entrypoint uses this to determine the maximum log level to enable for the guest.
/// The `RUST_LOG` environment variable is expected to be in the format of comma-separated
/// key-value pairs, where the key is a log target (e.g., "hyperlight_guest_bin") and the value is
/// a log level (e.g., "debug").
///
/// NOTE: This prioritizes the log level for the targets containing "hyperlight_guest" string, then
/// "hyperlight_host", and then general log level. If none of these targets are found, it
/// defaults to "error".
fn get_max_log_level_filter(rust_log: String) -> LevelFilter {
    // This is done as the guest will produce logs based on the log level returned here
    // producing those logs is expensive and we don't want to do it if the host is not
    // going to process them
    let level_str = rust_log
        .split(',')
        // Prioritize targets containing "hyperlight_guest"
        .find_map(|part| {
            let mut kv = part.splitn(2, '=');
            match (kv.next(), kv.next()) {
                (Some(k), Some(v)) if k.trim().contains("hyperlight_guest") => Some(v.trim()),
                _ => None,
            }
        })
        // Then check for "hyperlight_host"
        .or_else(|| {
            rust_log.split(',').find_map(|part| {
                let mut kv = part.splitn(2, '=');
                match (kv.next(), kv.next()) {
                    (Some(k), Some(v)) if k.trim().contains("hyperlight_host") => Some(v.trim()),
                    _ => None,
                }
            })
        })
        // Finally, check for general log level
        .or_else(|| {
            rust_log.split(',').find_map(|part| {
                if part.contains("=") {
                    None
                } else {
                    Some(part.trim())
                }
            })
        })
        .unwrap_or("");

    tracing::info!("Determined guest log level: {}", level_str);

    // If no value is found, default to Error
    LevelFilter::from_str(level_str).unwrap_or(LevelFilter::ERROR)
}

/// Converts a given [`Option<LevelFilter>`] to a `u64` value to be passed to the guest entrypoint
/// If the provided filter is `None`, it uses the `RUST_LOG` environment variable to determine the
/// maximum log level filter for the guest and converts it to a `u64` value.
pub(super) fn get_guest_log_filter(guest_max_log_level: Option<LevelFilter>) -> u64 {
    let guest_log_level_filter = match guest_max_log_level {
        Some(level) => level,
        None => get_max_log_level_filter(std::env::var("RUST_LOG").unwrap_or_default()),
    };
    GuestLogFilter::from(guest_log_level_filter).into()
}

/// DispatchGuestCall error
#[derive(Debug, thiserror::Error)]
pub enum DispatchGuestCallError {
    #[error("Failed to run vm: {0}")]
    Run(#[from] RunVmError),
    #[error("Failed to setup registers: {0}")]
    SetupRegs(RegisterError),
    #[error("VM was uninitialized")]
    Uninitialized,
}

impl DispatchGuestCallError {
    /// Returns true if this error should poison the sandbox
    pub(crate) fn is_poison_error(&self) -> bool {
        match self {
            // These errors poison the sandbox because they can leave it in an inconsistent state
            // by returning before the guest can unwind properly
            DispatchGuestCallError::Run(_) => true,
            DispatchGuestCallError::SetupRegs(_) | DispatchGuestCallError::Uninitialized => false,
        }
    }

    /// Converts a `DispatchGuestCallError` to a `HyperlightError`. Used for backwards compatibility.
    /// Also determines if the sandbox should be poisoned.
    ///
    /// Returns a tuple of (error, should_poison) where should_poison indicates whether
    /// the sandbox should be marked as poisoned due to incomplete guest execution.
    pub(crate) fn promote(self) -> (HyperlightError, bool) {
        let should_poison = self.is_poison_error();
        let promoted_error = match self {
            DispatchGuestCallError::Run(RunVmError::ExecutionCancelledByHost) => {
                HyperlightError::ExecutionCanceledByHost()
            }

            DispatchGuestCallError::Run(RunVmError::HandleIo(HandleIoError::Outb(
                HandleOutbError::GuestAborted { code, message },
            ))) => HyperlightError::GuestAborted(code, message),

            DispatchGuestCallError::Run(RunVmError::MemoryAccessViolation {
                addr,
                access_type,
                region_flags,
            }) => HyperlightError::MemoryAccessViolation(addr, access_type, region_flags),

            // Leave others as is
            other => HyperlightVmError::DispatchGuestCall(other).into(),
        };
        (promoted_error, should_poison)
    }
}

/// Initialize error
#[derive(Debug, thiserror::Error)]
pub enum InitializeError {
    #[error("Failed to convert pointer: {0}")]
    ConvertPointer(String),
    #[error("Failed to run vm: {0}")]
    Run(#[from] RunVmError),
    #[error("Failed to setup registers: {0}")]
    SetupRegs(#[from] RegisterError),
    #[error("Guest initialised stack pointer to architecturally invalid value: {0}")]
    InvalidStackPointer(u64),
}

/// Errors that can occur during VM execution in the run loop
#[derive(Debug, thiserror::Error)]
pub enum RunVmError {
    #[error("Execution was cancelled by the host")]
    ExecutionCancelledByHost,
    #[error("Failed to access page: {0}")]
    PageTableAccess(AccessPageTableError),
    #[error("IO handling error: {0}")]
    HandleIo(#[from] HandleIoError),
    #[error(
        "Memory access violation at address {addr:#x}: {access_type} access, but memory is marked as {region_flags}"
    )]
    MemoryAccessViolation {
        addr: u64,
        access_type: MemoryRegionFlags,
        region_flags: MemoryRegionFlags,
    },
    #[error("MMIO READ access to unmapped address {0:#x}")]
    MmioReadUnmapped(u64),
    #[error("MMIO WRITE access to unmapped address {0:#x}")]
    MmioWriteUnmapped(u64),
    #[error("vCPU run failed: {0}")]
    RunVcpu(#[from] RunVcpuError),
    #[error("Unexpected VM exit: {0}")]
    UnexpectedVmExit(String),
}

/// Errors that can occur during IO (outb) handling
#[derive(Debug, thiserror::Error)]
pub enum HandleIoError {
    #[error("No data was given in IO interrupt")]
    NoData,
    #[error("{0}")]
    Outb(#[from] HandleOutbError),
}

/// Errors that can occur when mapping a memory region
#[derive(Debug, thiserror::Error)]
pub enum MapRegionError {
    #[error("VM map memory error: {0}")]
    MapMemory(#[from] MapMemoryError),
    #[error("Region is not page-aligned (page size: {0:#x})")]
    NotPageAligned(usize),
}

/// Errors that can occur when unmapping a memory region
#[derive(Debug, thiserror::Error)]
pub enum UnmapRegionError {
    #[error("Region not found in mapped regions")]
    RegionNotFound,
    #[error("VM unmap memory error: {0}")]
    UnmapMemory(#[from] UnmapMemoryError),
}

/// Errors that can occur when updating the scratch mapping
#[derive(Debug, thiserror::Error)]
pub enum UpdateRegionError {
    #[error("VM map memory error: {0}")]
    MapMemory(#[from] MapMemoryError),
    #[error("VM unmap memory error: {0}")]
    UnmapMemory(#[from] UnmapMemoryError),
    #[error("Fixed-VA snapshot mmap at {va:#x} failed: {err}")]
    FixedVaMmap { va: u64, err: std::io::Error },
}

/// RAII handle over an mmap performed at a fixed host VA. Used to
/// place the snapshot kernel-shadow at `GUEST_VA_BASE + KERNEL_OFFSET`
/// inside the per-process reservation. Drop unmaps the region.
#[derive(Debug)]
pub(crate) struct FixedVaMapping {
    base: usize,
    size: usize,
}

// SAFETY: holds a raw pointer (`base`), but only as an integer index.
// Concurrent reads of the mapped region by other code are this
// struct's responsibility's caller — `FixedVaMapping` itself only
// owns the unmap on Drop.
unsafe impl Send for FixedVaMapping {}

impl FixedVaMapping {
    /// mmap `size` bytes at exactly `fixed_va` (rounded down to a
    /// page boundary; size rounded up). The region must lie inside a
    /// pre-reserved range, since we use `MAP_FIXED` to overlay it.
    /// After mmap, copy `size` bytes from `src` into the new region.
    fn new_with_contents(
        fixed_va: u64,
        size: usize,
        src: *const u8,
    ) -> Result<Self, UpdateRegionError> {
        // SAFETY: mmap is a kernel call; result checked below.
        let ptr = unsafe {
            libc::mmap(
                fixed_va as *mut libc::c_void,
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(UpdateRegionError::FixedVaMmap {
                va: fixed_va,
                err: std::io::Error::last_os_error(),
            });
        }
        if ptr as u64 != fixed_va {
            // SAFETY: ptr came from a successful mmap.
            unsafe {
                libc::munmap(ptr, size);
            }
            return Err(UpdateRegionError::FixedVaMmap {
                va: fixed_va,
                err: std::io::Error::other(format!(
                    "MAP_FIXED returned unexpected address {:#x}",
                    ptr as u64
                )),
            });
        }
        // SAFETY: src points to `size` valid bytes (the snapshot
        // mapping); dst is a brand-new mmap of at least `size` bytes
        // that nothing else references yet.
        unsafe {
            core::ptr::copy_nonoverlapping(src, ptr as *mut u8, size);
        }
        Ok(Self {
            base: ptr as usize,
            size,
        })
    }
}

impl Drop for FixedVaMapping {
    fn drop(&mut self) {
        // SAFETY: base/size came from a successful mmap and have not
        // been freed otherwise (the field is private and only this
        // Drop unmaps).
        unsafe {
            libc::munmap(self.base as *mut libc::c_void, self.size);
        }
    }
}

/// Errors that can occur when accessing the root page table state
#[derive(Debug, thiserror::Error)]
pub enum AccessPageTableError {
    #[error("Failed to get/set registers: {0}")]
    AccessRegs(#[from] RegisterError),
}

/// Errors that can occur during HyperlightVm creation
#[derive(Debug, thiserror::Error)]
pub enum CreateHyperlightVmError {
    #[error("No hypervisor was found")]
    NoHypervisorFound,
    #[error("VM operation error: {0}")]
    Vm(#[from] VmError),
    #[error("Set scratch error: {0}")]
    UpdateRegion(#[from] UpdateRegionError),
}

/// Unified error type for all HyperlightVm operations
#[derive(Debug, thiserror::Error)]
pub enum HyperlightVmError {
    #[error("Create VM error: {0}")]
    Create(#[from] CreateHyperlightVmError),
    #[error("Dispatch guest call error: {0}")]
    DispatchGuestCall(#[from] DispatchGuestCallError),
    #[error("Initialize error: {0}")]
    Initialize(#[from] InitializeError),
    #[error("Map region error: {0}")]
    MapRegion(#[from] MapRegionError),
    #[error("Restore VM (vcpu) error: {0}")]
    Restore(#[from] RegisterError),
    #[error("Unmap region error: {0}")]
    UnmapRegion(#[from] UnmapRegionError),
    #[error("Update region error: {0}")]
    UpdateRegion(#[from] UpdateRegionError),
    #[error("Access page table error: {0}")]
    AccessPageTable(#[from] AccessPageTableError),
}

/// Represents a Hyperlight Virtual Machine instance.
///
/// This struct manages the lifecycle of the VM, including:
/// - The underlying hypervisor implementation (KVM).
/// - Memory management, including initial sandbox regions and dynamic mappings.
/// - The vCPU execution loop and handling of VM exits (I/O, MMIO, interrupts).
pub(crate) struct HyperlightVm {
    pub(super) vm: Box<dyn VirtualMachine>,
    pub(super) entrypoint: NextAction, // only present if this vm has not yet been initialised
    pub(super) rsp_gva: u64,
    pub(super) interrupt_handles: Vec<Arc<dyn InterruptHandleImpl>>,

    pub(super) snapshot_slot: u32,
    // The current snapshot region, used to keep it alive as long as
    // it is used & when unmapping
    pub(super) snapshot_memory: Option<SnapshotSharedMemory<GuestSharedMemory>>,
    /// Fixed-VA shadow mmap that holds a copy of the snapshot bytes at
    /// `GUEST_VA_BASE + KERNEL_OFFSET`. KVM is pointed at this VA (not
    /// the original snapshot mmap) so the host process can later read
    /// the kernel through this region.
    pub(super) snapshot_fixed_va: Option<FixedVaMapping>,
    pub(super) scratch_slot: u32, // The slot number used for the scratch region
    // The current scratch region, used to keep it alive as long as it
    // is used & when unmapping
    pub(super) scratch_memory: Option<GuestSharedMemory>,

    pub(super) mmap_regions: Vec<(u32, MemoryRegion)>, // Later mapped regions (slot number, region)

    pub(super) pending_tlb_flush: AtomicBool,
}

impl HyperlightVm {
    /// Iterator over the dynamic memory regions registered via the
    /// VM's `map_region` API. Post-Stage-F.CoW the registration path
    /// is gone, so this is always empty — kept for the MMIO
    /// access-violation reporter, which iterates it to produce
    /// informative error messages.
    pub(crate) fn get_mapped_regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.mmap_regions.iter().map(|(_, region)| region)
    }

    /// Register the snapshot memory region with the VM. Called once
    /// during construction; post-Stage-F.CoW there is no rollback
    /// path that re-registers it.
    ///
    /// The snapshot's host VA is forced to
    /// `guest_va_base() + KERNEL_OFFSET` (= `SandboxMemoryLayout::
    /// kernel_base_va()`) by re-mmapping a fresh page-aligned region
    /// at that fixed VA and copying the snapshot bytes in. This sits
    /// inside the per-process reservation made by
    /// [`nub_host_common::layout::reserve_guest_va_range`], so we can
    /// safely use `MAP_FIXED` to overlay it.
    pub(crate) fn install_snapshot_mapping(
        &mut self,
        snapshot: SnapshotSharedMemory<GuestSharedMemory>,
    ) -> Result<(), UpdateRegionError> {
        let guest_base = crate::mem::layout::SandboxMemoryLayout::BASE_ADDRESS as u64;
        let orig_rgn = snapshot.mapping_at(guest_base, MemoryRegionType::Snapshot);

        // The guest's kernel-shadow VA — also where the kernel was
        // linked (link.x) and where the guest PT maps the kernel.
        let fixed_va =
            nub_host_common::layout::guest_va_base() + nub_host_common::layout::KERNEL_OFFSET;
        let size = orig_rgn.host_region.end - orig_rgn.host_region.start;
        let fixed = FixedVaMapping::new_with_contents(
            fixed_va,
            size,
            orig_rgn.host_region.start as *const u8,
        )?;

        let rgn = MemoryRegion {
            guest_region: orig_rgn.guest_region.clone(),
            host_region: fixed.base..(fixed.base + fixed.size),
            flags: orig_rgn.flags,
            region_type: orig_rgn.region_type,
        };

        // Keep the original snapshot mmap alive (Drop'ing it would
        // munmap the source); keep the fixed-VA shadow alive (Drop'ing
        // it would munmap the region KVM is pointed at).
        self.snapshot_memory = Some(snapshot);
        self.snapshot_fixed_va = Some(fixed);
        unsafe { self.vm.map_memory((self.snapshot_slot, &rgn))? };
        Ok(())
    }

    /// Register the scratch memory region with the VM. Called once
    /// during construction.
    pub(crate) fn install_scratch_mapping(
        &mut self,
        scratch: GuestSharedMemory,
    ) -> Result<(), UpdateRegionError> {
        let guest_base = nub_host_common::layout::scratch_base_gpa(scratch.mem_size());
        let rgn = scratch.mapping_at(guest_base, MemoryRegionType::Scratch);
        self.scratch_memory = Some(scratch);
        unsafe { self.vm.map_memory((self.scratch_slot, &rgn))? };
        Ok(())
    }

    pub(crate) fn interrupt_handle(&self) -> Arc<dyn InterruptHandle> {
        if self.interrupt_handles.len() == 1 {
            self.interrupt_handles[VcpuLane::PRIMARY.index()].clone()
        } else {
            Arc::new(MultiLaneInterruptHandle::new(
                self.interrupt_handles
                    .iter()
                    .map(|handle| handle.clone() as Arc<dyn InterruptHandle>)
                    .collect(),
            ))
        }
    }

    pub(crate) fn clear_cancel(&self) {
        for handle in &self.interrupt_handles {
            handle.clear_cancel();
        }
    }

    pub(super) fn run(
        &self,
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
        host_funcs: &Arc<Mutex<FunctionRegistry>>,
    ) -> std::result::Result<(), RunVmError> {
        self.run_on(VcpuLane::PRIMARY, mem_mgr, host_funcs)
    }

    pub(super) fn run_on(
        &self,
        lane: VcpuLane,
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
        host_funcs: &Arc<Mutex<FunctionRegistry>>,
    ) -> std::result::Result<(), RunVmError> {
        let interrupt_handle = self
            .interrupt_handles
            .get(lane.index())
            .ok_or_else(|| {
                RunVmError::UnexpectedVmExit(format!("invalid vCPU lane {}", lane.index()))
            })?
            .clone();
        let result = loop {
            // ===== KILL() TIMING POINT 2: Before set_tid() =====
            // If kill() is called and ran to completion BEFORE this line executes:
            //    - CANCEL_BIT will be set and we will return an early VmExit::Cancelled()
            //      without sending any signals/WHV api calls
            interrupt_handle.set_tid();
            interrupt_handle.set_running();
            // NOTE: `set_running()`` must be called before checking `is_cancelled()`
            // otherwise we risk missing a call to `kill()` because the vcpu would not be marked as running yet so signals won't be sent

            let exit_reason =
                if interrupt_handle.is_cancelled() || interrupt_handle.is_debug_interrupted() {
                    Ok(VmExit::Cancelled())
                } else {
                    // ==== KILL() TIMING POINT 3: Before calling run() ====
                    // If kill() is called and ran to completion BEFORE this line executes:
                    //    - Will still do a VM entry, but signals will be sent until VM exits
                    if lane == VcpuLane::PRIMARY {
                        self.vm.run_vcpu()
                    } else {
                        self.vm.run_vcpu_on(lane)
                    }
                };

            // ===== KILL() TIMING POINT 4: Before clear_running() =====
            // If kill() is called and ran to completion BEFORE this line executes:
            //    - CANCEL_BIT will be set. Cancellation is deferred to the next iteration.
            //    - Signals will be sent until `clear_running()` is called, which is ok
            interrupt_handle.clear_running();

            // ===== KILL() TIMING POINT 5: Before capturing cancel_requested =====
            // If kill() is called and ran to completion BEFORE this line executes:
            //    - CANCEL_BIT will be set. Cancellation is deferred to the next iteration.
            //    - Signals will not be sent
            let cancel_requested = interrupt_handle.is_cancelled();
            let debug_interrupted = interrupt_handle.is_debug_interrupted();

            // ===== KILL() TIMING POINT 6: Before checking exit_reason =====
            // If kill() is called and ran to completion BEFORE this line executes:
            //    - CANCEL_BIT will be set. Cancellation is deferred to the next iteration.
            //    - Signals will not be sent
            match exit_reason {
                Ok(VmExit::Halt()) => {
                    break Ok(());
                }
                Ok(VmExit::IoOut(port, data)) => {
                    self.handle_io(mem_mgr, host_funcs, port, data)?;
                }
                Ok(VmExit::MmioRead(addr)) => {
                    let all_regions = self.get_mapped_regions();
                    match get_memory_access_violation(
                        addr as usize,
                        MemoryRegionFlags::READ,
                        all_regions,
                    ) {
                        Some(MemoryAccess::AccessViolation(region_flags)) => {
                            break Err(RunVmError::MemoryAccessViolation {
                                addr,
                                access_type: MemoryRegionFlags::READ,
                                region_flags,
                            });
                        }
                        None => {
                            break Err(RunVmError::MmioReadUnmapped(addr));
                        }
                    }
                }
                Ok(VmExit::MmioWrite(addr)) => {
                    let all_regions = self.get_mapped_regions();
                    match get_memory_access_violation(
                        addr as usize,
                        MemoryRegionFlags::WRITE,
                        all_regions,
                    ) {
                        Some(MemoryAccess::AccessViolation(region_flags)) => {
                            break Err(RunVmError::MemoryAccessViolation {
                                addr,
                                access_type: MemoryRegionFlags::WRITE,
                                region_flags,
                            });
                        }
                        None => {
                            break Err(RunVmError::MmioWriteUnmapped(addr));
                        }
                    }
                }
                Ok(VmExit::Cancelled()) => {
                    // If cancellation was not requested for this specific guest function call,
                    // the vcpu was interrupted by a stale cancellation. This can occur when a
                    // signal from a previous call arrives late on Linux.
                    if !cancel_requested && !debug_interrupted {
                        // Track that an erroneous vCPU kick occurred
                        metrics::counter!(METRIC_ERRONEOUS_VCPU_KICKS).increment(1);
                        // treat this the same as a VmExit::Retry, the cancel was not meant for this call
                        continue;
                    }

                    metrics::counter!(METRIC_GUEST_CANCELLATION).increment(1);
                    break Err(RunVmError::ExecutionCancelledByHost);
                }
                Ok(VmExit::Unknown(reason)) => {
                    break Err(RunVmError::UnexpectedVmExit(reason));
                }
                Ok(VmExit::Retry()) => continue,
                Err(e) => {
                    break Err(RunVmError::RunVcpu(e));
                }
            }
        };

        match result {
            Ok(_) => Ok(()),
            Err(RunVmError::ExecutionCancelledByHost) => {
                // no need to crashdump this
                Err(RunVmError::ExecutionCancelledByHost)
            }
            Err(e) => Err(e),
        }
    }

    /// Handle an IO exit
    fn handle_io(
        &self,
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
        host_funcs: &Arc<Mutex<FunctionRegistry>>,
        port: u16,
        data: Vec<u8>,
    ) -> std::result::Result<(), HandleIoError> {
        if data.is_empty() {
            return Err(HandleIoError::NoData);
        }

        #[allow(clippy::get_first)]
        let val = u32::from_le_bytes([
            data.get(0).copied().unwrap_or(0),
            data.get(1).copied().unwrap_or(0),
            data.get(2).copied().unwrap_or(0),
            data.get(3).copied().unwrap_or(0),
        ]);

        handle_outb(mem_mgr, host_funcs, port, val)?;

        Ok(())
    }
}

impl Drop for HyperlightVm {
    fn drop(&mut self) {
        for handle in &self.interrupt_handles {
            handle.set_dropped();
        }
    }
}

/// The vCPU tried to access the given addr
enum MemoryAccess {
    /// The accessed region has the given flags
    AccessViolation(MemoryRegionFlags),
}

/// Determines if a known memory access violation occurred at the given address with the given action type.
/// Returns Some(reason) if violation reason could be determined, or None if violation occurred but in unmapped region.
fn get_memory_access_violation<'a>(
    gpa: usize,
    tried: MemoryRegionFlags,
    mut mem_regions: impl Iterator<Item = &'a MemoryRegion>,
) -> Option<MemoryAccess> {
    let region = mem_regions.find(|region| region.guest_region.contains(&gpa))?;
    if !region.flags.contains(tried) {
        return Some(MemoryAccess::AccessViolation(region.flags));
    }
    // gpa is in `region`, and region allows the tried access, but we got here anyway.
    // Treat as a generic access violation for now, unsure if this is reachable.
    None
}
