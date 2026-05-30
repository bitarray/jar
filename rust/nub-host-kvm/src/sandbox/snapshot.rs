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

use std::sync::atomic::{AtomicU64, Ordering};

use nub_host_common::layout::{scratch_base_gpa, scratch_base_gva};
use nub_host_common::vmem;
use nub_host_common::vmem::{BasicMapping, Mapping, MappingKind};
use tracing::{Span, instrument};

use crate::HyperlightError::MemoryRegionSizeMismatch;
use crate::Result;
use crate::mem::exe::{ExeInfo, LoadInfo};
use crate::mem::memory_region::{GuestMemoryRegion, MemoryRegion, MemoryRegionFlags};
use crate::mem::mgr::GuestPageTableBuffer;
use crate::mem::shared_mem::ReadonlySharedMemory;
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::uninitialized::{GuestBinary, GuestEnvironment};

pub(super) static SANDBOX_CONFIGURATION_COUNTER: AtomicU64 = AtomicU64::new(0);

const PTE_SIZE: usize = size_of::<vmem::PageTableEntry>();

/// Presently, a snapshot can be of a preinitialised sandbox, which
/// still needs an initialise function called in order to determine
/// how to call into it, or of an already-properly-initialised sandbox
/// which can be immediately called into. This keeps track of the
/// difference.
///
/// TODO: this should not necessarily be around in the long term:
/// ideally we would just preinitialise earlier in the snapshot
/// creation process and never need this.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum NextAction {
    /// A sandbox in the preinitialise state still needs to be
    /// initialised by calling the initialise function
    Initialise(u64),
    /// A sandbox in the ready state can immediately be called into,
    /// using the dispatch function pointer.
    Call(u64),
    /// Only when compiling for tests: a sandbox that cannot actually
    /// be used
    #[cfg(test)]
    None,
}

/// Initial guest memory layout + page tables produced from a binary.
///
/// Post-Stage-F.CoW: this is purely a build-time artifact — the
/// snapshot/restore rollback API that motivated rebuilding from a
/// running sandbox is gone, so `Snapshot::from_env` is the only
/// constructor and most accessors trimmed.
pub struct Snapshot {
    /// Layout object for the sandbox.
    layout: crate::mem::layout::SandboxMemoryLayout,
    /// Memory of the sandbox at the time this snapshot was taken
    memory: ReadonlySharedMemory,
    /// Extra debug information about the binary in this snapshot.
    load_info: LoadInfo,
    /// The hash of the other portions of the snapshot.
    hash: [u8; 32],
    /// The address of the top of the guest stack
    stack_top_gva: u64,
    /// The next action that should be performed on this snapshot
    entrypoint: NextAction,
}
impl nub_host_common::vmem::TableReadOps for Snapshot {
    type TableAddr = u64;
    fn entry_addr(addr: u64, offset: u64) -> u64 {
        addr + offset
    }
    unsafe fn read_entry(&self, addr: u64) -> vmem::PageTableEntry {
        let addr = addr as usize;
        let Some(pte_bytes) = self.memory.as_slice().get(addr..addr + PTE_SIZE) else {
            // Attacker-controlled data pointed out-of-bounds. We'll
            // default to returning 0 in this case, which, for most
            // architectures (x86-64, the only one we support) will be a
            // not-present entry.
            return 0;
        };
        // The `get()` above ensures exactly PTE_SIZE bytes.
        #[allow(clippy::unwrap_used)]
        vmem::PageTableEntry::from_le_bytes(pte_bytes.try_into().unwrap())
    }
    #[allow(clippy::unnecessary_cast)]
    fn to_phys(addr: u64) -> vmem::PhysAddr {
        addr as vmem::PhysAddr
    }
    #[allow(clippy::unnecessary_cast)]
    fn from_phys(addr: vmem::PhysAddr) -> u64 {
        addr as u64
    }
    fn root_table(&self) -> u64 {
        self.root_pt_gpa()
    }
}

/// Compute a deterministic hash of a snapshot.
///
/// This does not include the load info from the snapshot, because
/// that is only used for debugging builds.
fn hash(memory: &[u8], regions: &[MemoryRegion]) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(memory);
    for rgn in regions {
        hasher.update(&usize::to_le_bytes(rgn.guest_region.start));
        let guest_len = rgn.guest_region.end - rgn.guest_region.start;
        #[allow(clippy::useless_conversion)]
        let host_start_addr: usize = rgn.host_region.start.into();
        #[allow(clippy::useless_conversion)]
        let host_end_addr: usize = rgn.host_region.end.into();
        hasher.update(&usize::to_le_bytes(host_start_addr));
        let host_len = host_end_addr - host_start_addr;
        if guest_len != host_len {
            return Err(MemoryRegionSizeMismatch(
                host_len,
                guest_len,
                format!("{:?}", rgn),
            ));
        }
        // Ignore [`MemoryRegion::region_type`], since it is extra
        // information for debugging rather than a core part of the
        // identity of the snapshot/workload.
        hasher.update(&usize::to_le_bytes(guest_len));
        hasher.update(&u32::to_le_bytes(rgn.flags.bits()));
    }
    // Ignore [`load_info`], since it is extra information for
    // debugging rather than a core part of the identity of the
    // snapshot/workload.
    Ok(hasher.finalize().into())
}

fn map_specials(pt_buf: &GuestPageTableBuffer, scratch_size: usize) {
    // Map the scratch region
    let mapping = Mapping {
        phys_base: scratch_base_gpa(scratch_size),
        virt_base: scratch_base_gva(scratch_size),
        len: scratch_size as u64,
        kind: MappingKind::Basic(BasicMapping {
            readable: true,
            writable: true,
            // assume that the guest will map these pages elsewhere if
            // it actually needs to execute from them
            executable: false,
        }),
        user_accessible: false,
    };
    unsafe { vmem::map(pt_buf, mapping) };
}

impl Snapshot {
    /// Create a new snapshot from the guest binary identified by `env`. With the configuration
    /// specified in `cfg`.
    pub(crate) fn from_env<'a, 'b>(
        env: impl Into<GuestEnvironment<'a, 'b>>,
        cfg: SandboxConfiguration,
    ) -> Result<Self> {
        let env = env.into();
        let mut bin = env.guest_binary;
        bin.canonicalize()?;
        let blob = env.init_data;

        let exe_info = match bin {
            GuestBinary::FilePath(bin_path_str) => ExeInfo::from_file(&bin_path_str)?,
            GuestBinary::Buffer(buffer) => ExeInfo::from_buf(buffer)?,
        };

        // F4.2: dropped the host/guest version-mismatch check. As a
        // fork, our host crate's version (nub-host-kvm) intentionally
        // diverges from the upstream `hyperlight-guest-bin` ELF note
        // version. The note's bit-for-bit ABI contract is what
        // matters; we honor it. The `exe_info.guest_bin_version()`
        // accessor stays available for diagnostics.
        let _ = exe_info.guest_bin_version();

        let guest_blob_size = blob.as_ref().map(|b| b.data.len()).unwrap_or(0);
        let guest_blob_mem_flags = blob.as_ref().map(|b| b.permissions);

        let mut layout = crate::mem::layout::SandboxMemoryLayout::new(
            cfg,
            exe_info.loaded_size(),
            guest_blob_size,
            guest_blob_mem_flags,
        )?;

        let load_addr = layout.get_guest_code_address() as u64;
        let base_va = exe_info.base_va();
        let entrypoint_va: u64 = exe_info.entrypoint().into();
        let kernel_base_va = crate::mem::layout::SandboxMemoryLayout::kernel_base_va();

        let mut memory = vec![0; layout.get_memory_size()?];

        let load_info = exe_info.load(
            kernel_base_va,
            &mut memory[layout.get_guest_code_offset()..],
        )?;

        layout.write_peb(&mut memory)?;

        blob.map(|x| layout.write_init_data(&mut memory, x.data))
            .transpose()?;

        // Set up page table entries for the snapshot
        let pt_buf = GuestPageTableBuffer::new(layout.get_pt_base_gpa() as usize);

        // 1. Map the pages of snapshot data as plain RW basic mappings.
        // Pre-Stage-F these were CoW so the (now-deleted) snapshot/restore
        // machinery could roll back writes; we don't use it.
        //
        // Kernel half lives at high VA (`kernel_base_va()`); GPAs stay
        // identical, only the GVA shifts. Computes
        // `virt_base = kernel_base_va + (phys_base - BASE_ADDRESS)`.
        for rgn in layout.get_memory_regions_::<GuestMemoryRegion>(())?.iter() {
            let readable = rgn.flags.contains(MemoryRegionFlags::READ);
            let executable = rgn.flags.contains(MemoryRegionFlags::EXECUTE);
            let writable = rgn.flags.contains(MemoryRegionFlags::WRITE);
            let kind = MappingKind::Basic(BasicMapping {
                readable,
                writable,
                executable,
            });
            let phys_base = rgn.guest_region.start as u64;
            let virt_base = kernel_base_va
                + (phys_base - crate::mem::layout::SandboxMemoryLayout::BASE_ADDRESS as u64);
            let mapping = Mapping {
                phys_base,
                virt_base,
                len: rgn.guest_region.len() as u64,
                kind,
                user_accessible: false,
            };
            unsafe { vmem::map(&pt_buf, mapping) };
        }

        // 2. Map the special mappings
        map_specials(&pt_buf, layout.get_scratch_size());

        let pt_bytes = pt_buf.into_bytes();
        layout.set_pt_size(pt_bytes.len())?;
        memory.extend(&pt_bytes);

        let exn_stack_top_gva = nub_host_common::layout::MAX_GVA as u64
            - nub_host_common::layout::SCRATCH_TOP_EXN_STACK_OFFSET
            + 1;

        // Bump the configuration counter so `MultiUseSandbox::id`
        // values stay unique across constructions.
        SANDBOX_CONFIGURATION_COUNTER.fetch_add(1, Ordering::Relaxed);
        let extra_regions: Vec<MemoryRegion> = Vec::new();
        let hash = hash(&memory, &extra_regions)?;

        // Entrypoint GVA: kernel base + offset from ELF base to
        // entrypoint + offset from BASE_ADDRESS to the code's GPA.
        // For the PIE guest, `base_va == 0` and `entrypoint_va` is the
        // offset of the `entrypoint` symbol from the binary's start.
        let entrypoint_gva = kernel_base_va
            + (load_addr - crate::mem::layout::SandboxMemoryLayout::BASE_ADDRESS as u64)
            + (entrypoint_va - base_va);

        Ok(Self {
            memory: ReadonlySharedMemory::from_bytes(&memory)?,
            layout,
            load_info,
            hash,
            stack_top_gva: exn_stack_top_gva,
            entrypoint: NextAction::Initialise(entrypoint_gva),
        })
    }

    /// Return the main memory contents of the snapshot
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn memory(&self) -> &ReadonlySharedMemory {
        &self.memory
    }

    /// Return a copy of the load info for the exe in the snapshot
    pub(crate) fn load_info(&self) -> LoadInfo {
        self.load_info.clone()
    }

    pub(crate) fn layout(&self) -> &crate::mem::layout::SandboxMemoryLayout {
        &self.layout
    }

    pub(crate) fn root_pt_gpa(&self) -> u64 {
        self.layout.get_pt_base_gpa()
    }

    pub(crate) fn stack_top_gva(&self) -> u64 {
        self.stack_top_gva
    }

    pub(crate) fn entrypoint(&self) -> NextAction {
        self.entrypoint
    }
}

impl PartialEq for Snapshot {
    fn eq(&self, other: &Snapshot) -> bool {
        self.hash == other.hash
    }
}
