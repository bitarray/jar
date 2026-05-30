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
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use nub_host_common::vmem::{self, PAGE_TABLE_SIZE};
use tracing::{Span, instrument};

use super::layout::SandboxMemoryLayout;
use super::shared_mem::{
    ExclusiveSharedMemory, GuestSharedMemory, HostSharedMemory, ReadonlySharedMemory, SharedMemory,
};
use crate::Result;
use crate::sandbox::snapshot::{NextAction, Snapshot};

// `SnapshotSharedMemory<S: SharedMemory>` is unconditionally
// `ReadonlySharedMemory`, but it is expressed through an associated
// type with an unused type parameter `S`. rustc rejects an unused type
// parameter on a plain type alias, so this module wraps it in a trait
// to placate the compiler.
mod unused_hack {
    use crate::mem::shared_mem::ReadonlySharedMemory;
    use crate::mem::shared_mem::SharedMemory;
    pub trait SnapshotSharedMemoryT {
        type T<S: SharedMemory>;
    }
    pub struct SnapshotSharedMemory_;
    impl SnapshotSharedMemoryT for SnapshotSharedMemory_ {
        type T<S: SharedMemory> = ReadonlySharedMemory;
    }
    pub type SnapshotSharedMemory<S> = <SnapshotSharedMemory_ as SnapshotSharedMemoryT>::T<S>;
}
impl ReadonlySharedMemory {
    pub(crate) fn to_mgr_snapshot_mem(
        &self,
    ) -> Result<SnapshotSharedMemory<ExclusiveSharedMemory>> {
        let ret = self.clone();
        Ok(ret)
    }
}
pub(crate) use unused_hack::SnapshotSharedMemory;
/// A struct that is responsible for laying out and managing the memory
/// for a given `Sandbox`.
#[derive(Clone)]
pub(crate) struct SandboxMemoryManager<S: SharedMemory> {
    /// Shared memory for the Sandbox
    pub(crate) shared_mem: SnapshotSharedMemory<S>,
    /// Scratch memory for the Sandbox
    pub(crate) scratch_mem: S,
    /// The memory layout of the underlying shared memory
    pub(crate) layout: SandboxMemoryLayout,
    /// Offset for the execution entrypoint from `load_addr`
    pub(crate) entrypoint: NextAction,
    /// How many memory regions were mapped after sandbox creation
    pub(crate) mapped_rgns: u64,
    /// Buffer for accumulating guest abort messages
    pub(crate) abort_buffer: Vec<u8>,
    /// Generation counter: how many snapshots have been taken from
    /// this sandbox's execution path from init to here. Incremented
    /// on each `snapshot` call; on `restore_snapshot` we inherit the
    /// restored snapshot's own generation number so the guest-visible
    /// counter tracks which snapshot the sandbox is a clone of.
    pub(crate) snapshot_count: u64,
}

/// Buffer for building guest page tables during snapshot creation.
/// `TableAddr` is an absolute GPA (u64) so the same address space is
/// used regardless of entry size.
pub(crate) struct GuestPageTableBuffer {
    buffer: std::cell::RefCell<Vec<u8>>,
    phys_base: usize,
    /// Absolute GPA of the currently-active root table. For
    /// multi-root guests, `set_root` switches which root subsequent
    /// `vmem::map` / `vmem::space_aware_map` calls target — typically
    /// to an address previously returned by `alloc_table`.
    root: std::cell::Cell<u64>,
}

impl vmem::TableReadOps for GuestPageTableBuffer {
    type TableAddr = u64;

    fn entry_addr(addr: u64, offset: u64) -> u64 {
        addr + offset
    }

    unsafe fn read_entry(&self, addr: u64) -> vmem::PageTableEntry {
        let buffer = self.buffer.borrow();
        let byte_offset = addr as usize - self.phys_base;
        let pte_size = core::mem::size_of::<vmem::PageTableEntry>();
        let Some(bytes) = buffer.get(byte_offset..byte_offset + pte_size) else {
            return 0;
        };
        let mut buf = [0u8; 8];
        buf[..pte_size].copy_from_slice(bytes);
        vmem::PageTableEntry::from_le_bytes(buf[..pte_size].try_into().unwrap_or_default())
    }

    fn to_phys(addr: u64) -> vmem::PhysAddr {
        addr as vmem::PhysAddr
    }

    fn from_phys(addr: vmem::PhysAddr) -> u64 {
        #[allow(clippy::unnecessary_cast)]
        {
            addr as u64
        }
    }

    fn root_table(&self) -> u64 {
        self.root.get()
    }
}

impl vmem::TableOps for GuestPageTableBuffer {
    type TableMovability = vmem::MayNotMoveTable;

    unsafe fn alloc_table(&self) -> u64 {
        let mut b = self.buffer.borrow_mut();
        let offset = b.len();
        b.resize(offset + PAGE_TABLE_SIZE, 0);
        (self.phys_base + offset) as u64
    }

    unsafe fn write_entry(&self, addr: u64, entry: vmem::PageTableEntry) -> Option<vmem::Void> {
        let mut b = self.buffer.borrow_mut();
        let byte_offset = addr as usize - self.phys_base;
        let pte_size = core::mem::size_of::<vmem::PageTableEntry>();
        if let Some(slice) = b.get_mut(byte_offset..byte_offset + pte_size) {
            slice.copy_from_slice(&entry.to_le_bytes()[..pte_size]);
        }
        None
    }

    unsafe fn update_root(&self, impossible: vmem::Void) {
        match impossible {}
    }
}

impl core::convert::AsRef<GuestPageTableBuffer> for GuestPageTableBuffer {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl GuestPageTableBuffer {
    /// Create a new buffer with an initial zeroed root table at
    /// `phys_base`. The returned buffer's current root is `phys_base`;
    /// additional roots can be obtained by calling `alloc_table`.
    pub(crate) fn new(phys_base: usize) -> Self {
        GuestPageTableBuffer {
            buffer: std::cell::RefCell::new(vec![0u8; PAGE_TABLE_SIZE]),
            phys_base,
            root: std::cell::Cell::new(phys_base as u64),
        }
    }

    pub(crate) fn into_bytes(self) -> Box<[u8]> {
        self.buffer.into_inner().into_boxed_slice()
    }
}

impl<S> SandboxMemoryManager<S>
where
    S: SharedMemory,
{
    /// Create a new `SandboxMemoryManager` with the given parameters
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn new(
        layout: SandboxMemoryLayout,
        shared_mem: SnapshotSharedMemory<S>,
        scratch_mem: S,
        entrypoint: NextAction,
    ) -> Self {
        Self {
            layout,
            shared_mem,
            scratch_mem,
            entrypoint,
            mapped_rgns: 0,
            abort_buffer: Vec::new(),
            snapshot_count: 0,
        }
    }

    /// Get mutable access to the abort buffer
    pub(crate) fn get_abort_buffer_mut(&mut self) -> &mut Vec<u8> {
        &mut self.abort_buffer
    }
}

impl SandboxMemoryManager<ExclusiveSharedMemory> {
    pub(crate) fn from_snapshot(s: &Snapshot) -> Result<Self> {
        let layout = *s.layout();
        let shared_mem = s.memory().to_mgr_snapshot_mem()?;
        let scratch_mem = ExclusiveSharedMemory::new(s.layout().get_scratch_size())?;
        let entrypoint = s.entrypoint();
        Ok(Self::new(layout, shared_mem, scratch_mem, entrypoint))
    }

    /// Wraps ExclusiveSharedMemory::build
    // Morally, this should not have to be a Result: this operation is
    // infallible. The source of the Result is
    // update_scratch_bookkeeping(), which calls functions that can
    // fail due to bounds checks (which are statically known to be ok
    // in this situation) or due to failing to take the scratch shared
    // memory lock, but the scratch shared memory is built in this
    // function, its lock does not escape before the end of the
    // function, and the lock is taken by no other code path, so we
    // know it is not contended.
    pub fn build(
        self,
    ) -> Result<(
        SandboxMemoryManager<HostSharedMemory>,
        SandboxMemoryManager<GuestSharedMemory>,
    )> {
        let (hshm, gshm) = self.shared_mem.build();
        let (hscratch, gscratch) = self.scratch_mem.build();
        let mut host_mgr = SandboxMemoryManager {
            shared_mem: hshm,
            scratch_mem: hscratch,
            layout: self.layout,
            entrypoint: self.entrypoint,
            mapped_rgns: self.mapped_rgns,
            abort_buffer: self.abort_buffer,
            snapshot_count: self.snapshot_count,
        };
        let guest_mgr = SandboxMemoryManager {
            shared_mem: gshm,
            scratch_mem: gscratch,
            layout: self.layout,
            entrypoint: self.entrypoint,
            mapped_rgns: self.mapped_rgns,
            abort_buffer: Vec::new(), // Guest doesn't need abort buffer
            snapshot_count: self.snapshot_count,
        };
        host_mgr.update_scratch_bookkeeping()?;
        Ok((host_mgr, guest_mgr))
    }
}

impl SandboxMemoryManager<HostSharedMemory> {
    /// Push raw bytes (e.g. a rkyv-archived `Request` envelope) onto
    /// the guest's input data ring.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write_guest_function_call_raw(&mut self, buffer: &[u8]) -> Result<()> {
        self.scratch_mem.push_buffer(
            self.layout.get_input_data_buffer_scratch_host_offset(),
            self.layout.sandbox_memory_config.get_input_data_size(),
            buffer,
        )
    }

    /// Pop the response bytes (e.g. a rkyv-archived `Response`
    /// envelope) from the guest's output data ring.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn read_guest_function_call_result_raw(&mut self) -> Result<Vec<u8>> {
        self.scratch_mem.try_pop_buffer_raw(
            self.layout.get_output_data_buffer_scratch_host_offset(),
            self.layout.sandbox_memory_config.get_output_data_size(),
        )
    }

    /// Pop raw bytes from the output ring — used by the host's
    /// `OutBAction::CallFunction` arm to read the guest's request.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn read_host_function_call_raw(&mut self) -> Result<Vec<u8>> {
        self.scratch_mem.try_pop_buffer_raw(
            self.layout.get_output_data_buffer_scratch_host_offset(),
            self.layout.sandbox_memory_config.get_output_data_size(),
        )
    }

    /// Push raw bytes (response to a guest→host call) onto the
    /// guest's input data ring.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write_host_function_response_raw(&mut self, buffer: &[u8]) -> Result<()> {
        self.scratch_mem.push_buffer(
            self.layout.get_input_data_buffer_scratch_host_offset(),
            self.layout.sandbox_memory_config.get_input_data_size(),
            buffer,
        )
    }

    /// Read guest log data from the `SharedMemory` contained within `self`
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn read_guest_log_data(&mut self) -> Result<GuestLogData> {
        self.scratch_mem.try_pop_buffer_into::<GuestLogData>(
            self.layout.get_output_data_buffer_scratch_host_offset(),
            self.layout.sandbox_memory_config.get_output_data_size(),
        )
    }

    pub(crate) fn clear_io_buffers(&mut self) {
        // Clear the output data buffer
        loop {
            let Ok(_) = self.scratch_mem.try_pop_buffer_into::<Vec<u8>>(
                self.layout.get_output_data_buffer_scratch_host_offset(),
                self.layout.sandbox_memory_config.get_output_data_size(),
            ) else {
                break;
            };
        }
        // Clear the input data buffer
        loop {
            let Ok(_) = self.scratch_mem.try_pop_buffer_into::<Vec<u8>>(
                self.layout.get_input_data_buffer_scratch_host_offset(),
                self.layout.sandbox_memory_config.get_input_data_size(),
            ) else {
                break;
            };
        }
    }

    #[inline]
    fn update_scratch_bookkeeping_item(&mut self, offset: u64, value: u64) -> Result<()> {
        let scratch_size = self.scratch_mem.mem_size();
        let base_offset = scratch_size - offset as usize;
        self.scratch_mem.write::<u64>(base_offset, value)
    }

    fn update_scratch_bookkeeping(&mut self) -> Result<()> {
        use nub_host_common::layout::*;
        let scratch_size = self.scratch_mem.mem_size();
        self.update_scratch_bookkeeping_item(SCRATCH_TOP_SIZE_OFFSET, scratch_size as u64)?;
        self.update_scratch_bookkeeping_item(
            SCRATCH_TOP_ALLOCATOR_OFFSET,
            self.layout.get_first_free_scratch_gpa(),
        )?;
        // Record the GPA of the snapshot's copy of the page tables.
        // The copy lives at the tail of the snapshot blob; we copy it
        // into scratch below so the guest walker can run against
        // mutable, TLB-fresh tables. The guest reads this GPA during
        // CoW fault-in to follow the original PTs on the first write
        // — until the HV can execute directly out of the
        // snapshot-resident PTs, at which point the whole split goes
        // away.
        self.update_scratch_bookkeeping_item(
            SCRATCH_TOP_SNAPSHOT_PT_GPA_BASE_OFFSET,
            self.layout.get_pt_base_gpa(),
        )?;
        self.update_scratch_bookkeeping_item(
            SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET,
            self.snapshot_count,
        )?;

        // Initialise the guest input and output data buffers in
        // scratch memory. TODO: remove the need for this.
        self.scratch_mem.write::<u64>(
            self.layout.get_input_data_buffer_scratch_host_offset(),
            SandboxMemoryLayout::STACK_POINTER_SIZE_BYTES,
        )?;
        self.scratch_mem.write::<u64>(
            self.layout.get_output_data_buffer_scratch_host_offset(),
            SandboxMemoryLayout::STACK_POINTER_SIZE_BYTES,
        )?;

        // Copy page tables from `shared_mem` into scratch. PT bytes
        // are appended to the snapshot blob at build time and live
        // just past the end of the guest-visible KVM slot (see
        // `Snapshot::new`). Keeping them outside the KVM slot avoids
        // overlapping with `map_file_cow` regions installed
        // immediately after the snapshot in the guest PA space.
        let snapshot_pt_end = self.shared_mem.mem_size();
        let snapshot_pt_size = self.layout.get_pt_size();
        let snapshot_pt_start = snapshot_pt_end - snapshot_pt_size;
        self.scratch_mem.with_exclusivity(|scratch| {
            let bytes = &self.shared_mem.as_slice()[snapshot_pt_start..snapshot_pt_end];
            #[allow(clippy::needless_borrow)]
            scratch.copy_from_slice(&bytes, self.layout.get_pt_base_scratch_offset())
        })??;

        Ok(())
    }
}
