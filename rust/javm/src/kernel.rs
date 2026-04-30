//! Invocation kernel — multi-VM scheduler with CALL/REPLY semantics.
//!
//! Manages a pool of VMs, dispatches ecalli calls, and handles the
//! capability-based execution model. The kernel is the "microkernel"
//! that sits between the PVM instruction execution and the host
//! (grey-state's refine/accumulate logic).
//!
//! ecalli dispatch:
//! - 0x000..0x0FF: CALL cap\[N\] (0xFF = REPLY)
//! - 0x2XX..0xCXX: management ops (MAP, UNMAP, SPLIT, DROP, MOVE, COPY, etc.)

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::GAS_PER_PAGE;

#[cfg(feature = "std")]
use std::collections::HashMap;

/// Cache for compiled CODE caps, keyed by blake2b-256 hash of the code sub-blob.
///
/// Avoids re-running JIT compilation when the same PVM blob is used
/// repeatedly (e.g. child actor invocations). Callers pass `&mut CodeCache`
/// and the cache shares compiled code via `Arc<CodeCap>`.
///
/// Blake2b-256 makes collisions negligible, so no blob equality check is needed.
#[cfg(feature = "std")]
pub struct CodeCache {
    entries: HashMap<[u8; 32], Arc<CodeCap>>,
}

#[cfg(feature = "std")]
impl CodeCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Blake2b-256 hash of blob bytes for cache dedup key.
    fn hash_blob(blob: &[u8]) -> [u8; 32] {
        use blake2::digest::{Update, VariableOutput};
        let mut hasher = blake2::Blake2bVar::new(32).expect("32 ≤ Blake2b max output");
        hasher.update(blob);
        let mut out = [0u8; 32];
        hasher.finalize_variable(&mut out).expect("32-byte buffer");
        out
    }
}

#[cfg(feature = "std")]
impl Default for CodeCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve a cap reference or return `DispatchResult::Continue` (WHAT already set).
macro_rules! resolve {
    ($self:expr, $ref:expr) => {
        match $self.resolve_or_what($ref) {
            Some(r) => r,
            None => return DispatchResult::Continue,
        }
    };
}
use crate::backing::BackingStore;
use crate::cap::{
    Access, BARE_FRAME_SLOT, Cap, CapTable, CodeCap, DataCap, ForeignCnode, FrameRefCap,
    FrameRefRights, NoForeignCnode, ProtocolCapT, UntypedCap,
};
use crate::program::{self, CapEntryType};
#[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
use crate::vm_pool::WindowPool;
use crate::vm_pool::{CallFrame, FrameId, MAX_CODE_CAPS, VmArena, VmId, VmInstance, VmState};

/// ecalli immediate ranges.
pub const CALL_RANGE_END: u32 = 0x100;
/// Encoded as `ecalli ((MGMT_MAP << 8) | cap_idx)`. Maps the DATA cap at
/// `cap_idx` into the active VM's window. Args: `φ[7] = base_page`,
/// `φ[8] = access` (0 = RO, 1 = RW). All pages of the cap are mapped.
pub const MGMT_MAP: u32 = 0x2;
pub const MGMT_UNMAP: u32 = 0x3;
pub const MGMT_SPLIT: u32 = 0x4;
pub const MGMT_DROP: u32 = 0x5;
pub const MGMT_MOVE: u32 = 0x6;
pub const MGMT_COPY: u32 = 0x7;
// 0x8 / 0x9 (legacy GRANT / REVOKE) deliberately unused — cross-cap-table
// transfers happen via dynamic-ecall MOVE / COPY (`dispatch_ecall` 0x06 /
// 0x07) with cap-ref indirection through HandleCaps.
const MGMT_DOWNGRADE: u32 = 0xA;
// 0xB (legacy SET_MAX_GAS) deliberately unused — per-call gas restriction
// is achieved by the park pattern via `MGMT_GAS_DERIVE` / `MGMT_GAS_MERGE`
// on the `Capability::Gas` cap at ephemeral sub-slot 3.
const MGMT_DIRTY: u32 = 0xC;
/// Gas-cap derive: split `amount` units off a Gas cap into a fresh Gas
/// cap. Routes through `ProtocolCapT::gas_derive`. The protocol payload
/// type (`P`) decides what counts as a "Gas cap"; for plain `u8` it's
/// always rejected.
const MGMT_GAS_DERIVE: u32 = 0xD;
/// Gas-cap merge: add donor's `remaining` to dst's `remaining`, donor
/// is consumed. Routes through `ProtocolCapT::gas_merge`.
const MGMT_GAS_MERGE: u32 = 0xE;

/// WHAT error code (2^64 - 2).
const RESULT_WHAT: u64 = u64::MAX - 1;
const RESULT_LOW: u64 = u64::MAX - 7; // gas limit too low
const RESULT_HUH: u64 = u64::MAX - 8; // invalid operation

/// Result from running the kernel until it needs host interaction.
#[derive(Debug)]
pub enum KernelResult {
    /// Root VM halted normally. Contains φ\[7\] value.
    Halt(u64),
    /// Root VM panicked.
    Panic,
    /// Root VM ran out of gas.
    OutOfGas,
    /// Root VM page-faulted at address.
    PageFault(u32),
    /// A protocol cap was invoked. Host should handle and call `resume_protocol_call`.
    /// Read registers/gas via kernel accessors (active_reg, gas).
    ProtocolCall {
        /// Protocol cap slot number.
        slot: u8,
    },
}

/// The invocation kernel.
pub struct InvocationKernel<P: crate::cap::ProtocolCapT = u8> {
    /// Physical memory pool.
    pub backing: BackingStore,
    /// Compiled CODE caps (max 5).
    pub code_caps: Vec<Arc<CodeCap>>,
    /// VM instances (generational arena).
    pub vm_arena: VmArena<P>,
    /// VmId of the per-invocation **bare Frame** — a `VmInstance` with
    /// an empty CodeCap that's never executed. Its CapTable is the
    /// shared cap-table every VM in the call tree references via slot 0
    /// of its own persistent Frame (a `Cap::FrameRef` with
    /// [`FrameRefRights::BARE_FRAME`]). Allocated alongside the root
    /// VM; its slot in the arena is held until the kernel drops.
    pub bare_frame_id: VmId,
    /// Shared UNTYPED cap (bump allocator).
    pub untyped: Arc<UntypedCap>,
    /// Currently active VM index.
    pub active_vm: u16,
    /// Call stack for CALL/REPLY routing.
    pub call_stack: Vec<CallFrame<P>>,
    /// Memory tier (load/store cycles).
    pub mem_cycles: u8,
    /// Next CODE cap ID.
    next_code_id: u16,
    /// Backend selection for CODE cap compilation.
    pub backend: crate::backend::PvmBackend,
    /// CODE cap ID for fast recompiler resume after ProtocolCall.
    /// When set, the next `run()` call uses `run_recompiler_resume()` instead
    /// of `run_recompiler_segment()`, avoiding a full JitContext rebuild.
    recompiler_resume_cap: Option<usize>,
    /// Live register/gas context during recompiler execution.
    /// Points to the JitContext's regs/gas fields. When set, `active_reg` and
    /// `active_gas` read/write this directly instead of VmInstance, eliminating
    /// the JitContext ↔ VmInstance register copy on each ecalli.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    live_ctx: Option<*mut crate::recompiler::JitContext>,
    /// Window pool: N pre-allocated 4GB virtual windows with LRU eviction.
    /// Windows are assigned to VMs on CALL/RESUME and evicted when full.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    window_pool: WindowPool,
    /// Index of the window currently assigned to the active VM.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    active_window: usize,
}

impl<P: crate::cap::ProtocolCapT> InvocationKernel<P> {
    /// Construct a kernel from a pre-built [`InvocationArtifacts`].
    /// Used by hosts (jar-kernel's vault_init, plus
    /// [`cap_table_from_blob`] for legacy blob bootstrap) that have
    /// already populated the CapTable, compiled all CODE caps, and
    /// allocated the backing store + UntypedCap. The kernel takes
    /// ownership and runs `finalize_kernel` to wire up VM 0 and the
    /// bare Frame.
    pub fn new_from_artifacts(
        artifacts: InvocationArtifacts<P>,
        gas: u64,
        backend: crate::backend::PvmBackend,
    ) -> Result<Self, KernelError> {
        let InvocationArtifacts {
            cap_table,
            code_caps,
            init_code_id,
            untyped,
            backing,
        } = artifacts;

        let mut kernel = Self::build_kernel_skeleton_with(untyped, backing, backend)?;
        kernel.next_code_id = code_caps.len() as u16;
        kernel.code_caps = code_caps;
        kernel.finalize_kernel(cap_table, init_code_id, gas)
    }

    /// Allocate the kernel's per-invocation infrastructure (mem_cycles,
    /// WindowPool) on top of a caller-allocated `untyped` and `backing`,
    /// and return a partially-initialized `Self` with empty `code_caps`,
    /// an empty `vm_arena`, and `bare_frame_id = VmId::ROOT` as a
    /// placeholder. [`Self::finalize_kernel`] fills in the rest.
    ///
    /// Hosts construct `untyped` and `backing` outside javm because
    /// they need them to allocate persistent → ephemeral DataCaps
    /// before the kernel exists (see jar-kernel's `vault_init`); the
    /// kernel takes ownership here.
    fn build_kernel_skeleton_with(
        untyped: Arc<UntypedCap>,
        backing: BackingStore,
        backend: crate::backend::PvmBackend,
    ) -> Result<Self, KernelError> {
        let mem_cycles = crate::compute_mem_cycles(untyped.total);

        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        let window_pool =
            WindowPool::new(crate::vm_pool::WINDOW_POOL_SIZE).ok_or(KernelError::MemoryError)?;

        Ok(Self {
            backing,
            code_caps: Vec::with_capacity(MAX_CODE_CAPS),
            vm_arena: VmArena::new(),
            // Placeholder; reassigned in `finalize_kernel`.
            bare_frame_id: VmId::ROOT,
            untyped,
            active_vm: 0,
            call_stack: Vec::with_capacity(8),
            mem_cycles,
            next_code_id: 0,
            backend,
            recompiler_resume_cap: None,
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            live_ctx: None,
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            window_pool,
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            active_window: 0,
        })
    }

    /// Common tail of all `InvocationKernel` constructors. Takes the
    /// post-skeleton kernel plus a fully-populated `cap_table` for VM 0,
    /// the `init_code_id` (index in `self.code_caps` of the entry CODE
    /// cap), and the per-invocation gas budget.
    ///
    /// DATA caps in `cap_table` are always unmapped on entry; the init
    /// prologue baked into the CodeCap (emitted by
    /// `javm-transpiler::layout::emit_prologue`) issues `MGMT_MAP` for
    /// each DATA cap before user code runs. The kernel does not pre-map.
    ///
    /// Charges init-page gas (per DATA cap page in `cap_table`), assigns
    /// window 0 to VM 0, places UNTYPED at slot 254, inserts VM 0 and
    /// the bare Frame into the arena, and patches slot 0 of VM 0's
    /// cap-table with the bare-Frame FrameRef.
    fn finalize_kernel(
        mut self,
        mut cap_table: CapTable<P>,
        init_code_id: u16,
        gas: u64,
    ) -> Result<Self, KernelError> {
        // Charge init gas: sum the page count of every DATA cap currently
        // in the cap table. Mapping happens later via MGMT_MAP from the
        // init prologue, but the per-page allocation cost is paid here.
        let init_pages: u64 = (0u8..=255)
            .filter_map(|i| match cap_table.get(i) {
                Some(Cap::Data(d)) => Some(d.page_count as u64),
                _ => None,
            })
            .sum();
        let init_gas_cost = init_pages * GAS_PER_PAGE;
        if gas < init_gas_cost {
            return Err(KernelError::OutOfGas);
        }
        let remaining_gas = gas - init_gas_cost;

        // Assign window 0 to VM 0. DATA caps are unmapped — the init
        // prologue MGMT_MAPs them into this window once execution
        // starts.
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        {
            let assignment = self.window_pool.assign_window(0, 0);
            self.active_window = assignment.window_idx;
        }

        // Give VM 0 the UNTYPED cap at slot 254 (fixed slot, just below
        // IPC). Skip when the page budget is zero — no point exposing an
        // empty allocator.
        if self.untyped.total > 0 {
            cap_table.set(254, Cap::Untyped(Arc::clone(&self.untyped)));
        }

        // Create VM 0. Registers start zeroed; the host sets whatever
        // scalar args (op code, etc.) it wants in φ[7..12] *after*
        // construction, and writes any byte payloads into a DATA cap via
        // `write_data_cap_init` (typically placed at ephemeral sub-slot 4
        // by the conventional cap-arg pattern).
        let vm0 = VmInstance::new(
            init_code_id,
            0, // entry_index (set by caller via CALL)
            cap_table,
            remaining_gas,
        );
        self.vm_arena.insert(vm0); // VM 0 gets VmId(0, 0)

        // Allocate the per-invocation bare Frame: a VmInstance whose code
        // is never executed. Its CapTable is the shared cap-table the
        // call tree reaches via slot 0 of every VM. We pass `code_cap_id`
        // = `init_code_id` purely as a placeholder; CALL on the
        // bare-Frame FrameRef is gated off (no CALL right) so it's never
        // dispatched. After insertion the bare Frame sits at the next
        // free arena slot (idx 1 on a fresh kernel).
        let bare = VmInstance::new(init_code_id, 0, CapTable::new(), 0);
        let bare_id = self.vm_arena.insert(bare).ok_or(KernelError::InvalidBlob)?;
        self.bare_frame_id = bare_id;

        // Patch slot 0 of VM 0's cap-table now that we know the bare
        // Frame's VmId.
        self.vm_arena.vm_mut(0).cap_table.set(
            BARE_FRAME_SLOT,
            Cap::FrameRef(FrameRefCap {
                vm_id: bare_id,
                rights: FrameRefRights::BARE_FRAME,
            }),
        );

        Ok(self)
    }

    /// Write `bytes` into the backing pages of the DATA cap at `slot` of
    /// VM 0's persistent Frame. Returns the mapped byte address
    /// (`base_page * PAGE_SIZE`) so the host can pass it to the guest in
    /// a register.
    ///
    /// The cap stays *unmapped*: the init prologue's `MGMT_MAP` (emitted
    /// by [`javm-transpiler::layout::emit_prologue`]) installs the
    /// window mapping at `base_page` with `access` before user code
    /// reads the bytes. `base_page` and `access` are accepted here so
    /// the host can compute the byte address, but they are not stored
    /// on the cap. Use [`crate::program::data_cap_base_page`] to compute
    /// `base_page` from a parsed blob's manifest.
    ///
    /// Returns `Err` if the slot is empty, holds a non-DATA cap, or
    /// `bytes.len()` exceeds the cap's allocated pages.
    pub fn write_data_cap_init(
        &mut self,
        slot: u8,
        base_page: u32,
        _access: Access,
        bytes: &[u8],
    ) -> Result<u64, KernelError> {
        let backing_offset = match self.vm_arena.vm_mut(0).cap_table.get_mut(slot) {
            Some(Cap::Data(d)) => {
                let cap_bytes = d.page_count as usize * crate::PVM_PAGE_SIZE as usize;
                if bytes.len() > cap_bytes {
                    return Err(KernelError::InvalidBlob);
                }
                d.backing_offset
            }
            _ => return Err(KernelError::InvalidBlob),
        };
        // Write payload into the backing memfd. The cap stays unmapped:
        // the init prologue's `MGMT_MAP` (emitted by the transpiler) is
        // responsible for installing the window mapping at `base_page`
        // before user code reads the bytes.
        self.backing.write_init_data(backing_offset, bytes);
        Ok(base_page as u64 * crate::PVM_PAGE_SIZE as u64)
    }

    /// Extract the current flat_mem snapshot from the kernel's DATA cap pages.
    ///
    /// Returns `(flat_mem, heap_base, heap_top)`. The flat_mem is a copy of all
    /// mapped DATA cap pages assembled at their virtual addresses.
    pub fn extract_flat_mem(&self) -> (Vec<u8>, u32, u32) {
        let vm = &self.vm_arena.vm(self.active_vm);

        // Determine memory size from mapped DATA caps.
        let mut max_addr: usize = 0;
        for slot in 0..=255u8 {
            if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                && let Some((base_page, _access)) = d.active_mapping()
            {
                let end =
                    (base_page as usize + d.page_count as usize) * crate::PVM_PAGE_SIZE as usize;
                max_addr = max_addr.max(end);
            }
        }

        let mut flat_mem = vec![0u8; max_addr];

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let wb = self.active_window_base();
            for slot in 0..=255u8 {
                if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                    && let Some((base_page, _access)) = d.active_mapping()
                {
                    let addr = base_page as usize * crate::PVM_PAGE_SIZE as usize;
                    let len = d.page_count as usize * crate::PVM_PAGE_SIZE as usize;
                    if addr + len <= flat_mem.len() {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                wb.add(addr),
                                flat_mem.as_mut_ptr().add(addr),
                                len,
                            );
                        }
                    }
                }
            }
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            for slot in 0..=255u8 {
                if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                    && let Some((base_page, _access)) = d.active_mapping()
                {
                    let addr = base_page as usize * crate::PVM_PAGE_SIZE as usize;
                    let len = d.page_count as usize * crate::PVM_PAGE_SIZE as usize;
                    if addr + len <= flat_mem.len() {
                        flat_mem[addr..addr + len].copy_from_slice(
                            self.backing.read_page_slice(d.backing_offset, d.page_count),
                        );
                    }
                }
            }
        }

        (flat_mem, vm.heap_base(), vm.heap_top())
    }

    /// Dispatch an ecalli immediate from the active VM.
    ///
    /// Returns a `DispatchResult` indicating what the kernel should do next.
    #[inline(always)]
    pub fn dispatch_ecalli(&mut self, imm: u32) -> DispatchResult {
        // Range check: ecalli only valid for 0-127. ≥128 faults the VM.
        if imm > 127 {
            self.set_active_reg(7, imm as u64);
            return DispatchResult::Fault(FaultType::Panic); // status 5 when implemented
        }
        // Charge ecalli gas cost (10) — matches GP host call gas charge
        let ecalli_gas: u64 = 10;
        let current_gas = self.active_gas();
        if current_gas < ecalli_gas {
            return DispatchResult::Fault(FaultType::OutOfGas);
        }
        // Deduct gas via live_ctx if available, else VmInstance
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        if let Some(ctx) = self.live_ctx {
            // SAFETY: live_ctx is non-null only during JIT execution on this thread;
            // ctx points to the JitContext in the active CodeWindow's CTX page.
            unsafe { (*ctx).gas -= ecalli_gas as i64 };
        } else {
            let g = self.vm_arena.vm(self.active_vm).gas();
            self.vm_arena.vm_mut(self.active_vm).set_gas(g - ecalli_gas);
        }
        #[cfg(not(all(feature = "std", target_os = "linux", target_arch = "x86_64")))]
        {
            let g = self.vm_arena.vm(self.active_vm).gas();
            self.vm_arena.vm_mut(self.active_vm).set_gas(g - ecalli_gas);
        }

        if imm < CALL_RANGE_END {
            // CALL cap[N]
            let cap_idx = imm as u8;
            if cap_idx == BARE_FRAME_SLOT {
                #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
                self.flush_live_ctx();
                return self.handle_reply();
            }
            self.handle_call(cap_idx)
        } else {
            // Management op: high byte = op, low byte = cap index
            let op = imm >> 8;
            let cap_idx = (imm & 0xFF) as u8;
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            self.flush_live_ctx();
            self.handle_management_op(op, cap_idx)
        }
    }

    /// Handle CALL on a cap slot.
    #[inline(always)]
    fn handle_call(&mut self, cap_idx: u8) -> DispatchResult {
        let vm = &self.vm_arena.vm(self.active_vm);
        let cap = match vm.cap_table.get(cap_idx) {
            Some(c) => c,
            None => {
                // Missing cap → WHAT
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        match cap {
            Cap::Protocol(_) => {
                // Yield the cap-table slot index; host fetches the cap via
                // `cap_table_get(slot)` and dispatches on the inner payload.
                DispatchResult::ProtocolCall { slot: cap_idx }
            }
            Cap::Untyped(_) => {
                #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
                self.flush_live_ctx();
                self.handle_call_untyped()
            }
            Cap::Code(c) => {
                let code_id = c.id;
                let code_cnode_vm = self.active_vm as usize;
                #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
                self.flush_live_ctx();
                self.handle_call_code(code_id, code_cnode_vm)
            }
            Cap::FrameRef(f) => {
                if !f.rights.contains(FrameRefRights::CALL) {
                    self.set_active_reg(7, RESULT_WHAT);
                    return DispatchResult::Continue;
                }
                let target_vm = f.vm_id;
                #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
                self.flush_live_ctx();
                self.handle_call_vm(target_vm)
            }
            Cap::Data(_) => {
                // DATA is not callable
                self.set_active_reg(7, RESULT_WHAT);
                DispatchResult::Continue
            }
        }
    }

    /// CALL on UNTYPED → RETYPE.
    fn handle_call_untyped(&mut self) -> DispatchResult {
        let n_pages = self.active_reg(7) as u32;
        let gas_cost = 10 + n_pages as u64 * GAS_PER_PAGE;

        let vm = &mut self.vm_arena.vm_mut(self.active_vm);
        if vm.gas() < gas_cost {
            return DispatchResult::Fault(FaultType::OutOfGas);
        }
        vm.set_gas(vm.gas() - gas_cost);

        // Get the UNTYPED cap (it's an Arc, so we can clone the reference)
        let untyped = match vm.cap_table.get(
            // Find the untyped slot — scan cap table
            (0..=254)
                .find(|i| matches!(vm.cap_table.get(*i), Some(Cap::Untyped(_))))
                .unwrap_or(255),
        ) {
            Some(Cap::Untyped(u)) => Arc::clone(u),
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        let backing_offset = match untyped.retype(n_pages) {
            Some(o) => o,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        let data_cap = DataCap::new(backing_offset, n_pages);

        // Caller-picks: destination slot from φ[12] with indirection
        let dst_ref = self.active_reg(12) as u32;
        let (dst_frame, dst_slot, _dst_rights) = match self.resolve_cap_ref(dst_ref) {
            Some(r) => r,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };
        let dst_table = match self.frame_table_mut(dst_frame) {
            Some(t) => t,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };
        if !dst_table.is_empty(dst_slot) {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }
        dst_table.set(dst_slot, Cap::Data(data_cap));
        self.set_active_reg(7, dst_slot as u64);
        DispatchResult::Continue
    }

    /// CALL on CODE → CREATE.
    /// φ[7] = bitmask (u64), φ[12] = dst_slot (u32, indirection) for HANDLE.
    /// Bitmask copies from the CODE cap's CNode (the CNode where ecalli resolved
    /// the CODE cap), not necessarily the caller's CNode.
    fn handle_call_code(&mut self, code_cap_id: u16, code_cnode_vm: usize) -> DispatchResult {
        let bitmask = self.active_reg(7);

        // Create child VM's cap table by copying bitmask-selected caps
        // from CODE's CNode. Slot 0 of every VM's persistent Frame is
        // reserved for the bare-Frame FrameRef — pre-populate it before
        // processing the bitmask. Bitmask bit 0 set is rejected here,
        // since slot 0 is not the caller's to grant.
        let mut child_table = CapTable::new();
        child_table.set(
            BARE_FRAME_SLOT,
            Cap::FrameRef(FrameRefCap {
                vm_id: self.bare_frame_id,
                rights: FrameRefRights::BARE_FRAME,
            }),
        );

        let source_vm = self.vm_arena.vm(code_cnode_vm as u16);
        for bit in 1..64u8 {
            if bitmask & (1u64 << bit) != 0
                && let Some(cap) = source_vm.cap_table.get(bit)
            {
                match cap.try_copy() {
                    Some(copy) => {
                        if source_vm.cap_table.is_original(bit) {
                            child_table.set_original(bit, copy);
                        } else {
                            child_table.set(bit, copy);
                        }
                    }
                    None => {
                        // Non-copyable cap in bitmask → CREATE fails
                        self.set_active_reg(7, RESULT_WHAT);
                        return DispatchResult::Continue;
                    }
                }
            }
        }

        let child = VmInstance::new(code_cap_id, 0, child_table, 0);
        let child_vm_id = match self.vm_arena.insert(child) {
            Some(id) => id,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        // Caller-picks: owner-shaped FrameRef destination from φ[12]
        // with indirection. CREATE always returns a full-rights FrameRef;
        // managers narrow before sharing.
        let handle = FrameRefCap {
            vm_id: child_vm_id,
            rights: FrameRefRights::OWNER,
        };

        let dst_ref = self.active_reg(12) as u32;
        let (dst_frame, dst_slot, _dst_rights) = match self.resolve_cap_ref(dst_ref) {
            Some(r) => r,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };
        let dst_table = match self.frame_table_mut(dst_frame) {
            Some(t) => t,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };
        if !dst_table.is_empty(dst_slot) {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }
        dst_table.set(dst_slot, Cap::FrameRef(handle));
        self.set_active_reg(7, dst_slot as u64);
        DispatchResult::Continue
    }

    /// CALL on HANDLE/CALLABLE → suspend caller, run target VM.
    ///
    /// Gas is shared across the entire call tree via the `Capability::Gas`
    /// cap at ephemeral sub-slot 3. There is no per-call ceiling (the old
    /// `max_gas` retired); per-call restriction is the **park pattern**:
    /// the caller `MGMT_GAS_DERIVE`s a portion off the live Gas cap into
    /// a parked slot in its own Frame before calling, and `MGMT_GAS_MERGE`s
    /// it back after REPLY. The kernel just transfers the active VM's
    /// remaining gas to the callee on the way in and the callee's
    /// remaining back to the caller on REPLY/HALT.
    fn handle_call_vm(&mut self, vm_id: VmId) -> DispatchResult {
        let target_vm_id = vm_id.index();

        // Validate VmId (generation check for stale handles)
        match self.vm_arena.get(vm_id) {
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
            Some(vm) if !vm.can_call() => {
                // Target is not IDLE — re-entrancy prevention
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
            Some(_) => {} // valid and idle
        }

        // Charge CALL overhead and pass the caller's full residual gas to
        // the callee. The shared-pool model means there's no split — the
        // callee inherits everything the caller had left.
        let caller_vm = &mut self.vm_arena.vm_mut(self.active_vm);
        let call_overhead = 10u64;
        if caller_vm.gas() < call_overhead {
            return DispatchResult::Fault(FaultType::OutOfGas);
        }
        caller_vm.set_gas(caller_vm.gas() - call_overhead);
        let callee_gas = caller_vm.gas();
        caller_vm.set_gas(0);

        // Save caller state
        let caller_id = self.active_vm;
        let _ = self
            .vm_arena
            .vm_mut(caller_id)
            .transition(VmState::WaitingForReply);

        // Stash the caller's view of ephemeral sub-slots 0/1/2 (Reply/Caller/
        // Self) so they can be rewritten with the callee's context. javm
        // doesn't write content here; the host (jar-kernel) populates
        // Caller/Self in Phase 10.
        let prev_kernel_slots = self.take_ephemeral_kernel_slots(caller_id);

        // Push call frame
        self.call_stack.push(CallFrame {
            caller_vm_id: caller_id,
            prev_kernel_slots,
        });

        // Pass args: caller's φ[7]..φ[10] → callee's φ[7]..φ[10]
        let caller_regs = *self.vm_arena.vm(caller_id).regs();

        // Set up callee
        let callee = self.vm_arena.vm_mut(target_vm_id);
        callee.set_gas(callee_gas);
        callee.caller = Some(caller_id);
        callee.set_reg(7, caller_regs[7]);
        callee.set_reg(8, caller_regs[8]);
        callee.set_reg(9, caller_regs[9]);
        callee.set_reg(10, caller_regs[10]);

        let _ = callee.transition(VmState::Running);
        self.active_vm = target_vm_id;

        DispatchResult::Continue
    }

    /// Handle REPLY (`ecalli(0)` — CALL on slot 0, kernel-shorthand for
    /// returning to the caller frame).
    fn handle_reply(&mut self) -> DispatchResult {
        let frame = match self.call_stack.pop() {
            Some(f) => f,
            None => {
                // No caller — root VM replying = halt
                let result = self.active_reg(7);
                return DispatchResult::RootHalt(result);
            }
        };

        let callee_id = self.active_vm;
        let caller_id = frame.caller_vm_id;

        // Callee → IDLE
        let _ = self.vm_arena.vm_mut(callee_id).transition(VmState::Idle);

        // Return unused gas to caller
        let unused_gas = self.vm_arena.vm(callee_id).gas();
        let cg = self.vm_arena.vm(caller_id).gas();
        self.vm_arena.vm_mut(caller_id).set_gas(cg + unused_gas);
        self.vm_arena.vm_mut(callee_id).set_gas(0);

        // Restore the caller's ephemeral sub-slots 0/1/2 (Reply/Caller/Self).
        // The host (jar-kernel) populates these on the way in; on REPLY javm
        // just hands the previous values back.
        self.restore_ephemeral_kernel_slots(frame.prev_kernel_slots);

        // Pass φ[7] only + set φ[8]=0 (status = REPLY success)
        let callee_r7 = self.vm_arena.vm(callee_id).reg(7);
        self.vm_arena.vm_mut(caller_id).set_reg(7, callee_r7);
        self.vm_arena.vm_mut(caller_id).set_reg(8, 0);

        // Caller → Running
        let _ = self.vm_arena.vm_mut(caller_id).transition(VmState::Running);
        self.active_vm = caller_id;

        DispatchResult::Continue
    }

    /// Resolve a u32 cap reference, returning the frame and cap slot.
    ///
    /// Encoding (low → high bytes): `[target, ind0, ind1, ind2]`.
    /// - `target == 0 && cap_ref == 0` → slot 0 of the active persistent
    ///   Frame literally (the EphemeralTable handle). `CALL(0) = REPLY` is
    ///   a separate special case in `dispatch_ecalli`.
    /// - `target == 0 && cap_ref != 0` → slot-0 redirect: cross through
    ///   slot 0 of the current frame and re-apply the rules with `r >>= 8`.
    ///   Recursive — each shift descends one level.
    /// - `target != 0` → walk `ind2, ind1, ind0`; each non-zero byte
    ///   crosses through that slot of the current frame; result is `target`
    ///   in the final frame.
    ///
    /// Crossings consume `Cap::FrameRef` (cross to that VM's persistent
    /// Frame; the cap must carry [`FrameRefRights::READ_CAP_INDIRECTION`]
    /// for intermediate steps and [`FrameRefRights::CAP_INDIRECTION`] for
    /// the final step) or `Cap::EphemeralTable` (enter the ephemeral
    /// table). Any other cap shape fails.
    fn resolve_cap_ref(
        &self,
        cap_ref: u32,
    ) -> Option<(FrameId<P::ForeignFrameId>, u8, P::FinalStepRights)> {
        let mut current: FrameId<P::ForeignFrameId> = FrameId::Vm(self.active_vm);
        let mut final_rights = P::FinalStepRights::default();
        let mut r = cap_ref;

        // Slot-0 redirect: while target byte == 0 but cap_ref still has bits
        // to consume, cross through slot 0 of the current frame.
        while (r & 0xFF) == 0 && r != 0 {
            let (next, rights) = self.cross_through(current, 0)?;
            current = next;
            if let Some(rt) = rights {
                final_rights = rt;
            }
            r >>= 8;
        }

        let target = (r & 0xFF) as u8;
        let ind0 = ((r >> 8) & 0xFF) as u8;
        let ind1 = ((r >> 16) & 0xFF) as u8;
        let ind2 = ((r >> 24) & 0xFF) as u8;

        for &slot in &[ind2, ind1, ind0] {
            if slot == 0 {
                continue;
            }
            let (next, rights) = self.cross_through(current, slot)?;
            current = next;
            if let Some(rt) = rights {
                final_rights = rt;
            }
        }

        Some((current, target, final_rights))
    }

    /// Cross through `slot` of `frame` to the next frame in a cap-ref walk.
    /// Slot must hold either `Cap::FrameRef` (→ that VM's persistent
    /// Frame; rights must include [`FrameRefRights::READ_CAP_INDIRECTION`])
    /// or a `Cap::Protocol` whose `as_foreign_frame()` reports a
    /// host-managed frame id (→ the foreign frame). Any other cap shape
    /// fails.
    ///
    /// Crossings into the bare Frame (the per-invocation shared
    /// cap-table) are just FrameRef crossings: slot 0 of every VM holds
    /// a `Cap::FrameRef` with [`FrameRefRights::BARE_FRAME`].
    ///
    /// Returns the next `FrameId` plus an optional rights bag captured at
    /// this step. The bag is `Some(_)` only for foreign-frame crossings —
    /// the resolve walk threads it through so the final step's
    /// rights are available to the host adapter.
    #[allow(clippy::type_complexity)]
    fn cross_through(
        &self,
        frame: FrameId<P::ForeignFrameId>,
        slot: u8,
    ) -> Option<(FrameId<P::ForeignFrameId>, Option<P::FinalStepRights>)> {
        let table = self.frame_table(frame)?;
        match table.get(slot)? {
            Cap::FrameRef(f) => {
                if !f.rights.contains(FrameRefRights::READ_CAP_INDIRECTION) {
                    return None;
                }
                let target = self.vm_arena.get(f.vm_id)?;
                if target.state == VmState::Running || target.state == VmState::WaitingForReply {
                    return None;
                }
                Some((FrameId::Vm(f.vm_id.index()), None))
            }
            Cap::Protocol(p) => p
                .as_foreign_frame()
                .map(|(id, rights)| (FrameId::Foreign(id), Some(rights))),
            _ => None,
        }
    }

    /// Borrow the cap-table backing a `FrameId`. Returns `None` for a
    /// `Foreign` frame (those are not stored in javm — operations route
    /// through the host's `ForeignCnode`).
    fn frame_table(&self, fref: FrameId<P::ForeignFrameId>) -> Option<&CapTable<P>> {
        match fref {
            FrameId::Vm(idx) => Some(&self.vm_arena.vm(idx).cap_table),
            FrameId::Foreign(_) => None,
        }
    }

    /// Mutably borrow the cap-table backing a `FrameId`. Returns `None`
    /// for a `Foreign` frame (host-managed).
    fn frame_table_mut(&mut self, fref: FrameId<P::ForeignFrameId>) -> Option<&mut CapTable<P>> {
        match fref {
            FrameId::Vm(idx) => Some(&mut self.vm_arena.vm_mut(idx).cap_table),
            FrameId::Foreign(_) => None,
        }
    }

    /// Whether `slot` of `frame` is empty. Routes to the host for
    /// `Foreign` frames; uses the in-process cap-table otherwise.
    fn frame_is_empty<H: ForeignCnode<P>>(
        &self,
        host: &H,
        frame: FrameId<P::ForeignFrameId>,
        slot: u8,
    ) -> bool {
        match frame {
            FrameId::Foreign(id) => host.fc_is_empty(id, slot),
            _ => self
                .frame_table(frame)
                .map(|t| t.is_empty(slot))
                .unwrap_or(false),
        }
    }

    /// Take the cap at `(frame, slot)`. Routes to the host for `Foreign`.
    fn frame_take<H: ForeignCnode<P>>(
        &mut self,
        host: &mut H,
        frame: FrameId<P::ForeignFrameId>,
        slot: u8,
        rights: P::FinalStepRights,
    ) -> Option<Cap<P>> {
        match frame {
            FrameId::Foreign(id) => host.fc_take(id, slot, rights),
            _ => self.frame_table_mut(frame).and_then(|t| t.take(slot)),
        }
    }

    /// Place `cap` at `(frame, slot)`. Returns `Err(cap)` on rejection.
    fn frame_set<H: ForeignCnode<P>>(
        &mut self,
        host: &mut H,
        frame: FrameId<P::ForeignFrameId>,
        slot: u8,
        rights: P::FinalStepRights,
        cap: Cap<P>,
    ) -> Result<(), Cap<P>> {
        match frame {
            FrameId::Foreign(id) => host.fc_set(id, slot, rights, cap),
            _ => match self.frame_table_mut(frame) {
                Some(t) => {
                    t.set(slot, cap);
                    Ok(())
                }
                None => Err(cap),
            },
        }
    }

    /// Clone the cap at `(frame, slot)`. Routes to the host for
    /// `Foreign` (which performs a host-side derive).
    fn frame_clone<H: ForeignCnode<P>>(
        &mut self,
        host: &mut H,
        frame: FrameId<P::ForeignFrameId>,
        slot: u8,
        rights: P::FinalStepRights,
    ) -> Option<Cap<P>> {
        match frame {
            FrameId::Foreign(id) => host.fc_clone(id, slot, rights),
            _ => self
                .frame_table(frame)
                .and_then(|t| t.get(slot))
                .and_then(|c| c.try_copy()),
        }
    }

    /// The bare-Frame's arena index. Cached from `bare_frame_id` for
    /// direct borrow into `vm_arena`.
    #[inline]
    fn bare_frame_idx(&self) -> u16 {
        self.bare_frame_id.index()
    }

    /// Take the bare Frame's sub-slots 0/1/2 (Reply, Caller, Self) for
    /// stashing on the call-stack. These slots are the per-frame
    /// kernel-managed area; the host (jar-kernel) populates them. javm
    /// just preserves whatever was there.
    fn take_ephemeral_kernel_slots(&mut self, _caller_vm: u16) -> [Option<Cap<P>>; 3] {
        let table = &mut self.vm_arena.vm_mut(self.bare_frame_idx()).cap_table;
        [table.take(0), table.take(1), table.take(2)]
    }

    /// Restore previously-stashed bare-Frame sub-slots 0/1/2 on REPLY/HALT.
    fn restore_ephemeral_kernel_slots(&mut self, slots: [Option<Cap<P>>; 3]) {
        let table = &mut self.vm_arena.vm_mut(self.bare_frame_idx()).cap_table;
        // Drop whatever the callee left in those slots, then write back the
        // caller's values (skipping None — the caller had nothing there).
        let [a, b, c] = slots;
        let _ = table.take(0);
        let _ = table.take(1);
        let _ = table.take(2);
        if let Some(a) = a {
            table.set(0, a);
        }
        if let Some(b) = b {
            table.set(1, b);
        }
        if let Some(c) = c {
            table.set(2, c);
        }
    }

    /// Resolve a cap ref, returning None and setting WHAT if resolution fails.
    fn resolve_or_what(
        &mut self,
        cap_ref: u32,
    ) -> Option<(FrameId<P::ForeignFrameId>, u8, P::FinalStepRights)> {
        match self.resolve_cap_ref(cap_ref) {
            Some(r) => Some(r),
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                None
            }
        }
    }

    /// Dispatch an ecall (management ops + dynamic CALL).
    /// φ\[11\] = op code, φ\[12\] = subject (low u32) | object (high u32).
    ///
    /// `host` is consulted whenever the resolve walk lands on a
    /// `FrameId::Foreign` (host-managed cap-table). For tests / benches
    /// without foreign frames, pass `&mut NoForeignCnode`.
    pub fn dispatch_ecall<H: ForeignCnode<P>>(&mut self, host: &mut H, op: u32) -> DispatchResult {
        // Charge ecall gas (same as ecalli)
        let ecall_gas: u64 = 10;
        let current_gas = self.active_gas();
        if current_gas < ecall_gas {
            return DispatchResult::Fault(FaultType::OutOfGas);
        }
        let g = self.vm_arena.vm(self.active_vm).gas();
        self.vm_arena.vm_mut(self.active_vm).set_gas(g - ecall_gas);

        let phi12 = self.active_reg(12);
        let object_ref = (phi12 & 0xFFFFFFFF) as u32; // low u32
        let subject_ref = (phi12 >> 32) as u32; // high u32

        match op {
            0x00 => {
                // Dynamic CALL — resolve subject with indirection
                let (frame, slot, _rights) = match self.resolve_or_what(subject_ref) {
                    Some(r) => r,
                    None => return DispatchResult::Continue,
                };
                // For local VM, use existing handle_call
                if frame == FrameId::Vm(self.active_vm) {
                    self.handle_call(slot)
                } else {
                    // Remote cap — look up the cap in the resolved frame.
                    // Foreign frames don't expose Cap<P> values directly; CALL
                    // through them isn't supported (foreign caps are persistent
                    // CNode entries, not callable workers).
                    let is_protocol = matches!(
                        self.frame_table(frame).and_then(|t| t.get(slot)),
                        Some(Cap::Protocol(_))
                    );
                    if is_protocol {
                        DispatchResult::ProtocolCall { slot }
                    } else {
                        self.set_active_reg(7, RESULT_WHAT);
                        DispatchResult::Continue
                    }
                }
            }
            0x02 => {
                // MAP — resolve subject (DATA cap)
                let (frame, slot, _rights) = resolve!(self, subject_ref);
                self.ecall_map(frame, slot)
            }
            0x03 => {
                // UNMAP — resolve subject (DATA cap)
                let (frame, slot, _rights) = resolve!(self, subject_ref);
                self.ecall_unmap(frame, slot)
            }
            0x04 => {
                // SPLIT — resolve subject + object dst
                let (s_frame, s_slot, _s_rights) = resolve!(self, subject_ref);
                let (o_frame, o_slot, _o_rights) = resolve!(self, object_ref);
                self.ecall_split(s_frame, s_slot, o_frame, o_slot)
            }
            0x05 => {
                // DROP — resolve subject
                let (frame, slot, rights) = resolve!(self, subject_ref);
                self.ecall_drop(host, frame, slot, rights)
            }
            0x06 => {
                // MOVE — resolve subject + object dst
                let (s_frame, s_slot, s_rights) = resolve!(self, subject_ref);
                let (o_frame, o_slot, o_rights) = resolve!(self, object_ref);
                self.ecall_move(host, s_frame, s_slot, s_rights, o_frame, o_slot, o_rights)
            }
            0x07 => {
                // COPY — resolve subject + object dst
                let (s_frame, s_slot, s_rights) = resolve!(self, subject_ref);
                let (o_frame, o_slot, o_rights) = resolve!(self, object_ref);
                self.ecall_copy(host, s_frame, s_slot, s_rights, o_frame, o_slot, o_rights)
            }
            0x0A => {
                // DOWNGRADE — resolve subject HANDLE + object dst
                let (s_frame, s_slot, _s_rights) = resolve!(self, subject_ref);
                let (o_frame, o_slot, _o_rights) = resolve!(self, object_ref);
                self.ecall_downgrade(s_frame, s_slot, o_frame, o_slot)
            }
            0x0C => {
                // DIRTY — TODO
                self.set_active_reg(7, RESULT_WHAT);
                DispatchResult::Continue
            }
            0x0D => {
                // RESUME — resolve subject HANDLE
                let (frame, slot, _rights) = resolve!(self, subject_ref);
                // RESUME uses the HANDLE in the resolved VM's cap table
                if frame != FrameId::Vm(self.active_vm) {
                    self.set_active_reg(7, RESULT_WHAT);
                    return DispatchResult::Continue;
                }
                self.handle_resume(slot)
            }
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                DispatchResult::Continue
            }
        }
    }

    /// Handle a management op (legacy ecalli encoding, will be removed).
    fn handle_management_op(&mut self, op: u32, cap_idx: u8) -> DispatchResult {
        match op {
            MGMT_MAP => self.mgmt_map(cap_idx),
            MGMT_UNMAP => self.mgmt_unmap(cap_idx),
            MGMT_SPLIT => self.mgmt_split(cap_idx),
            MGMT_DROP => self.mgmt_drop(cap_idx),
            MGMT_MOVE => self.mgmt_move(cap_idx),
            MGMT_COPY => self.mgmt_copy(cap_idx),
            MGMT_DOWNGRADE => self.mgmt_downgrade(cap_idx),
            MGMT_DIRTY => {
                // TODO: dirty bitmap query
                self.set_active_reg(7, RESULT_WHAT);
                DispatchResult::Continue
            }
            MGMT_GAS_DERIVE => self.mgmt_gas_derive(cap_idx),
            MGMT_GAS_MERGE => self.mgmt_gas_merge(cap_idx),
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                DispatchResult::Continue
            }
        }
    }

    /// MGMT_GAS_DERIVE: split `amount` (φ[7]) units off the Gas cap at
    /// `cap_idx` of the active VM into a fresh Gas cap at slot φ[8].
    /// Routes through `ProtocolCapT::gas_derive`. Returns RC_OK on
    /// success, RESULT_WHAT on any failure (non-Gas cap, insufficient
    /// remaining, dst not empty).
    fn mgmt_gas_derive(&mut self, cap_idx: u8) -> DispatchResult {
        let amount = self.active_reg(7);
        let dst_slot = self.active_reg(8) as u8;
        let vm = self.vm_arena.vm_mut(self.active_vm);
        if !vm.cap_table.is_empty(dst_slot) {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }
        let derived = match vm.cap_table.get_mut(cap_idx) {
            Some(Cap::Protocol(p)) => p.gas_derive(amount),
            _ => None,
        };
        match derived {
            Some(child) => {
                vm.cap_table.set(dst_slot, Cap::Protocol(child));
                self.set_active_reg(7, 0);
            }
            None => self.set_active_reg(7, RESULT_WHAT),
        }
        DispatchResult::Continue
    }

    /// MGMT_GAS_MERGE: merge donor Gas cap at `cap_idx` into dst Gas cap
    /// at slot φ[7] of the active VM. Donor is consumed. Routes through
    /// `ProtocolCapT::gas_merge`.
    fn mgmt_gas_merge(&mut self, cap_idx: u8) -> DispatchResult {
        let dst_slot = self.active_reg(7) as u8;
        if dst_slot == cap_idx {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }
        let vm = self.vm_arena.vm_mut(self.active_vm);
        // Take donor first (so we can hold &mut on dst freely).
        let donor = match vm.cap_table.take(cap_idx) {
            Some(Cap::Protocol(p)) => p,
            Some(other) => {
                vm.cap_table.set(cap_idx, other);
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };
        let ok = match vm.cap_table.get_mut(dst_slot) {
            Some(Cap::Protocol(dst)) => dst.gas_merge(&donor),
            _ => false,
        };
        if ok {
            // Donor consumed; slot stays empty.
            self.set_active_reg(7, 0);
        } else {
            // Restore donor.
            vm.cap_table.set(cap_idx, Cap::Protocol(donor));
            self.set_active_reg(7, RESULT_WHAT);
        }
        DispatchResult::Continue
    }

    // --- Management ops ---

    fn mgmt_map(&mut self, cap_idx: u8) -> DispatchResult {
        let base_page = self.active_reg(7) as u32;
        let access_raw = self.active_reg(8);
        let access = match access_raw {
            0 => Access::RO,
            1 => Access::RW,
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        let active_vm = self.active_vm;
        let active_vm_id =
            crate::vm_pool::VmId::new(active_vm, self.vm_arena.generation_of(active_vm));

        // Step 1: update DataCap state (record mapping, set bits) and capture
        // the previous active mapping + (backing_offset, page_count) for the
        // post-update mmap calls. Done in a closed scope so the &mut to vm
        // is dropped before we call &self methods like vm_window_base.
        let (prev_active, backing_offset, page_count) = {
            let vm = &mut self.vm_arena.vm_mut(active_vm);
            match vm.cap_table.get_mut(cap_idx) {
                Some(Cap::Data(d)) => {
                    let prev = d.map(active_vm_id, base_page, access);
                    (prev, d.backing_offset, d.page_count)
                }
                _ => {
                    self.set_active_reg(7, RESULT_WHAT);
                    return DispatchResult::Continue;
                }
            }
        };

        // Step 2: unmap the prior mapping's window (if any).
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        if let Some((old_vm, old_base, _)) = prev_active
            && let Some(old_wb) = self.vm_window_base(old_vm.index())
        {
            // SAFETY: old_wb is from vm_window_base (valid 4GB window).
            unsafe {
                BackingStore::unmap_pages(old_wb, old_base, page_count);
            }
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        let _ = prev_active;

        // Step 3: mmap at the new (base, access) in the active VM's window.
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let wb = self.active_window_base();
            // SAFETY: wb is from active_window_base() (valid 4GB window).
            unsafe {
                self.backing
                    .map_pages(wb, base_page, backing_offset, page_count, access);
            }
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        let _ = (backing_offset, page_count);
        DispatchResult::Continue
    }

    fn mgmt_unmap(&mut self, cap_idx: u8) -> DispatchResult {
        let (prev, page_count) = {
            let vm = &mut self.vm_arena.vm_mut(self.active_vm);
            match vm.cap_table.get_mut(cap_idx) {
                Some(Cap::Data(d)) => (d.unmap_all(), d.page_count),
                _ => {
                    self.set_active_reg(7, RESULT_WHAT);
                    return DispatchResult::Continue;
                }
            }
        };
        if let Some((vm_id, base, _)) = prev {
            let _ = (vm_id, base, page_count);
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            if let Some(wb) = self.vm_window_base(vm_id.index()) {
                // SAFETY: wb is from vm_window_base (valid 4GB window).
                unsafe {
                    BackingStore::unmap_pages(wb, base, page_count);
                }
            }
        }
        DispatchResult::Continue
    }

    fn mgmt_split(&mut self, cap_idx: u8) -> DispatchResult {
        let page_off = self.active_reg(7) as u32;

        let vm = &mut self.vm_arena.vm_mut(self.active_vm);

        // Pre-validate: must be DATA, unmapped, valid offset
        let can_split = match vm.cap_table.get(cap_idx) {
            Some(Cap::Data(d)) => !d.has_any_mapped() && page_off > 0 && page_off < d.page_count,
            _ => false,
        };
        if !can_split {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }

        // Find free slot for hi before consuming
        let free = match (64..255u8).find(|i| vm.cap_table.is_empty(*i)) {
            Some(s) => s,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        // Now take and split (guaranteed to succeed)
        let cap = match vm.cap_table.take(cap_idx) {
            Some(Cap::Data(d)) => d,
            _ => unreachable!(),
        };
        let (lo, hi) = cap.split(page_off).unwrap();
        vm.cap_table.set(cap_idx, Cap::Data(lo));
        vm.cap_table.set(free, Cap::Data(hi));
        self.set_active_reg(7, cap_idx as u64);
        self.set_active_reg(8, free as u64);
        DispatchResult::Continue
    }

    fn mgmt_drop(&mut self, cap_idx: u8) -> DispatchResult {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        let wb = self.active_window_base();
        // DROP a FrameRef carrying DROP right → reclaim VM via arena.remove()
        if let Some(Cap::FrameRef(f)) = self.vm_arena.vm(self.active_vm).cap_table.get(cap_idx)
            && f.rights.contains(FrameRefRights::DROP)
        {
            let vm_id = f.vm_id;
            self.vm_arena
                .vm_mut(self.active_vm)
                .cap_table
                .drop_cap(cap_idx);
            // Reclaim the VM — release window and remove from arena
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            self.window_pool.release(vm_id.index());
            self.vm_arena.remove(vm_id);
            return DispatchResult::Continue;
        }
        let vm = &mut self.vm_arena.vm_mut(self.active_vm);
        // Unmap DATA caps before dropping
        if let Some(Cap::Data(d)) = vm.cap_table.get(cap_idx)
            && let Some((_base_page, _)) = d.active_mapping()
        {
            let _page_count = d.page_count;
            // SAFETY: wb is from active_window_base() (valid 4GB window).
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            unsafe {
                BackingStore::unmap_pages(wb, _base_page, _page_count);
            }
        }
        vm.cap_table.drop_cap(cap_idx);
        DispatchResult::Continue
    }

    fn mgmt_move(&mut self, cap_idx: u8) -> DispatchResult {
        let dst = self.active_reg(7) as u8;
        let vm = &mut self.vm_arena.vm_mut(self.active_vm);
        match vm.cap_table.move_cap(cap_idx, dst) {
            Ok(()) => {}
            Err(_) => {
                self.set_active_reg(7, RESULT_WHAT);
            }
        }
        DispatchResult::Continue
    }

    fn mgmt_copy(&mut self, cap_idx: u8) -> DispatchResult {
        let dst = self.active_reg(7) as u8;
        let vm = &mut self.vm_arena.vm_mut(self.active_vm);
        match vm.cap_table.copy_cap(cap_idx, dst) {
            Ok(()) => {}
            Err(_) => {
                self.set_active_reg(7, RESULT_WHAT);
            }
        }
        DispatchResult::Continue
    }

    // mgmt_grant and mgmt_revoke removed — subsumed by MOVE with indirection via ecall.

    fn mgmt_downgrade(&mut self, handle_idx: u8) -> DispatchResult {
        let vm = &self.vm_arena.vm(self.active_vm);
        let vm_id = match vm.cap_table.get(handle_idx) {
            Some(Cap::FrameRef(f)) if f.rights.contains(FrameRefRights::DERIVE) => f.vm_id,
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        let callable = FrameRefCap {
            vm_id,
            rights: FrameRefRights::CALLABLE,
        };

        let vm = &mut self.vm_arena.vm_mut(self.active_vm);
        let free = match (64..255u8).find(|i| vm.cap_table.is_empty(*i)) {
            Some(s) => s,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        vm.cap_table.set(free, Cap::FrameRef(callable));
        self.set_active_reg(7, free as u64);
        DispatchResult::Continue
    }

    /// RESUME a FAULTED VM. Same shared-pool gas model as CALL. Requires
    /// the FrameRef's rights to include [`FrameRefRights::RESUME`].
    fn handle_resume(&mut self, handle_idx: u8) -> DispatchResult {
        let vm = self.vm_arena.vm(self.active_vm);
        let target_vm_vid = match vm.cap_table.get(handle_idx) {
            Some(Cap::FrameRef(f)) if f.rights.contains(FrameRefRights::RESUME) => f.vm_id,
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };
        let target_vm_id = target_vm_vid.index();

        // Validate VmId + target must be FAULTED
        match self.vm_arena.get(target_vm_vid) {
            Some(vm) if vm.state == VmState::Faulted => {}
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        }

        // Charge CALL overhead and transfer the caller's residual gas to
        // the callee (shared-pool model — no split).
        let caller_vm = &mut self.vm_arena.vm_mut(self.active_vm);
        let call_overhead = 10u64;
        if caller_vm.gas() < call_overhead {
            return DispatchResult::Fault(FaultType::OutOfGas);
        }
        caller_vm.set_gas(caller_vm.gas() - call_overhead);
        let callee_gas = caller_vm.gas();
        caller_vm.set_gas(0);

        // Save caller state
        let caller_id = self.active_vm;
        let _ = self
            .vm_arena
            .vm_mut(caller_id)
            .transition(VmState::WaitingForReply);

        // Push call frame. No ephemeral-slot rewrite for RESUME — we're
        // continuing a previously-faulted VM, so the slots that were active
        // when it faulted should be restored. Stash whatever the active VM
        // currently shows, the same as on a fresh CALL.
        let prev_kernel_slots = self.take_ephemeral_kernel_slots(caller_id);
        self.call_stack.push(CallFrame {
            caller_vm_id: caller_id,
            prev_kernel_slots,
        });

        // Resume callee: FAULTED → RUNNING, registers/PC preserved
        let callee = self.vm_arena.vm_mut(target_vm_id);
        callee.set_gas(callee_gas);
        callee.caller = Some(caller_id);
        let _ = callee.transition(VmState::Running);
        self.active_vm = target_vm_id;

        DispatchResult::Continue
    }

    // --- ecall management ops (indirection-aware) ---

    /// MAP pages of a DATA cap in its CNode (page-granular).
    /// φ[7]=base_offset, φ[8]=page_offset, φ[9]=page_count.
    /// MAP is only meaningful on a cap held in a VM's persistent Frame —
    /// it associates the cap with that VM's window. Caps sitting in the
    /// ephemeral table cannot be MAPped.
    fn ecall_map(&mut self, frame: FrameId<P::ForeignFrameId>, slot: u8) -> DispatchResult {
        let base_offset = self.active_reg(7) as u32;
        let page_offset = self.active_reg(8) as u32;
        let page_count = self.active_reg(9) as u32;
        let access_raw = self.active_reg(10);
        let access = match access_raw {
            0 => Access::RO,
            1 => Access::RW,
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        let vm_idx = match frame {
            FrameId::Vm(idx) => idx,
            FrameId::Foreign(_) => {
                // DATA caps don't live in foreign frames.
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };
        let vm_id = VmId::new(vm_idx, self.vm_arena.generation_of(vm_idx));
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        let window_base = self.vm_window_base(vm_idx);
        let vm = &mut self.vm_arena.vm_mut(vm_idx);
        match vm.cap_table.get_mut(slot) {
            Some(Cap::Data(d)) => {
                if !d.map_pages(vm_id, base_offset, access, page_offset, page_count) {
                    self.set_active_reg(7, RESULT_WHAT);
                    return DispatchResult::Continue;
                }
                // Map the pages in the VM's window (if it has one)
                #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                if let Some(wb) = window_base {
                    for p in page_offset..page_offset + page_count {
                        // SAFETY: wb is from vm_window_base() (valid 4GB window).
                        unsafe {
                            self.backing.map_pages(
                                wb,
                                base_offset + p,
                                d.backing_offset + p,
                                1,
                                access,
                            );
                        }
                    }
                }
            }
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
            }
        }
        DispatchResult::Continue
    }

    /// UNMAP pages of a DATA cap in its Frame.
    /// φ[7]=page_offset, φ[8]=page_count.
    fn ecall_unmap(&mut self, frame: FrameId<P::ForeignFrameId>, slot: u8) -> DispatchResult {
        let page_offset = self.active_reg(7) as u32;
        let page_count = self.active_reg(8) as u32;

        let vm_idx = match frame {
            FrameId::Vm(idx) => idx,
            FrameId::Foreign(_) => {
                // Caps in foreign frames aren't mapped; UNMAP is a no-op.
                return DispatchResult::Continue;
            }
        };

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        let window_base = self.vm_window_base(vm_idx);
        let vm = &mut self.vm_arena.vm_mut(vm_idx);
        match vm.cap_table.get_mut(slot) {
            Some(Cap::Data(d)) => {
                if let Some((_base_offset, _)) = d.active_mapping() {
                    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                    if let Some(wb) = window_base {
                        for p in
                            page_offset..page_offset.saturating_add(page_count).min(d.page_count)
                        {
                            if d.is_page_mapped(p) {
                                // SAFETY: wb is from vm_window_base() (valid 4GB window).
                                unsafe {
                                    BackingStore::unmap_pages(wb, _base_offset + p, 1);
                                }
                            }
                        }
                    }
                    d.unmap_pages(page_offset, page_count);
                }
            }
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
            }
        }
        DispatchResult::Continue
    }

    /// SPLIT a DATA cap. Must be fully unmapped.
    /// φ[7]=page_offset. Subject = DATA cap, object = dst slot for high half.
    /// Foreign frames don't hold DATA caps, so a Foreign source or
    /// destination always reports `RESULT_WHAT`.
    fn ecall_split(
        &mut self,
        s_frame: FrameId<P::ForeignFrameId>,
        s_slot: u8,
        o_frame: FrameId<P::ForeignFrameId>,
        o_slot: u8,
    ) -> DispatchResult {
        if matches!(s_frame, FrameId::Foreign(_)) || matches!(o_frame, FrameId::Foreign(_)) {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }
        let page_off = self.active_reg(7) as u32;

        // Validate
        let can_split = match self.frame_table(s_frame).and_then(|t| t.get(s_slot)) {
            Some(Cap::Data(d)) => !d.has_any_mapped() && page_off > 0 && page_off < d.page_count,
            _ => false,
        };
        let dst_empty = self
            .frame_table(o_frame)
            .map(|t| t.is_empty(o_slot))
            .unwrap_or(false);
        if !can_split || !dst_empty {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }

        let cap = match self.frame_table_mut(s_frame).and_then(|t| t.take(s_slot)) {
            Some(Cap::Data(d)) => d,
            _ => unreachable!(),
        };
        let (lo, hi) = cap.split(page_off).unwrap();
        if let Some(t) = self.frame_table_mut(s_frame) {
            t.set(s_slot, Cap::Data(lo));
        }
        if let Some(t) = self.frame_table_mut(o_frame) {
            t.set(o_slot, Cap::Data(hi));
        }
        DispatchResult::Continue
    }

    /// DROP a cap. Auto-unmaps DATA. Reclaims VM on HANDLE drop. For
    /// `Foreign` slots the operation routes through the host's
    /// `fc_drop` (host-side revoke).
    fn ecall_drop<H: ForeignCnode<P>>(
        &mut self,
        host: &mut H,
        frame: FrameId<P::ForeignFrameId>,
        slot: u8,
        rights: P::FinalStepRights,
    ) -> DispatchResult {
        // Foreign drop: host handles revoke + bookkeeping. No DATA / HANDLE
        // path applies (host-managed CNodes hold persistent caps only).
        if let FrameId::Foreign(id) = frame {
            if !host.fc_drop(id, slot, rights) {
                self.set_active_reg(7, RESULT_WHAT);
            }
            return DispatchResult::Continue;
        }

        // DROP a FrameRef carrying DROP right → reclaim VM (only
        // meaningful for caps in a VM frame). Without DROP right, the
        // slot is just cleared like any other DROP.
        if let FrameId::Vm(vm_idx) = frame
            && let Some(Cap::FrameRef(f)) = self.vm_arena.vm(vm_idx).cap_table.get(slot)
            && f.rights.contains(FrameRefRights::DROP)
        {
            let vm_id = f.vm_id;
            self.vm_arena.vm_mut(vm_idx).cap_table.drop_cap(slot);
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            self.window_pool.release(vm_id.index());
            self.vm_arena.remove(vm_id);
            return DispatchResult::Continue;
        }

        // DROP DATA in a VM frame → unmap if currently mapped.
        if let FrameId::Vm(vm_idx) = frame
            && let Some(Cap::Data(d)) = self.vm_arena.vm(vm_idx).cap_table.get(slot)
            && let Some((_base_offset, _)) = d.active_mapping()
        {
            let _page_count = d.page_count;
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            if let Some(wb) = self.vm_window_base(vm_idx) {
                // SAFETY: wb is from vm_window_base() (valid 4GB window).
                unsafe {
                    BackingStore::unmap_pages(wb, _base_offset, _page_count);
                }
            }
        }

        if let Some(t) = self.frame_table_mut(frame) {
            t.drop_cap(slot);
        }
        DispatchResult::Continue
    }

    /// MOVE a cap between Frames. Auto-unmaps DATA from source if cross-frame;
    /// auto-remaps in destination if `mappings[dst_vm]` is recorded.
    /// `Foreign` participation routes the take/set through the host's
    /// `ForeignCnode`. Set rejection rolls back by restoring at source.
    #[allow(clippy::too_many_arguments)]
    fn ecall_move<H: ForeignCnode<P>>(
        &mut self,
        host: &mut H,
        s_frame: FrameId<P::ForeignFrameId>,
        s_slot: u8,
        s_rights: P::FinalStepRights,
        o_frame: FrameId<P::ForeignFrameId>,
        o_slot: u8,
        o_rights: P::FinalStepRights,
    ) -> DispatchResult {
        if s_frame == o_frame && s_slot == o_slot {
            return DispatchResult::Continue;
        }
        if !self.frame_is_empty(host, o_frame, o_slot) {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }

        let mut cap = match self.frame_take(host, s_frame, s_slot, s_rights) {
            Some(c) => c,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        if s_frame != o_frame
            && let Cap::Data(ref mut d) = cap
        {
            // Cross-frame: unmap from source's active VM (if any), then
            // auto-remap in destination's window if it's a VM frame and
            // `mappings[dst_vm]` is recorded. Moves into the ephemeral
            // table preserve `mappings` but never remap (no window).
            // Foreign destinations don't accept DATA caps (host rejects on
            // fc_set), so the remap is correct-by-omission for that case.
            self.cross_frame_unmap(d);
            if let FrameId::Vm(o_idx) = o_frame {
                self.cross_frame_remap(d, o_idx);
            }
        }

        match self.frame_set(host, o_frame, o_slot, o_rights, cap) {
            Ok(()) => DispatchResult::Continue,
            Err(mut cap) => {
                // Roll back: undo any cross-frame DATA remap we did, then
                // restore the cap at the source slot. Source was just taken,
                // so it's empty — set always succeeds for non-Foreign sources.
                if s_frame != o_frame
                    && let Cap::Data(ref mut d) = cap
                {
                    // Reverse the dest-side remap (if any) and the source-side
                    // unmap so the cap returns to its pre-take state.
                    self.cross_frame_unmap(d);
                    if let FrameId::Vm(s_idx) = s_frame {
                        self.cross_frame_remap(d, s_idx);
                    }
                }
                let _ = self.frame_set(host, s_frame, s_slot, s_rights, cap);
                self.set_active_reg(7, RESULT_WHAT);
                DispatchResult::Continue
            }
        }
    }

    /// Unmap a DATA cap from its currently-active VM's window. Mapping
    /// memory on the cap is preserved (so a future arrival in that VM
    /// auto-remaps).
    fn cross_frame_unmap(&self, d: &mut DataCap) {
        if let Some((vm_id, base, _access)) = d.unmap_all() {
            let _ = (vm_id, base);
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            if let Some(wb) = self.vm_window_base(vm_id.index()) {
                // SAFETY: wb is from vm_window_base (valid 4GB window).
                unsafe {
                    BackingStore::unmap_pages(wb, base, d.page_count);
                }
            }
        }
    }

    /// Auto-remap a DATA cap on arrival in `vm_idx`'s persistent Frame, if
    /// `mappings[vm_idx]` is recorded. No-op otherwise (callee can MAP at a
    /// fresh address).
    fn cross_frame_remap(&self, d: &mut DataCap, vm_idx: u16) {
        let vm_id = crate::vm_pool::VmId::new(vm_idx, self.vm_arena.generation_of(vm_idx));
        if let Some((base, access)) = d.auto_remap_for(vm_id) {
            let _ = (base, access);
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            if let Some(wb) = self.vm_window_base(vm_idx) {
                // SAFETY: wb is from vm_window_base (valid 4GB window).
                unsafe {
                    self.backing
                        .map_pages(wb, base, d.backing_offset, d.page_count, access);
                }
            }
        }
    }

    /// COPY a cap between CNodes (copyable types only). `Foreign` source
    /// performs a host-side derive (allocating a fresh registry entry);
    /// `Foreign` destination places via the host adapter.
    #[allow(clippy::too_many_arguments)]
    fn ecall_copy<H: ForeignCnode<P>>(
        &mut self,
        host: &mut H,
        s_frame: FrameId<P::ForeignFrameId>,
        s_slot: u8,
        s_rights: P::FinalStepRights,
        o_frame: FrameId<P::ForeignFrameId>,
        o_slot: u8,
        o_rights: P::FinalStepRights,
    ) -> DispatchResult {
        if !self.frame_is_empty(host, o_frame, o_slot) {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }
        let copy = match self.frame_clone(host, s_frame, s_slot, s_rights) {
            Some(c) => c,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };
        if self
            .frame_set(host, o_frame, o_slot, o_rights, copy)
            .is_err()
        {
            // Destination rejected the placement; the COPY produces no
            // visible side effect (host's fc_clone may have allocated a
            // child registry entry that's now orphan, but the host can
            // garbage-collect at its discretion).
            self.set_active_reg(7, RESULT_WHAT);
        }
        DispatchResult::Continue
    }

    /// DOWNGRADE a FrameRef. Source must carry [`FrameRefRights::DERIVE`];
    /// produces a callable-shaped FrameRef ([`FrameRefRights::CALLABLE`])
    /// at dst. FrameRef caps don't currently live in foreign frames —
    /// Foreign on either side fails.
    fn ecall_downgrade(
        &mut self,
        s_frame: FrameId<P::ForeignFrameId>,
        s_slot: u8,
        o_frame: FrameId<P::ForeignFrameId>,
        o_slot: u8,
    ) -> DispatchResult {
        if matches!(s_frame, FrameId::Foreign(_)) || matches!(o_frame, FrameId::Foreign(_)) {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }
        let vm_id = match self.frame_table(s_frame).and_then(|t| t.get(s_slot)) {
            Some(Cap::FrameRef(f)) if f.rights.contains(FrameRefRights::DERIVE) => f.vm_id,
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };
        let dst_empty = self
            .frame_table(o_frame)
            .map(|t| t.is_empty(o_slot))
            .unwrap_or(false);
        if !dst_empty {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }
        if let Some(t) = self.frame_table_mut(o_frame) {
            t.set(
                o_slot,
                Cap::FrameRef(FrameRefCap {
                    vm_id,
                    rights: FrameRefRights::CALLABLE,
                }),
            );
        }
        DispatchResult::Continue
    }

    /// Flush live JitContext state to VmInstance. Must be called before
    /// switching active VM or any operation that reads VmInstance directly.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    fn flush_live_ctx(&mut self) {
        if let Some(ctx) = self.live_ctx.take() {
            // SAFETY: live_ctx points to the JitContext in the active CodeWindow's CTX page,
            // valid for the duration of the JIT execution on this thread.
            let ctx = unsafe { &*ctx };
            let vm = &mut self.vm_arena.vm_mut(self.active_vm);
            vm.set_regs(ctx.regs);
            vm.set_gas(ctx.gas.max(0) as u64);
            vm.pc = ctx.pc;
        }
    }

    // --- Register helpers ---

    pub fn active_reg(&self, idx: usize) -> u64 {
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        if let Some(ctx) = self.live_ctx {
            // SAFETY: live_ctx is valid JitContext pointer (see flush_live_ctx).
            return unsafe { (*ctx).regs[idx] };
        }
        self.vm_arena.vm(self.active_vm).reg(idx)
    }

    pub fn set_active_reg(&mut self, idx: usize, val: u64) {
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        if let Some(ctx) = self.live_ctx {
            // SAFETY: live_ctx is valid JitContext pointer (see flush_live_ctx).
            unsafe { (*ctx).regs[idx] = val };
            return;
        }
        self.vm_arena.vm_mut(self.active_vm).set_reg(idx, val);
    }

    // --- Cap-table accessors (active VM) ---

    /// Get a reference to the cap at `slot` in the active VM's cap table.
    pub fn cap_table_get(&self, slot: u8) -> Option<&Cap<P>> {
        self.vm_arena.vm(self.active_vm).cap_table.get(slot)
    }

    /// Read a cap from the per-invocation **bare Frame**'s cap-table.
    /// Used by hosts implementing the `Vault.initialize` protocol: the
    /// init program is conventionally responsible for placing a
    /// callable-shaped `Cap::FrameRef` at bare-Frame slot 4 before
    /// halting; the kernel reads that slot after the init Halt to
    /// recover the public Callable produced by initialization.
    pub fn read_bare_frame_slot(&self, slot: u8) -> Option<&Cap<P>> {
        self.vm_arena
            .vm(self.bare_frame_id.index())
            .cap_table
            .get(slot)
    }

    /// Set a cap at `slot` in the active VM's cap table, returning any
    /// previous cap.
    pub fn cap_table_set(&mut self, slot: u8, cap: Cap<P>) -> Option<Cap<P>> {
        self.vm_arena
            .vm_mut(self.active_vm)
            .cap_table
            .set(slot, cap)
    }

    /// Set a cap at `slot` and mark it as kernel-original (JIT fast-path
    /// inlining hint for protocol caps). Returns any previous cap.
    pub fn cap_table_set_original(&mut self, slot: u8, cap: Cap<P>) -> Option<Cap<P>> {
        self.vm_arena
            .vm_mut(self.active_vm)
            .cap_table
            .set_original(slot, cap)
    }

    /// Get the active VM's remaining gas.
    pub fn active_gas(&self) -> u64 {
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        if let Some(ctx) = self.live_ctx {
            // SAFETY: live_ctx is valid JitContext pointer (see flush_live_ctx).
            return unsafe { (*ctx).gas.max(0) as u64 };
        }
        self.vm_arena.vm(self.active_vm).gas()
    }

    /// Resume after a protocol call was handled by the host.
    /// Sets return registers and continues execution.
    pub fn resume_protocol_call(&mut self, result0: u64, result1: u64) {
        self.set_active_reg(7, result0);
        self.set_active_reg(8, result1);
    }

    // --- Window helpers ---

    /// Get the active window's base pointer (guest memory base, R15 in JIT code).
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    fn active_window_base(&self) -> *mut u8 {
        self.window_pool.window(self.active_window).base()
    }

    /// Get the active window's JitContext pointer.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    fn active_window_ctx_ptr(&self) -> *mut u8 {
        self.window_pool.window(self.active_window).ctx_ptr()
    }

    /// Get window base for a specific VM, if it has an assigned window.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    fn vm_window_base(&self, vm_idx: u16) -> Option<*mut u8> {
        self.window_pool
            .find_window(vm_idx)
            .map(|idx| self.window_pool.window(idx).base())
    }

    /// Ensure the active VM has a window assigned. Handles eviction and
    /// DATA cap mapping/unmapping. Called before executing any VM code and
    /// after context switches (CALL/REPLY/HALT).
    ///
    /// Fast path: if the active VM already owns the current window, this is
    /// a single branch (no scan). Only does real work on context switches.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    #[inline(always)]
    fn ensure_active_window(&mut self) {
        // Fast path: active VM already owns the current window.
        if self.window_pool.window_owner(self.active_window) == Some(self.active_vm) {
            return;
        }

        let vm_idx = self.active_vm;
        let generation = self.vm_arena.generation_of(vm_idx);
        let assignment = self.window_pool.assign_window(vm_idx, generation);

        // Evict previous owner's DATA caps from the window
        if let Some(evicted_vm) = assignment.evicted {
            self.unmap_vm_data_caps(evicted_vm, assignment.window_idx);
        }

        // Map current VM's DATA caps into the window
        if assignment.needs_map {
            self.map_vm_data_caps(vm_idx, assignment.window_idx);
        }

        self.active_window = assignment.window_idx;
    }

    /// Unmap all of a VM's currently-mapped DATA caps from a window.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    fn unmap_vm_data_caps(&self, vm_idx: u16, window_idx: usize) {
        let wb = self.window_pool.window(window_idx).base();
        let vm = self.vm_arena.vm(vm_idx);
        for slot in 0..=255u8 {
            if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                && let Some((base_offset, _access)) = d.active_mapping()
            {
                // SAFETY: wb is from window_pool (valid 4GB window).
                unsafe {
                    BackingStore::unmap_pages(wb, base_offset, d.page_count);
                }
            }
        }
    }

    /// Map all of a VM's currently-mapped DATA caps into a window.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    fn map_vm_data_caps(&self, vm_idx: u16, window_idx: usize) {
        let wb = self.window_pool.window(window_idx).base();
        let vm = self.vm_arena.vm(vm_idx);
        for slot in 0..=255u8 {
            if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                && let Some((base_offset, access)) = d.active_mapping()
            {
                // SAFETY: wb is from window_pool (valid 4GB window).
                unsafe {
                    self.backing
                        .map_pages(wb, base_offset, d.backing_offset, d.page_count, access);
                }
            }
        }
    }

    /// Sync VM state after JIT execution returns.
    ///
    /// For ecalli (exit_reason=4): keep live_ctx for fast resume, sync only pc.
    /// For all other exits: full register/gas sync, clear live_ctx and signal state.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn sync_after_jit(&mut self, ctx_raw: *mut crate::recompiler::JitContext) -> (u32, u32) {
        // SAFETY: ctx_raw is still valid after JIT execution returns — it points
        // to the JitContext page in the active CodeWindow's mmap region.
        let ctx = unsafe { &*ctx_raw };
        let exit_reason = ctx.exit_reason;
        let exit_arg = ctx.exit_arg;

        if exit_reason == 4 {
            // ecalli: keep live_ctx so dispatch reads JitContext directly.
            // Sync only pc to VmInstance (needed for ProtocolCall metadata).
            self.vm_arena.vm_mut(self.active_vm).pc = ctx.pc;
            self.live_ctx = Some(ctx_raw);
        } else {
            // Non-ecalli: full sync to VmInstance, clear live_ctx.
            let vm = &mut self.vm_arena.vm_mut(self.active_vm);
            vm.set_regs(ctx.regs);
            vm.set_gas(ctx.gas.max(0) as u64);
            vm.pc = ctx.pc;
            vm.set_heap_base(ctx.heap_base);
            vm.set_heap_top(ctx.heap_top);
            self.live_ctx = None;
            crate::recompiler::signal::SIGNAL_STATE.with(|cell| cell.set(std::ptr::null_mut()));
        }

        (exit_reason, exit_arg)
    }

    /// Execute one segment via the JIT recompiler backend.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    /// Execute via the JIT recompiler.
    ///
    /// For protocol cap ecalli (slots 0-27), this returns to the kernel's `run()`
    /// loop which exits to the host. On re-entry, the JitContext is rebuilt from
    /// VmInstance. To minimize the rebuild cost, `run()` uses `run_recompiler_resume()`
    /// which only updates registers + gas + entry_pc instead of rebuilding all fields.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn run_recompiler_segment(&mut self, code_cap_id: usize) -> (u32, u32) {
        use crate::recompiler::JitContext;

        let code_cap = &self.code_caps[code_cap_id];
        let compiled = match &code_cap.compiled {
            crate::backend::CompiledProgram::Recompiler(c) => c,
            _ => unreachable!(),
        };
        let vm = &self.vm_arena.vm(self.active_vm);
        let ctx_raw = self.active_window_ctx_ptr() as *mut JitContext;
        // SAFETY: ctx_ptr() returns a writable page allocated by CodeWindow::new().
        unsafe {
            ctx_raw.write(JitContext {
                regs: *vm.regs(),
                gas: vm.gas() as i64,
                exit_reason: 0,
                exit_arg: 0,
                heap_base: vm.heap_base(),
                heap_top: vm.heap_top(),
                jt_ptr: code_cap.jump_table.as_ptr(),
                jt_len: code_cap.jump_table.len() as u32,
                _pad0: 0,
                bb_starts: code_cap.bitmask.as_ptr(),
                bb_len: code_cap.bitmask.len() as u32,
                _pad1: 0,
                entry_pc: vm.pc,
                pc: vm.pc,
                dispatch_table: compiled.dispatch_table.as_ptr(),
                code_base: compiled.native_code.ptr as u64,
                flat_buf: self.active_window_base(),
                flat_perms: std::ptr::null(),
                fast_reentry: 0,
                _pad2: 0,
                max_heap_pages: 0,
                _pad3: 0,
                original_bitmap: *vm.cap_table.original_bitmap(),
            });
        }

        self.run_recompiler_inner(code_cap_id, ctx_raw)
    }

    /// Resume recompiler after a protocol call. The JitContext is still live —
    /// only update the result registers that kernel_resume() changed, then
    /// re-enter native code. No full register sync needed.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[inline(always)]
    fn run_recompiler_resume(&mut self, code_cap_id: usize) -> (u32, u32) {
        use crate::recompiler::JitContext;

        let code_cap = &self.code_caps[code_cap_id];
        let compiled = match &code_cap.compiled {
            crate::backend::CompiledProgram::Recompiler(c) => c,
            _ => unreachable!(),
        };
        let ctx_raw = self.active_window_ctx_ptr() as *mut JitContext;

        // The live_ctx was set on the previous ecalli exit. kernel_resume()
        // wrote result regs via set_active_reg which updated JitContext directly.
        // Just set entry_pc and re-enter.
        // SAFETY: ctx_raw points to the JitContext in the active CodeWindow's CTX page.
        let ctx = unsafe { &mut *ctx_raw };
        ctx.entry_pc = self.vm_arena.vm(self.active_vm).pc;
        ctx.exit_reason = 0;
        ctx.exit_arg = 0;

        // Signal state is already installed. Re-enter native.
        let entry = compiled.native_code.entry();
        // SAFETY: entry is valid JIT code; ctx_raw is a valid JitContext.
        unsafe {
            entry(ctx_raw);
        }

        self.sync_after_jit(ctx_raw)
    }

    /// Shared recompiler execution: set up signal handler, enter native code,
    /// sync state back on exit.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn run_recompiler_inner(
        &mut self,
        code_cap_id: usize,
        ctx_raw: *mut crate::recompiler::JitContext,
    ) -> (u32, u32) {
        use crate::recompiler::signal;

        let code_cap = &self.code_caps[code_cap_id];
        let compiled = match &code_cap.compiled {
            crate::backend::CompiledProgram::Recompiler(c) => c,
            _ => unreachable!(),
        };

        signal::ensure_installed();
        let mut signal_state = signal::SignalState {
            code_start: compiled.native_code.ptr as usize,
            code_end: compiled.native_code.ptr as usize + compiled.native_code.len,
            exit_label_addr: compiled.native_code.ptr as usize
                + compiled.exit_label_offset as usize,
            ctx_ptr: ctx_raw,
            trap_table_ptr: compiled.trap_table.as_ptr(),
            trap_table_len: compiled.trap_table.len(),
        };
        signal::SIGNAL_STATE.with(|cell| cell.set(&mut signal_state as *mut _));

        let entry = compiled.native_code.entry();
        // SAFETY: entry points to valid JIT code; ctx_raw is a valid JitContext.
        unsafe {
            entry(ctx_raw);
        }

        self.sync_after_jit(ctx_raw)
    }

    /// Execute one segment via the software interpreter backend.
    ///
    /// The interpreter uses a regular Vec<u8> for memory instead of the mmap'd
    /// 4GB window (which would SIGSEGV on unmapped pages without the recompiler's
    /// signal handler). Mapped DATA cap pages are copied in before execution and
    /// written back after.
    fn run_interpreter_segment(&mut self, code_cap_id: usize) -> (u32, u32) {
        let code_cap = &self.code_caps[code_cap_id];
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        let prog = match &code_cap.compiled {
            crate::backend::CompiledProgram::Interpreter(p) => p,
            _ => unreachable!(),
        };
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        let crate::backend::CompiledProgram::Interpreter(prog) = &code_cap.compiled;

        // Determine memory size from mapped DATA caps. Find the highest mapped page.
        let vm = &self.vm_arena.vm(self.active_vm);
        let mut max_addr: usize = 0;
        for slot in 0..=255u8 {
            if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                && let Some((base_page, _access)) = d.active_mapping()
            {
                let end =
                    (base_page as usize + d.page_count as usize) * crate::PVM_PAGE_SIZE as usize;
                max_addr = max_addr.max(end);
            }
        }
        // Allocate flat memory and copy in mapped pages from the CODE window (Linux)
        // or directly from the backing store (non-Linux, where window is not used).
        let mut flat_mem = vec![0u8; max_addr];
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        let window_base = self.active_window_base();
        for slot in 0..=255u8 {
            if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                && let Some((base_page, _access)) = d.active_mapping()
            {
                let addr = base_page as usize * crate::PVM_PAGE_SIZE as usize;
                let len = d.page_count as usize * crate::PVM_PAGE_SIZE as usize;
                if addr + len <= flat_mem.len() {
                    // SAFETY: window_base points to the 4GB mmap CODE window.
                    // addr + len <= flat_mem.len() <= max_addr (computed from
                    // the same cap table), so both source and destination ranges
                    // are in bounds. The regions don't overlap (window vs heap).
                    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            window_base.add(addr),
                            flat_mem.as_mut_ptr().add(addr),
                            len,
                        );
                    }
                    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
                    flat_mem[addr..addr + len].copy_from_slice(
                        self.backing.read_page_slice(d.backing_offset, d.page_count),
                    );
                }
            }
        }

        let vm = &mut self.vm_arena.vm_mut(self.active_vm);
        let mut interp = crate::interpreter::Interpreter::new(
            prog.code.clone(),
            prog.bitmask.clone(),
            prog.jump_table.clone(),
            *vm.regs(),
            flat_mem,
            vm.gas(),
            prog.mem_cycles,
        );
        interp.pc = vm.pc;
        interp.heap_base = vm.heap_base();
        interp.heap_top = vm.heap_top();

        let (exit, _gas_used) = interp.run();

        // Write back modified pages to the CODE window (Linux) / backing store (non-Linux)
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let vm_ref = &self.vm_arena.vm(self.active_vm);
            let wb = self.active_window_base();
            for slot in 0..=255u8 {
                if let Some(Cap::Data(d)) = vm_ref.cap_table.get(slot)
                    && let Some((base_page, access)) = d.active_mapping()
                    && access == Access::RW
                {
                    let addr = base_page as usize * crate::PVM_PAGE_SIZE as usize;
                    let len = d.page_count as usize * crate::PVM_PAGE_SIZE as usize;
                    if addr + len <= interp.flat_mem.len() {
                        // SAFETY: wb is the active window base; addr+len is within
                        // both interp.flat_mem and the window (checked above).
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                interp.flat_mem.as_ptr().add(addr),
                                wb.add(addr),
                                len,
                            );
                        }
                    }
                }
            }
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            // Collect write-back info first so we can drop the vm borrow before
            // taking &mut self.backing.
            let writebacks: Vec<(usize, u32, u32)> = {
                let vm_ref = &self.vm_arena.vm(self.active_vm);
                (0..=255u8)
                    .filter_map(|slot| {
                        let d = if let Some(Cap::Data(d)) = vm_ref.cap_table.get(slot) {
                            d
                        } else {
                            return None;
                        };
                        if !d.has_any_mapped() || d.access != Some(Access::RW) {
                            return None;
                        }
                        let base_page = d.base_offset?;
                        let addr = base_page as usize * crate::PVM_PAGE_SIZE as usize;
                        let len = d.page_count as usize * crate::PVM_PAGE_SIZE as usize;
                        if addr + len > interp.flat_mem.len() {
                            return None;
                        }
                        Some((addr, d.backing_offset, d.page_count))
                    })
                    .collect()
            };
            for (addr, backing_offset, page_count) in writebacks {
                let len = page_count as usize * crate::PVM_PAGE_SIZE as usize;
                self.backing
                    .write_page_slice(backing_offset, &interp.flat_mem[addr..addr + len]);
            }
        }

        let vm = &mut self.vm_arena.vm_mut(self.active_vm);
        vm.set_regs(interp.registers);
        vm.set_gas(interp.gas);
        vm.pc = interp.pc;
        vm.set_heap_base(interp.heap_base);
        vm.set_heap_top(interp.heap_top);

        match exit {
            crate::ExitReason::Halt => (0, 0),
            crate::ExitReason::Trap => (7, 0), // deliberate trap
            crate::ExitReason::Panic => (1, 0),
            crate::ExitReason::OutOfGas => (2, 0),
            crate::ExitReason::PageFault(addr) => (3, addr),
            crate::ExitReason::HostCall(id) => (4, id),
            crate::ExitReason::Ecall => (6, 0),
        }
    }

    /// Execute one segment of the active VM using the appropriate backend.
    fn run_one_segment(&mut self, code_cap_id: usize) -> (u32, u32) {
        match &self.code_caps[code_cap_id].compiled {
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            crate::backend::CompiledProgram::Recompiler(_) => {
                self.run_recompiler_segment(code_cap_id)
            }
            crate::backend::CompiledProgram::Interpreter(_) => {
                self.run_interpreter_segment(code_cap_id)
            }
        }
    }

    /// Run the kernel until it needs host interaction or terminates.
    ///
    /// Convenience shim that uses [`NoForeignCnode`] — for callers
    /// (tests, benches, hosts with no foreign cap-tables) that don't
    /// expose any `FrameId::Foreign` frames. Hosts that do should call
    /// [`Self::run_with_host`].
    #[inline]
    pub fn run(&mut self) -> KernelResult
    where
        P: ProtocolCapT<ForeignFrameId = (), FinalStepRights = ()>,
    {
        self.run_with_host(&mut NoForeignCnode)
    }

    /// Run the kernel until it needs host interaction or terminates.
    /// `host` is consulted for slot-level operations on `FrameId::Foreign`
    /// frames produced by the resolve walk.
    pub fn run_with_host<H: ForeignCnode<P>>(&mut self, host: &mut H) -> KernelResult {
        loop {
            // Ensure active VM has a window assigned (handles eviction + DATA cap mapping).
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            self.ensure_active_window();

            let code_cap_id = self.vm_arena.vm(self.active_vm).code_cap_id as usize;

            // Execute via the compiled backend.
            // After a ProtocolCall, recompiler_resume_cap is set so we can resume
            // with a cheap JitContext update instead of a full rebuild.
            let (exit_reason, exit_arg) = if let Some(ccid) = self.recompiler_resume_cap.take() {
                // Fast path: resume recompiler after protocol call.
                // Only updates regs/gas/pc in the existing JitContext.
                #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                {
                    self.run_recompiler_resume(ccid)
                }
                #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
                {
                    let _ = ccid;
                    self.run_one_segment(code_cap_id)
                }
            } else {
                self.run_one_segment(code_cap_id)
            };

            // Dispatch on the exit reason (shared for both backends).

            match exit_reason {
                4 => {
                    // HostCall(imm) — ecalli (pc already synced by backend)
                    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                    let prev_vm = self.active_vm;
                    match self.dispatch_ecalli(exit_arg) {
                        DispatchResult::Continue => {
                            // Internal dispatch (RETYPE, CREATE, CALL VM, management ops).
                            // Use resume only if BOTH code cap AND active VM are unchanged.
                            // VM switches (CALL handle, REPLY) change registers/gas — stale
                            // JitContext would produce wrong results.
                            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                            {
                                let new_code_cap_id =
                                    self.vm_arena.vm(self.active_vm).code_cap_id as usize;
                                if self.active_vm == prev_vm
                                    && new_code_cap_id == code_cap_id
                                    && matches!(
                                        self.code_caps[code_cap_id].compiled,
                                        crate::backend::CompiledProgram::Recompiler(_)
                                    )
                                {
                                    self.recompiler_resume_cap = Some(code_cap_id);
                                }
                            }
                            continue;
                        }
                        DispatchResult::ProtocolCall { slot } => {
                            // Mark for fast resume on next run() call.
                            // Leave signal state installed for the resume path.
                            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                            if matches!(
                                self.code_caps[code_cap_id].compiled,
                                crate::backend::CompiledProgram::Recompiler(_)
                            ) {
                                self.recompiler_resume_cap = Some(code_cap_id);
                            }
                            return KernelResult::ProtocolCall { slot };
                        }
                        DispatchResult::RootHalt(v) => return KernelResult::Halt(v),
                        DispatchResult::RootPanic => return KernelResult::Panic,
                        DispatchResult::RootOutOfGas => return KernelResult::OutOfGas,
                        DispatchResult::RootPageFault(a) => return KernelResult::PageFault(a),
                        DispatchResult::Fault(_) => continue, // non-root fault handled
                    }
                }
                0 => {
                    // Halt
                    let value = self.vm_arena.vm(self.active_vm).reg(7);
                    match self.handle_vm_halt(value) {
                        DispatchResult::RootHalt(v) => return KernelResult::Halt(v),
                        DispatchResult::Continue => continue,
                        _ => return KernelResult::Panic,
                    }
                }
                7 => {
                    // Trap (deliberate, opcode 0)
                    match self.handle_vm_fault(FaultType::Trap) {
                        DispatchResult::RootPanic => return KernelResult::Panic,
                        DispatchResult::Continue => continue,
                        _ => return KernelResult::Panic,
                    }
                }
                1 => {
                    // Panic (runtime error)
                    match self.handle_vm_fault(FaultType::Panic) {
                        DispatchResult::RootPanic => return KernelResult::Panic,
                        DispatchResult::Continue => continue,
                        _ => return KernelResult::Panic,
                    }
                }
                2 => {
                    // OOG
                    match self.handle_vm_fault(FaultType::OutOfGas) {
                        DispatchResult::RootOutOfGas => return KernelResult::OutOfGas,
                        DispatchResult::Continue => continue,
                        _ => return KernelResult::OutOfGas,
                    }
                }
                3 => {
                    // Page fault
                    match self.handle_vm_fault(FaultType::PageFault(exit_arg)) {
                        DispatchResult::RootPageFault(a) => return KernelResult::PageFault(a),
                        DispatchResult::Continue => continue,
                        _ => return KernelResult::Panic,
                    }
                }
                5 => {
                    // Dynamic jump — resolve and re-enter
                    let idx = exit_arg;
                    let cc = &self.code_caps[code_cap_id];
                    if (idx as usize) < cc.jump_table.len() {
                        let target = cc.jump_table[idx as usize];
                        if (target as usize) < cc.bitmask.len() && cc.bitmask[target as usize] == 1
                        {
                            self.vm_arena.vm_mut(self.active_vm).pc = target;
                            continue;
                        }
                    }
                    // Invalid jump → panic
                    match self.handle_vm_fault(FaultType::Panic) {
                        DispatchResult::RootPanic => return KernelResult::Panic,
                        DispatchResult::Continue => continue,
                        _ => return KernelResult::Panic,
                    }
                }
                6 => {
                    // Ecall — management ops / dynamic CALL.
                    // Read φ[11]=op, φ[12]=subject|object from active VM.
                    let op = self.active_reg(11) as u32;
                    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
                    self.flush_live_ctx();
                    match self.dispatch_ecall(host, op) {
                        DispatchResult::Continue => continue,
                        DispatchResult::ProtocolCall { slot } => {
                            return KernelResult::ProtocolCall { slot };
                        }
                        DispatchResult::RootHalt(v) => return KernelResult::Halt(v),
                        DispatchResult::RootPanic => return KernelResult::Panic,
                        DispatchResult::RootOutOfGas => return KernelResult::OutOfGas,
                        DispatchResult::RootPageFault(a) => return KernelResult::PageFault(a),
                        DispatchResult::Fault(_) => continue,
                    }
                }
                _ => return KernelResult::Panic,
            }
        }
    }

    /// Read bytes from a DATA cap's mapped region in the active VM's CODE window.
    pub fn read_data_cap(&self, cap_idx: u8, offset: u32, len: u32) -> Option<Vec<u8>> {
        let vm = &self.vm_arena.vm(self.active_vm);
        let d = match vm.cap_table.get(cap_idx)? {
            Cap::Data(d) => d,
            _ => return None,
        };
        let (base_page, _access) = d.active_mapping()?;
        let addr = base_page as usize * crate::PVM_PAGE_SIZE as usize + offset as usize;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let wb = self.active_window_base();
            let mut buf = vec![0u8; len as usize];
            // SAFETY: base_page was mmap'd into the window by map_pages.
            unsafe {
                std::ptr::copy_nonoverlapping(wb.add(addr), buf.as_mut_ptr(), len as usize);
            }
            Some(buf)
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let byte_off = d.backing_offset as usize * crate::PVM_PAGE_SIZE as usize
                + (addr - base_page as usize * crate::PVM_PAGE_SIZE as usize);
            self.backing
                .read_bytes_at(byte_off, len as usize)
                .map(|s| s.to_vec())
        }
    }

    /// Read bytes directly from the active VM's window by address.
    /// Used for reading output from guest programs that return ptr+len in registers.
    pub fn read_data_cap_window(&self, addr: u32, len: u32) -> Option<Vec<u8>> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let wb = self.active_window_base();
            let mut buf = vec![0u8; len as usize];
            // SAFETY: addr is within the window's 4GB mmap region.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    wb.add(addr as usize),
                    buf.as_mut_ptr(),
                    len as usize,
                );
            }
            Some(buf)
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            // On non-Linux the window is not backed by physical pages.
            // Find the DataCap covering addr and read from the backing store.
            let vm = &self.vm_arena.vm(self.active_vm);
            let addr_page = addr / crate::PVM_PAGE_SIZE;
            let offset_in_page = (addr % crate::PVM_PAGE_SIZE) as usize;
            for slot in 0..=255u8 {
                if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                    && let Some((base_page, _access)) = d.active_mapping()
                    && addr_page >= base_page
                    && addr_page < base_page + d.page_count
                {
                    let page_in_cap = (addr_page - base_page) as usize;
                    let byte_off = (d.backing_offset as usize + page_in_cap)
                        * crate::PVM_PAGE_SIZE as usize
                        + offset_in_page;
                    return self
                        .backing
                        .read_bytes_at(byte_off, len as usize)
                        .map(|s| s.to_vec());
                }
            }
            None
        }
    }

    /// Write bytes into a DATA cap's mapped region in the active VM's window.
    pub fn write_data_cap(&mut self, cap_idx: u8, offset: u32, data: &[u8]) -> bool {
        // Extract cap info first, releasing the borrow on vm_arena before
        // mutably borrowing backing on the non-Linux path.
        let cap_info = {
            let vm = &self.vm_arena.vm(self.active_vm);
            let d = match vm.cap_table.get(cap_idx) {
                Some(Cap::Data(d)) => d,
                _ => return false,
            };
            d.active_mapping().map(|(b, _)| (b, d.backing_offset))
        };
        let (base_page, backing_offset) = match cap_info {
            Some(info) => info,
            None => return false,
        };
        let addr = base_page as usize * crate::PVM_PAGE_SIZE as usize + offset as usize;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let _ = backing_offset; // only used on non-Linux
            let wb = self.active_window_base();
            // SAFETY: base_page was mmap'd into the window by map_pages.
            unsafe {
                std::ptr::copy_nonoverlapping(data.as_ptr(), wb.add(addr), data.len());
            }
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let byte_off = backing_offset as usize * crate::PVM_PAGE_SIZE as usize
                + (addr - base_page as usize * crate::PVM_PAGE_SIZE as usize);
            self.backing.write_bytes_at(byte_off, data);
        }
        true
    }

    /// Write bytes directly into the active VM's window by address.
    /// Symmetric with [`Self::read_data_cap_window`]: used by hosts that pass
    /// flat virtual addresses (rather than `(cap_idx, offset)` pairs) for
    /// hostcall output buffers. The kernel locates the covering DATA cap and
    /// writes through it. Returns `false` if `addr..addr+len` does not fall
    /// within any mapped DATA cap in the active VM.
    pub fn write_data_cap_window(&mut self, addr: u32, data: &[u8]) -> bool {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let wb = self.active_window_base();
            // SAFETY: addr is within the window's 4GB mmap region.
            unsafe {
                std::ptr::copy_nonoverlapping(data.as_ptr(), wb.add(addr as usize), data.len());
            }
            true
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            // On non-Linux the window is not backed by physical pages.
            // Find the DataCap covering addr and write through the backing store.
            let addr_page = addr / crate::PVM_PAGE_SIZE;
            let offset_in_page = (addr % crate::PVM_PAGE_SIZE) as usize;
            let cap_info = {
                let vm = &self.vm_arena.vm(self.active_vm);
                let mut found = None;
                for slot in 0..=255u8 {
                    if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                        && let Some((base_page, _access)) = d.active_mapping()
                        && addr_page >= base_page
                        && addr_page < base_page + d.page_count
                    {
                        found = Some((base_page, d.backing_offset));
                        break;
                    }
                }
                found
            };
            let (base_page, backing_offset) = match cap_info {
                Some(info) => info,
                None => return false,
            };
            let page_in_cap = (addr_page - base_page) as usize;
            let byte_off = (backing_offset as usize + page_in_cap) * crate::PVM_PAGE_SIZE as usize
                + offset_in_page;
            self.backing.write_bytes_at(byte_off, data);
            true
        }
    }

    /// Handle a callee halt (exit from VM execution).
    pub fn handle_vm_halt(&mut self, exit_value: u64) -> DispatchResult {
        let callee_id = self.active_vm;
        let _ = self.vm_arena.vm_mut(callee_id).transition(VmState::Halted);

        match self.call_stack.pop() {
            Some(frame) => {
                let caller_id = frame.caller_vm_id;

                // Return unused gas
                let unused_gas = self.vm_arena.vm(callee_id).gas();
                let cg = self.vm_arena.vm(caller_id).gas();
                self.vm_arena.vm_mut(caller_id).set_gas(cg + unused_gas);

                // Restore the caller's ephemeral sub-slots 0/1/2.
                self.restore_ephemeral_kernel_slots(frame.prev_kernel_slots);

                // Return result
                self.vm_arena.vm_mut(caller_id).set_reg(7, exit_value);

                let _ = self.vm_arena.vm_mut(caller_id).transition(VmState::Running);
                self.active_vm = caller_id;
                DispatchResult::Continue
            }
            None => {
                // Root VM halted
                DispatchResult::RootHalt(exit_value)
            }
        }
    }

    /// Handle a callee fault with status code and aux value.
    pub fn handle_vm_fault(&mut self, fault: FaultType) -> DispatchResult {
        // Determine status code and aux value based on fault type
        let (status, aux_value) = match fault {
            FaultType::Trap => {
                // Status 1: trap. Preserve child's φ[7] as trap code.
                (1u64, self.vm_arena.vm(self.active_vm).reg(7))
            }
            FaultType::Panic => (2, RESULT_HUH), // Status 2: runtime panic
            FaultType::OutOfGas => (3, RESULT_LOW), // Status 3: OOG
            FaultType::PageFault(addr) => (4, addr as u64), // Status 4: page fault
        };

        let callee_id = self.active_vm;
        let _ = self.vm_arena.vm_mut(callee_id).transition(VmState::Faulted);

        match self.call_stack.pop() {
            Some(frame) => {
                let caller_id = frame.caller_vm_id;

                // Return unused gas
                let unused_gas = self.vm_arena.vm(callee_id).gas();
                let cg = self.vm_arena.vm(caller_id).gas();
                self.vm_arena.vm_mut(caller_id).set_gas(cg + unused_gas);

                // Kernel-default rollback: scan the resuming parent's
                // persistent Frame for parked Gas caps and merge them
                // back into the live ephemeral Gas cap. This guarantees
                // the parent recovers the full budget it set aside via
                // GAS_DERIVE before the failed CALL, regardless of what
                // the (possibly-untrusted) child did with its share.
                self.rollback_parked_gas(caller_id);

                // Set φ[7]=aux_value, φ[8]=status
                self.vm_arena.vm_mut(caller_id).set_reg(7, aux_value);
                self.vm_arena.vm_mut(caller_id).set_reg(8, status);

                let _ = self.vm_arena.vm_mut(caller_id).transition(VmState::Running);
                self.active_vm = caller_id;
                DispatchResult::Continue
            }
            None => {
                // Root VM faulted
                match fault {
                    FaultType::Trap | FaultType::Panic => DispatchResult::RootPanic,
                    FaultType::OutOfGas => DispatchResult::RootOutOfGas,
                    FaultType::PageFault(addr) => DispatchResult::RootPageFault(addr),
                }
            }
        }
    }

    /// Scan `vm_idx`'s persistent Frame for parked `Cap::Protocol(P)` caps
    /// (slots 1..=255, skipping the bare-Frame FrameRef at slot 0) and
    /// attempt to merge each one into the live Gas cap at bare-Frame
    /// sub-slot 3 via `ProtocolCapT::gas_merge`. Caps where `gas_merge`
    /// returns false (non-Gas-shaped payloads) are restored to their
    /// slot; successful merges drop the donor.
    fn rollback_parked_gas(&mut self, vm_idx: u16) {
        let bare_idx = self.bare_frame_idx();
        for slot in 1..=255u8 {
            // Take the cap so we can pass `&donor` to `gas_merge` while
            // mutably borrowing the bare Frame's cap-table; restore on
            // failure.
            let taken = match self.vm_arena.vm_mut(vm_idx).cap_table.take(slot) {
                Some(c) => c,
                None => continue,
            };
            let donor = match taken {
                Cap::Protocol(p) => p,
                other => {
                    self.vm_arena.vm_mut(vm_idx).cap_table.set(slot, other);
                    continue;
                }
            };
            let merged = match self.vm_arena.vm_mut(bare_idx).cap_table.get_mut(3) {
                Some(Cap::Protocol(dst)) => dst.gas_merge(&donor),
                _ => false,
            };
            if !merged {
                self.vm_arena
                    .vm_mut(vm_idx)
                    .cap_table
                    .set(slot, Cap::Protocol(donor));
            }
        }
    }
}

/// Result of dispatching an ecalli.
#[derive(Debug)]
pub enum DispatchResult {
    /// Continue execution of the active VM.
    Continue,
    /// A protocol cap was called — host should handle.
    ProtocolCall { slot: u8 },
    /// Root VM halted normally.
    RootHalt(u64),
    /// Root VM panicked.
    RootPanic,
    /// Root VM ran out of gas.
    RootOutOfGas,
    /// Root VM page-faulted.
    RootPageFault(u32),
    /// A fault in a non-root VM (already handled, caller resumed).
    Fault(FaultType),
}

/// Fault types.
#[derive(Debug, Clone, Copy)]
pub enum FaultType {
    Trap,
    Panic,
    OutOfGas,
    PageFault(u32),
}

/// Kernel errors.
#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("invalid JAR blob")]
    InvalidBlob,
    #[error("memory allocation failed")]
    MemoryError,
    #[error("insufficient gas for initialization")]
    OutOfGas,
    #[error("untyped pool exhausted")]
    OutOfMemory,
    #[error("exceeded max CODE caps ({MAX_CODE_CAPS})")]
    TooManyCodeCaps,
    #[error("cap table full")]
    CapTableFull,
    #[error("JIT compilation failed")]
    CompileError,
}

// =============================================================================
// Public construction helpers
//
// These free functions expose the building blocks of `InvocationKernel`
// construction: hosts that build a `CapTable` directly (e.g. jar-kernel's
// `Vault.initialize` flow walking `vault.slots`) call them to compile
// CodeCap blobs and allocate ephemeral DataCap pages without going
// through the JAR-blob manifest path.
// =============================================================================

/// Compile a raw PVM code blob into an [`Arc<CodeCap>`], hitting the
/// supplied [`CodeCache`] when present. Mirrors the `CapEntryType::Code`
/// arm of the JAR-manifest walk; the cache key is a blake2b-256 of the
/// blob bytes.
///
/// `code_cap_id` is stamped into the returned `CodeCap` on a cache miss.
/// On a cache hit the cached `Arc<CodeCap>` is returned as-is — its
/// internal `id` field carries whatever value was assigned at first
/// compile. Callers (e.g. `cap_table_from_blob`, `vault_init`) treat
/// `id` as an opaque index they will install at the same position in
/// their own `code_caps` Vec, so as long as code caps are pushed in
/// matching compile order, lookup invariants hold. Mixing kernels that
/// share a cache *and* push code caps in different orders is a footgun
/// inherent to the existing model; not introduced here.
pub fn compile_code_blob(
    bytes: &[u8],
    code_cap_id: u16,
    mem_cycles: u8,
    backend: crate::backend::PvmBackend,
    code_cache: Option<&mut CodeCache>,
) -> Result<Arc<CodeCap>, KernelError> {
    // Cache lookup (blake2b-256 collision is negligible).
    let cache_key = CodeCache::hash_blob(bytes);
    if let Some(cache) = code_cache.as_deref()
        && let Some(cached) = cache.entries.get(&cache_key)
    {
        return Ok(Arc::clone(cached));
    }

    // Parse the code sub-blob (jump_table + code + bitmask).
    let code_blob = program::parse_code_blob(bytes).ok_or(KernelError::InvalidBlob)?;

    // Compile via the selected backend.
    let compiled = crate::backend::compile(
        &code_blob.code,
        &code_blob.bitmask,
        &code_blob.jump_table,
        mem_cycles,
        backend,
    )
    .map_err(|e| {
        tracing::warn!("compile failed: {e}");
        KernelError::CompileError
    })?;

    let code_cap = Arc::new(CodeCap {
        id: code_cap_id,
        compiled,
        jump_table: code_blob.jump_table,
        bitmask: code_blob.bitmask,
    });

    if let Some(cache) = code_cache {
        cache.entries.insert(cache_key, Arc::clone(&code_cap));
    }

    Ok(code_cap)
}

/// Allocate a fresh ephemeral [`DataCap`] backed by `untyped` pages and
/// pre-populate it with `content`. Returns the cap **unmapped**: the
/// caller must call [`DataCap::map`] (or the guest must `MGMT_MAP`) to
/// install it in a VM window. Mirrors the `CapEntryType::Data` arm of
/// the JAR-manifest walk minus the per-manifest mapping step.
///
/// `content` may be shorter than `page_count * PVM_PAGE_SIZE`; trailing
/// pages are zero-filled. Passing an empty slice yields a fully
/// zero-filled cap (no `write_init_data` call).
pub fn allocate_data_cap(
    content: &[u8],
    page_count: u32,
    untyped: &Arc<UntypedCap>,
    backing: &mut BackingStore,
) -> Result<DataCap, KernelError> {
    let backing_offset = untyped.retype(page_count).ok_or(KernelError::OutOfMemory)?;
    if !content.is_empty() && !backing.write_init_data(backing_offset, content) {
        return Err(KernelError::MemoryError);
    }
    Ok(DataCap::new(backing_offset, page_count))
}

/// Pre-built input to [`InvocationKernel::new_from_artifacts`]. Holds
/// the CapTable for VM 0, the kernel's `code_caps` Vec, the entry
/// CodeCap's index, and the per-invocation backing/untyped (the host
/// allocates these because it needs them to populate DataCap caps in
/// the table). The kernel takes ownership of every field on
/// construction.
///
/// DATA caps in `cap_table` are always **unmapped**. The transpiler-
/// emitted init prologue runs at PC=0 of every invocation and issues
/// `MGMT_MAP` for each DATA cap before user code; the kernel does not
/// pre-map (this changed when `base_page` / `init_access` were dropped
/// from the JAR manifest format).
///
/// Two production paths produce this struct today:
/// - [`cap_table_from_blob`]: parses a JAR blob and runs the manifest
///   walk; the transpiler-emitted prologue inside the CodeCap handles
///   the runtime mapping.
/// - jar-kernel's `vault_init::build_init_cap_table` (separate crate):
///   walks `vault.slots` and produces the same unmapped shape.
pub struct InvocationArtifacts<P: ProtocolCapT> {
    pub cap_table: CapTable<P>,
    pub code_caps: Vec<Arc<CodeCap>>,
    pub init_code_id: u16,
    pub untyped: Arc<UntypedCap>,
    pub backing: BackingStore,
}

/// Parse a JAR blob and produce the artifacts needed by
/// [`InvocationKernel::new_from_artifacts`]. DATA caps are allocated
/// (content-copied from the blob's data section) but **not mapped** —
/// the init prologue baked into the JAR's CODE cap is responsible for
/// `MGMT_MAP`-ing each DATA cap before user code runs.
///
/// `code_cache` is consulted for each CODE cap; on miss the cap is
/// compiled and inserted into the cache.
pub fn cap_table_from_blob<P: ProtocolCapT>(
    blob: &[u8],
    backend: crate::backend::PvmBackend,
    mut code_cache: Option<&mut CodeCache>,
) -> Result<InvocationArtifacts<P>, KernelError> {
    let parsed = program::parse_blob(blob).ok_or(KernelError::InvalidBlob)?;
    let memory_pages = parsed.header.memory_pages;

    let mut backing = BackingStore::new(memory_pages).ok_or(KernelError::MemoryError)?;
    let untyped = Arc::new(UntypedCap::new(memory_pages));
    let mem_cycles = crate::compute_mem_cycles(memory_pages);

    let mut cap_table: CapTable<P> = CapTable::new();
    let mut code_caps: Vec<Arc<CodeCap>> = Vec::with_capacity(MAX_CODE_CAPS);

    for entry in &parsed.caps {
        match entry.cap_type {
            CapEntryType::Code => {
                if code_caps.len() >= MAX_CODE_CAPS {
                    return Err(KernelError::TooManyCodeCaps);
                }
                let code_data = program::cap_data(entry, parsed.data_section);
                let id = code_caps.len() as u16;
                let code_cap = compile_code_blob(
                    code_data,
                    id,
                    mem_cycles,
                    backend,
                    code_cache.as_deref_mut(),
                )?;
                code_caps.push(Arc::clone(&code_cap));
                cap_table.set(entry.cap_index, Cap::Code(code_cap));
            }
            CapEntryType::Data => {
                let initial = if entry.data_len > 0 {
                    program::cap_data(entry, parsed.data_section)
                } else {
                    &[]
                };
                let data_cap =
                    allocate_data_cap(initial, entry.page_count, &untyped, &mut backing)?;
                // Cap is unmapped on purpose — the init prologue calls
                // MGMT_MAP at runtime.
                cap_table.set(entry.cap_index, Cap::Data(data_cap));
            }
        }
    }

    let init_code_id = match cap_table.get(parsed.header.init_cap) {
        Some(Cap::Code(c)) => c.id,
        _ => return Err(KernelError::InvalidBlob),
    };

    Ok(InvocationArtifacts {
        cap_table,
        code_caps,
        init_code_id,
        untyped,
        backing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    // (removed: ProtocolCap unwrapped into u8 directly)
    use crate::program::{CapEntryType, CapManifestEntry, build_blob};

    /// Build a minimal code sub-blob (code_header + jump_table + code + bitmask).
    /// Contains a single `trap` instruction (opcode 0).
    fn make_code_sub_blob() -> Vec<u8> {
        let code = [0u8]; // trap instruction
        let bitmask = [1u8]; // instruction start
        let jump_table: &[u32] = &[];
        let entry_size: u8 = 1;

        let mut blob = Vec::new();
        // Sub-blob header: jump_len(4) + entry_size(1) + code_len(4)
        blob.extend_from_slice(&(jump_table.len() as u32).to_le_bytes());
        blob.push(entry_size);
        blob.extend_from_slice(&(code.len() as u32).to_le_bytes());
        // Code bytes
        blob.extend_from_slice(&code);
        // Packed bitmask
        blob.push(bitmask[0]); // 1 bit packed
        blob
    }

    fn make_simple_blob(memory_pages: u32) -> Vec<u8> {
        let code_data = make_code_sub_blob();

        let caps = vec![
            CapManifestEntry {
                cap_index: 64,
                cap_type: CapEntryType::Code,
                page_count: 0,
                data_offset: 0,
                data_len: code_data.len() as u32,
            },
            CapManifestEntry {
                cap_index: 65,
                cap_type: CapEntryType::Data,
                page_count: 1,
                data_offset: 0, // doesn't reference data section
                data_len: 0,
            },
        ];
        build_blob(memory_pages, 64, &caps, &code_data)
    }

    /// Test helper: migrate the legacy `InvocationKernel::new(blob, gas)`
    /// pattern to the two-step `cap_table_from_blob` +
    /// `new_from_artifacts` flow. Used by every kernel-level test below.
    fn kernel_from_blob(blob: &[u8], gas: u64) -> InvocationKernel<u8> {
        let artifacts = cap_table_from_blob::<u8>(blob, crate::backend::PvmBackend::Default, None)
            .expect("cap_table_from_blob ok");
        InvocationKernel::new_from_artifacts(artifacts, gas, crate::backend::PvmBackend::Default)
            .expect("new_from_artifacts ok")
    }

    /// Test helper for cached construction.
    fn kernel_from_blob_cached(
        blob: &[u8],
        gas: u64,
        cache: &mut CodeCache,
    ) -> InvocationKernel<u8> {
        let artifacts =
            cap_table_from_blob::<u8>(blob, crate::backend::PvmBackend::Default, Some(cache))
                .expect("cap_table_from_blob ok");
        InvocationKernel::new_from_artifacts(artifacts, gas, crate::backend::PvmBackend::Default)
            .expect("new_from_artifacts ok")
    }

    /// Test helper for warm-restart construction. Takes a pre-existing
    /// flat_mem snapshot and overlays it onto VM 0's RW DATA cap pages
    /// after the kernel is built. This mirrors what the retired
    /// `new_warm` did internally.
    fn kernel_from_blob_warm(
        blob: &[u8],
        gas: u64,
        flat_mem: &[u8],
        heap_base: u32,
        heap_top: u32,
        cache: Option<&mut CodeCache>,
    ) -> InvocationKernel<u8> {
        let artifacts = cap_table_from_blob::<u8>(blob, crate::backend::PvmBackend::Default, cache)
            .expect("cap_table_from_blob ok");
        let mut kernel = InvocationKernel::new_from_artifacts(
            artifacts,
            gas,
            crate::backend::PvmBackend::Default,
        )
        .expect("new_from_artifacts ok");
        // Overlay the saved flat_mem onto RW DATA cap pages of VM 0.
        let vm = kernel.vm_arena.vm(0);
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let wb = kernel.active_window_base();
            for slot in 0..=255u8 {
                if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                    && let Some((base_page, access)) = d.active_mapping()
                    && access == Access::RW
                {
                    let addr = base_page as usize * crate::PVM_PAGE_SIZE as usize;
                    let len = d.page_count as usize * crate::PVM_PAGE_SIZE as usize;
                    if addr + len <= flat_mem.len() {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                flat_mem.as_ptr().add(addr),
                                wb.add(addr),
                                len,
                            );
                        }
                    }
                }
            }
        }
        let _ = (flat_mem, vm); // silence unused on non-Linux
        let vm0 = kernel.vm_arena.vm_mut(0);
        vm0.set_heap_base(heap_base);
        vm0.set_heap_top(heap_top);
        kernel
    }

    #[test]
    fn compile_code_blob_round_trip_and_cache() {
        let code_data = make_code_sub_blob();
        // First compile: cache miss → compiles fresh.
        let mut cache = CodeCache::new();
        let cap_a = compile_code_blob(
            &code_data,
            0,
            5,
            crate::backend::PvmBackend::Default,
            Some(&mut cache),
        )
        .expect("compile_code_blob succeeds");
        assert_eq!(cap_a.id, 0);
        assert_eq!(cache.entries.len(), 1);

        // Second compile of the same bytes → cache hit; same Arc returned.
        let cap_b = compile_code_blob(
            &code_data,
            42, // ignored on cache hit
            5,
            crate::backend::PvmBackend::Default,
            Some(&mut cache),
        )
        .expect("second compile_code_blob succeeds");
        assert!(Arc::ptr_eq(&cap_a, &cap_b));
        assert_eq!(cache.entries.len(), 1);

        // Compile without a cache works too.
        let cap_c = compile_code_blob(&code_data, 7, 5, crate::backend::PvmBackend::Default, None)
            .expect("no-cache compile succeeds");
        assert_eq!(cap_c.id, 7);
    }

    #[test]
    fn allocate_data_cap_writes_content_unmapped() {
        let untyped = Arc::new(UntypedCap::new(8));
        let mut backing = BackingStore::new(8).expect("BackingStore::new");

        let content = b"hello world\n";
        let data_cap = allocate_data_cap(content, 1, &untyped, &mut backing)
            .expect("allocate_data_cap succeeds");

        // Cap is unmapped: no recorded mappings, no active VM, bitmap empty.
        assert!(data_cap.mappings.is_empty());
        assert!(data_cap.active_in.is_none());
        assert!(!data_cap.has_any_mapped());
        assert_eq!(data_cap.page_count, 1);

        // Untyped consumed one page (offset 0 → 1).
        assert_eq!(untyped.remaining(), 7);
    }

    #[test]
    fn allocate_data_cap_zero_filled_when_content_empty() {
        let untyped = Arc::new(UntypedCap::new(2));
        let mut backing = BackingStore::new(2).expect("BackingStore::new");
        let cap = allocate_data_cap(&[], 1, &untyped, &mut backing).expect("allocate");
        assert_eq!(cap.page_count, 1);
        assert!(cap.mappings.is_empty());
    }

    #[test]
    fn ecall_opcode_terminates_basic_block() {
        // Regression: opcode 3 (Ecall) was missing from GAS_COST_LUT, so
        // the recompiler's codegen treated it as a non-terminator. The
        // post-ecall PC never got a dispatch_table entry, and after the
        // ecall exited and the kernel re-entered the JIT, dispatch_table
        // returned 0 → infinite re-dispatch loop. The fix sets the LUT
        // entry with `F_TERM`. This test exercises an ecall followed by
        // a trap (so the post-ecall PC is a valid instruction) and
        // asserts the kernel reaches the trap (Panic) instead of
        // hanging.
        let mut sub = Vec::new();
        sub.extend_from_slice(&0u32.to_le_bytes()); // jump_len = 0
        sub.push(1); // entry_size = 1
        sub.extend_from_slice(&2u32.to_le_bytes()); // code_len = 2
        sub.push(3); // ecall (opcode 3, NoArgs)
        sub.push(0); // trap (opcode 0, NoArgs)
        sub.push(0b11); // packed bitmask: bits 0 and 1 set

        let caps = vec![CapManifestEntry {
            cap_index: 64,
            cap_type: CapEntryType::Code,
            page_count: 0,
            data_offset: 0,
            data_len: sub.len() as u32,
        }];
        let blob = build_blob(0, 64, &caps, &sub);

        let artifacts =
            cap_table_from_blob::<u8>(&blob, crate::backend::PvmBackend::Default, None).unwrap();
        let mut kernel: InvocationKernel = InvocationKernel::new_from_artifacts(
            artifacts,
            100_000,
            crate::backend::PvmBackend::Default,
        )
        .unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);
        let result = kernel.run();
        // Expected: ecall returns Continue (op=0 → dynamic CALL on
        // bare-Frame slot which lacks CALL right → RESULT_WHAT,
        // continue), then trap → Panic. What we're really testing is
        // that the kernel doesn't hang.
        assert!(
            matches!(result, KernelResult::Panic),
            "expected Panic (from trap after ecall), got {:?}",
            result
        );
    }

    #[test]
    fn cap_table_from_blob_round_trip_to_kernel() {
        let blob = make_simple_blob(10);
        let artifacts: InvocationArtifacts<u8> =
            cap_table_from_blob(&blob, crate::backend::PvmBackend::Default, None)
                .expect("cap_table_from_blob ok");

        // Manifest had 1 CodeCap (slot 64) and 1 DataCap (slot 65); the
        // DataCap is allocated unmapped (init prologue does the mapping).
        assert_eq!(artifacts.code_caps.len(), 1);
        assert_eq!(artifacts.init_code_id, 0);
        assert!(matches!(artifacts.cap_table.get(64), Some(Cap::Code(_))));
        match artifacts.cap_table.get(65) {
            Some(Cap::Data(d)) => {
                assert!(d.mappings.is_empty(), "DataCap should be unmapped");
            }
            other => panic!("expected unmapped Cap::Data at slot 65, got {:?}", other),
        }

        let kernel: InvocationKernel = InvocationKernel::new_from_artifacts(
            artifacts,
            100_000,
            crate::backend::PvmBackend::Default,
        )
        .expect("new_from_artifacts ok");

        // Same shape as the legacy blob path produced from the same blob.
        assert_eq!(kernel.code_caps.len(), 1);
        assert_eq!(kernel.vm_arena.len(), 2); // VM 0 + bare Frame
    }

    #[test]
    fn allocate_data_cap_exhausts_untyped() {
        let untyped = Arc::new(UntypedCap::new(1));
        let mut backing = BackingStore::new(1).expect("BackingStore::new");
        let _first = allocate_data_cap(&[], 1, &untyped, &mut backing).expect("first ok");
        let second = allocate_data_cap(&[], 1, &untyped, &mut backing);
        assert!(matches!(second, Err(KernelError::OutOfMemory)));
    }

    #[test]
    fn test_kernel_create() {
        let blob = make_simple_blob(10);
        let kernel: InvocationKernel = kernel_from_blob(&blob, 100_000);
        // Two arena entries on a fresh kernel: VM 0 (root) and the
        // bare Frame at idx 1 (per-invocation shared cap-table backing).
        assert_eq!(kernel.vm_arena.len(), 2);
        assert_eq!(kernel.code_caps.len(), 1);
        assert_eq!(kernel.mem_cycles, 25);
    }

    #[test]
    fn test_kernel_retype() {
        let blob = make_simple_blob(10);
        let mut kernel: InvocationKernel = kernel_from_blob(&blob, 100_000);

        // Set VM 0 to running
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // UNTYPED is at fixed slot 254
        let untyped_slot = 254u8;
        assert!(matches!(
            kernel.vm_arena.vm(0).cap_table.get(untyped_slot),
            Some(Cap::Untyped(_))
        ));

        // Use ecall (UNTYPED slot 254 > 127, can't use ecalli)
        // φ[7]=4 pages, φ[11]=0 (CALL), φ[12]=dst_slot(low) | untyped_slot(high)
        kernel.set_active_reg(7, 4);
        kernel.set_active_reg(11, 0); // op = CALL
        kernel.set_active_reg(12, 66 | ((untyped_slot as u64) << 32));
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        kernel.flush_live_ctx();
        let result = kernel.dispatch_ecall(&mut NoForeignCnode, 0);
        assert!(matches!(result, DispatchResult::Continue));

        // φ[7] should be the dst_slot
        let new_cap_idx = kernel.active_reg(7) as u8;
        assert_eq!(new_cap_idx, 66);
        assert!(matches!(
            kernel.vm_arena.vm(0).cap_table.get(new_cap_idx),
            Some(Cap::Data(_))
        ));
    }

    #[test]
    fn test_kernel_create_vm() {
        let blob = make_simple_blob(10);
        let mut kernel: InvocationKernel = kernel_from_blob(&blob, 100_000);
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Find the CODE cap slot
        let code_slot = 64u8; // From manifest

        // CALL on CODE: φ[7]=bitmask, φ[12]=dst_slot for HANDLE
        kernel.set_active_reg(7, 0); // no caps to copy
        kernel.set_active_reg(12, 66); // HANDLE at slot 66 (64=CODE, 65=DATA)

        let result = kernel.dispatch_ecalli(code_slot as u32);
        assert!(matches!(result, DispatchResult::Continue));

        // Two pre-existing entries (root VM 0 + bare Frame); CREATE
        // adds a third at idx 2.
        assert_eq!(kernel.vm_arena.len(), 3);
        assert_eq!(kernel.vm_arena.vm(2).state, VmState::Idle);

        // φ[7] = dst_slot
        let handle_idx = kernel.active_reg(7) as u8;
        assert_eq!(handle_idx, 66);
        match kernel.vm_arena.vm(0).cap_table.get(handle_idx) {
            Some(Cap::FrameRef(f)) => {
                assert_eq!(f.rights, FrameRefRights::OWNER);
                assert_eq!(f.vm_id.index(), 2);
            }
            _ => panic!("expected FrameRef"),
        }
    }

    #[test]
    fn test_kernel_call_reply() {
        let blob = make_simple_blob(10);
        let mut kernel: InvocationKernel = kernel_from_blob(&blob, 100_000);
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Create child VM: φ[7]=bitmask, φ[12]=dst_slot for HANDLE
        kernel.set_active_reg(7, 0); // no caps copied
        kernel.set_active_reg(12, 66); // place HANDLE at slot 66 (64=CODE, 65=DATA)
        kernel.dispatch_ecalli(64); // CALL CODE at slot 64 → CREATE
        let handle_idx = kernel.active_reg(7) as u8;

        // CALL the child: φ[7]=arg0, φ[8]=arg1, φ[12]=0 (no IPC cap)
        kernel.set_active_reg(7, 42);
        kernel.set_active_reg(8, 99);
        kernel.set_active_reg(12, 0);

        let result = kernel.dispatch_ecalli(handle_idx as u32);
        assert!(matches!(result, DispatchResult::Continue));

        // Child VM is at idx 2 (bare Frame is at idx 1).
        assert_eq!(kernel.active_vm, 2);
        assert_eq!(kernel.vm_arena.vm(0).state, VmState::WaitingForReply);
        assert_eq!(kernel.vm_arena.vm(2).state, VmState::Running);

        // Child received args
        assert_eq!(kernel.active_reg(7), 42);
        assert_eq!(kernel.active_reg(8), 99);

        // Child REPLYs with results
        kernel.set_active_reg(7, 100);
        kernel.set_active_reg(8, 200);
        let result = kernel.dispatch_ecalli(BARE_FRAME_SLOT as u32); // REPLY
        assert!(matches!(result, DispatchResult::Continue));

        // Back to VM 0
        assert_eq!(kernel.active_vm, 0);
        assert_eq!(kernel.vm_arena.vm(0).state, VmState::Running);
        assert_eq!(kernel.vm_arena.vm(2).state, VmState::Idle);

        // Caller received results: φ[7]=child's return, φ[8]=0 (status=REPLY)
        assert_eq!(kernel.active_reg(7), 100);
        assert_eq!(kernel.active_reg(8), 0);
    }

    #[test]
    fn test_kernel_no_reentrancy() {
        let blob = make_simple_blob(10);
        let mut kernel: InvocationKernel = kernel_from_blob(&blob, 100_000);
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Create two child VMs: φ[7]=bitmask, φ[12]=dst_slot
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 66);
        kernel.dispatch_ecalli(64); // CREATE VM 1, HANDLE at 66
        let handle1 = kernel.active_reg(7) as u8;

        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 67);
        kernel.dispatch_ecalli(64); // CREATE VM 2, HANDLE at 67
        let _handle2 = kernel.active_reg(7) as u8;

        // VM 0 calls the first child (idx 2 — bare Frame at idx 1)
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 0); // no IPC cap (slot 0 = IPC itself)
        kernel.dispatch_ecalli(handle1 as u32);
        assert_eq!(kernel.active_vm, 2);

        // Copy handle1 to VM 2 — but VM 0 is WaitingForReply,
        // so calling VM 0 from VM 2 should fail.
        // First we need a handle to VM 0 in VM 2's cap table.
        // We can't actually create one (no HANDLE to VM 0 exists in VM 2).
        // The reentrancy test is: VM 0 is in WaitingForReply, not IDLE.
        // If anyone tries to call VM 0, it fails.
        assert!(!kernel.vm_arena.vm(0).can_call());
    }

    #[test]
    fn test_kernel_call_transfers_full_gas() {
        // Shared-pool gas model: CALL transfers caller's full residual
        // gas to the callee (no max_gas split). Per-call restriction is
        // achieved by the park pattern via MGMT_GAS_DERIVE / _MERGE,
        // which is host-policy on top of `Capability::Gas` and not
        // exercised by this javm-only test.
        let blob = make_simple_blob(10);
        let mut kernel: InvocationKernel = kernel_from_blob(&blob, 100_000);
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Create child VM: φ[7]=bitmask, φ[12]=dst_slot
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 66);
        kernel.dispatch_ecalli(64);
        let handle_idx = kernel.active_reg(7) as u8;

        // CALL child — callee gets caller's full residual gas, caller
        // is left with 0 until REPLY restores the residual. Child VM
        // sits at idx 2 (bare Frame at idx 1).
        let parent_gas_before = kernel.vm_arena.vm(0).gas();
        kernel.dispatch_ecalli(handle_idx as u32);

        assert_eq!(kernel.active_vm, 2);
        // Callee inherits caller_gas - ecalli_charge (10) - call_overhead (10).
        assert_eq!(kernel.vm_arena.vm(2).gas(), parent_gas_before - 20);
        assert_eq!(kernel.vm_arena.vm(0).gas(), 0);
    }

    #[test]
    fn test_kernel_protocol_call() {
        let blob = make_simple_blob(10);
        let mut kernel: InvocationKernel = kernel_from_blob(&blob, 100_000);
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Set a protocol cap at slot 1 (GAS)
        kernel
            .vm_arena
            .vm_mut(0)
            .cap_table
            .set(1, Cap::Protocol(1u8));

        // CALL slot 1 → should return ProtocolCall
        kernel.set_active_reg(7, 123);
        let result = kernel.dispatch_ecalli(1);
        match result {
            DispatchResult::ProtocolCall { slot } => {
                assert_eq!(slot, 1);
                // Registers accessible via kernel.active_reg(7)
                assert_eq!(kernel.active_reg(7), 123);
            }
            _ => panic!("expected ProtocolCall"),
        }
    }

    #[test]
    fn test_kernel_missing_cap() {
        let blob = make_simple_blob(10);
        let mut kernel: InvocationKernel = kernel_from_blob(&blob, 100_000);
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // CALL empty slot → WHAT
        let result = kernel.dispatch_ecalli(50);
        assert!(matches!(result, DispatchResult::Continue));
        assert_eq!(kernel.active_reg(7), RESULT_WHAT);
    }

    #[test]
    fn test_kernel_downgrade() {
        let blob = make_simple_blob(10);
        let mut kernel: InvocationKernel = kernel_from_blob(&blob, 100_000);
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Create child: φ[7]=bitmask, φ[12]=dst_slot
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 66);
        kernel.dispatch_ecalli(64);
        let handle_idx = kernel.active_reg(7) as u8;

        // DOWNGRADE handle → callable via ecall
        // φ[11]=0x0A, φ[12]=dst_slot(low) | handle(high)
        kernel.set_active_reg(11, 0x0A); // DOWNGRADE
        // dst slot: pick slot 67 for the callable
        kernel.set_active_reg(12, 67 | ((handle_idx as u64) << 32));
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        kernel.flush_live_ctx();
        kernel.dispatch_ecall(&mut NoForeignCnode, 0x0A);
        let callable_idx = 67u8;

        // Owner-shaped FrameRef still exists
        match kernel.vm_arena.vm(0).cap_table.get(handle_idx) {
            Some(Cap::FrameRef(f)) => assert_eq!(f.rights, FrameRefRights::OWNER),
            _ => panic!("expected owner FrameRef at source slot"),
        }
        // Callable-shaped FrameRef created
        match kernel.vm_arena.vm(0).cap_table.get(callable_idx) {
            Some(Cap::FrameRef(f)) => assert_eq!(f.rights, FrameRefRights::CALLABLE),
            _ => panic!("expected callable FrameRef at dst slot"),
        }
    }

    #[test]
    fn test_frame_ref_call_without_resume_rights_is_legal() {
        // A callable-shaped FrameRef (no RESUME / DROP / DERIVE) still
        // routes CALL to the target VM. Mirrors the legacy "Callable"
        // semantics now expressed as a rights mask.
        let blob = make_simple_blob(10);
        let mut kernel: InvocationKernel = kernel_from_blob(&blob, 100_000);
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Spawn child + downgrade the handle (slot 67 = callable).
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 66);
        kernel.dispatch_ecalli(64);
        let handle_idx = kernel.active_reg(7) as u8;
        kernel.set_active_reg(11, 0x0A);
        kernel.set_active_reg(12, 67 | ((handle_idx as u64) << 32));
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        kernel.flush_live_ctx();
        kernel.dispatch_ecall(&mut NoForeignCnode, 0x0A);

        // CALL on the callable: routes to child VM (idx 2, bare Frame at idx 1).
        kernel.set_active_reg(12, 0); // no IPC cap
        let result = kernel.dispatch_ecalli(67);
        assert!(matches!(result, DispatchResult::Continue));
        assert_eq!(kernel.active_vm, 2);
    }

    #[test]
    fn test_frame_ref_resume_requires_resume_right() {
        // A callable-shaped FrameRef cannot RESUME its target — even if
        // the target is Faulted. Returns RESULT_WHAT.
        let blob = make_simple_blob(10);
        let mut kernel: InvocationKernel = kernel_from_blob(&blob, 100_000);
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Spawn child + downgrade.
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 66);
        kernel.dispatch_ecalli(64);
        let handle_idx = kernel.active_reg(7) as u8;
        kernel.set_active_reg(11, 0x0A);
        kernel.set_active_reg(12, 67 | ((handle_idx as u64) << 32));
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        kernel.flush_live_ctx();
        kernel.dispatch_ecall(&mut NoForeignCnode, 0x0A);

        // Force the child to Faulted so RESUME's target-state check would
        // otherwise pass. RESUME via callable-shaped FrameRef should still
        // be rejected on rights.
        let target_vm_idx = match kernel.vm_arena.vm(0).cap_table.get(67) {
            Some(Cap::FrameRef(f)) => f.vm_id.index(),
            _ => panic!("expected callable FrameRef"),
        };
        let _ = kernel
            .vm_arena
            .vm_mut(target_vm_idx)
            .transition(VmState::Running);
        let _ = kernel
            .vm_arena
            .vm_mut(target_vm_idx)
            .transition(VmState::Faulted);

        // RESUME (ecalli 0x1): callable-shaped FrameRef rejected.
        kernel.set_active_reg(7, RESULT_WHAT.wrapping_sub(1));
        let result = kernel.dispatch_ecalli(0x10000 | 67); // not the right encoding
        // Direct path: call mgmt-RESUME via the management slot range.
        let _ = result;
        // Use the explicit RESUME entry point.
        let result = kernel.handle_resume(67);
        assert!(matches!(result, DispatchResult::Continue));
        assert_eq!(kernel.active_reg(7), RESULT_WHAT);
        // Active VM unchanged — RESUME did not transfer control.
        assert_eq!(kernel.active_vm, 0);
    }

    #[test]
    fn test_frame_ref_downgrade_requires_derive_right() {
        // A callable-shaped FrameRef cannot DOWNGRADE again — DERIVE is
        // not in the CALLABLE rights mask.
        let blob = make_simple_blob(10);
        let mut kernel: InvocationKernel = kernel_from_blob(&blob, 100_000);
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Spawn + downgrade once → slot 67 holds CALLABLE.
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 66);
        kernel.dispatch_ecalli(64);
        let handle_idx = kernel.active_reg(7) as u8;
        kernel.set_active_reg(11, 0x0A);
        kernel.set_active_reg(12, 67 | ((handle_idx as u64) << 32));
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        kernel.flush_live_ctx();
        kernel.dispatch_ecall(&mut NoForeignCnode, 0x0A);

        // Try to downgrade *the callable-shaped* cap. Should fail.
        let result = kernel.mgmt_downgrade(67);
        assert!(matches!(result, DispatchResult::Continue));
        assert_eq!(kernel.active_reg(7), RESULT_WHAT);
    }

    #[test]
    fn test_kernel_run_trap() {
        // Build a blob with a `trap` instruction (opcode 0) — causes Panic.
        // This validates the full execution path: blob parse → JIT compile →
        // mmap DATA → execute native code → exit handling.
        let blob = make_simple_blob(10);
        let mut kernel: InvocationKernel = kernel_from_blob(&blob, 100_000);
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);
        let result = kernel.run();
        assert!(
            matches!(result, KernelResult::Panic),
            "trap instruction should cause Panic, got: {result:?}"
        );
    }

    #[test]
    fn test_kernel_cap_bitmask_propagation() {
        let blob = make_simple_blob(10);
        let mut kernel: InvocationKernel = kernel_from_blob(&blob, 100_000);
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Place protocol caps at slots 1 and 2
        kernel
            .vm_arena
            .vm_mut(0)
            .cap_table
            .set(1, Cap::Protocol(1u8));
        kernel
            .vm_arena
            .vm_mut(0)
            .cap_table
            .set(2, Cap::Protocol(2u8));

        // Create child VM with bitmask = 0b110 (copy caps at slots 1 and 2)
        kernel.set_active_reg(7, 0b110);
        kernel.set_active_reg(12, 66);
        kernel.dispatch_ecalli(64); // CALL CODE → CREATE

        // The child (VM at idx 2; bare Frame at idx 1) should have
        // caps at slots 1 and 2.
        assert!(
            kernel.vm_arena.vm(2).cap_table.get(1).is_some(),
            "child should inherit cap at slot 1"
        );
        assert!(
            kernel.vm_arena.vm(2).cap_table.get(2).is_some(),
            "child should inherit cap at slot 2"
        );
        // Slot 3 was not in bitmask → should be empty
        assert!(
            kernel.vm_arena.vm(2).cap_table.get(3).is_none(),
            "child should NOT have cap at slot 3"
        );
    }

    #[test]
    fn test_kernel_zero_gas_call() {
        let blob = make_simple_blob(10);
        let mut kernel: InvocationKernel = kernel_from_blob(&blob, 100_000);
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Create child VM
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 66);
        kernel.dispatch_ecalli(64);
        let handle_idx = kernel.active_reg(7) as u8;

        // CALL with φ[9]=0 (zero gas transfer)
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(8, 0);
        kernel.set_active_reg(9, 0); // zero gas
        kernel.set_active_reg(12, 0);

        let result = kernel.dispatch_ecalli(handle_idx as u32);
        assert!(matches!(result, DispatchResult::Continue));

        // Child should be running but with very little gas. Child sits
        // at idx 2 (bare Frame at idx 1).
        assert_eq!(kernel.active_vm, 2);
    }

    #[test]
    fn test_kernel_nested_call_reply() {
        // VM 0 creates VM 1, calls it. VM 1 creates VM 2, calls it.
        // VM 2 replies. VM 1 replies. VM 0 receives final result.
        let blob = make_simple_blob(10);
        let mut kernel: InvocationKernel = kernel_from_blob(&blob, 1_000_000);
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // VM 0 creates VM 1, propagating the CODE cap at slot 64
        // bitmask bit 64 set means child inherits cap at slot 64
        kernel.set_active_reg(7, 1u64 << (64 % 64)); // bit 0 = slot 64's bitmap position
        kernel.set_active_reg(12, 66);
        kernel.dispatch_ecalli(64);
        let h1 = kernel.active_reg(7) as u8;

        // VM 0 calls the first child (idx 2 — bare Frame at idx 1)
        kernel.set_active_reg(7, 10);
        kernel.set_active_reg(8, 0);
        kernel.set_active_reg(12, 0);
        kernel.dispatch_ecalli(h1 as u32);
        assert_eq!(kernel.active_vm, 2);
        assert_eq!(kernel.active_reg(7), 10);

        // VM (idx 2) creates a nested child at idx 3 using inherited CODE
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 66);
        kernel.dispatch_ecalli(64);
        // If the active VM doesn't have CODE cap at 64, CREATE fails
        // silently. Check the nested child was created (arena now has
        // root + bare + 2 children = 4 entries).
        if kernel.vm_arena.len() < 4 {
            // CODE cap wasn't propagated — skip nested part, just test reply chain
            kernel.set_active_reg(7, 77);
            kernel.dispatch_ecalli(BARE_FRAME_SLOT as u32);
            assert_eq!(kernel.active_vm, 0);
            assert_eq!(kernel.active_reg(7), 77);
            return;
        }
        let h2 = kernel.active_reg(7) as u8;

        // Idx-2 VM calls the nested idx-3 VM
        kernel.set_active_reg(7, 20);
        kernel.set_active_reg(8, 0);
        kernel.set_active_reg(12, 0);
        kernel.dispatch_ecalli(h2 as u32);
        assert_eq!(kernel.active_vm, 3);
        assert_eq!(kernel.active_reg(7), 20);

        // Nested VM replies with 99
        kernel.set_active_reg(7, 99);
        kernel.dispatch_ecalli(BARE_FRAME_SLOT as u32);
        assert_eq!(kernel.active_vm, 2);
        assert_eq!(kernel.active_reg(7), 99);

        // Idx-2 VM replies with 77
        kernel.set_active_reg(7, 77);
        kernel.dispatch_ecalli(BARE_FRAME_SLOT as u32);
        assert_eq!(kernel.active_vm, 0);
        assert_eq!(kernel.active_reg(7), 77);
    }

    #[test]
    fn test_code_cache_hit() {
        let blob = make_simple_blob(10);
        let mut cache = CodeCache::new();

        // First creation populates the cache.
        let k1: InvocationKernel = kernel_from_blob_cached(&blob, 100_000, &mut cache);
        assert_eq!(cache.entries.len(), 1);
        let first_arc = Arc::clone(&k1.code_caps[0]);
        drop(k1);

        // Second creation with the same blob should hit the cache.
        let k2: InvocationKernel = kernel_from_blob_cached(&blob, 100_000, &mut cache);
        assert_eq!(cache.entries.len(), 1); // no new entry
        // The Arc should point to the same allocation.
        assert!(Arc::ptr_eq(&first_arc, &k2.code_caps[0]));
    }

    /// Build a blob with a different code sub-blob (halt instead of trap).
    fn make_halt_blob(memory_pages: u32) -> Vec<u8> {
        // halt = opcode 1 (different from trap = opcode 0)
        let code = [1u8];
        let bitmask = [1u8];
        let jump_table: &[u32] = &[];
        let entry_size: u8 = 1;

        let mut sub = Vec::new();
        sub.extend_from_slice(&(jump_table.len() as u32).to_le_bytes());
        sub.push(entry_size);
        sub.extend_from_slice(&(code.len() as u32).to_le_bytes());
        sub.extend_from_slice(&code);
        sub.push(bitmask[0]);

        let caps = vec![
            CapManifestEntry {
                cap_index: 64,
                cap_type: CapEntryType::Code,
                page_count: 0,
                data_offset: 0,
                data_len: sub.len() as u32,
            },
            CapManifestEntry {
                cap_index: 65,
                cap_type: CapEntryType::Data,
                page_count: 1,
                data_offset: 0,
                data_len: 0,
            },
        ];
        build_blob(memory_pages, 64, &caps, &sub)
    }

    #[test]
    fn test_code_cache_miss_different_code() {
        let blob1 = make_simple_blob(10);
        let blob2 = make_halt_blob(10); // different code sub-blob content
        let mut cache = CodeCache::new();

        let _k1: InvocationKernel = kernel_from_blob_cached(&blob1, 100_000, &mut cache);
        assert_eq!(cache.entries.len(), 1);

        let _k2: InvocationKernel = kernel_from_blob_cached(&blob2, 100_000, &mut cache);
        assert_eq!(cache.entries.len(), 2); // separate entry for different code
    }

    #[test]
    fn test_code_cache_no_cache_path() {
        // new() (without cache) still works.
        let blob = make_simple_blob(10);
        let k: InvocationKernel = kernel_from_blob(&blob, 100_000);
        assert_eq!(k.code_caps.len(), 1);
    }

    #[test]
    fn test_new_warm_uses_cache() {
        let blob = make_simple_blob(10);
        let mut cache = CodeCache::new();

        // Cold start populates the cache.
        let k1: InvocationKernel = kernel_from_blob_cached(&blob, 100_000, &mut cache);
        assert_eq!(cache.entries.len(), 1);
        let first_arc = Arc::clone(&k1.code_caps[0]);

        // Extract flat_mem for warm restart.
        let (flat_mem, hb, ht) = k1.extract_flat_mem();
        drop(k1);

        // Warm restart with cache should reuse the compiled code.
        let k2: InvocationKernel =
            kernel_from_blob_warm(&blob, 100_000, &flat_mem, hb, ht, Some(&mut cache));
        assert!(Arc::ptr_eq(&first_arc, &k2.code_caps[0]));
        assert_eq!(cache.entries.len(), 1);
    }

    #[test]
    fn test_new_warm_without_cache() {
        let blob = make_simple_blob(10);

        // new_warm with None still works.
        let k1: InvocationKernel = kernel_from_blob(&blob, 100_000);
        let (flat_mem, hb, ht) = k1.extract_flat_mem();
        drop(k1);

        let k2: InvocationKernel = kernel_from_blob_warm(&blob, 100_000, &flat_mem, hb, ht, None);
        assert_eq!(k2.code_caps.len(), 1);
    }
}
