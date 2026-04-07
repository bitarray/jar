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
use crate::backing::BackingStore;
use crate::cap::{
    Access, CallableCap, Cap, CapTable, CodeCap, DataCap, HandleCap, IPC_SLOT, UntypedCap,
};
use crate::program::{self, CapEntryType, CapManifestEntry, ParsedBlob};
#[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
use crate::vm_pool::WindowPool;
use crate::vm_pool::{CallFrame, MAX_CODE_CAPS, VmArena, VmId, VmInstance, VmState};

/// ecalli immediate ranges.
const CALL_RANGE_END: u32 = 0x100;
const MGMT_MAP: u32 = 0x2;
const MGMT_UNMAP: u32 = 0x3;
const MGMT_SPLIT: u32 = 0x4;
const MGMT_DROP: u32 = 0x5;
const MGMT_MOVE: u32 = 0x6;
const MGMT_COPY: u32 = 0x7;
const MGMT_GRANT: u32 = 0x8;
const MGMT_REVOKE: u32 = 0x9;
const MGMT_DOWNGRADE: u32 = 0xA;
const MGMT_SET_MAX_GAS: u32 = 0xB;
const MGMT_DIRTY: u32 = 0xC;

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
pub struct InvocationKernel {
    /// Physical memory pool.
    pub backing: BackingStore,
    /// Compiled CODE caps (max 5).
    pub code_caps: Vec<Arc<CodeCap>>,
    /// VM instances (generational arena).
    pub vm_arena: VmArena,
    /// Shared UNTYPED cap (bump allocator).
    pub untyped: Arc<UntypedCap>,
    /// Currently active VM index.
    pub active_vm: u16,
    /// Call stack for CALL/REPLY routing.
    pub call_stack: Vec<CallFrame>,
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

impl InvocationKernel {
    /// Create a new kernel from a JAR blob.
    ///
    pub fn new(blob: &[u8], _args: &[u8], gas: u64) -> Result<Self, KernelError> {
        Self::new_with_backend(blob, _args, gas, crate::backend::PvmBackend::Default)
    }

    /// Create a new kernel with a specific backend selection.
    pub fn new_with_backend(
        blob: &[u8],
        _args: &[u8],
        gas: u64,
        backend: crate::backend::PvmBackend,
    ) -> Result<Self, KernelError> {
        let parsed = program::parse_blob(blob).ok_or(KernelError::InvalidBlob)?;

        let backing =
            BackingStore::new(parsed.header.memory_pages).ok_or(KernelError::MemoryError)?;

        let mem_cycles = crate::compute_mem_cycles(parsed.header.memory_pages);
        let untyped = Arc::new(UntypedCap::new(parsed.header.memory_pages));

        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        let window_pool =
            WindowPool::new(crate::vm_pool::WINDOW_POOL_SIZE).ok_or(KernelError::MemoryError)?;

        let mut kernel = Self {
            backing,
            code_caps: Vec::with_capacity(MAX_CODE_CAPS),
            vm_arena: VmArena::new(),
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
        };

        // Build VM 0's cap table: protocol caps + manifest caps
        let mut cap_table = CapTable::new();

        // Populate protocol caps (slots 1-28). Slot 0 is IPC (REPLY).
        // These are kernel-handled and exit to the host via ProtocolCall when CALLed.
        use crate::cap::ProtocolCap;
        for id in 1..=28u8 {
            cap_table.set_original(id, Cap::Protocol(ProtocolCap { id }));
        }
        let mut init_pages: u32 = 0;
        let mut data_caps_to_map: Vec<(u32, u32, u32, Access)> = Vec::new(); // (base_page, backing_offset, page_count, access)

        for entry in &parsed.caps {
            let cap = kernel.create_cap_from_manifest(entry, &parsed)?;
            if let Cap::Data(ref d) = cap {
                init_pages += d.page_count;
                // Record DATA caps that need mapping into the CODE window
                if d.has_any_mapped()
                    && let (Some(base_page), Some(access)) = (d.base_offset, d.access)
                {
                    data_caps_to_map.push((base_page, d.backing_offset, d.page_count, access));
                }
            }
            cap_table.set(entry.cap_index, cap);
        }

        // Charge init gas
        let init_gas_cost = init_pages as u64 * GAS_PER_PAGE;
        if gas < init_gas_cost {
            return Err(KernelError::OutOfGas);
        }
        let remaining_gas = gas - init_gas_cost;

        // Resolve the invoke CODE cap to find its code_caps index
        let invoke_code_id = match cap_table.get(parsed.header.invoke_cap) {
            Some(Cap::Code(c)) => c.id,
            _ => return Err(KernelError::InvalidBlob),
        };

        // Assign window 0 to VM 0 and map DATA caps into it.
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        {
            let assignment = kernel.window_pool.assign_window(0, 0);
            kernel.active_window = assignment.window_idx;
            let window_base = kernel.window_pool.window(assignment.window_idx).base();
            for (base_page, backing_offset, page_count, access) in &data_caps_to_map {
                // SAFETY: window_base is from CodeWindow::base() (valid 4GB mmap region).
                unsafe {
                    if !kernel.backing.map_pages(
                        window_base,
                        *base_page,
                        *backing_offset,
                        *page_count,
                        *access,
                    ) {
                        return Err(KernelError::MemoryError);
                    }
                }
            }
        }
        // Non-recompiler platforms: DATA cap mapping is handled at interpreter run time.
        #[cfg(not(all(feature = "std", target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = &data_caps_to_map;
        }

        // Give VM 0 the UNTYPED cap at slot 254 (fixed slot, just below IPC).
        // Skip when memory_pages == 0 — no point creating an empty allocator.
        if parsed.header.memory_pages > 0 {
            cap_table.set(254, Cap::Untyped(Arc::clone(&kernel.untyped)));
        }

        // Write arguments into args cap (cap_index=0xFF = IPC slot)
        let mut args_base: u64 = 0;
        let args_len: u64 = _args.len() as u64;
        if !_args.is_empty() {
            // Find args cap by scanning for cap_index=IPC_SLOT (0)
            let args_cap_entry = parsed.caps.iter().find(|e| e.cap_index == IPC_SLOT);
            if let Some(entry) = args_cap_entry {
                args_base = entry.base_page as u64 * crate::PVM_PAGE_SIZE as u64;
                if let Some(Cap::Data(d)) = cap_table.get(IPC_SLOT) {
                    kernel.backing.write_init_data(d.backing_offset, _args);
                }
            }
        }

        // Create VM 0 — kernel sets φ[0]=halt, φ[7]=args_base, φ[8]=args_len.
        // Program sets SP in its preamble (transpiler emits load_imm_64 SP, stack_top).
        let mut vm0 = VmInstance::new(
            invoke_code_id,
            0, // entry_index (set by caller via CALL)
            cap_table,
            remaining_gas,
        );
        // φ[7]=op set by caller (refine/accumulate), φ[8]=args_base, φ[9]=args_len
        vm0.set_reg(8, args_base);
        vm0.set_reg(9, args_len);
        kernel.vm_arena.insert(vm0); // VM 0 gets VmId(0, 0)

        Ok(kernel)
    }

    /// Create a capability from a manifest entry.
    fn create_cap_from_manifest(
        &mut self,
        entry: &CapManifestEntry,
        parsed: &ParsedBlob<'_>,
    ) -> Result<Cap, KernelError> {
        match entry.cap_type {
            CapEntryType::Code => {
                let code_data = program::cap_data(entry, parsed.data_section);
                let id = self.next_code_id;
                self.next_code_id += 1;
                if self.code_caps.len() >= MAX_CODE_CAPS {
                    return Err(KernelError::TooManyCodeCaps);
                }

                // Parse the code sub-blob (jump_table + code + bitmask)
                let code_blob =
                    program::parse_code_blob(code_data).ok_or(KernelError::InvalidBlob)?;

                // Compile via selected backend (interpreter or recompiler)
                let compiled = crate::backend::compile(
                    &code_blob.code,
                    &code_blob.bitmask,
                    &code_blob.jump_table,
                    self.mem_cycles,
                    self.backend,
                )
                .map_err(|e| {
                    tracing::warn!("compile failed: {e}");
                    KernelError::CompileError
                })?;

                let code_cap = Arc::new(CodeCap {
                    id,
                    compiled,
                    jump_table: code_blob.jump_table,
                    bitmask: code_blob.bitmask,
                });
                self.code_caps.push(Arc::clone(&code_cap));
                Ok(Cap::Code(code_cap))
            }
            CapEntryType::Data => {
                // Allocate pages from UNTYPED
                let backing_offset = self
                    .untyped
                    .retype(entry.page_count)
                    .ok_or(KernelError::OutOfMemory)?;

                // Write initial data if present
                if entry.data_len > 0 {
                    let data = program::cap_data(entry, parsed.data_section);
                    if !self.backing.write_init_data(backing_offset, data) {
                        return Err(KernelError::MemoryError);
                    }
                }

                // Create DATA cap, marked as mapped (actual mmap happens after all caps are created)
                let mut data_cap = DataCap::new(backing_offset, entry.page_count);
                data_cap.map(entry.base_page, entry.init_access);
                Ok(Cap::Data(data_cap))
            }
        }
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
            if cap_idx == IPC_SLOT {
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
            Cap::Protocol(p) => {
                let slot = p.id;
                DispatchResult::ProtocolCall { slot }
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
            Cap::Handle(h) => {
                let target_vm = h.vm_id;
                let max_gas = h.max_gas;
                #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
                self.flush_live_ctx();
                self.handle_call_vm(target_vm, max_gas)
            }
            Cap::Callable(c) => {
                let target_vm = c.vm_id;
                let max_gas = c.max_gas;
                #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
                self.flush_live_ctx();
                self.handle_call_vm(target_vm, max_gas)
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
        let (dst_vm, dst_slot) = match self.resolve_cap_ref(dst_ref) {
            Some(r) => r,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };
        if !self.vm_arena.vm(dst_vm as u16).cap_table.is_empty(dst_slot) {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }

        self.vm_arena
            .vm_mut(dst_vm as u16)
            .cap_table
            .set(dst_slot, Cap::Data(data_cap));
        self.set_active_reg(7, dst_slot as u64);
        DispatchResult::Continue
    }

    /// CALL on CODE → CREATE.
    /// φ[7] = bitmask (u64), φ[12] = dst_slot (u32, indirection) for HANDLE.
    /// Bitmask copies from the CODE cap's CNode (the CNode where ecalli resolved
    /// the CODE cap), not necessarily the caller's CNode.
    fn handle_call_code(&mut self, code_cap_id: u16, code_cnode_vm: usize) -> DispatchResult {
        let bitmask = self.active_reg(7);

        // Create child VM's cap table by copying bitmask-selected caps from CODE's CNode
        let mut child_table = CapTable::new();
        let source_vm = self.vm_arena.vm(code_cnode_vm as u16);

        for bit in 0..64u8 {
            if bitmask & (1u64 << bit) != 0
                && let Some(cap) = source_vm.cap_table.get(bit)
            {
                match cap.try_copy() {
                    Some(copy) => {
                        child_table.set(bit, copy);
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

        // Caller-picks: HANDLE destination from φ[12] with indirection
        let handle = HandleCap {
            vm_id: child_vm_id,
            max_gas: None,
        };

        let dst_ref = self.active_reg(12) as u32;
        let (dst_vm, dst_slot) = match self.resolve_cap_ref(dst_ref) {
            Some(r) => r,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };
        if !self.vm_arena.vm(dst_vm as u16).cap_table.is_empty(dst_slot) {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }
        self.vm_arena
            .vm_mut(dst_vm as u16)
            .cap_table
            .set(dst_slot, Cap::Handle(handle));
        self.set_active_reg(7, dst_slot as u64);
        DispatchResult::Continue
    }

    /// CALL on HANDLE/CALLABLE → suspend caller, run target VM.
    fn handle_call_vm(&mut self, vm_id: VmId, max_gas: Option<u64>) -> DispatchResult {
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

        // Determine gas budget for callee
        let caller_vm = &mut self.vm_arena.vm_mut(self.active_vm);
        let call_overhead = 10u64;
        if caller_vm.gas() < call_overhead {
            return DispatchResult::Fault(FaultType::OutOfGas);
        }
        caller_vm.set_gas(caller_vm.gas() - call_overhead);

        let callee_gas = match max_gas {
            Some(limit) => caller_vm.gas().min(limit),
            None => caller_vm.gas(),
        };
        caller_vm.set_gas(caller_vm.gas() - callee_gas);

        // Save caller state
        let caller_id = self.active_vm;
        let _ = self
            .vm_arena
            .vm_mut(caller_id)
            .transition(VmState::WaitingForReply);

        // Handle IPC cap (φ[12]). 0 = no cap to pass (slot 0 is IPC itself).
        let ipc_cap_slot = self.active_reg(12) as u8;
        let mut ipc_cap_idx = None;
        let mut ipc_was_mapped = None;

        if ipc_cap_slot != 0 && !self.vm_arena.vm(caller_id).cap_table.is_empty(ipc_cap_slot) {
            // Take cap from caller, auto-unmap if DATA
            if let Some(mut cap) = self.vm_arena.vm_mut(caller_id).cap_table.take(ipc_cap_slot) {
                if let Cap::Data(ref mut d) = cap {
                    ipc_was_mapped = d.unmap();
                }
                ipc_cap_idx = Some(ipc_cap_slot);
                // Place in callee's IPC slot [0]
                self.vm_arena
                    .vm_mut(target_vm_id)
                    .cap_table
                    .set(IPC_SLOT, cap);
            }
        }

        // Push call frame
        self.call_stack.push(CallFrame {
            caller_vm_id: caller_id,
            ipc_cap_idx,
            ipc_was_mapped,
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

    /// Handle REPLY (ecalli(0xFF) = CALL on IPC slot).
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

        // Return IPC cap
        if let Some(caller_slot) = frame.ipc_cap_idx
            && let Some(mut cap) = self.vm_arena.vm_mut(callee_id).cap_table.take(IPC_SLOT)
        {
            // Auto-remap DATA cap at caller's original base_page
            if let Some((base_page, access)) = frame.ipc_was_mapped
                && let Cap::Data(d) = &mut cap
            {
                d.map(base_page, access);
            }
            self.vm_arena
                .vm_mut(caller_id)
                .cap_table
                .set(caller_slot, cap);
        }

        // Pass φ[7] only + set φ[8]=0 (status = REPLY success)
        let callee_r7 = self.vm_arena.vm(callee_id).reg(7);
        self.vm_arena.vm_mut(caller_id).set_reg(7, callee_r7);
        self.vm_arena.vm_mut(caller_id).set_reg(8, 0);

        // Caller → Running
        let _ = self.vm_arena.vm_mut(caller_id).transition(VmState::Running);
        self.active_vm = caller_id;

        DispatchResult::Continue
    }

    /// Resolve a u32 cap reference with HANDLE-chain indirection.
    ///
    /// Encoding: byte 0 = target slot, bytes 1-3 = HANDLE chain (0x00 = end).
    /// Returns (vm_index, cap_slot) or None if resolution fails.
    /// Each intermediate VM must hold a HANDLE and be non-RUNNING.
    fn resolve_cap_ref(&self, cap_ref: u32) -> Option<(usize, u8)> {
        let target_slot = (cap_ref & 0xFF) as u8;
        let ind0 = ((cap_ref >> 8) & 0xFF) as u8;
        let ind1 = ((cap_ref >> 16) & 0xFF) as u8;
        let ind2 = ((cap_ref >> 24) & 0xFF) as u8;

        let mut vm_idx = self.active_vm as usize;

        // Walk indirection chain (high bytes first: ind2, ind1, ind0)
        for &handle_slot in &[ind2, ind1, ind0] {
            if handle_slot == 0 {
                continue; // end of chain
            }
            let vm = &self.vm_arena.vm(vm_idx as u16);
            match vm.cap_table.get(handle_slot) {
                Some(Cap::Handle(h)) => {
                    // Validate VmId (generation check for stale handles)
                    let target = self.vm_arena.get(h.vm_id)?;
                    if target.state == VmState::Running || target.state == VmState::WaitingForReply
                    {
                        return None; // target must be non-RUNNING
                    }
                    vm_idx = h.vm_id.index() as usize;
                }
                _ => return None, // not a HANDLE
            }
        }

        Some((vm_idx, target_slot))
    }

    /// Resolve a cap ref, returning None and setting WHAT if resolution fails.
    fn resolve_or_what(&mut self, cap_ref: u32) -> Option<(usize, u8)> {
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
    pub fn dispatch_ecall(&mut self, op: u32) -> DispatchResult {
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
                let (vm_idx, slot) = match self.resolve_or_what(subject_ref) {
                    Some(r) => r,
                    None => return DispatchResult::Continue,
                };
                // For local VM, use existing handle_call
                if vm_idx == self.active_vm as usize {
                    self.handle_call(slot)
                } else {
                    // Remote cap — look up the cap in the remote VM
                    let cap_type = self
                        .vm_arena
                        .vm(vm_idx as u16)
                        .cap_table
                        .get(slot)
                        .map(|c| match c {
                            Cap::Protocol(p) => Some(p.id),
                            _ => None,
                        });
                    match cap_type {
                        Some(Some(id)) => DispatchResult::ProtocolCall { slot: id },
                        _ => {
                            self.set_active_reg(7, RESULT_WHAT);
                            DispatchResult::Continue
                        }
                    }
                }
            }
            0x02 => {
                // MAP — resolve subject (DATA cap)
                let (vm_idx, slot) = match self.resolve_or_what(subject_ref) {
                    Some(r) => r,
                    None => return DispatchResult::Continue,
                };
                self.ecall_map(vm_idx, slot)
            }
            0x03 => {
                // UNMAP — resolve subject (DATA cap)
                let (vm_idx, slot) = match self.resolve_or_what(subject_ref) {
                    Some(r) => r,
                    None => return DispatchResult::Continue,
                };
                self.ecall_unmap(vm_idx, slot)
            }
            0x04 => {
                // SPLIT — resolve subject + object dst
                let (s_vm, s_slot) = match self.resolve_or_what(subject_ref) {
                    Some(r) => r,
                    None => return DispatchResult::Continue,
                };
                let (o_vm, o_slot) = match self.resolve_or_what(object_ref) {
                    Some(r) => r,
                    None => return DispatchResult::Continue,
                };
                self.ecall_split(s_vm, s_slot, o_vm, o_slot)
            }
            0x05 => {
                // DROP — resolve subject
                let (vm_idx, slot) = match self.resolve_or_what(subject_ref) {
                    Some(r) => r,
                    None => return DispatchResult::Continue,
                };
                self.ecall_drop(vm_idx, slot)
            }
            0x06 => {
                // MOVE — resolve subject + object dst
                let (s_vm, s_slot) = match self.resolve_or_what(subject_ref) {
                    Some(r) => r,
                    None => return DispatchResult::Continue,
                };
                let (o_vm, o_slot) = match self.resolve_or_what(object_ref) {
                    Some(r) => r,
                    None => return DispatchResult::Continue,
                };
                self.ecall_move(s_vm, s_slot, o_vm, o_slot)
            }
            0x07 => {
                // COPY — resolve subject + object dst
                let (s_vm, s_slot) = match self.resolve_or_what(subject_ref) {
                    Some(r) => r,
                    None => return DispatchResult::Continue,
                };
                let (o_vm, o_slot) = match self.resolve_or_what(object_ref) {
                    Some(r) => r,
                    None => return DispatchResult::Continue,
                };
                self.ecall_copy(s_vm, s_slot, o_vm, o_slot)
            }
            0x0A => {
                // DOWNGRADE — resolve subject HANDLE + object dst
                let (s_vm, s_slot) = match self.resolve_or_what(subject_ref) {
                    Some(r) => r,
                    None => return DispatchResult::Continue,
                };
                let (o_vm, o_slot) = match self.resolve_or_what(object_ref) {
                    Some(r) => r,
                    None => return DispatchResult::Continue,
                };
                self.ecall_downgrade(s_vm, s_slot, o_vm, o_slot)
            }
            0x0B => {
                // SET_MAX_GAS — resolve subject HANDLE
                let (vm_idx, slot) = match self.resolve_or_what(subject_ref) {
                    Some(r) => r,
                    None => return DispatchResult::Continue,
                };
                self.ecall_set_max_gas(vm_idx, slot)
            }
            0x0C => {
                // DIRTY — TODO
                self.set_active_reg(7, RESULT_WHAT);
                DispatchResult::Continue
            }
            0x0D => {
                // RESUME — resolve subject HANDLE
                let (vm_idx, slot) = match self.resolve_or_what(subject_ref) {
                    Some(r) => r,
                    None => return DispatchResult::Continue,
                };
                // RESUME uses the HANDLE in the resolved VM's cap table
                if vm_idx != self.active_vm as usize {
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
            MGMT_GRANT | MGMT_REVOKE => {
                // Removed: use MOVE with indirection via ecall instead
                self.set_active_reg(7, RESULT_WHAT);
                DispatchResult::Continue
            }
            MGMT_DOWNGRADE => self.mgmt_downgrade(cap_idx),
            MGMT_SET_MAX_GAS => self.mgmt_set_max_gas(cap_idx),
            MGMT_DIRTY => {
                // TODO: dirty bitmap query
                self.set_active_reg(7, RESULT_WHAT);
                DispatchResult::Continue
            }
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                DispatchResult::Continue
            }
        }
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

        let wb = self.active_window_base();
        let vm = &mut self.vm_arena.vm_mut(self.active_vm);
        match vm.cap_table.get_mut(cap_idx) {
            Some(Cap::Data(d)) => {
                // Unmap previous mapping if remapping
                if let Some((old_base, _)) = d.map(base_page, access) {
                    // SAFETY: wb is from active_window_base() (valid 4GB window).
                    unsafe {
                        BackingStore::unmap_pages(wb, old_base, d.page_count);
                    }
                }
                // Map new location
                // SAFETY: wb is from active_window_base() (valid 4GB window).
                unsafe {
                    self.backing
                        .map_pages(wb, base_page, d.backing_offset, d.page_count, access);
                }
            }
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
            }
        }
        DispatchResult::Continue
    }

    fn mgmt_unmap(&mut self, cap_idx: u8) -> DispatchResult {
        let wb = self.active_window_base();
        let vm = &mut self.vm_arena.vm_mut(self.active_vm);
        match vm.cap_table.get_mut(cap_idx) {
            Some(Cap::Data(d)) => {
                if let Some((base_page, _)) = d.unmap() {
                    // SAFETY: wb is from active_window_base() (valid 4GB window).
                    unsafe {
                        BackingStore::unmap_pages(wb, base_page, d.page_count);
                    }
                }
            }
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
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
        let wb = self.active_window_base();
        // DROP HANDLE → reclaim VM via arena.remove()
        if let Some(Cap::Handle(h)) = self.vm_arena.vm(self.active_vm).cap_table.get(cap_idx) {
            let vm_id = h.vm_id;
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
            && d.has_any_mapped()
            && let Some(base_page) = d.base_offset
        {
            let page_count = d.page_count;
            // SAFETY: wb is from active_window_base() (valid 4GB window).
            unsafe {
                BackingStore::unmap_pages(wb, base_page, page_count);
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
        let (vm_id, max_gas) = match vm.cap_table.get(handle_idx) {
            Some(Cap::Handle(h)) => (h.vm_id, h.max_gas),
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        let callable = CallableCap { vm_id, max_gas };

        let vm = &mut self.vm_arena.vm_mut(self.active_vm);
        let free = match (64..255u8).find(|i| vm.cap_table.is_empty(*i)) {
            Some(s) => s,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        vm.cap_table.set(free, Cap::Callable(callable));
        self.set_active_reg(7, free as u64);
        DispatchResult::Continue
    }

    fn mgmt_set_max_gas(&mut self, handle_idx: u8) -> DispatchResult {
        let gas_limit = self.active_reg(7);
        let vm = &mut self.vm_arena.vm_mut(self.active_vm);
        match vm.cap_table.get_mut(handle_idx) {
            Some(Cap::Handle(h)) => {
                h.max_gas = Some(gas_limit);
            }
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
            }
        }
        DispatchResult::Continue
    }

    /// RESUME a FAULTED VM. Same gas model as CALL.
    fn handle_resume(&mut self, handle_idx: u8) -> DispatchResult {
        let vm = self.vm_arena.vm(self.active_vm);
        let (target_vm_vid, max_gas) = match vm.cap_table.get(handle_idx) {
            Some(Cap::Handle(h)) => (h.vm_id, h.max_gas),
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

        // Gas transfer (same as CALL)
        let caller_vm = &mut self.vm_arena.vm_mut(self.active_vm);
        let call_overhead = 10u64;
        if caller_vm.gas() < call_overhead {
            return DispatchResult::Fault(FaultType::OutOfGas);
        }
        caller_vm.set_gas(caller_vm.gas() - call_overhead);

        let callee_gas = match max_gas {
            Some(limit) => caller_vm.gas().min(limit),
            None => caller_vm.gas(),
        };
        caller_vm.set_gas(caller_vm.gas() - callee_gas);

        // Save caller state
        let caller_id = self.active_vm;
        let _ = self
            .vm_arena
            .vm_mut(caller_id)
            .transition(VmState::WaitingForReply);

        // Push call frame (no IPC cap for RESUME)
        self.call_stack.push(CallFrame {
            caller_vm_id: caller_id,
            ipc_cap_idx: None,
            ipc_was_mapped: None,
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
    fn ecall_map(&mut self, vm_idx: usize, slot: u8) -> DispatchResult {
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

        let window_base = self.vm_window_base(vm_idx as u16);
        let vm = &mut self.vm_arena.vm_mut(vm_idx as u16);
        match vm.cap_table.get_mut(slot) {
            Some(Cap::Data(d)) => {
                if !d.map_pages(base_offset, access, page_offset, page_count) {
                    self.set_active_reg(7, RESULT_WHAT);
                    return DispatchResult::Continue;
                }
                // Map the pages in the VM's window (if it has one)
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

    /// UNMAP pages of a DATA cap in its CNode.
    /// φ[7]=page_offset, φ[8]=page_count.
    fn ecall_unmap(&mut self, vm_idx: usize, slot: u8) -> DispatchResult {
        let page_offset = self.active_reg(7) as u32;
        let page_count = self.active_reg(8) as u32;

        let window_base = self.vm_window_base(vm_idx as u16);
        let vm = &mut self.vm_arena.vm_mut(vm_idx as u16);
        match vm.cap_table.get_mut(slot) {
            Some(Cap::Data(d)) => {
                if let Some(base_offset) = d.base_offset {
                    if let Some(wb) = window_base {
                        for p in
                            page_offset..page_offset.saturating_add(page_count).min(d.page_count)
                        {
                            if d.is_page_mapped(p) {
                                // SAFETY: wb is from vm_window_base() (valid 4GB window).
                                unsafe {
                                    BackingStore::unmap_pages(wb, base_offset + p, 1);
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
    fn ecall_split(&mut self, s_vm: usize, s_slot: u8, o_vm: usize, o_slot: u8) -> DispatchResult {
        let page_off = self.active_reg(7) as u32;

        // Validate
        let can_split = match self.vm_arena.vm(s_vm as u16).cap_table.get(s_slot) {
            Some(Cap::Data(d)) => !d.has_any_mapped() && page_off > 0 && page_off < d.page_count,
            _ => false,
        };
        if !can_split || !self.vm_arena.vm(o_vm as u16).cap_table.is_empty(o_slot) {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }

        let cap = match self.vm_arena.vm_mut(s_vm as u16).cap_table.take(s_slot) {
            Some(Cap::Data(d)) => d,
            _ => unreachable!(),
        };
        let (lo, hi) = cap.split(page_off).unwrap();
        self.vm_arena
            .vm_mut(s_vm as u16)
            .cap_table
            .set(s_slot, Cap::Data(lo));
        self.vm_arena
            .vm_mut(o_vm as u16)
            .cap_table
            .set(o_slot, Cap::Data(hi));
        DispatchResult::Continue
    }

    /// DROP a cap. Auto-unmaps DATA. Reclaims VM on HANDLE drop.
    fn ecall_drop(&mut self, vm_idx: usize, slot: u8) -> DispatchResult {
        // DROP HANDLE → reclaim VM
        if let Some(Cap::Handle(h)) = self.vm_arena.vm(vm_idx as u16).cap_table.get(slot) {
            let vm_id = h.vm_id;
            self.vm_arena.vm_mut(vm_idx as u16).cap_table.drop_cap(slot);
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            self.window_pool.release(vm_id.index());
            self.vm_arena.remove(vm_id);
            return DispatchResult::Continue;
        }
        if let Some(Cap::Data(d)) = self.vm_arena.vm(vm_idx as u16).cap_table.get(slot)
            && d.has_any_mapped()
            && let Some(base_offset) = d.base_offset
        {
            let page_count = d.page_count;
            if let Some(wb) = self.vm_window_base(vm_idx as u16) {
                // SAFETY: wb is from vm_window_base() (valid 4GB window).
                unsafe {
                    BackingStore::unmap_pages(wb, base_offset, page_count);
                }
            }
        }
        self.vm_arena.vm_mut(vm_idx as u16).cap_table.drop_cap(slot);
        DispatchResult::Continue
    }

    /// MOVE a cap between CNodes. Auto-unmaps DATA on CNode change.
    fn ecall_move(&mut self, s_vm: usize, s_slot: u8, o_vm: usize, o_slot: u8) -> DispatchResult {
        if s_vm == o_vm && s_slot == o_slot {
            return DispatchResult::Continue;
        }
        if !self.vm_arena.vm(o_vm as u16).cap_table.is_empty(o_slot) {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }

        let mut cap = match self.vm_arena.vm_mut(s_vm as u16).cap_table.take(s_slot) {
            Some(c) => c,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        // Auto-unmap DATA caps crossing CNode boundaries
        if s_vm != o_vm
            && let Cap::Data(ref mut d) = cap
            && d.has_any_mapped()
            && let Some(base_offset) = d.base_offset
        {
            if let Some(wb) = self.vm_window_base(s_vm as u16) {
                // SAFETY: wb is from vm_window_base() (valid 4GB window).
                unsafe {
                    BackingStore::unmap_pages(wb, base_offset, d.page_count);
                }
            }
            d.unmap_all();
        }

        self.vm_arena.vm_mut(o_vm as u16).cap_table.set(o_slot, cap);
        DispatchResult::Continue
    }

    /// COPY a cap between CNodes (copyable types only).
    fn ecall_copy(&mut self, s_vm: usize, s_slot: u8, o_vm: usize, o_slot: u8) -> DispatchResult {
        if !self.vm_arena.vm(o_vm as u16).cap_table.is_empty(o_slot) {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }
        let copy = match self.vm_arena.vm(s_vm as u16).cap_table.get(s_slot) {
            Some(c) => match c.try_copy() {
                Some(copy) => copy,
                None => {
                    self.set_active_reg(7, RESULT_WHAT);
                    return DispatchResult::Continue;
                }
            },
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };
        self.vm_arena
            .vm_mut(o_vm as u16)
            .cap_table
            .set(o_slot, copy);
        DispatchResult::Continue
    }

    /// DOWNGRADE a HANDLE to CALLABLE. Places CALLABLE at dst.
    fn ecall_downgrade(
        &mut self,
        s_vm: usize,
        s_slot: u8,
        o_vm: usize,
        o_slot: u8,
    ) -> DispatchResult {
        let (vm_id, max_gas) = match self.vm_arena.vm(s_vm as u16).cap_table.get(s_slot) {
            Some(Cap::Handle(h)) => (h.vm_id, h.max_gas),
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };
        if !self.vm_arena.vm(o_vm as u16).cap_table.is_empty(o_slot) {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }
        self.vm_arena
            .vm_mut(o_vm as u16)
            .cap_table
            .set(o_slot, Cap::Callable(CallableCap { vm_id, max_gas }));
        DispatchResult::Continue
    }

    /// SET_MAX_GAS on a HANDLE.
    fn ecall_set_max_gas(&mut self, vm_idx: usize, slot: u8) -> DispatchResult {
        let gas_limit = self.active_reg(7);
        match self.vm_arena.vm_mut(vm_idx as u16).cap_table.get_mut(slot) {
            Some(Cap::Handle(h)) => {
                h.max_gas = Some(gas_limit);
            }
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
            }
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

    /// Unmap all of a VM's mapped DATA caps from a window.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    fn unmap_vm_data_caps(&self, vm_idx: u16, window_idx: usize) {
        let wb = self.window_pool.window(window_idx).base();
        let vm = self.vm_arena.vm(vm_idx);
        for slot in 0..=255u8 {
            if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                && d.has_any_mapped()
                && let Some(base_offset) = d.base_offset
            {
                // SAFETY: wb is from window_pool (valid 4GB window).
                unsafe {
                    BackingStore::unmap_pages(wb, base_offset, d.page_count);
                }
            }
        }
    }

    /// Map all of a VM's mapped DATA caps into a window.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    fn map_vm_data_caps(&self, vm_idx: u16, window_idx: usize) {
        let wb = self.window_pool.window(window_idx).base();
        let vm = self.vm_arena.vm(vm_idx);
        for slot in 0..=255u8 {
            if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                && d.has_any_mapped()
                && let Some(base_offset) = d.base_offset
            {
                let access = d.access.unwrap_or(Access::RO);
                // SAFETY: wb is from window_pool (valid 4GB window).
                unsafe {
                    self.backing
                        .map_pages(wb, base_offset, d.backing_offset, d.page_count, access);
                }
            }
        }
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
                heap_base: 0,
                heap_top: 0,
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

        // SAFETY: ctx_raw is still valid after JIT execution returns.
        let ctx = unsafe { &*ctx_raw };
        let exit_reason = ctx.exit_reason;
        let exit_arg = ctx.exit_arg;

        if exit_reason == 4 {
            // ecalli: keep live_ctx, sync only pc
            self.vm_arena.vm_mut(self.active_vm).pc = ctx.pc;
            self.live_ctx = Some(ctx_raw);
        } else {
            // Non-ecalli: full sync, clear live_ctx
            let vm = &mut self.vm_arena.vm_mut(self.active_vm);
            vm.set_regs(ctx.regs);
            vm.set_gas(ctx.gas.max(0) as u64);
            vm.pc = ctx.pc;
            self.live_ctx = None;
            crate::recompiler::signal::SIGNAL_STATE.with(|cell| cell.set(std::ptr::null_mut()));
        }

        (exit_reason, exit_arg)
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

        // SAFETY: ctx_raw is still valid after JIT execution returns.
        let ctx = unsafe { &*ctx_raw };
        let exit_reason = ctx.exit_reason;
        let exit_arg = ctx.exit_arg;

        if exit_reason == 4 {
            // ecalli: set live_ctx so dispatch reads JitContext directly.
            // Sync only pc to VmInstance (needed for ProtocolCall metadata).
            self.vm_arena.vm_mut(self.active_vm).pc = ctx.pc;
            self.live_ctx = Some(ctx_raw);
        } else {
            // Non-ecalli: full sync to VmInstance, clear live_ctx.
            let vm = &mut self.vm_arena.vm_mut(self.active_vm);
            vm.set_regs(ctx.regs);
            vm.set_gas(ctx.gas.max(0) as u64);
            vm.pc = ctx.pc;
            self.live_ctx = None;
            signal::SIGNAL_STATE.with(|cell| cell.set(std::ptr::null_mut()));
        }

        (exit_reason, exit_arg)
    }

    /// Execute one segment via the software interpreter backend.
    ///
    /// The interpreter uses a regular Vec<u8> for memory instead of the mmap'd
    /// 4GB window (which would SIGSEGV on unmapped pages without the recompiler's
    /// signal handler). Mapped DATA cap pages are copied in before execution and
    /// written back after.
    fn run_interpreter_segment(&mut self, code_cap_id: usize) -> (u32, u32) {
        let code_cap = &self.code_caps[code_cap_id];
        let prog = match &code_cap.compiled {
            crate::backend::CompiledProgram::Interpreter(p) => p,
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            _ => unreachable!(),
        };

        // Determine memory size from mapped DATA caps. Find the highest mapped page.
        let vm = &self.vm_arena.vm(self.active_vm);
        let mut max_addr: usize = 0;
        for slot in 0..=255u8 {
            if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                && d.has_any_mapped()
                && let Some(base_page) = d.base_offset
            {
                let end =
                    (base_page as usize + d.page_count as usize) * crate::PVM_PAGE_SIZE as usize;
                max_addr = max_addr.max(end);
            }
        }
        // Allocate flat memory and copy in mapped pages from the window
        let mut flat_mem = vec![0u8; max_addr];
        let window_base = self.active_window_base();
        for slot in 0..=255u8 {
            if let Some(Cap::Data(d)) = vm.cap_table.get(slot)
                && d.has_any_mapped()
                && let Some(base_page) = d.base_offset
            {
                let addr = base_page as usize * crate::PVM_PAGE_SIZE as usize;
                let len = d.page_count as usize * crate::PVM_PAGE_SIZE as usize;
                if addr + len <= flat_mem.len() {
                    // SAFETY: window_base is valid (active window); addr+len
                    // is within both the window and flat_mem (checked above).
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            window_base.add(addr),
                            flat_mem.as_mut_ptr().add(addr),
                            len,
                        );
                    }
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

        let (exit, _gas_used) = interp.run();

        // Write back modified pages to the window
        let vm_ref = &self.vm_arena.vm(self.active_vm);
        let wb = self.active_window_base();
        for slot in 0..=255u8 {
            if let Some(Cap::Data(d)) = vm_ref.cap_table.get(slot)
                && d.has_any_mapped()
                && d.access == Some(Access::RW)
                && let Some(base_page) = d.base_offset
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

        let vm = &mut self.vm_arena.vm_mut(self.active_vm);
        vm.set_regs(interp.registers);
        vm.set_gas(interp.gas);
        vm.pc = interp.pc;

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
    pub fn run(&mut self) -> KernelResult {
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
                    match self.dispatch_ecall(op) {
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
        let base_page = d.base_offset?;
        if !d.has_any_mapped() {
            return None;
        }
        let wb = self.active_window_base();
        let addr = base_page as usize * crate::PVM_PAGE_SIZE as usize + offset as usize;
        let mut buf = vec![0u8; len as usize];
        // SAFETY: base_page was mmap'd into the window by map_pages.
        unsafe {
            std::ptr::copy_nonoverlapping(wb.add(addr), buf.as_mut_ptr(), len as usize);
        }
        Some(buf)
    }

    /// Read bytes directly from the active VM's window by address.
    /// Used for reading output from guest programs that return ptr+len in registers.
    pub fn read_data_cap_window(&self, addr: u32, len: u32) -> Option<Vec<u8>> {
        let wb = self.active_window_base();
        let mut buf = vec![0u8; len as usize];
        // SAFETY: addr is within the window's 4GB mmap region.
        unsafe {
            std::ptr::copy_nonoverlapping(wb.add(addr as usize), buf.as_mut_ptr(), len as usize);
        }
        Some(buf)
    }

    /// Write bytes into a DATA cap's mapped region in the active VM's window.
    pub fn write_data_cap(&self, cap_idx: u8, offset: u32, data: &[u8]) -> bool {
        let vm = &self.vm_arena.vm(self.active_vm);
        let d = match vm.cap_table.get(cap_idx) {
            Some(Cap::Data(d)) => d,
            _ => return false,
        };
        let base_page = match d.base_offset {
            Some(b) if d.has_any_mapped() => b,
            _ => return false,
        };
        let wb = self.active_window_base();
        let addr = base_page as usize * crate::PVM_PAGE_SIZE as usize + offset as usize;
        // SAFETY: base_page was mmap'd into the window by map_pages.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), wb.add(addr), data.len());
        }
        true
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

                // Return IPC cap
                if let Some(caller_slot) = frame.ipc_cap_idx
                    && let Some(mut cap) = self.vm_arena.vm_mut(callee_id).cap_table.take(IPC_SLOT)
                {
                    if let Some((bp, acc)) = frame.ipc_was_mapped
                        && let Cap::Data(d) = &mut cap
                    {
                        d.map(bp, acc);
                    }
                    self.vm_arena
                        .vm_mut(caller_id)
                        .cap_table
                        .set(caller_slot, cap);
                }

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
#[derive(Debug)]
pub enum KernelError {
    InvalidBlob,
    MemoryError,
    OutOfGas,
    OutOfMemory,
    TooManyCodeCaps,
    CapTableFull,
    CompileError,
}

impl core::fmt::Display for KernelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidBlob => write!(f, "invalid JAR blob"),
            Self::MemoryError => write!(f, "memory allocation failed"),
            Self::OutOfGas => write!(f, "insufficient gas for initialization"),
            Self::OutOfMemory => write!(f, "untyped pool exhausted"),
            Self::TooManyCodeCaps => write!(f, "exceeded max CODE caps ({MAX_CODE_CAPS})"),
            Self::CapTableFull => write!(f, "cap table full"),
            Self::CompileError => write!(f, "JIT compilation failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::ProtocolCap;
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
                base_page: 0,
                page_count: 0,
                init_access: Access::RO,
                data_offset: 0,
                data_len: code_data.len() as u32,
            },
            CapManifestEntry {
                cap_index: 65,
                cap_type: CapEntryType::Data,
                base_page: 0,
                page_count: 1,
                init_access: Access::RW,
                data_offset: 0, // doesn't reference data section
                data_len: 0,
            },
        ];
        build_blob(memory_pages, 64, &caps, &code_data)
    }

    #[test]
    fn test_kernel_create() {
        let blob = make_simple_blob(10);
        let kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        assert_eq!(kernel.vm_arena.len(), 1);
        assert_eq!(kernel.code_caps.len(), 1);
        assert_eq!(kernel.mem_cycles, 25);
    }

    #[test]
    fn test_kernel_retype() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();

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
        let result = kernel.dispatch_ecall(0);
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
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Find the CODE cap slot
        let code_slot = 64u8; // From manifest

        // CALL on CODE: φ[7]=bitmask, φ[12]=dst_slot for HANDLE
        kernel.set_active_reg(7, 0); // no caps to copy
        kernel.set_active_reg(12, 66); // HANDLE at slot 66 (64=CODE, 65=DATA)

        let result = kernel.dispatch_ecalli(code_slot as u32);
        assert!(matches!(result, DispatchResult::Continue));

        // Should have created VM 1
        assert_eq!(kernel.vm_arena.len(), 2);
        assert_eq!(kernel.vm_arena.vm(1).state, VmState::Idle);

        // φ[7] = dst_slot
        let handle_idx = kernel.active_reg(7) as u8;
        assert_eq!(handle_idx, 66);
        assert!(matches!(
            kernel.vm_arena.vm(0).cap_table.get(handle_idx),
            Some(Cap::Handle(_))
        ));
    }

    #[test]
    fn test_kernel_call_reply() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
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

        // Active VM should now be the child (VM 1)
        assert_eq!(kernel.active_vm, 1);
        assert_eq!(kernel.vm_arena.vm(0).state, VmState::WaitingForReply);
        assert_eq!(kernel.vm_arena.vm(1).state, VmState::Running);

        // Child received args
        assert_eq!(kernel.active_reg(7), 42);
        assert_eq!(kernel.active_reg(8), 99);

        // Child REPLYs with results
        kernel.set_active_reg(7, 100);
        kernel.set_active_reg(8, 200);
        let result = kernel.dispatch_ecalli(IPC_SLOT as u32); // REPLY
        assert!(matches!(result, DispatchResult::Continue));

        // Back to VM 0
        assert_eq!(kernel.active_vm, 0);
        assert_eq!(kernel.vm_arena.vm(0).state, VmState::Running);
        assert_eq!(kernel.vm_arena.vm(1).state, VmState::Idle);

        // Caller received results: φ[7]=child's return, φ[8]=0 (status=REPLY)
        assert_eq!(kernel.active_reg(7), 100);
        assert_eq!(kernel.active_reg(8), 0);
    }

    #[test]
    fn test_kernel_no_reentrancy() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
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

        // VM 0 calls VM 1
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 0); // no IPC cap (slot 0 = IPC itself)
        kernel.dispatch_ecalli(handle1 as u32);
        assert_eq!(kernel.active_vm, 1);

        // Copy handle1 to VM 1 — but VM 0 is WaitingForReply,
        // so calling VM 0 from VM 1 should fail.
        // First we need a handle to VM 0 in VM 1's cap table.
        // We can't actually create one (no HANDLE to VM 0 exists in VM 1).
        // The reentrancy test is: VM 0 is in WaitingForReply, not IDLE.
        // If anyone tries to call VM 0, it fails.
        assert!(!kernel.vm_arena.vm(0).can_call());
    }

    #[test]
    fn test_kernel_gas_bounding() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Create child VM: φ[7]=bitmask, φ[12]=dst_slot
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 66);
        kernel.dispatch_ecalli(64);
        let handle_idx = kernel.active_reg(7) as u8;

        // SET_MAX_GAS on handle via ecall: φ[7]=5000, φ[11]=0x0B, φ[12]=handle(high)
        kernel.set_active_reg(7, 5000);
        kernel.set_active_reg(11, 0x0B); // SET_MAX_GAS
        kernel.set_active_reg(12, (handle_idx as u64) << 32); // subject=handle, object=0
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        kernel.flush_live_ctx();
        kernel.dispatch_ecall(0x0B);

        // CALL child — gas should be capped at 5000
        let parent_gas_before = kernel.vm_arena.vm(0).gas();
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 0); // no IPC cap (slot 0 = IPC itself)
        kernel.dispatch_ecalli(handle_idx as u32);

        assert_eq!(kernel.active_vm, 1);
        assert_eq!(kernel.vm_arena.vm(1).gas(), 5000);

        // Parent lost 10 (ecalli) + 10 (call overhead) + 5000 (transfer)
        assert_eq!(kernel.vm_arena.vm(0).gas(), parent_gas_before - 5020);
    }

    #[test]
    fn test_kernel_protocol_call() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // Set a protocol cap at slot 1 (GAS)
        kernel
            .vm_arena
            .vm_mut(0)
            .cap_table
            .set(1, Cap::Protocol(ProtocolCap { id: 1 }));

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
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

        // CALL empty slot → WHAT
        let result = kernel.dispatch_ecalli(50);
        assert!(matches!(result, DispatchResult::Continue));
        assert_eq!(kernel.active_reg(7), RESULT_WHAT);
    }

    #[test]
    fn test_kernel_downgrade() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
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
        kernel.dispatch_ecall(0x0A);
        let callable_idx = 67u8;

        // Handle still exists
        assert!(matches!(
            kernel.vm_arena.vm(0).cap_table.get(handle_idx),
            Some(Cap::Handle(_))
        ));
        // Callable created
        assert!(matches!(
            kernel.vm_arena.vm(0).cap_table.get(callable_idx),
            Some(Cap::Callable(_))
        ));
    }

    #[test]
    fn test_kernel_run_trap() {
        // Build a blob with a `trap` instruction (opcode 0) — causes Panic.
        // This validates the full execution path: blob parse → JIT compile →
        // mmap DATA → execute native code → exit handling.
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);
        let result = kernel.run();
        assert!(
            matches!(result, KernelResult::Panic),
            "trap instruction should cause Panic, got: {result:?}"
        );
    }
}
