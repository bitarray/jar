//! Invocation kernel — multi-VM scheduler with CALL/REPLY semantics.
//!
//! Manages a pool of VMs, dispatches ecalli calls, and handles the
//! capability-based execution model. The kernel is the "microkernel"
//! that sits between the PVM instruction execution and the host
//! (grey-state's refine/accumulate logic).
//!
//! ecalli dispatch:
//! - 0x000..0x0FF: CALL cap[N] (0xFF = REPLY)
//! - 0x2XX..0xCXX: management ops (MAP, UNMAP, SPLIT, DROP, MOVE, COPY, etc.)

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::backing::{BackingStore, CodeWindow};
use crate::cap::{
    Access, CallableCap, Cap, CapTable, CodeCap, DataCap, HandleCap, IPC_SLOT, UntypedCap,
};
use crate::GAS_PER_PAGE;
use crate::program_v2::{self, CapEntryType, CapManifestEntry, ParsedBlobV2};
use crate::vm_pool::{CallFrame, VmInstance, VmState, MAX_CODE_CAPS, MAX_VMS};

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

/// Result from running the kernel until it needs host interaction.
#[derive(Debug)]
pub enum KernelResult {
    /// Root VM halted normally. Contains φ[7] value.
    Halt(u64),
    /// Root VM panicked.
    Panic,
    /// Root VM ran out of gas.
    OutOfGas,
    /// Root VM page-faulted at address.
    PageFault(u32),
    /// A protocol cap was invoked. Host should handle and call `resume_protocol_call`.
    ProtocolCall {
        /// Protocol cap slot number.
        slot: u8,
        /// VM registers at the time of the call.
        regs: [u64; 13],
        /// Gas remaining.
        gas: u64,
    },
}

/// The invocation kernel.
pub struct InvocationKernel {
    /// Physical memory pool.
    pub backing: BackingStore,
    /// Compiled CODE caps (max 5).
    pub code_caps: Vec<Arc<CodeCap>>,
    /// VM instances (max 1024).
    pub vms: Vec<VmInstance>,
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
}

impl InvocationKernel {
    /// Create a new kernel from a JAR blob (v2 or v1 format).
    ///
    /// Tries v2 capability manifest first. Falls back to v1 linear blob format
    /// by converting it to a synthetic v2 manifest.
    pub fn new(blob: &[u8], _args: &[u8], gas: u64) -> Result<Self, KernelError> {
        let parsed = match program_v2::parse_v2_blob(blob) {
            Some(p) => p,
            None => {
                // Fallback: parse v1 blob and convert to synthetic v2 manifest
                return Self::new_from_v1(blob, _args, gas);
            }
        };

        let backing =
            BackingStore::new(parsed.header.memory_pages).ok_or(KernelError::MemoryError)?;

        let mem_cycles = crate::compute_mem_cycles(parsed.header.memory_pages);
        let untyped = Arc::new(UntypedCap::new(parsed.header.memory_pages));

        let mut kernel = Self {
            backing,
            code_caps: Vec::with_capacity(MAX_CODE_CAPS),
            vms: Vec::with_capacity(16),
            untyped,
            active_vm: 0,
            call_stack: Vec::with_capacity(8),
            mem_cycles,
            next_code_id: 0,
        };

        // Build VM 0's cap table from the manifest
        let mut cap_table = CapTable::new();
        let mut init_pages: u32 = 0;
        let mut data_caps_to_map: Vec<(u32, u32, u32, Access)> = Vec::new(); // (base_page, backing_offset, page_count, access)

        for entry in &parsed.caps {
            let cap = kernel.create_cap_from_manifest(entry, &parsed)?;
            if let Cap::Data(ref d) = cap {
                init_pages += d.page_count;
                // Record DATA caps that need mapping into the CODE window
                if let Some((base_page, access)) = d.mapped {
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

        // Map DATA caps into the invoke CODE cap's window
        let invoke_code_cap = &kernel.code_caps[invoke_code_id as usize];
        for (base_page, backing_offset, page_count, access) in &data_caps_to_map {
            unsafe {
                if !kernel.backing.map_pages(
                    invoke_code_cap.window.base(),
                    *base_page,
                    *backing_offset,
                    *page_count,
                    *access,
                ) {
                    return Err(KernelError::MemoryError);
                }
            }
        }

        // Give VM 0 the UNTYPED cap at a free slot
        let untyped_slot = (64..255u8)
            .find(|i| cap_table.is_empty(*i))
            .ok_or(KernelError::CapTableFull)?;
        cap_table.set(untyped_slot, Cap::Untyped(Arc::clone(&kernel.untyped)));

        // Write arguments into args cap (cap_index=0xFF = IPC slot)
        let mut args_base: u64 = 0;
        let args_len: u64 = _args.len() as u64;
        if !_args.is_empty() {
            // Find args cap by scanning for cap_index=0xFF
            let args_cap_entry = parsed.caps.iter().find(|e| e.cap_index == 0xFF);
            if let Some(entry) = args_cap_entry {
                args_base = entry.base_page as u64 * crate::PVM_PAGE_SIZE as u64;
                if let Some(Cap::Data(d)) = cap_table.get(0xFF) {
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
        vm0.registers[8] = args_base;
        vm0.registers[9] = args_len;
        kernel.vms.push(vm0);

        Ok(kernel)
    }

    /// Create a kernel from a v1 (JAR\x01) blob by converting to v2 internally.
    fn new_from_v1(blob: &[u8], args: &[u8], gas: u64) -> Result<Self, KernelError> {
        // Use the v1 parser to extract components, then build a v2 blob
        let v2_blob = crate::program::convert_v1_to_v2(blob, args)
            .ok_or(KernelError::InvalidBlob)?;
        // Re-enter with the converted blob
        Self::new(&v2_blob, args, gas)
    }

    /// Create a capability from a manifest entry.
    fn create_cap_from_manifest(
        &mut self,
        entry: &CapManifestEntry,
        parsed: &ParsedBlobV2<'_>,
    ) -> Result<Cap, KernelError> {
        match entry.cap_type {
            CapEntryType::Code => {
                let code_data = program_v2::cap_data(entry, parsed.data_section);
                let id = self.next_code_id;
                self.next_code_id += 1;
                if self.code_caps.len() >= MAX_CODE_CAPS {
                    return Err(KernelError::TooManyCodeCaps);
                }

                // Parse the code sub-blob (jump_table + code + bitmask)
                let code_blob = program_v2::parse_code_blob(code_data)
                    .ok_or(KernelError::InvalidBlob)?;

                // JIT compile to native x86-64
                let compiled = crate::recompiler::compile_code(
                    &code_blob.code,
                    &code_blob.bitmask,
                    &code_blob.jump_table,
                    self.mem_cycles,
                )
                .map_err(|e| {
                    tracing::warn!("JIT compile failed: {e}");
                    KernelError::CompileError
                })?;

                // Allocate 4GB virtual window
                let window = CodeWindow::new().ok_or(KernelError::MemoryError)?;

                let code_cap = Arc::new(CodeCap {
                    id,
                    window,
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
                    let data = program_v2::cap_data(entry, parsed.data_section);
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
    pub fn dispatch_ecalli(&mut self, imm: u32) -> DispatchResult {
        // Charge ecalli gas cost (10) — matches GP host call gas charge
        let ecalli_gas: u64 = 10;
        let vm = &mut self.vms[self.active_vm as usize];
        if vm.gas < ecalli_gas {
            return DispatchResult::Fault(FaultType::OutOfGas);
        }
        vm.gas -= ecalli_gas;

        if imm < CALL_RANGE_END {
            // CALL cap[N]
            let cap_idx = imm as u8;
            if cap_idx == IPC_SLOT {
                return self.handle_reply();
            }
            self.handle_call(cap_idx)
        } else {
            // Management op: high byte = op, low byte = cap index
            let op = imm >> 8;
            let cap_idx = (imm & 0xFF) as u8;
            self.handle_management_op(op, cap_idx)
        }
    }

    /// Handle CALL on a cap slot.
    fn handle_call(&mut self, cap_idx: u8) -> DispatchResult {
        let vm = &self.vms[self.active_vm as usize];
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
                let regs = self.vms[self.active_vm as usize].registers;
                let gas = self.vms[self.active_vm as usize].gas;
                DispatchResult::ProtocolCall { slot, regs, gas }
            }
            Cap::Untyped(_) => self.handle_call_untyped(),
            Cap::Code(_) => self.handle_call_code(),
            Cap::Handle(h) => {
                let target_vm = h.vm_id;
                let max_gas = h.max_gas;
                self.handle_call_vm(target_vm, max_gas)
            }
            Cap::Callable(c) => {
                let target_vm = c.vm_id;
                let max_gas = c.max_gas;
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

        let vm = &mut self.vms[self.active_vm as usize];
        if vm.gas < gas_cost {
            return DispatchResult::Fault(FaultType::OutOfGas);
        }
        vm.gas -= gas_cost;

        // Get the UNTYPED cap (it's an Arc, so we can clone the reference)
        let untyped = match vm.cap_table.get(
            // Find the untyped slot — scan cap table
            (0..=254).find(|i| matches!(vm.cap_table.get(*i), Some(Cap::Untyped(_)))).unwrap_or(255)
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

        // Find a free slot for the new DATA cap
        let vm = &mut self.vms[self.active_vm as usize];
        let free_slot = match (64..255u8).find(|i| vm.cap_table.is_empty(*i)) {
            Some(s) => s,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        vm.cap_table.set(free_slot, Cap::Data(data_cap));
        self.set_active_reg(7, free_slot as u64);
        DispatchResult::Continue
    }

    /// CALL on CODE → CREATE.
    fn handle_call_code(&mut self) -> DispatchResult {
        let entry_idx = self.active_reg(7) as u32;
        let bitmask = self.active_reg(8);

        if self.vms.len() >= MAX_VMS {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }

        // Create child VM's cap table by copying bitmask-selected caps from parent
        let mut child_table = CapTable::new();
        let parent_vm = &self.vms[self.active_vm as usize];

        for bit in 0..64u8 {
            if bitmask & (1u64 << bit) != 0
                && let Some(cap) = parent_vm.cap_table.get(bit)
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

        let child_vm_id = self.vms.len() as u16;
        let child = VmInstance::new(0, entry_idx, child_table, 0);
        self.vms.push(child);

        // Create HANDLE for the parent
        let handle = HandleCap {
            vm_id: child_vm_id,
            max_gas: None,
        };

        let parent_vm = &mut self.vms[self.active_vm as usize];
        let free_slot = match (64..255u8).find(|i| parent_vm.cap_table.is_empty(*i)) {
            Some(s) => s,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };
        parent_vm.cap_table.set(free_slot, Cap::Handle(handle));
        self.set_active_reg(7, free_slot as u64);
        DispatchResult::Continue
    }

    /// CALL on HANDLE/CALLABLE → suspend caller, run target VM.
    fn handle_call_vm(&mut self, target_vm_id: u16, max_gas: Option<u64>) -> DispatchResult {
        if target_vm_id as usize >= self.vms.len() {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }

        if !self.vms[target_vm_id as usize].can_call() {
            // Target is not IDLE — re-entrancy prevention
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }

        // Determine gas budget for callee
        let caller_vm = &mut self.vms[self.active_vm as usize];
        let call_overhead = 10u64;
        if caller_vm.gas < call_overhead {
            return DispatchResult::Fault(FaultType::OutOfGas);
        }
        caller_vm.gas -= call_overhead;

        let callee_gas = match max_gas {
            Some(limit) => caller_vm.gas.min(limit),
            None => caller_vm.gas,
        };
        caller_vm.gas -= callee_gas;

        // Save caller state
        let caller_id = self.active_vm;
        let _ = self.vms[caller_id as usize].transition(VmState::WaitingForReply);

        // Handle IPC cap (φ[12])
        let ipc_cap_slot = self.active_reg(12) as u8;
        let mut ipc_cap_idx = None;
        let mut ipc_was_mapped = None;

        if ipc_cap_slot != 0xFF
            && !self.vms[caller_id as usize]
                .cap_table
                .is_empty(ipc_cap_slot)
        {
            // Take cap from caller, auto-unmap if DATA
            if let Some(mut cap) = self.vms[caller_id as usize].cap_table.take(ipc_cap_slot) {
                if let Cap::Data(ref mut d) = cap {
                    ipc_was_mapped = d.unmap();
                }
                ipc_cap_idx = Some(ipc_cap_slot);
                // Place in callee's IPC slot [255]
                self.vms[target_vm_id as usize].cap_table.set(IPC_SLOT, cap);
            }
        }

        // Push call frame
        self.call_stack.push(CallFrame {
            caller_vm_id: caller_id,
            ipc_cap_idx,
            ipc_was_mapped,
        });

        // Pass args: caller's φ[7]..φ[10] → callee's φ[7]..φ[10]
        let caller_regs = self.vms[caller_id as usize].registers;

        // Set up callee
        let callee = &mut self.vms[target_vm_id as usize];
        callee.gas = callee_gas;
        callee.caller = Some(caller_id);
        callee.registers[7] = caller_regs[7];
        callee.registers[8] = caller_regs[8];
        callee.registers[9] = caller_regs[9];
        callee.registers[10] = caller_regs[10];

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
        let _ = self.vms[callee_id as usize].transition(VmState::Idle);

        // Return unused gas to caller
        let unused_gas = self.vms[callee_id as usize].gas;
        self.vms[caller_id as usize].gas += unused_gas;
        self.vms[callee_id as usize].gas = 0;

        // Return IPC cap
        if let Some(caller_slot) = frame.ipc_cap_idx
            && let Some(mut cap) = self.vms[callee_id as usize].cap_table.take(IPC_SLOT)
        {
            // Auto-remap DATA cap at caller's original base_page
            if let Some((base_page, access)) = frame.ipc_was_mapped
                && let Cap::Data(d) = &mut cap
            {
                d.map(base_page, access);
            }
            self.vms[caller_id as usize].cap_table.set(caller_slot, cap);
        }

        // Pass results: callee's φ[7], φ[8] → caller's φ[7], φ[8]
        let callee_regs = self.vms[callee_id as usize].registers;
        self.vms[caller_id as usize].registers[7] = callee_regs[7];
        self.vms[caller_id as usize].registers[8] = callee_regs[8];

        // Caller → Running
        let _ = self.vms[caller_id as usize].transition(VmState::Running);
        self.active_vm = caller_id;

        DispatchResult::Continue
    }

    /// Handle a management op.
    fn handle_management_op(&mut self, op: u32, cap_idx: u8) -> DispatchResult {
        match op {
            MGMT_MAP => self.mgmt_map(cap_idx),
            MGMT_UNMAP => self.mgmt_unmap(cap_idx),
            MGMT_SPLIT => self.mgmt_split(cap_idx),
            MGMT_DROP => self.mgmt_drop(cap_idx),
            MGMT_MOVE => self.mgmt_move(cap_idx),
            MGMT_COPY => self.mgmt_copy(cap_idx),
            MGMT_GRANT => self.mgmt_grant(cap_idx),
            MGMT_REVOKE => self.mgmt_revoke(cap_idx),
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

        let vm = &self.vms[self.active_vm as usize];
        let code_cap_id = vm.code_cap_id;
        let vm = &mut self.vms[self.active_vm as usize];
        match vm.cap_table.get_mut(cap_idx) {
            Some(Cap::Data(d)) => {
                // Unmap previous mapping if remapping
                if let Some((old_base, _)) = d.map(base_page, access) {
                    let code_cap = &self.code_caps[code_cap_id as usize];
                    unsafe {
                        BackingStore::unmap_pages(code_cap.window.base(), old_base, d.page_count);
                    }
                }
                // Map new location
                let code_cap = &self.code_caps[code_cap_id as usize];
                unsafe {
                    self.backing.map_pages(
                        code_cap.window.base(),
                        base_page,
                        d.backing_offset,
                        d.page_count,
                        access,
                    );
                }
            }
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
            }
        }
        DispatchResult::Continue
    }

    fn mgmt_unmap(&mut self, cap_idx: u8) -> DispatchResult {
        let code_cap_id = self.vms[self.active_vm as usize].code_cap_id;
        let vm = &mut self.vms[self.active_vm as usize];
        match vm.cap_table.get_mut(cap_idx) {
            Some(Cap::Data(d)) => {
                if let Some((base_page, _)) = d.unmap() {
                    let code_cap = &self.code_caps[code_cap_id as usize];
                    unsafe {
                        BackingStore::unmap_pages(
                            code_cap.window.base(),
                            base_page,
                            d.page_count,
                        );
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

        let vm = &mut self.vms[self.active_vm as usize];

        // Pre-validate: must be DATA, unmapped, valid offset
        let can_split = match vm.cap_table.get(cap_idx) {
            Some(Cap::Data(d)) => {
                d.mapped.is_none() && page_off > 0 && page_off < d.page_count
            }
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
        let code_cap_id = self.vms[self.active_vm as usize].code_cap_id;
        let vm = &mut self.vms[self.active_vm as usize];
        // Unmap DATA caps before dropping
        if let Some(Cap::Data(d)) = vm.cap_table.get(cap_idx)
            && let Some((base_page, _)) = d.mapped
        {
            let page_count = d.page_count;
            let code_cap = &self.code_caps[code_cap_id as usize];
            unsafe {
                BackingStore::unmap_pages(code_cap.window.base(), base_page, page_count);
            }
        }
        vm.cap_table.drop_cap(cap_idx);
        DispatchResult::Continue
    }

    fn mgmt_move(&mut self, cap_idx: u8) -> DispatchResult {
        let dst = self.active_reg(7) as u8;
        let vm = &mut self.vms[self.active_vm as usize];
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
        let vm = &mut self.vms[self.active_vm as usize];
        match vm.cap_table.copy_cap(cap_idx, dst) {
            Ok(()) => {}
            Err(_) => {
                self.set_active_reg(7, RESULT_WHAT);
            }
        }
        DispatchResult::Continue
    }

    fn mgmt_grant(&mut self, handle_idx: u8) -> DispatchResult {
        let cap_idx = self.active_reg(7) as u8;

        let vm = &self.vms[self.active_vm as usize];
        let target_vm_id = match vm.cap_table.get(handle_idx) {
            Some(Cap::Handle(h)) => h.vm_id,
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        if target_vm_id as usize >= self.vms.len() {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }

        // Take cap from parent
        let mut cap = match self.vms[self.active_vm as usize].cap_table.take(cap_idx) {
            Some(c) => c,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        // Auto-unmap DATA caps crossing boundary
        if let Cap::Data(ref mut d) = cap {
            d.unmap();
        }

        // Find free slot in child
        let child = &mut self.vms[target_vm_id as usize];
        let free = match (0..255u8).find(|i| child.cap_table.is_empty(*i)) {
            Some(s) => s,
            None => {
                // Put it back
                self.vms[self.active_vm as usize]
                    .cap_table
                    .set(cap_idx, cap);
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        child.cap_table.set(free, cap);
        self.set_active_reg(7, free as u64);
        DispatchResult::Continue
    }

    fn mgmt_revoke(&mut self, handle_idx: u8) -> DispatchResult {
        let remote_idx = self.active_reg(7) as u8;

        let vm = &self.vms[self.active_vm as usize];
        let target_vm_id = match vm.cap_table.get(handle_idx) {
            Some(Cap::Handle(h)) => h.vm_id,
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        if target_vm_id as usize >= self.vms.len() {
            self.set_active_reg(7, RESULT_WHAT);
            return DispatchResult::Continue;
        }

        // Take cap from child
        let mut cap = match self.vms[target_vm_id as usize].cap_table.take(remote_idx) {
            Some(c) => c,
            None => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        // Auto-unmap DATA caps crossing boundary
        if let Cap::Data(ref mut d) = cap {
            d.unmap();
        }

        // Find free slot in parent
        let parent = &mut self.vms[self.active_vm as usize];
        let free = match (64..255u8).find(|i| parent.cap_table.is_empty(*i)) {
            Some(s) => s,
            None => {
                // Put it back in child
                self.vms[target_vm_id as usize]
                    .cap_table
                    .set(remote_idx, cap);
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        parent.cap_table.set(free, cap);
        self.set_active_reg(7, free as u64);
        DispatchResult::Continue
    }

    fn mgmt_downgrade(&mut self, handle_idx: u8) -> DispatchResult {
        let vm = &self.vms[self.active_vm as usize];
        let (vm_id, max_gas) = match vm.cap_table.get(handle_idx) {
            Some(Cap::Handle(h)) => (h.vm_id, h.max_gas),
            _ => {
                self.set_active_reg(7, RESULT_WHAT);
                return DispatchResult::Continue;
            }
        };

        let callable = CallableCap { vm_id, max_gas };

        let vm = &mut self.vms[self.active_vm as usize];
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
        let vm = &mut self.vms[self.active_vm as usize];
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

    // --- Register helpers ---

    fn active_reg(&self, idx: usize) -> u64 {
        self.vms[self.active_vm as usize].registers[idx]
    }

    fn set_active_reg(&mut self, idx: usize, val: u64) {
        self.vms[self.active_vm as usize].registers[idx] = val;
    }

    /// Resume after a protocol call was handled by the host.
    /// Sets return registers and continues execution.
    pub fn resume_protocol_call(&mut self, result0: u64, result1: u64) {
        self.set_active_reg(7, result0);
        self.set_active_reg(8, result1);
    }

    /// Run the kernel until it needs host interaction or terminates.
    ///
    /// This is the main execution loop. It:
    /// 1. Sets up JitContext in the active CODE cap's window
    /// 2. Executes native code
    /// 3. On ecalli exit, dispatches via dispatch_ecalli
    /// 4. Continues or returns to host
    pub fn run(&mut self) -> KernelResult {
        use crate::recompiler::{signal, JitContext};

        loop {
            let vm = &self.vms[self.active_vm as usize];
            let code_cap = &self.code_caps[vm.code_cap_id as usize];

            // Place JitContext at window.ctx_ptr()
            let ctx_raw = code_cap.window.ctx_ptr() as *mut JitContext;
            // SAFETY: ctx_ptr() returns a writable page allocated by CodeWindow::new().
            unsafe {
                ctx_raw.write(JitContext {
                    regs: vm.registers,
                    gas: vm.gas as i64,
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
                    dispatch_table: code_cap.compiled.dispatch_table.as_ptr(),
                    code_base: code_cap.compiled.native_code.ptr as u64,
                    flat_buf: code_cap.window.base(),
                    flat_perms: std::ptr::null(), // not used with signals
                    fast_reentry: 0,
                    _pad2: 0,
                    max_heap_pages: 0,
                    _pad3: 0,
                });
            }

            // Set up signal state for SIGSEGV handler
            signal::ensure_installed();
            let mut signal_state = signal::SignalState {
                code_start: code_cap.compiled.native_code.ptr as usize,
                code_end: code_cap.compiled.native_code.ptr as usize
                    + code_cap.compiled.native_code.len,
                exit_label_addr: code_cap.compiled.native_code.ptr as usize
                    + code_cap.compiled.exit_label_offset as usize,
                ctx_ptr: ctx_raw,
                trap_table: code_cap.compiled.trap_table.clone(),
            };
            signal::SIGNAL_STATE.with(|cell| cell.set(&mut signal_state as *mut _));

            // Execute native code
            let entry = code_cap.compiled.native_code.entry();
            // SAFETY: entry points to valid JIT code; ctx_raw is a valid JitContext.
            unsafe {
                entry(ctx_raw);
            }

            // Clear signal state
            signal::SIGNAL_STATE.with(|cell| cell.set(std::ptr::null_mut()));

            // Read back results
            let ctx = unsafe { &*ctx_raw };
            let exit_reason = ctx.exit_reason;
            let exit_arg = ctx.exit_arg;

            // Sync registers and gas back to VM
            let vm = &mut self.vms[self.active_vm as usize];
            vm.registers = ctx.regs;
            vm.gas = ctx.gas.max(0) as u64;
            vm.pc = ctx.pc;

            match exit_reason {
                4 => {
                    // HostCall(imm) — ecalli
                    vm.pc = ctx.pc; // entry_pc for re-entry
                    match self.dispatch_ecalli(exit_arg) {
                        DispatchResult::Continue => continue,
                        DispatchResult::ProtocolCall { slot, regs, gas } => {
                            return KernelResult::ProtocolCall { slot, regs, gas };
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
                    let value = vm.registers[7];
                    match self.handle_vm_halt(value) {
                        DispatchResult::RootHalt(v) => return KernelResult::Halt(v),
                        DispatchResult::Continue => continue,
                        _ => return KernelResult::Panic,
                    }
                }
                1 => {
                    // Panic
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
                    if (idx as usize) < code_cap.jump_table.len() {
                        let target = code_cap.jump_table[idx as usize];
                        if (target as usize) < code_cap.bitmask.len()
                            && code_cap.bitmask[target as usize] == 1
                        {
                            self.vms[self.active_vm as usize].pc = target;
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
                _ => return KernelResult::Panic,
            }
        }
    }

    /// Read bytes from a DATA cap's mapped region in the active VM's CODE window.
    pub fn read_data_cap(&self, cap_idx: u8, offset: u32, len: u32) -> Option<Vec<u8>> {
        let vm = &self.vms[self.active_vm as usize];
        let d = match vm.cap_table.get(cap_idx)? {
            Cap::Data(d) => d,
            _ => return None,
        };
        let (base_page, _) = d.mapped?;
        let code_cap = &self.code_caps[vm.code_cap_id as usize];
        let addr = base_page as usize * crate::PVM_PAGE_SIZE as usize + offset as usize;
        let mut buf = vec![0u8; len as usize];
        // SAFETY: base_page was mmap'd into the CODE window by map_pages.
        unsafe {
            std::ptr::copy_nonoverlapping(
                code_cap.window.base().add(addr),
                buf.as_mut_ptr(),
                len as usize,
            );
        }
        Some(buf)
    }

    /// Read bytes directly from the active VM's CODE window by address.
    /// Used for reading output from guest programs that return ptr+len in registers.
    pub fn read_data_cap_window(&self, addr: u32, len: u32) -> Option<Vec<u8>> {
        let vm = &self.vms[self.active_vm as usize];
        let code_cap = &self.code_caps[vm.code_cap_id as usize];
        let mut buf = vec![0u8; len as usize];
        // SAFETY: addr is within the CODE window's 4GB mmap region.
        unsafe {
            std::ptr::copy_nonoverlapping(
                code_cap.window.base().add(addr as usize),
                buf.as_mut_ptr(),
                len as usize,
            );
        }
        Some(buf)
    }

    /// Write bytes into a DATA cap's mapped region in the active VM's CODE window.
    pub fn write_data_cap(&self, cap_idx: u8, offset: u32, data: &[u8]) -> bool {
        let vm = &self.vms[self.active_vm as usize];
        let d = match vm.cap_table.get(cap_idx) {
            Some(Cap::Data(d)) => d,
            _ => return false,
        };
        let (base_page, _) = match d.mapped {
            Some(m) => m,
            None => return false,
        };
        let code_cap = &self.code_caps[vm.code_cap_id as usize];
        let addr = base_page as usize * crate::PVM_PAGE_SIZE as usize + offset as usize;
        // SAFETY: base_page was mmap'd into the CODE window by map_pages.
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                code_cap.window.base().add(addr),
                data.len(),
            );
        }
        true
    }

    /// Handle a callee halt (exit from VM execution).
    pub fn handle_vm_halt(&mut self, exit_value: u64) -> DispatchResult {
        let callee_id = self.active_vm;
        let _ = self.vms[callee_id as usize].transition(VmState::Halted);

        match self.call_stack.pop() {
            Some(frame) => {
                let caller_id = frame.caller_vm_id;

                // Return unused gas
                let unused_gas = self.vms[callee_id as usize].gas;
                self.vms[caller_id as usize].gas += unused_gas;

                // Return IPC cap
                if let Some(caller_slot) = frame.ipc_cap_idx
                    && let Some(mut cap) =
                        self.vms[callee_id as usize].cap_table.take(IPC_SLOT)
                {
                    if let Some((bp, acc)) = frame.ipc_was_mapped
                        && let Cap::Data(d) = &mut cap
                    {
                        d.map(bp, acc);
                    }
                    self.vms[caller_id as usize].cap_table.set(caller_slot, cap);
                }

                // Return result
                self.vms[caller_id as usize].registers[7] = exit_value;

                let _ = self.vms[caller_id as usize].transition(VmState::Running);
                self.active_vm = caller_id;
                DispatchResult::Continue
            }
            None => {
                // Root VM halted
                DispatchResult::RootHalt(exit_value)
            }
        }
    }

    /// Handle a callee fault (panic/OOG/page fault).
    pub fn handle_vm_fault(&mut self, fault: FaultType) -> DispatchResult {
        let callee_id = self.active_vm;
        let _ = self.vms[callee_id as usize].transition(VmState::Faulted);

        match self.call_stack.pop() {
            Some(frame) => {
                let caller_id = frame.caller_vm_id;

                // Return unused gas
                let unused_gas = self.vms[callee_id as usize].gas;
                self.vms[caller_id as usize].gas += unused_gas;

                // IPC cap is lost (callee faulted)
                // Set error status in caller registers
                self.vms[caller_id as usize].registers[7] = RESULT_WHAT;

                let _ = self.vms[caller_id as usize].transition(VmState::Running);
                self.active_vm = caller_id;
                DispatchResult::Continue
            }
            None => {
                // Root VM faulted
                match fault {
                    FaultType::Panic => DispatchResult::RootPanic,
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
    ProtocolCall { slot: u8, regs: [u64; 13], gas: u64 },
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
            Self::InvalidBlob => write!(f, "invalid JAR v2 blob"),
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
    use crate::program_v2::{build_v2_blob, CapManifestEntry, CapEntryType};

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
        build_v2_blob(memory_pages, 64, &caps, &code_data)
    }

    #[test]
    fn test_kernel_create() {
        let blob = make_simple_blob(10);
        let kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        assert_eq!(kernel.vms.len(), 1);
        assert_eq!(kernel.code_caps.len(), 1);
        assert_eq!(kernel.mem_cycles, 25);
    }

    #[test]
    fn test_kernel_retype() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();

        // Set VM 0 to running
        let _ = kernel.vms[0].transition(VmState::Running);

        // CALL on UNTYPED (find the untyped slot first)
        let untyped_slot = (64..255u8)
            .find(|i| matches!(kernel.vms[0].cap_table.get(*i), Some(Cap::Untyped(_))))
            .unwrap();

        // Set φ[7] = 4 pages
        kernel.set_active_reg(7, 4);

        // Dispatch CALL on UNTYPED slot
        let result = kernel.dispatch_ecalli(untyped_slot as u32);
        assert!(matches!(result, DispatchResult::Continue));

        // φ[7] should be the new cap index
        let new_cap_idx = kernel.active_reg(7) as u8;
        assert!(matches!(
            kernel.vms[0].cap_table.get(new_cap_idx),
            Some(Cap::Data(_))
        ));
    }

    #[test]
    fn test_kernel_create_vm() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vms[0].transition(VmState::Running);

        // Find the CODE cap slot
        let code_slot = 64u8; // From manifest

        // CALL on CODE: φ[7]=entry_idx, φ[8]=bitmask
        kernel.set_active_reg(7, 0); // entry_index = 0
        kernel.set_active_reg(8, 0); // no caps to copy

        let result = kernel.dispatch_ecalli(code_slot as u32);
        assert!(matches!(result, DispatchResult::Continue));

        // Should have created VM 1
        assert_eq!(kernel.vms.len(), 2);
        assert_eq!(kernel.vms[1].state, VmState::Idle);

        // φ[7] = handle cap index
        let handle_idx = kernel.active_reg(7) as u8;
        assert!(matches!(
            kernel.vms[0].cap_table.get(handle_idx),
            Some(Cap::Handle(_))
        ));
    }

    #[test]
    fn test_kernel_call_reply() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vms[0].transition(VmState::Running);

        // Create child VM
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(8, 0);
        kernel.dispatch_ecalli(64); // CALL CODE → CREATE
        let handle_idx = kernel.active_reg(7) as u8;

        // CALL the child: φ[7]=arg0, φ[8]=arg1, φ[12]=0xFF (no IPC cap)
        kernel.set_active_reg(7, 42);
        kernel.set_active_reg(8, 99);
        kernel.set_active_reg(12, 0xFF);

        let result = kernel.dispatch_ecalli(handle_idx as u32);
        assert!(matches!(result, DispatchResult::Continue));

        // Active VM should now be the child (VM 1)
        assert_eq!(kernel.active_vm, 1);
        assert_eq!(kernel.vms[0].state, VmState::WaitingForReply);
        assert_eq!(kernel.vms[1].state, VmState::Running);

        // Child received args
        assert_eq!(kernel.active_reg(7), 42);
        assert_eq!(kernel.active_reg(8), 99);

        // Child REPLYs with results
        kernel.set_active_reg(7, 100);
        kernel.set_active_reg(8, 200);
        let result = kernel.dispatch_ecalli(0xFF); // REPLY
        assert!(matches!(result, DispatchResult::Continue));

        // Back to VM 0
        assert_eq!(kernel.active_vm, 0);
        assert_eq!(kernel.vms[0].state, VmState::Running);
        assert_eq!(kernel.vms[1].state, VmState::Idle);

        // Caller received results
        assert_eq!(kernel.active_reg(7), 100);
        assert_eq!(kernel.active_reg(8), 200);
    }

    #[test]
    fn test_kernel_no_reentrancy() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vms[0].transition(VmState::Running);

        // Create two child VMs
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(8, 0);
        kernel.dispatch_ecalli(64); // CREATE VM 1
        let handle1 = kernel.active_reg(7) as u8;

        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(8, 0);
        kernel.dispatch_ecalli(64); // CREATE VM 2
        let _handle2 = kernel.active_reg(7) as u8;

        // VM 0 calls VM 1
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 0xFF);
        kernel.dispatch_ecalli(handle1 as u32);
        assert_eq!(kernel.active_vm, 1);

        // Copy handle1 to VM 1 — but VM 0 is WaitingForReply,
        // so calling VM 0 from VM 1 should fail.
        // First we need a handle to VM 0 in VM 1's cap table.
        // We can't actually create one (no HANDLE to VM 0 exists in VM 1).
        // The reentrancy test is: VM 0 is in WaitingForReply, not IDLE.
        // If anyone tries to call VM 0, it fails.
        assert!(!kernel.vms[0].can_call());
    }

    #[test]
    fn test_kernel_gas_bounding() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vms[0].transition(VmState::Running);

        // Create child VM
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(8, 0);
        kernel.dispatch_ecalli(64);
        let handle_idx = kernel.active_reg(7) as u8;

        // SET_MAX_GAS on handle: limit to 5000 gas
        kernel.set_active_reg(7, 5000);
        kernel.dispatch_ecalli((MGMT_SET_MAX_GAS << 8) | handle_idx as u32);

        // CALL child — gas should be capped at 5000
        let parent_gas_before = kernel.vms[0].gas;
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(12, 0xFF);
        kernel.dispatch_ecalli(handle_idx as u32);

        assert_eq!(kernel.active_vm, 1);
        assert_eq!(kernel.vms[1].gas, 5000);

        // Parent lost 10 (ecalli) + 10 (call overhead) + 5000 (transfer)
        assert_eq!(kernel.vms[0].gas, parent_gas_before - 5020);
    }

    #[test]
    fn test_kernel_protocol_call() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vms[0].transition(VmState::Running);

        // Set a protocol cap at slot 0
        kernel.vms[0]
            .cap_table
            .set(0, Cap::Protocol(ProtocolCap { id: 0 }));

        // CALL slot 0 → should return ProtocolCall
        kernel.set_active_reg(7, 123);
        let result = kernel.dispatch_ecalli(0);
        match result {
            DispatchResult::ProtocolCall { slot, regs, .. } => {
                assert_eq!(slot, 0);
                assert_eq!(regs[7], 123);
            }
            _ => panic!("expected ProtocolCall"),
        }
    }

    #[test]
    fn test_kernel_missing_cap() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vms[0].transition(VmState::Running);

        // CALL empty slot → WHAT
        let result = kernel.dispatch_ecalli(50);
        assert!(matches!(result, DispatchResult::Continue));
        assert_eq!(kernel.active_reg(7), RESULT_WHAT);
    }

    #[test]
    fn test_kernel_downgrade() {
        let blob = make_simple_blob(10);
        let mut kernel = InvocationKernel::new(&blob, &[], 100_000).unwrap();
        let _ = kernel.vms[0].transition(VmState::Running);

        // Create child
        kernel.set_active_reg(7, 0);
        kernel.set_active_reg(8, 0);
        kernel.dispatch_ecalli(64);
        let handle_idx = kernel.active_reg(7) as u8;

        // DOWNGRADE handle → callable
        kernel.dispatch_ecalli((MGMT_DOWNGRADE << 8) | handle_idx as u32);
        let callable_idx = kernel.active_reg(7) as u8;

        // Handle still exists
        assert!(matches!(
            kernel.vms[0].cap_table.get(handle_idx),
            Some(Cap::Handle(_))
        ));
        // Callable created
        assert!(matches!(
            kernel.vms[0].cap_table.get(callable_idx),
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
        let _ = kernel.vms[0].transition(VmState::Running);
        let result = kernel.run();
        assert!(
            matches!(result, KernelResult::Panic),
            "trap instruction should cause Panic, got: {result:?}"
        );
    }
}
