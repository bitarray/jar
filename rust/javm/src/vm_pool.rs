//! VM instance pool and state machine for the capability-based JAVM v2.
//!
//! Each VM has a state (Idle/Running/WaitingForReply/Halted/Faulted),
//! a cap table, register state, and a reference to its CODE cap.
//! Only IDLE VMs can be CALLed — this prevents reentrancy by construction.

use crate::PVM_REGISTER_COUNT;
use crate::cap::{CapTable, ProtocolCapT};

/// VM lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    /// Waiting for a CALL. Only state that accepts incoming calls.
    Idle,
    /// Currently executing PVM code.
    Running,
    /// Blocked at a CALL ecalli, waiting for the callee to reply.
    WaitingForReply,
    /// Clean exit (REPLY from root VM).
    Halted,
    /// Abnormal termination (panic, OOG, page fault).
    Faulted,
}

/// A single VM instance in the pool.
#[derive(Debug)]
pub struct VmInstance<P: ProtocolCapT = u8> {
    /// Current lifecycle state.
    pub state: VmState,
    /// Index of the CODE cap this VM runs (in the kernel's code_caps list).
    pub code_cap_id: u16,
    /// PVM registers (13 × 64-bit). Use reg()/set_reg()/regs() for access.
    registers: [u64; PVM_REGISTER_COUNT],
    /// Program counter.
    pub pc: u32,
    /// Per-VM capability table.
    pub cap_table: CapTable<P>,
    /// Who called this VM (for REPLY routing). None if called by kernel.
    pub caller: Option<u16>,
    /// Jump table entry index (used on first CALL).
    pub entry_index: u32,
    /// Gas remaining for this VM. Use gas()/set_gas() for access.
    gas: u64,
    /// Guest heap base address (tracked for continuation snapshots).
    heap_base: u32,
    /// Guest heap top address (tracked for continuation snapshots).
    heap_top: u32,
}

impl<P: ProtocolCapT> VmInstance<P> {
    /// Create a new VM in IDLE state.
    pub fn new(code_cap_id: u16, entry_index: u32, cap_table: CapTable<P>, gas: u64) -> Self {
        let registers = [0u64; PVM_REGISTER_COUNT];
        Self {
            state: VmState::Idle,
            code_cap_id,
            registers,
            pc: 0, // Will be set to jump_table[entry_index] on first CALL
            cap_table,
            caller: None,
            entry_index,
            gas,
            heap_base: 0,
            heap_top: 0,
        }
    }

    /// Read a register (cold path — for non-active or suspended VMs).
    pub fn reg(&self, idx: usize) -> u64 {
        self.registers[idx]
    }

    /// Write a register (cold path — for non-active or suspended VMs).
    pub fn set_reg(&mut self, idx: usize, val: u64) {
        self.registers[idx] = val;
    }

    /// Get all registers (cold snapshot).
    pub fn regs(&self) -> &[u64; PVM_REGISTER_COUNT] {
        &self.registers
    }

    /// Set all registers at once (cold path — JitContext sync, interpreter sync).
    pub fn set_regs(&mut self, regs: [u64; PVM_REGISTER_COUNT]) {
        self.registers = regs;
    }

    /// Get gas (cold path).
    pub fn gas(&self) -> u64 {
        self.gas
    }

    /// Set gas (cold path).
    pub fn set_gas(&mut self, gas: u64) {
        self.gas = gas;
    }

    /// Get heap base (for continuation snapshots).
    pub fn heap_base(&self) -> u32 {
        self.heap_base
    }

    /// Set heap base (for warm restart).
    pub fn set_heap_base(&mut self, val: u32) {
        self.heap_base = val;
    }

    /// Get heap top (for continuation snapshots).
    pub fn heap_top(&self) -> u32 {
        self.heap_top
    }

    /// Set heap top (for warm restart).
    pub fn set_heap_top(&mut self, val: u32) {
        self.heap_top = val;
    }

    /// Transition to a new state. Returns error if the transition is invalid.
    pub fn transition(&mut self, new_state: VmState) -> Result<(), VmStateError> {
        use VmState::*;
        let valid = matches!(
            (self.state, new_state),
            (Idle, Running)
                | (Running, Idle) // REPLY
                | (Running, WaitingForReply) // CALL to another VM
                | (Running, Halted) // halt
                | (Running, Faulted) // panic/OOG/page fault
                | (WaitingForReply, Running) // callee replied, caller resumes
                | (Faulted, Running) // RESUME: parent restarts faulted VM
        );
        if !valid {
            return Err(VmStateError {
                from: self.state,
                to: new_state,
            });
        }
        self.state = new_state;
        Ok(())
    }

    /// Whether this VM can be CALLed.
    pub fn can_call(&self) -> bool {
        self.state == VmState::Idle
    }
}

/// Call frame saved on the kernel's call stack when a VM calls another.
#[derive(Debug)]
pub struct CallFrame {
    /// VM that initiated the CALL.
    pub caller_vm_id: u16,
    /// Cap slot in the caller that held the IPC DATA cap (for auto-return on REPLY).
    pub ipc_cap_idx: Option<u8>,
    /// If the IPC DATA cap was mapped, its original mapping state (for auto-remap on REPLY).
    pub ipc_was_mapped: Option<(u32, crate::cap::Access)>,
}

/// Errors from VM state transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid VM state transition: {from:?} -> {to:?}")]
pub struct VmStateError {
    pub from: VmState,
    pub to: VmState,
}

/// Maximum number of CODE caps per invocation.
pub const MAX_CODE_CAPS: usize = 5;

/// Maximum number of concurrent VMs per invocation.
pub const MAX_VMS: usize = u16::MAX as usize;

// ============================================================================
// Generational Arena
// ============================================================================

/// Packed VM ID: low 16 bits = arena index, high 16 bits = generation.
/// Generation prevents use-after-free: a stale HANDLE with the wrong
/// generation is detected on lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmId(u32);

impl VmId {
    pub fn new(index: u16, generation: u16) -> Self {
        Self((generation as u32) << 16 | index as u32)
    }

    pub fn index(self) -> u16 {
        self.0 as u16
    }

    pub fn generation(self) -> u16 {
        (self.0 >> 16) as u16
    }
}

/// Arena entry: optional VM + generation counter.
#[derive(Debug)]
struct ArenaEntry<P: ProtocolCapT> {
    vm: Option<VmInstance<P>>,
    generation: u16,
}

/// Generational arena for VM instances. Supports O(1) create, lookup,
/// and drop with slot reuse. Stale handles detected via generation mismatch.
#[derive(Debug)]
pub struct VmArena<P: ProtocolCapT = u8> {
    entries: Vec<ArenaEntry<P>>,
    free_list: Vec<u16>,
    live_count: u16,
}

impl<P: ProtocolCapT> Default for VmArena<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: ProtocolCapT> VmArena<P> {
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(16),
            free_list: Vec::new(),
            live_count: 0,
        }
    }

    /// Insert a new VM into the arena. Returns its VmId.
    pub fn insert(&mut self, vm: VmInstance<P>) -> Option<VmId> {
        if self.live_count as usize >= MAX_VMS {
            return None;
        }
        self.live_count += 1;

        if let Some(index) = self.free_list.pop() {
            let entry = &mut self.entries[index as usize];
            let id = VmId::new(index, entry.generation);
            entry.vm = Some(vm);
            Some(id)
        } else {
            let index = self.entries.len() as u16;
            let generation = 0u16;
            self.entries.push(ArenaEntry {
                vm: Some(vm),
                generation,
            });
            Some(VmId::new(index, generation))
        }
    }

    /// Look up a VM by ID. Returns None if the slot is empty or generation mismatches.
    pub fn get(&self, id: VmId) -> Option<&VmInstance<P>> {
        let idx = id.index() as usize;
        if idx >= self.entries.len() {
            return None;
        }
        let entry = &self.entries[idx];
        if entry.generation != id.generation() {
            return None; // stale handle
        }
        entry.vm.as_ref()
    }

    /// Mutable lookup by ID.
    pub fn get_mut(&mut self, id: VmId) -> Option<&mut VmInstance<P>> {
        let idx = id.index() as usize;
        if idx >= self.entries.len() {
            return None;
        }
        let entry = &mut self.entries[idx];
        if entry.generation != id.generation() {
            return None;
        }
        entry.vm.as_mut()
    }

    /// Remove a VM from the arena, reclaiming the slot.
    /// Increments generation so stale handles are detected.
    /// Returns the removed VmInstance (for cleanup).
    pub fn remove(&mut self, id: VmId) -> Option<VmInstance<P>> {
        let idx = id.index() as usize;
        if idx >= self.entries.len() {
            return None;
        }
        let entry = &mut self.entries[idx];
        if entry.generation != id.generation() {
            return None;
        }
        let vm = entry.vm.take()?;
        entry.generation = entry.generation.wrapping_add(1);
        self.free_list.push(id.index());
        self.live_count -= 1;
        Some(vm)
    }

    /// Direct access by arena index (no generation check). Panics if slot is empty.
    /// Use for VMs known to be live (active VM, caller on call stack).
    pub fn vm(&self, idx: u16) -> &VmInstance<P> {
        self.entries[idx as usize]
            .vm
            .as_ref()
            .expect("VM slot empty")
    }

    /// Mutable direct access by arena index (no generation check). Panics if slot is empty.
    pub fn vm_mut(&mut self, idx: u16) -> &mut VmInstance<P> {
        self.entries[idx as usize]
            .vm
            .as_mut()
            .expect("VM slot empty")
    }

    /// Get the current generation for a slot. Used for window pool call_count tracking.
    pub fn generation_of(&self, idx: u16) -> u16 {
        self.entries
            .get(idx as usize)
            .map(|e| e.generation)
            .unwrap_or(0)
    }

    /// Number of live VMs.
    pub fn len(&self) -> usize {
        self.live_count as usize
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.live_count == 0
    }
}

// ============================================================================
// Ephemeral Table Arena
// ============================================================================
//
// One ephemeral table per outermost javm invocation, allocated by the kernel
// at invocation entry and freed at invocation exit. Every VM in the call tree
// holds a `Cap::EphemeralTable` at slot 0 of its persistent Frame referring
// to the same arena entry.
//
// Sub-slot conventions (when populated by the host):
//   0     Reply Handle              (per-frame; kernel rewrites on CALL/REPLY)
//   1     Caller cap (badge)        (per-frame; kernel rewrites)
//   2     Self cap                  (per-frame; kernel rewrites)
//   3     Gas cap                   (per-invocation; single shared budget)
//   4..127  reserved kernel-managed
//   128..255 guest cap-args

/// Packed ephemeral-table ID: low 16 bits = arena index, high 16 bits = generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EphemeralTableId(u32);

impl EphemeralTableId {
    pub fn new(index: u16, generation: u16) -> Self {
        Self((generation as u32) << 16 | index as u32)
    }
    pub fn index(self) -> u16 {
        self.0 as u16
    }
    pub fn generation(self) -> u16 {
        (self.0 >> 16) as u16
    }
}

#[derive(Debug)]
struct EphemeralTableEntry<P: ProtocolCapT> {
    table: Option<CapTable<P>>,
    generation: u16,
}

/// Generational arena of ephemeral tables. Today the kernel allocates one
/// per invocation, but the arena is sized for future expansion.
#[derive(Debug)]
pub struct EphemeralTableArena<P: ProtocolCapT = u8> {
    entries: Vec<EphemeralTableEntry<P>>,
    free_list: Vec<u16>,
    live_count: u16,
}

impl<P: ProtocolCapT> Default for EphemeralTableArena<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: ProtocolCapT> EphemeralTableArena<P> {
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(2),
            free_list: Vec::new(),
            live_count: 0,
        }
    }

    pub fn insert(&mut self, table: CapTable<P>) -> EphemeralTableId {
        self.live_count += 1;
        if let Some(index) = self.free_list.pop() {
            let entry = &mut self.entries[index as usize];
            let id = EphemeralTableId::new(index, entry.generation);
            entry.table = Some(table);
            id
        } else {
            let index = self.entries.len() as u16;
            self.entries.push(EphemeralTableEntry {
                table: Some(table),
                generation: 0,
            });
            EphemeralTableId::new(index, 0)
        }
    }

    pub fn get(&self, id: EphemeralTableId) -> Option<&CapTable<P>> {
        let idx = id.index() as usize;
        let entry = self.entries.get(idx)?;
        if entry.generation != id.generation() {
            return None;
        }
        entry.table.as_ref()
    }

    pub fn get_mut(&mut self, id: EphemeralTableId) -> Option<&mut CapTable<P>> {
        let idx = id.index() as usize;
        let entry = self.entries.get_mut(idx)?;
        if entry.generation != id.generation() {
            return None;
        }
        entry.table.as_mut()
    }

    pub fn remove(&mut self, id: EphemeralTableId) -> Option<CapTable<P>> {
        let idx = id.index() as usize;
        let entry = self.entries.get_mut(idx)?;
        if entry.generation != id.generation() {
            return None;
        }
        let table = entry.table.take()?;
        entry.generation = entry.generation.wrapping_add(1);
        self.free_list.push(id.index());
        self.live_count -= 1;
        Some(table)
    }

    pub fn len(&self) -> usize {
        self.live_count as usize
    }

    pub fn is_empty(&self) -> bool {
        self.live_count == 0
    }
}

// ============================================================================
// Window Pool — N pre-allocated 4GB windows with LRU eviction
// ============================================================================

/// Number of pre-allocated 4GB virtual windows.
pub const WINDOW_POOL_SIZE: usize = 5;

/// Window pool: N pre-allocated 4GB virtual windows with LRU eviction.
///
/// Each running VM needs a window for memory-mapped execution. Windows are
/// assigned on CALL/RESUME and evicted (LRU by call_count) when all windows
/// are occupied. The compiled native code is relocatable (R15-relative), so
/// the same compiled code works with any window.
#[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
pub struct WindowPool {
    /// Pre-allocated 4GB windows.
    windows: Vec<crate::backing::CodeWindow>,
    /// Which VM owns each window (None = free).
    owner: [Option<u16>; WINDOW_POOL_SIZE],
    /// Per-VM-slot: (generation at last use, cumulative call count).
    /// Resets when the arena slot's generation changes.
    call_counts: Vec<(u16, u32)>,
}

#[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
impl WindowPool {
    /// Create a new pool with N pre-allocated windows.
    pub fn new(n: usize) -> Option<Self> {
        let mut windows = Vec::with_capacity(n);
        for _ in 0..n {
            windows.push(crate::backing::CodeWindow::new(0)?);
        }
        Some(Self {
            windows,
            owner: [None; WINDOW_POOL_SIZE],
            call_counts: Vec::new(),
        })
    }

    /// Ensure call_counts covers at least `vm_count` slots.
    pub fn ensure_capacity(&mut self, vm_count: usize) {
        if self.call_counts.len() < vm_count {
            self.call_counts.resize(vm_count, (0, 0));
        }
    }

    /// Find the window index assigned to a VM, if any.
    pub fn find_window(&self, vm_idx: u16) -> Option<usize> {
        self.owner.iter().position(|o| *o == Some(vm_idx))
    }

    /// Assign a window to a VM. Returns assignment result with window index
    /// and optional evicted VM (whose DATA caps need unmapping by the kernel).
    ///
    /// Bumps call_count. If the VM already owns a window, returns it (free).
    /// Otherwise assigns a free window or evicts the lowest call_count owner.
    pub fn assign_window(&mut self, vm_idx: u16, vm_generation: u16) -> WindowAssignment {
        self.ensure_capacity(vm_idx as usize + 1);

        // Reset call_count if generation changed (slot was reused)
        let entry = &mut self.call_counts[vm_idx as usize];
        if entry.0 != vm_generation {
            entry.0 = vm_generation;
            entry.1 = 0;
        }
        entry.1 = entry.1.saturating_add(1);

        // Already owns a window? Return it (no eviction, no mapping needed).
        if let Some(idx) = self.find_window(vm_idx) {
            return WindowAssignment {
                window_idx: idx,
                evicted: None,
                needs_map: false,
            };
        }

        // Find a free window.
        if let Some(idx) = self.owner.iter().position(|o| o.is_none()) {
            self.owner[idx] = Some(vm_idx);
            return WindowAssignment {
                window_idx: idx,
                evicted: None,
                needs_map: true,
            };
        }

        // Evict: pick the window whose owner has the lowest call_count.
        let victim_idx = self
            .owner
            .iter()
            .enumerate()
            .filter_map(|(i, o)| {
                let owner_vm = (*o)?;
                let (_, count) = self.call_counts.get(owner_vm as usize)?;
                Some((i, *count))
            })
            .min_by_key(|(_, count)| *count)
            .map(|(i, _)| i)
            .expect("all windows occupied but no owner found");

        let evicted = self.owner[victim_idx];
        self.owner[victim_idx] = Some(vm_idx);
        WindowAssignment {
            window_idx: victim_idx,
            evicted,
            needs_map: true,
        }
    }

    /// Release a VM's window (e.g., on DROP HANDLE).
    pub fn release(&mut self, vm_idx: u16) {
        if let Some(idx) = self.find_window(vm_idx) {
            self.owner[idx] = None;
        }
    }

    /// Get the window at a given index.
    pub fn window(&self, idx: usize) -> &crate::backing::CodeWindow {
        &self.windows[idx]
    }

    /// Get the owner of a window (for fast-path check in ensure_active_window).
    #[inline(always)]
    pub fn window_owner(&self, idx: usize) -> Option<u16> {
        self.owner[idx]
    }
}

/// Result of a window assignment operation.
#[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
pub struct WindowAssignment {
    /// Index into the window pool.
    pub window_idx: usize,
    /// VM that was evicted from this window (needs DATA cap unmapping).
    pub evicted: Option<u16>,
    /// Whether the new VM's DATA caps need mapping into the window.
    pub needs_map: bool,
}

#[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
impl core::fmt::Debug for WindowPool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WindowPool")
            .field("owner", &self.owner)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_state_transitions() {
        let mut vm: VmInstance = VmInstance::new(0, 0, CapTable::new(), 1_000_000);
        assert_eq!(vm.state, VmState::Idle);
        assert!(vm.can_call());

        // Idle -> Running
        assert!(vm.transition(VmState::Running).is_ok());
        assert!(!vm.can_call());

        // Running -> WaitingForReply
        assert!(vm.transition(VmState::WaitingForReply).is_ok());
        assert!(!vm.can_call());

        // WaitingForReply -> Running (callee replied)
        assert!(vm.transition(VmState::Running).is_ok());

        // Running -> Idle (REPLY)
        assert!(vm.transition(VmState::Idle).is_ok());
        assert!(vm.can_call());
    }

    #[test]
    fn test_invalid_transitions() {
        let mut vm: VmInstance = VmInstance::new(0, 0, CapTable::new(), 1_000_000);

        // Idle -> WaitingForReply (invalid — must go through Running)
        assert!(vm.transition(VmState::WaitingForReply).is_err());

        // Idle -> Halted (invalid)
        assert!(vm.transition(VmState::Halted).is_err());

        vm.transition(VmState::Running).unwrap();
        vm.transition(VmState::Halted).unwrap();

        // Halted -> anything (terminal)
        assert!(vm.transition(VmState::Idle).is_err());
        assert!(vm.transition(VmState::Running).is_err());
    }

    #[test]
    fn test_vm_initial_registers() {
        let vm: VmInstance = VmInstance::new(0, 5, CapTable::new(), 1_000_000);
        assert_eq!(vm.registers[0], 0); // no halt address, all regs start at 0
        for i in 1..13 {
            assert_eq!(vm.registers[i], 0);
        }
        assert_eq!(vm.entry_index, 5);
    }

    #[test]
    fn test_faulted_is_terminal() {
        let mut vm: VmInstance = VmInstance::new(0, 0, CapTable::new(), 1_000_000);
        vm.transition(VmState::Running).unwrap();
        vm.transition(VmState::Faulted).unwrap();
        assert!(!vm.can_call());
        assert!(vm.transition(VmState::Idle).is_err());
    }

    #[test]
    fn test_vm_id_pack_unpack() {
        let id = VmId::new(42, 7);
        assert_eq!(id.index(), 42);
        assert_eq!(id.generation(), 7);

        let id2 = VmId::new(0, 0);
        assert_eq!(id2.index(), 0);
        assert_eq!(id2.generation(), 0);

        let id3 = VmId::new(u16::MAX, u16::MAX);
        assert_eq!(id3.index(), u16::MAX);
        assert_eq!(id3.generation(), u16::MAX);
    }

    #[test]
    fn test_arena_insert_get() {
        let mut arena: VmArena = VmArena::new();
        let vm: VmInstance = VmInstance::new(0, 0, CapTable::new(), 1000);
        let id = arena.insert(vm).unwrap();
        assert_eq!(arena.len(), 1);

        let vm_ref = arena.get(id).unwrap();
        assert_eq!(vm_ref.gas(), 1000);
    }

    #[test]
    fn test_arena_remove_reuse() {
        let mut arena: VmArena = VmArena::new();

        let id1 = arena
            .insert(VmInstance::new(0, 0, CapTable::new(), 100))
            .unwrap();
        assert_eq!(id1.index(), 0);
        assert_eq!(id1.generation(), 0);

        // Remove
        let removed = arena.remove(id1).unwrap();
        assert_eq!(removed.gas(), 100);
        assert_eq!(arena.len(), 0);

        // Stale lookup fails
        assert!(arena.get(id1).is_none());

        // Reuse slot — same index, new generation
        let id2 = arena
            .insert(VmInstance::new(0, 0, CapTable::new(), 200))
            .unwrap();
        assert_eq!(id2.index(), 0); // same slot
        assert_eq!(id2.generation(), 1); // incremented

        // Old id still fails
        assert!(arena.get(id1).is_none());
        // New id works
        assert_eq!(arena.get(id2).unwrap().gas(), 200);
    }

    #[test]
    fn test_arena_stale_handle() {
        let mut arena: VmArena = VmArena::new();

        let id = arena
            .insert(VmInstance::new(0, 0, CapTable::new(), 100))
            .unwrap();
        arena.remove(id).unwrap();

        // Insert new VM in same slot
        let _id2 = arena
            .insert(VmInstance::new(0, 0, CapTable::new(), 200))
            .unwrap();

        // Old id has wrong generation → None
        assert!(arena.get(id).is_none());
        assert!(arena.get_mut(id).is_none());
        assert!(arena.remove(id).is_none());
    }

    #[test]
    fn test_arena_multiple_slots() {
        let mut arena: VmArena = VmArena::new();
        let mut ids = Vec::new();

        for i in 0..10 {
            let id = arena
                .insert(VmInstance::new(0, 0, CapTable::new(), i as u64))
                .unwrap();
            ids.push(id);
        }
        assert_eq!(arena.len(), 10);

        // Remove odd slots
        for i in (1..10).step_by(2) {
            arena.remove(ids[i]).unwrap();
        }
        assert_eq!(arena.len(), 5);

        // Reuse should fill freed slots
        for _ in 0..5 {
            arena
                .insert(VmInstance::new(0, 0, CapTable::new(), 999))
                .unwrap();
        }
        assert_eq!(arena.len(), 10);
    }
}
