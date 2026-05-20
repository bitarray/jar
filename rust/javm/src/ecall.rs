//! Ecall dispatch.
//!
//! The `Vm` impls `javm_exec::EcallHandler`. The interpreter / JIT
//! invokes `handle` for every PVM `ecall` (opcode 3, no immediate)
//! and `ecalli imm` (opcode 10, u32 immediate). The handler decodes
//! the operation from the immediate and routes to the appropriate
//! sub-dispatcher.
//!
//! ## ecalli opcode encoding (Stage 3 baseline)
//!
//! The `imm` value of an `ecalli` instruction is partitioned by range:
//!
//! ```text
//!   0          REPLY (kernel-shorthand for "return to caller")
//!                — driven by run_instance / Interpreter::Halt translation.
//!   1..=15     MGMT operations (this module).
//!   16..=63    Kernel-known host calls (this module; sub-stages 3.8 ↑).
//!   64..       Chain-user host calls (out of scope; reserved).
//! ```
//!
//! MGMT operand encoding (register-based, simple flat addressing —
//! single-step root-cnode slot indices):
//!
//! ```text
//!   Common: φ[7] = src_slot_idx (u8 in low byte)
//!           φ[8] = dst_slot_idx (u8 in low byte)
//!   MGMT_COPY        (op=1)   src→dst
//!   MGMT_MOVE        (op=2)   src→dst
//!   MGMT_DROP        (op=3)   src
//!   MGMT_CNODE_SWAP  (op=4)   a=φ[7], b=φ[8]
//!   MGMT_CNODE_MINT  (op=5)   dst=φ[7], size_log=φ[8] (u8)
//! ```
//!
//! Host call operand encoding (Stage 3.8+):
//!
//! ```text
//!   HOST_YIELD       (op=16)  φ[7] = marker_slot_idx (u8)
//! ```
//!
//! After the move to the `javm_cap::Cap<A>` cache model, ecalls
//! operate on `CapHashOrRef` targets in the running root cnode and
//! cross-reference into the caller-supplied `Cache<Global>` for
//! kind dispatch. The `Cache<Global>` is NOT borrowed for the
//! duration of `Interpreter::run` — the ecall handler keeps the
//! call-stack mutation local; host calls that need cache writes
//! (host_open / host_save / host_mint_data_cap) are deferred to
//! Stage 4 once the borrow model crystallizes.

use javm_cap::{Blake2b256, CapHashOrRef, Hash, SlotIdx};
use javm_exec::{EcallHandler, EcallKind, EcallResult, ExitReason, Memory, Regs};

use crate::callstack::Entry;
use crate::error::VmError;
use crate::kernel_assist::KernelAssist;
use crate::vm::Vm;

/// MGMT opcode space (in the `ecalli` immediate).
pub mod mgmt_op {
    pub const COPY: u32 = 1;
    pub const MOVE: u32 = 2;
    pub const DROP: u32 = 3;
    pub const CNODE_SWAP: u32 = 4;
    pub const CNODE_MINT: u32 = 5;
    /// Inclusive upper bound of the MGMT range.
    pub const MAX: u32 = 15;
}

/// Kernel-known host call opcode space (in the `ecalli` immediate),
/// 16..=63. Stage 3.8 lands `HOST_YIELD`; subsequent sub-stages fill
/// the rest.
pub mod host_op {
    pub const HOST_YIELD: u32 = 16;
    /// `set_image(image_slot=φ[7])` — extend the active Instance's
    /// `image_hash_chain` with the Image at `image_slot`.
    pub const SET_IMAGE: u32 = 17;
    /// `host_derive_spawn(image_slot=φ[7], dst_slot=φ[8])`.
    pub const DERIVE_SPAWN: u32 = 18;
    /// `host_make_image(...)` — Stage 3.9 stub.
    pub const MAKE_IMAGE: u32 = 19;
    /// `host_same_type(slot_a=φ[7], slot_b=φ[8])`.
    pub const HOST_SAME_TYPE: u32 = 20;
    /// `host_type_of(src_slot=φ[7], dst_slot=φ[8])` — Stage 4 (needs
    /// cache write).
    pub const HOST_TYPE_OF: u32 = 21;
    /// `host_read_data_cap` — Stage 4 (needs cache read into mem).
    pub const HOST_READ_DATA_CAP: u32 = 22;
    /// `host_mint_data_cap` — Stage 4 (needs cache write).
    pub const HOST_MINT_DATA_CAP: u32 = 23;
    /// `host_open` — Stage 4 (needs cache read + slot write).
    pub const HOST_OPEN: u32 = 24;
    /// `host_save` — Stage 4 (needs cache write + slot write).
    pub const HOST_SAVE: u32 = 25;
    /// Inclusive upper bound of the kernel-known host call range.
    pub const MAX: u32 = 63;
}

impl<K: KernelAssist> EcallHandler for Vm<K> {
    fn handle(&mut self, kind: EcallKind, regs: &mut Regs, mem: &mut dyn Memory) -> EcallResult {
        match kind {
            EcallKind::Ecalli(op) => self.dispatch_ecalli(op, regs, mem),
            EcallKind::Ecall => self.dispatch_ecall(regs, mem),
        }
    }
}

impl<K: KernelAssist> Vm<K> {
    fn dispatch_ecalli(&mut self, op: u32, _regs: &mut Regs, _mem: &mut dyn Memory) -> EcallResult {
        match op {
            0 => {
                // REPLY is handled by the CALL/HALT driver.
                EcallResult::Exit(ExitReason::Halt)
            }
            o if o <= mgmt_op::MAX => match self.dispatch_mgmt(o, _regs) {
                Ok(()) => EcallResult::Continue,
                Err(_) => EcallResult::Exit(ExitReason::Trap),
            },
            o if o <= host_op::MAX => self.dispatch_host_call(o, _regs, _mem),
            _ => {
                // Chain-user host calls (64+) land later. Continue
                // silently for now so prologue-like ecalls (used by
                // javm-transpiler's blob format) don't fault.
                EcallResult::Continue
            }
        }
    }

    /// Dispatch a kernel-known host call (op-codes 16..=63).
    fn dispatch_host_call(
        &mut self,
        op: u32,
        regs: &mut Regs,
        _mem: &mut dyn Memory,
    ) -> EcallResult {
        fn trap_on_err<T>(r: Result<T, VmError>, ok: impl FnOnce(T) -> EcallResult) -> EcallResult {
            match r {
                Ok(v) => ok(v),
                Err(_) => EcallResult::Exit(ExitReason::Trap),
            }
        }
        match op {
            host_op::HOST_YIELD => trap_on_err(self.dispatch_host_yield(regs), |r| r),
            host_op::SET_IMAGE => {
                trap_on_err(self.dispatch_set_image(regs), |()| EcallResult::Continue)
            }
            host_op::DERIVE_SPAWN => {
                trap_on_err(self.dispatch_derive_spawn(regs), |()| EcallResult::Continue)
            }
            host_op::MAKE_IMAGE => {
                // Stage 3.9 stub.
                EcallResult::Exit(ExitReason::Trap)
            }
            host_op::HOST_SAME_TYPE => trap_on_err(self.dispatch_host_same_type(regs), |()| {
                EcallResult::Continue
            }),
            host_op::HOST_TYPE_OF
            | host_op::HOST_READ_DATA_CAP
            | host_op::HOST_MINT_DATA_CAP
            | host_op::HOST_OPEN
            | host_op::HOST_SAVE => {
                // These host calls all require cache writes, which the
                // interpreter-borrow shape doesn't allow until Stage 4
                // wires a deferred-effect channel. For now, trap.
                EcallResult::Exit(ExitReason::Trap)
            }
            _ => {
                // Chain-user host calls (64+) land later. Continue
                // silently for now.
                EcallResult::Continue
            }
        }
    }

    /// `host_yield(marker_slot=φ[7])`.
    fn dispatch_host_yield(&mut self, regs: &mut Regs) -> Result<EcallResult, VmError> {
        let marker_slot = SlotIdx((regs.gpr[7] & 0xFF) as u32);

        // 1. Read marker's hash from the running Instance's cnode.
        //    In the new model the slot stores a `CapHashOrRef`; we
        //    key yield routing on the Hash form (the marker template
        //    image_hash). Ref-form markers are not catchable in V1.
        let marker_hash = {
            let running = self
                .stack
                .running_instance()
                .ok_or(VmError::CallStackEmpty)?;
            match running.root_cnode.get(marker_slot) {
                Some(CapHashOrRef::Hash(h)) => h,
                Some(CapHashOrRef::Ref(_)) => {
                    return Err(VmError::SlotKindMismatch(marker_slot.get()));
                }
                None => return Err(VmError::SlotEmpty(marker_slot.get())),
            }
        };

        // 2. Walk the stack top→bottom (skip the top — that's the
        //    yielder). Find first InstanceEntry whose declared
        //    yield_marker_slot holds a YieldCatcher catching this
        //    marker.
        let stack_len = self.stack.entries().len();
        let mut target_pos: Option<usize> = None;
        for pos in (0..stack_len.saturating_sub(1)).rev() {
            let ie = match &self.stack.entries()[pos] {
                Entry::Instance(ie) => ie.as_ref(),
                Entry::Reference(_) => continue,
            };
            let Some(catcher_slot) = ie.yield_marker_slot else {
                continue;
            };
            let catcher_hash = match ie.root_cnode.get(catcher_slot) {
                Some(CapHashOrRef::Hash(h)) => h,
                _ => continue,
            };
            let markers = self.kernel_assist.yield_catcher_markers(catcher_hash);
            if markers.contains(&marker_hash) {
                target_pos = Some(pos);
                break;
            }
        }

        let pos = target_pos.ok_or(VmError::UnhandledMarker)?;

        // 3. Push the ReferenceEntry. The yielder transitions to
        //    Waiting; the new reference becomes Running.
        self.stack.push_reference(pos)?;

        Ok(EcallResult::Exit(ExitReason::HostCall(host_op::HOST_YIELD)))
    }

    /// `set_image(image_slot=φ[7])`.
    ///
    /// Reads the Cap::Image hash at the named slot; chain_extends the
    /// running instance's `image_hash_chain` with the slot's hash.
    /// The new model resolves Image bytes from the cache rather than
    /// the kernel-assist registry — but since the cache isn't
    /// reachable from inside `Interpreter::run` in V1, set_image
    /// updates only the chain hash; bytecode swap is deferred.
    fn dispatch_set_image(&mut self, regs: &mut Regs) -> Result<(), VmError> {
        let image_slot = SlotIdx((regs.gpr[7] & 0xFF) as u32);

        // 1. Resolve the Cap::Image hash from the slot.
        let new_image_hash = {
            let running = self
                .stack
                .running_instance()
                .ok_or(VmError::CallStackEmpty)?;
            match running.root_cnode.get(image_slot) {
                Some(CapHashOrRef::Hash(h)) => h,
                Some(CapHashOrRef::Ref(_)) => {
                    return Err(VmError::SlotKindMismatch(image_slot.get()));
                }
                None => return Err(VmError::SlotEmpty(image_slot.get())),
            }
        };

        // 2. Extend the chain hash.
        let extended_chain = {
            let running = self
                .stack
                .running_instance()
                .ok_or(VmError::CallStackEmpty)?;
            Blake2b256::hash_pair(&running.image_hash_chain, &new_image_hash)
        };

        // 3. Install the chain extension. Bytecode swap deferred —
        //    Stage 4 wires the cache borrow.
        let running = self
            .stack
            .running_instance_mut()
            .ok_or(VmError::CallStackEmpty)?;
        running.image_hash_chain = extended_chain;
        running.image_hash = new_image_hash;
        Ok(())
    }

    /// `host_derive_spawn(image_slot=φ[7], dst_slot=φ[8])`.
    ///
    /// Mint a fresh `CapHashOrRef::Hash` carrying
    /// `chain_extend(self.image_hash_chain, image_hash)`. The cap
    /// content (a full Cap::Instance referencing the image with
    /// placeholder regs/pc/etc.) lives in the cache in Stage 4; V1
    /// stores only the chain hash as the slot target.
    fn dispatch_derive_spawn(&mut self, regs: &mut Regs) -> Result<(), VmError> {
        let image_slot = SlotIdx((regs.gpr[7] & 0xFF) as u32);
        let dst_slot = SlotIdx((regs.gpr[8] & 0xFF) as u32);

        // 1. Read Image hash at image_slot.
        let new_image_hash = {
            let running = self
                .stack
                .running_instance()
                .ok_or(VmError::CallStackEmpty)?;
            match running.root_cnode.get(image_slot) {
                Some(CapHashOrRef::Hash(h)) => h,
                Some(CapHashOrRef::Ref(_)) => {
                    return Err(VmError::SlotKindMismatch(image_slot.get()));
                }
                None => return Err(VmError::SlotEmpty(image_slot.get())),
            }
        };

        // 2. Derive the child chain hash.
        let extended = {
            let running = self
                .stack
                .running_instance()
                .ok_or(VmError::CallStackEmpty)?;
            Blake2b256::hash_pair(&running.image_hash_chain, &new_image_hash)
        };

        // 3. Place at dst_slot (rejects pinned).
        let running = self
            .stack
            .running_instance_mut()
            .ok_or(VmError::CallStackEmpty)?;
        if running.pinned_slots.binary_search(&dst_slot).is_ok() {
            return Err(javm_cap::OpError::SlotPinned(dst_slot.get()).into());
        }
        running
            .root_cnode
            .set(dst_slot, Some(CapHashOrRef::Hash(extended)))?;
        Ok(())
    }

    /// `host_same_type(slot_a=φ[7], slot_b=φ[8])`.
    ///
    /// Compares the slot targets' Hash bytes (which encode
    /// image_hash_chain identity in V1). Result 1 if same, 0
    /// otherwise, into φ[7].
    fn dispatch_host_same_type(&mut self, regs: &mut Regs) -> Result<(), VmError> {
        let a = SlotIdx((regs.gpr[7] & 0xFF) as u32);
        let b = SlotIdx((regs.gpr[8] & 0xFF) as u32);
        let running = self
            .stack
            .running_instance()
            .ok_or(VmError::CallStackEmpty)?;
        let ha = match running.root_cnode.get(a) {
            Some(CapHashOrRef::Hash(h)) => h,
            _ => return Err(VmError::SlotEmpty(a.get())),
        };
        let hb = match running.root_cnode.get(b) {
            Some(CapHashOrRef::Hash(h)) => h,
            _ => return Err(VmError::SlotEmpty(b.get())),
        };
        regs.gpr[7] = if ha == hb { 1 } else { 0 };
        Ok(())
    }
}

/// Canonical-form length: number of leading bytes before trailing
/// zeros. Used by host_mint_data_cap once that host call lands
/// (Stage 4 wires the cache borrow).
#[allow(dead_code)]
pub(crate) fn strip_trailing_zeros_len(bytes: &[u8]) -> usize {
    let mut n = bytes.len();
    while n > 0 && bytes[n - 1] == 0 {
        n -= 1;
    }
    n
}

impl<K: KernelAssist> Vm<K> {
    /// Plain `ecall` (opcode 3, no immediate). Spec §4 reads φ[11]
    /// (mgmt_op) and φ[12] (subject|object) for the management
    /// dispatch. Stage 3 routes the same way as `ecalli imm`, treating
    /// φ[11] as the op.
    fn dispatch_ecall(&mut self, regs: &mut Regs, mem: &mut dyn Memory) -> EcallResult {
        let op = regs.gpr[11] as u32;
        self.dispatch_ecalli(op, regs, mem)
    }

    fn dispatch_mgmt(&mut self, op: u32, regs: &mut Regs) -> Result<(), VmError> {
        let a = SlotIdx((regs.gpr[7] & 0xFF) as u32);
        let b = SlotIdx((regs.gpr[8] & 0xFF) as u32);
        match op {
            mgmt_op::COPY => self.mgmt_copy(a, b),
            mgmt_op::MOVE => self.mgmt_move(a, b),
            mgmt_op::DROP => self.mgmt_drop(a),
            mgmt_op::CNODE_SWAP => self.mgmt_cnode_swap(a, b),
            mgmt_op::CNODE_MINT => {
                let size_log = (regs.gpr[8] & 0xFF) as u8;
                self.mgmt_cnode_mint(a, size_log)
            }
            _ => Err(VmError::Invariant("unknown MGMT op")),
        }
    }

    fn mgmt_copy(&mut self, a: SlotIdx, b: SlotIdx) -> Result<(), VmError> {
        let running = self
            .stack
            .running_instance_mut()
            .ok_or(VmError::CallStackEmpty)?;
        if running.pinned_slots.binary_search(&b).is_ok() {
            return Err(javm_cap::OpError::SlotPinned(b.get()).into());
        }
        let src = running
            .root_cnode
            .get(a)
            .ok_or(javm_cap::OpError::SourceEmpty)?;
        running.root_cnode.set(b, Some(src))?;
        Ok(())
    }

    fn mgmt_move(&mut self, a: SlotIdx, b: SlotIdx) -> Result<(), VmError> {
        let running = self
            .stack
            .running_instance_mut()
            .ok_or(VmError::CallStackEmpty)?;
        if running.pinned_slots.binary_search(&a).is_ok() {
            return Err(javm_cap::OpError::SlotPinned(a.get()).into());
        }
        if running.pinned_slots.binary_search(&b).is_ok() {
            return Err(javm_cap::OpError::SlotPinned(b.get()).into());
        }
        let src = running
            .root_cnode
            .take(a)?
            .ok_or(javm_cap::OpError::SourceEmpty)?;
        running.root_cnode.set(b, Some(src))?;
        Ok(())
    }

    fn mgmt_drop(&mut self, a: SlotIdx) -> Result<(), VmError> {
        let running = self
            .stack
            .running_instance_mut()
            .ok_or(VmError::CallStackEmpty)?;
        if running.pinned_slots.binary_search(&a).is_ok() {
            return Err(javm_cap::OpError::SlotPinned(a.get()).into());
        }
        running.root_cnode.take(a)?;
        Ok(())
    }

    fn mgmt_cnode_swap(&mut self, a: SlotIdx, b: SlotIdx) -> Result<(), VmError> {
        let running = self
            .stack
            .running_instance_mut()
            .ok_or(VmError::CallStackEmpty)?;
        if running.pinned_slots.binary_search(&a).is_ok() {
            return Err(javm_cap::OpError::SlotPinned(a.get()).into());
        }
        if running.pinned_slots.binary_search(&b).is_ok() {
            return Err(javm_cap::OpError::SlotPinned(b.get()).into());
        }
        let av = running.root_cnode.take(a)?;
        let bv = running.root_cnode.take(b)?;
        if let Some(t) = bv {
            running.root_cnode.set(a, Some(t))?;
        }
        if let Some(t) = av {
            running.root_cnode.set(b, Some(t))?;
        }
        Ok(())
    }

    fn mgmt_cnode_mint(&mut self, dst: SlotIdx, size_log: u8) -> Result<(), VmError> {
        // Create a fresh empty CNodeCap, hash it via `cap_hash`, and
        // store the hash at `dst`. The cnode content itself isn't
        // published to the cache here (V1: deferred-effect channel
        // not yet wired). The hash is stable for an empty cnode of
        // the given size so callers can address the slot
        // consistently across invocations.
        use javm_cap::Cap;
        let cn = javm_cap::CNodeCap::<allocator_api2::alloc::Global>::new(size_log)?;
        let h = javm_cap::cap_hash(&Cap::CNode(cn));
        let running = self
            .stack
            .running_instance_mut()
            .ok_or(VmError::CallStackEmpty)?;
        if running.pinned_slots.binary_search(&dst).is_ok() {
            return Err(javm_cap::OpError::SlotPinned(dst.get()).into());
        }
        running.root_cnode.set(dst, Some(CapHashOrRef::Hash(h)))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callstack::{EntryStatus, InstanceEntry};
    use crate::kernel_assist::InProcessKernelAssist;
    use allocator_api2::alloc::Global;
    use javm_cap::CNodeCap;
    use javm_exec::{GasCounter, Mem, PvmProgram, Regs};
    use std::sync::Arc;

    fn fixture_vm() -> Vm<InProcessKernelAssist> {
        let mut vm = Vm::new(InProcessKernelAssist::new());
        let mut cnode = CNodeCap::<Global>::new(4).unwrap();
        // Seed slot 2 with a Hash-form target (treated as an Image hash).
        cnode
            .set(SlotIdx(2), Some(CapHashOrRef::Hash([0xAA; 32])))
            .unwrap();
        let prog = Arc::new(PvmProgram::new(vec![0u8], vec![1u8], vec![], 25).unwrap());
        let entry = InstanceEntry {
            instance_ref: CapHashOrRef::Hash([1u8; 32]),
            image_hash_chain: [1u8; 32],
            image_hash: [2u8; 32],
            program: prog,
            root_cnode: cnode,
            yield_marker_slot: None,
            pinned_slots: Vec::new(),
            regs: Regs::new(),
            mem: Mem::new(),
            gas: GasCounter::new(1000),
            status: EntryStatus::Waiting,
        };
        vm.stack.push_instance(entry).unwrap();
        vm
    }

    #[test]
    fn mgmt_copy_dispatch_via_ecalli() {
        let mut vm = fixture_vm();
        let mut regs = Regs::new();
        regs.gpr[7] = 2; // src
        regs.gpr[8] = 7; // dst
        let mut mem = Mem::new();
        let r = vm.handle(EcallKind::Ecalli(mgmt_op::COPY), &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Continue));
        let cnode = &vm.stack.running_instance().unwrap().root_cnode;
        assert!(cnode.get(SlotIdx(2)).is_some());
        assert!(cnode.get(SlotIdx(7)).is_some());
    }

    #[test]
    fn mgmt_move_dispatch_via_ecalli() {
        let mut vm = fixture_vm();
        let mut regs = Regs::new();
        regs.gpr[7] = 2;
        regs.gpr[8] = 9;
        let mut mem = Mem::new();
        let r = vm.handle(EcallKind::Ecalli(mgmt_op::MOVE), &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Continue));
        let cnode = &vm.stack.running_instance().unwrap().root_cnode;
        assert!(cnode.get(SlotIdx(2)).is_none()); // source moved out
        assert!(cnode.get(SlotIdx(9)).is_some()); // dst now holds it
    }

    #[test]
    fn mgmt_drop_dispatch_via_ecalli() {
        let mut vm = fixture_vm();
        let mut regs = Regs::new();
        regs.gpr[7] = 2;
        let mut mem = Mem::new();
        let r = vm.handle(EcallKind::Ecalli(mgmt_op::DROP), &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Continue));
        let cnode = &vm.stack.running_instance().unwrap().root_cnode;
        assert!(cnode.get(SlotIdx(2)).is_none());
    }

    #[test]
    fn mgmt_cnode_mint_places_hash_at_dst() {
        let mut vm = fixture_vm();
        let mut regs = Regs::new();
        regs.gpr[7] = 5; // dst
        regs.gpr[8] = 3; // size_log = 8 slots
        let mut mem = Mem::new();
        let r = vm.handle(EcallKind::Ecalli(mgmt_op::CNODE_MINT), &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Continue));
        let cnode = &vm.stack.running_instance().unwrap().root_cnode;
        assert!(matches!(cnode.get(SlotIdx(5)), Some(CapHashOrRef::Hash(_))));
    }

    #[test]
    fn mgmt_cnode_swap_swaps_slots() {
        let mut vm = fixture_vm();
        vm.stack
            .running_instance_mut()
            .unwrap()
            .root_cnode
            .set(SlotIdx(3), Some(CapHashOrRef::Hash([0xBB; 32])))
            .unwrap();
        let mut regs = Regs::new();
        regs.gpr[7] = 2;
        regs.gpr[8] = 3;
        let mut mem = Mem::new();
        let r = vm.handle(EcallKind::Ecalli(mgmt_op::CNODE_SWAP), &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Continue));
        let cnode = &vm.stack.running_instance().unwrap().root_cnode;
        let s2 = cnode.get(SlotIdx(2)).unwrap();
        let s3 = cnode.get(SlotIdx(3)).unwrap();
        assert_eq!(s2, CapHashOrRef::Hash([0xBB; 32]));
        assert_eq!(s3, CapHashOrRef::Hash([0xAA; 32]));
    }

    #[test]
    fn mgmt_op_on_empty_stack_traps() {
        let mut vm: Vm<InProcessKernelAssist> = Vm::new(InProcessKernelAssist::new());
        let mut regs = Regs::new();
        let mut mem = Mem::new();
        let r = vm.handle(EcallKind::Ecalli(mgmt_op::DROP), &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Exit(ExitReason::Trap)));
    }

    #[test]
    fn ecalli_reply_zero_exits_halt() {
        let mut vm = fixture_vm();
        let mut regs = Regs::new();
        let mut mem = Mem::new();
        let r = vm.handle(EcallKind::Ecalli(0), &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Exit(ExitReason::Halt)));
    }

    #[test]
    fn plain_ecall_reads_op_from_phi11() {
        let mut vm = fixture_vm();
        let mut regs = Regs::new();
        regs.gpr[11] = mgmt_op::DROP as u64;
        regs.gpr[7] = 2;
        let mut mem = Mem::new();
        let r = vm.handle(EcallKind::Ecall, &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Continue));
        assert!(
            vm.stack
                .running_instance()
                .unwrap()
                .root_cnode
                .get(SlotIdx(2))
                .is_none()
        );
    }

    #[test]
    fn unknown_op_continues_silently() {
        let mut vm = fixture_vm();
        let mut regs = Regs::new();
        let mut mem = Mem::new();
        let r = vm.handle(EcallKind::Ecalli(999), &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Continue));
    }

    #[test]
    fn set_image_extends_chain_hash() {
        let mut vm = fixture_vm();
        let original_chain = vm.stack.running_instance().unwrap().image_hash_chain;
        let mut regs = Regs::new();
        regs.gpr[7] = 2;
        let mut mem = Mem::new();
        let r = vm.handle(EcallKind::Ecalli(host_op::SET_IMAGE), &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Continue));
        let new_chain = vm.stack.running_instance().unwrap().image_hash_chain;
        assert_ne!(original_chain, new_chain);
    }

    #[test]
    fn derive_spawn_mints_extended_chain_target() {
        let mut vm = fixture_vm();
        let parent_chain = vm.stack.running_instance().unwrap().image_hash_chain;
        let mut regs = Regs::new();
        regs.gpr[7] = 2;
        regs.gpr[8] = 5;
        let mut mem = Mem::new();
        let r = vm.handle(
            EcallKind::Ecalli(host_op::DERIVE_SPAWN),
            &mut regs,
            &mut mem,
        );
        assert!(matches!(r, EcallResult::Continue));
        let cnode = &vm.stack.running_instance().unwrap().root_cnode;
        let child = cnode.get(SlotIdx(5)).unwrap();
        match child {
            CapHashOrRef::Hash(h) => assert_ne!(h, parent_chain),
            _ => panic!("expected Hash form at dst"),
        }
    }

    #[test]
    fn host_same_type_compares_chain() {
        let mut vm = fixture_vm();
        vm.stack
            .running_instance_mut()
            .unwrap()
            .root_cnode
            .set(SlotIdx(3), Some(CapHashOrRef::Hash([0xAA; 32])))
            .unwrap();
        vm.stack
            .running_instance_mut()
            .unwrap()
            .root_cnode
            .set(SlotIdx(4), Some(CapHashOrRef::Hash([0x99; 32])))
            .unwrap();
        // slot 2 already has [0xAA;32].
        let mut regs = Regs::new();
        regs.gpr[7] = 2;
        regs.gpr[8] = 3;
        let mut mem = Mem::new();
        let r = vm.handle(
            EcallKind::Ecalli(host_op::HOST_SAME_TYPE),
            &mut regs,
            &mut mem,
        );
        assert!(matches!(r, EcallResult::Continue));
        assert_eq!(regs.gpr[7], 1);

        regs.gpr[7] = 2;
        regs.gpr[8] = 4;
        let r = vm.handle(
            EcallKind::Ecalli(host_op::HOST_SAME_TYPE),
            &mut regs,
            &mut mem,
        );
        assert!(matches!(r, EcallResult::Continue));
        assert_eq!(regs.gpr[7], 0);
    }

    #[test]
    fn make_image_stubbed_traps() {
        let mut vm = fixture_vm();
        let mut regs = Regs::new();
        let mut mem = Mem::new();
        let r = vm.handle(EcallKind::Ecalli(host_op::MAKE_IMAGE), &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Exit(ExitReason::Trap)));
    }

    #[test]
    fn cache_dependent_host_calls_trap() {
        // host_read_data_cap / host_mint_data_cap / host_open /
        // host_save / host_type_of all need cache access during
        // interpreter run — deferred to Stage 4. They trap in V1.
        for op in [
            host_op::HOST_TYPE_OF,
            host_op::HOST_READ_DATA_CAP,
            host_op::HOST_MINT_DATA_CAP,
            host_op::HOST_OPEN,
            host_op::HOST_SAVE,
        ] {
            let mut vm = fixture_vm();
            let mut regs = Regs::new();
            let mut mem = Mem::new();
            let r = vm.handle(EcallKind::Ecalli(op), &mut regs, &mut mem);
            assert!(
                matches!(r, EcallResult::Exit(ExitReason::Trap)),
                "op {} should trap (cache-dependent host call)",
                op
            );
        }
    }

    #[test]
    fn strip_trailing_zeros_basic() {
        assert_eq!(strip_trailing_zeros_len(&[1, 2, 3]), 3);
        assert_eq!(strip_trailing_zeros_len(&[1, 2, 3, 0, 0]), 3);
        assert_eq!(strip_trailing_zeros_len(&[0, 0, 0]), 0);
        assert_eq!(strip_trailing_zeros_len(&[]), 0);
    }
}
