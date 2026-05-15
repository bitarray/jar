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
//!   HOST_YIELD       (op=16)  φ[7] = marker_slot_idx (u8) — the slot
//!                              in the running Instance's cnode that
//!                              holds the Cap::Instance[YieldMarker]
//!                              being thrown. The marker payload is
//!                              this same cap, reflected to the
//!                              caller's slot[0] at resume.
//! ```
//!
//! Multi-step `SlotPath` operands are out of scope for Stage 3; the
//! kernel's spec-canonical encoding (single u32 packed path or a
//! pointer to a path buffer in memory) lands when chain bytecode
//! starts using nested cnodes routinely.

use jar_cap::{Cap, SlotIdx, mgmt_cnode_mint, mgmt_cnode_swap, mgmt_copy, mgmt_drop, mgmt_move};
use javm_exec::{EcallHandler, EcallKind, EcallResult, ExitReason, Mem, Regs};

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
    /// Inclusive upper bound of the kernel-known host call range.
    pub const MAX: u32 = 63;
}

impl<K: KernelAssist> EcallHandler for Vm<K> {
    fn handle(&mut self, kind: EcallKind, regs: &mut Regs, mem: &mut Mem) -> EcallResult {
        match kind {
            EcallKind::Ecalli(op) => self.dispatch_ecalli(op, regs, mem),
            EcallKind::Ecall => self.dispatch_ecall(regs, mem),
        }
    }
}

impl<K: KernelAssist> Vm<K> {
    fn dispatch_ecalli(&mut self, op: u32, _regs: &mut Regs, _mem: &mut Mem) -> EcallResult {
        match op {
            0 => {
                // REPLY is handled by the CALL/HALT driver (Stage 3.7).
                // Until then, treat it as a halt-equivalent exit so the
                // interpreter's outer driver sees a clean termination.
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
                // javm-transpiler's blob format) don't fault the bench
                // harness.
                EcallResult::Continue
            }
        }
    }

    /// Dispatch a kernel-known host call (op-codes 16..=63).
    fn dispatch_host_call(&mut self, op: u32, regs: &mut Regs, _mem: &mut Mem) -> EcallResult {
        match op {
            host_op::HOST_YIELD => match self.dispatch_host_yield(regs) {
                Ok(r) => r,
                Err(_) => EcallResult::Exit(ExitReason::Trap),
            },
            _ => {
                // 3.9 / 3.10 fill the rest. For now treat as a no-op.
                EcallResult::Continue
            }
        }
    }

    /// `host_yield(marker_slot=φ[7])`.
    ///
    /// Resolves the marker cap from the running Instance's cnode,
    /// walks the call stack top→bottom looking for an InstanceEntry
    /// whose `Image.yield_marker_slot` references a
    /// `Cap::Instance[YieldCatcher]` whose marker list contains the
    /// thrown marker's `image_hash_chain`. On match: push a
    /// ReferenceEntry pointing at the catcher's position; exit the
    /// interpreter with `ExitReason::HostCall(HOST_YIELD)` so
    /// `run_instance` surfaces `CallResult::Paused`.
    ///
    /// Errors:
    /// - `VmError::CallStackEmpty` if there's no running entry.
    /// - `VmError::SlotKindMismatch` / `SlotEmpty` if the marker slot
    ///   doesn't hold a `Cap::Instance`.
    /// - `VmError::UnhandledMarker` if no catcher on the stack catches
    ///   this marker.
    fn dispatch_host_yield(&mut self, regs: &mut Regs) -> Result<EcallResult, VmError> {
        let marker_slot = SlotIdx((regs.gpr[7] & 0xFF) as u32);

        // 1. Read marker's image_hash_chain from the running Instance's cnode.
        let marker_hash = {
            let running = self
                .stack
                .running_instance()
                .ok_or(VmError::CallStackEmpty)?;
            match running.cnode.get(marker_slot)? {
                Some(Cap::Instance(ic)) => ic.image_hash_chain,
                Some(_) => return Err(VmError::SlotKindMismatch(marker_slot.get())),
                None => return Err(VmError::SlotEmpty(marker_slot.get())),
            }
        };

        // 2. Walk the stack top→bottom (skip the top — that's the
        //    yielder). Find first InstanceEntry whose declared
        //    yield_marker_slot holds a YieldCatcher catching this
        //    marker.
        let stack_len = self.stack.entries().len();
        let mut target_pos: Option<usize> = None;
        // The yielder is at stack_len-1; iterate over positions below.
        for pos in (0..stack_len.saturating_sub(1)).rev() {
            let ie = match &self.stack.entries()[pos] {
                Entry::Instance(ie) => ie.as_ref(),
                Entry::Reference(_) => continue,
            };
            let Some(catcher_slot) = ie.image.yield_marker_slot else {
                continue;
            };
            let catcher_hash = match ie.cnode.get(catcher_slot)? {
                Some(Cap::Instance(ic)) => ic.content_hash,
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
        //    Waiting; the new reference becomes Running and (via
        //    `running_instance_mut`) resolves to the catcher's entry.
        self.stack.push_reference(pos)?;

        Ok(EcallResult::Exit(ExitReason::HostCall(host_op::HOST_YIELD)))
    }

    /// Plain `ecall` (opcode 3, no immediate). Spec §4 reads φ[11]
    /// (mgmt_op) and φ[12] (subject|object) for the management
    /// dispatch. Stage 3 routes the same way as `ecalli imm`, treating
    /// φ[11] as the op.
    fn dispatch_ecall(&mut self, regs: &mut Regs, mem: &mut Mem) -> EcallResult {
        let op = regs.gpr[11] as u32;
        self.dispatch_ecalli(op, regs, mem)
    }

    fn dispatch_mgmt(&mut self, op: u32, regs: &mut Regs) -> Result<(), VmError> {
        let running = self
            .stack
            .running_instance_mut()
            .ok_or(VmError::CallStackEmpty)?;
        let pinned: Vec<SlotIdx> = running.image.pinned_slots.keys().copied().collect();
        let cnode = running.cnode.as_mut();
        let a = SlotIdx((regs.gpr[7] & 0xFF) as u32);
        let b = SlotIdx((regs.gpr[8] & 0xFF) as u32);
        match op {
            mgmt_op::COPY => mgmt_copy(cnode, &pinned, a, b)?,
            mgmt_op::MOVE => mgmt_move(cnode, &pinned, a, b)?,
            mgmt_op::DROP => mgmt_drop(cnode, &pinned, a)?,
            mgmt_op::CNODE_SWAP => mgmt_cnode_swap(cnode, &pinned, a, b)?,
            mgmt_op::CNODE_MINT => {
                let size_log = (regs.gpr[8] & 0xFF) as u8;
                mgmt_cnode_mint(cnode, &pinned, a, size_log)?
            }
            _ => return Err(VmError::Invariant("unknown MGMT op")),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callstack::{EntryStatus, InstanceEntry};
    use crate::kernel_assist::InProcessKernelAssist;
    use jar_cap::{CNodeBackend, Cap, ImageCap, InMemoryCNode, InstanceCap, image::Image};
    use javm_exec::{GasCounter, Mem, PvmProgram, Regs};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn empty_image() -> Image {
        Image {
            code: vec![0u8],
            endpoints: core::array::from_fn(|_| None),
            memory_mappings: Vec::new(),
            gas_slots: Vec::new(),
            quota_slots: Vec::new(),
            pinned_slots: BTreeMap::new(),
            yield_marker_slot: None,
        }
    }

    fn fixture_vm() -> Vm<InProcessKernelAssist> {
        let mut vm = Vm::new(InProcessKernelAssist::new());
        let mut cnode = Box::new(InMemoryCNode::<Cap>::new(4).unwrap());
        // Seed slot 2 with an Image cap.
        cnode
            .set(
                SlotIdx(2),
                Some(Cap::Image(ImageCap {
                    content_hash: [0xAA; 32],
                })),
            )
            .unwrap();
        let img = Arc::new(empty_image());
        let prog = Arc::new(PvmProgram::new(vec![0u8], vec![1u8], vec![], 25).unwrap());
        let entry = InstanceEntry {
            instance: InstanceCap {
                image_hash_chain: [1u8; 32],
                content_hash: [2u8; 32],
            },
            image: img,
            program: prog,
            cnode,
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
        let cnode = &vm.stack.running_instance().unwrap().cnode;
        assert!(cnode.get(SlotIdx(2)).unwrap().is_some());
        assert!(cnode.get(SlotIdx(7)).unwrap().is_some());
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
        let cnode = &vm.stack.running_instance().unwrap().cnode;
        assert!(cnode.get(SlotIdx(2)).unwrap().is_none()); // source moved out
        assert!(cnode.get(SlotIdx(9)).unwrap().is_some()); // dst now holds it
    }

    #[test]
    fn mgmt_drop_dispatch_via_ecalli() {
        let mut vm = fixture_vm();
        let mut regs = Regs::new();
        regs.gpr[7] = 2;
        let mut mem = Mem::new();
        let r = vm.handle(EcallKind::Ecalli(mgmt_op::DROP), &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Continue));
        let cnode = &vm.stack.running_instance().unwrap().cnode;
        assert!(cnode.get(SlotIdx(2)).unwrap().is_none());
    }

    #[test]
    fn mgmt_cnode_mint_creates_nested_cnode() {
        let mut vm = fixture_vm();
        let mut regs = Regs::new();
        regs.gpr[7] = 5; // dst
        regs.gpr[8] = 3; // size_log = 8 slots
        let mut mem = Mem::new();
        let r = vm.handle(EcallKind::Ecalli(mgmt_op::CNODE_MINT), &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Continue));
        let cnode = &vm.stack.running_instance().unwrap().cnode;
        assert!(matches!(
            cnode.get(SlotIdx(5)).unwrap(),
            Some(Cap::CNode(_))
        ));
    }

    #[test]
    fn mgmt_cnode_swap_swaps_slots() {
        let mut vm = fixture_vm();
        // Seed slot 3 with another cap so we have something to swap.
        vm.stack
            .running_instance_mut()
            .unwrap()
            .cnode
            .set(
                SlotIdx(3),
                Some(Cap::Image(ImageCap {
                    content_hash: [0xBB; 32],
                })),
            )
            .unwrap();
        let mut regs = Regs::new();
        regs.gpr[7] = 2;
        regs.gpr[8] = 3;
        let mut mem = Mem::new();
        let r = vm.handle(EcallKind::Ecalli(mgmt_op::CNODE_SWAP), &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Continue));
        let cnode = &vm.stack.running_instance().unwrap().cnode;
        let slot2 = match cnode.get(SlotIdx(2)).unwrap() {
            Some(Cap::Image(c)) => c.content_hash,
            _ => panic!(),
        };
        let slot3 = match cnode.get(SlotIdx(3)).unwrap() {
            Some(Cap::Image(c)) => c.content_hash,
            _ => panic!(),
        };
        assert_eq!(slot2, [0xBB; 32]);
        assert_eq!(slot3, [0xAA; 32]);
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
                .cnode
                .get(SlotIdx(2))
                .unwrap()
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
}
