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
//! After the move to the `javm_cap::Cap` cache model, ecalls
//! operate on `CapHashOrRef` targets in the running root cnode and
//! cross-reference into the caller-supplied `CacheDirectory` for kind
//! dispatch. `Vm::drive_and_translate` installs a short-lived
//! `CachedEcallHandler` for interpreter runs, so cache-touching host
//! calls can read/write cap content without storing the cache borrow
//! in the long-lived `Vm`.

use javm_cap::{
    Blake2b256, CacheDirectory, Cap, CapHashOrRef, DataCap, DataContent, Hash, SlotIdx, TypeCap,
};
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
    /// `host_call(instance_slot=φ[7], endpoint_idx=φ[8])` — push a
    /// child `InstanceEntry` from the `Cap::Instance` at
    /// `instance_slot`, move the caller's `slot[0]` into the child's
    /// `slot[0]`. The interpreter exits with
    /// `ExitReason::HostCall(HOST_CALL)`; the `drive_and_translate`
    /// loop re-enters `Interpreter::run` on the new top frame. On
    /// child HALT the loop pops the child, reflects its `slot[0]`
    /// back into the caller's `slot[0]`, and resumes the caller.
    pub const HOST_CALL: u32 = 26;
    /// Inclusive upper bound of the kernel-known host call range.
    pub const MAX: u32 = 63;
}

impl<K: KernelAssist> EcallHandler for Vm<K> {
    fn handle(&mut self, kind: EcallKind, regs: &mut Regs, mem: &mut dyn Memory) -> EcallResult {
        match kind {
            EcallKind::Ecalli(op) => self.dispatch_ecalli(op, regs, mem, None),
            EcallKind::Ecall => self.dispatch_ecall(regs, mem, None),
        }
    }
}

pub(crate) struct CachedEcallHandler<'a, K: KernelAssist> {
    pub(crate) vm: &'a mut Vm<K>,
    pub(crate) cache: &'a mut CacheDirectory,
}

impl<K: KernelAssist> EcallHandler for CachedEcallHandler<'_, K> {
    fn handle(&mut self, kind: EcallKind, regs: &mut Regs, mem: &mut dyn Memory) -> EcallResult {
        match kind {
            EcallKind::Ecalli(op) => self
                .vm
                .dispatch_ecalli(op, regs, mem, Some(&mut *self.cache)),
            EcallKind::Ecall => self.vm.dispatch_ecall(regs, mem, Some(&mut *self.cache)),
        }
    }
}

impl<K: KernelAssist> Vm<K> {
    fn dispatch_ecalli(
        &mut self,
        op: u32,
        regs: &mut Regs,
        mem: &mut dyn Memory,
        cache: Option<&mut CacheDirectory>,
    ) -> EcallResult {
        match op {
            0 => {
                // REPLY is handled by the CALL/HALT driver.
                EcallResult::Exit(ExitReason::Halt)
            }
            o if o <= mgmt_op::MAX => match self.dispatch_mgmt(o, regs, cache) {
                Ok(()) => EcallResult::Continue,
                Err(_) => EcallResult::Exit(ExitReason::Trap),
            },
            o if o <= host_op::MAX => self.dispatch_host_call(o, regs, mem, cache),
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
        mem: &mut dyn Memory,
        cache: Option<&mut CacheDirectory>,
    ) -> EcallResult {
        fn trap_on_err<T>(r: Result<T, VmError>, ok: impl FnOnce(T) -> EcallResult) -> EcallResult {
            match r {
                Ok(v) => ok(v),
                Err(_) => EcallResult::Exit(ExitReason::Trap),
            }
        }
        match op {
            host_op::HOST_YIELD => trap_on_err(self.dispatch_host_yield(regs), |r| r),
            host_op::SET_IMAGE => match cache {
                Some(cache) => trap_on_err(self.dispatch_set_image_cached(regs, cache), |()| {
                    EcallResult::Exit(ExitReason::HostCall(host_op::SET_IMAGE))
                }),
                None => trap_on_err(self.dispatch_set_image(regs), |()| EcallResult::Continue),
            },
            host_op::DERIVE_SPAWN => match cache {
                Some(cache) => trap_on_err(self.dispatch_derive_spawn_cached(regs, cache), |()| {
                    EcallResult::Continue
                }),
                None => trap_on_err(self.dispatch_derive_spawn(regs), |()| EcallResult::Continue),
            },
            host_op::MAKE_IMAGE => {
                // Stage 3.9 stub.
                EcallResult::Exit(ExitReason::Trap)
            }
            host_op::HOST_SAME_TYPE => trap_on_err(self.dispatch_host_same_type(regs), |()| {
                EcallResult::Continue
            }),
            host_op::HOST_TYPE_OF => match cache {
                Some(cache) => trap_on_err(self.dispatch_host_type_of(regs, cache), |()| {
                    EcallResult::Continue
                }),
                None => EcallResult::Exit(ExitReason::Trap),
            },
            host_op::HOST_READ_DATA_CAP => match cache {
                Some(cache) => {
                    trap_on_err(self.dispatch_host_read_data_cap(regs, mem, cache), |()| {
                        EcallResult::Continue
                    })
                }
                None => EcallResult::Exit(ExitReason::Trap),
            },
            host_op::HOST_MINT_DATA_CAP => match cache {
                Some(cache) => {
                    trap_on_err(self.dispatch_host_mint_data_cap(regs, mem, cache), |()| {
                        EcallResult::Continue
                    })
                }
                None => EcallResult::Exit(ExitReason::Trap),
            },
            host_op::HOST_OPEN => match cache {
                Some(cache) => trap_on_err(self.dispatch_host_open(regs, cache), |()| {
                    EcallResult::Continue
                }),
                None => EcallResult::Exit(ExitReason::Trap),
            },
            host_op::HOST_SAVE => match cache {
                Some(cache) => trap_on_err(self.dispatch_host_save(regs, cache), |()| {
                    EcallResult::Continue
                }),
                None => EcallResult::Exit(ExitReason::Trap),
            },
            host_op::HOST_CALL => match cache {
                Some(cache) => trap_on_err(self.dispatch_host_call_cached(regs, cache), |()| {
                    EcallResult::Exit(ExitReason::HostCall(host_op::HOST_CALL))
                }),
                None => EcallResult::Exit(ExitReason::Trap),
            },
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

    fn dispatch_set_image_cached(
        &mut self,
        regs: &mut Regs,
        cache: &CacheDirectory,
    ) -> Result<(), VmError> {
        let image_slot = SlotIdx((regs.gpr[7] & 0xFF) as u32);
        let (new_image_hash, extended_chain) = {
            let running = self
                .stack
                .running_instance()
                .ok_or(VmError::CallStackEmpty)?;
            let new_image_hash = match running.root_cnode.get(image_slot) {
                Some(CapHashOrRef::Hash(h)) => h,
                Some(CapHashOrRef::Ref(_)) => {
                    return Err(VmError::SlotKindMismatch(image_slot.get()));
                }
                None => return Err(VmError::SlotEmpty(image_slot.get())),
            };
            (
                new_image_hash,
                Blake2b256::hash_pair(&running.image_hash_chain, &new_image_hash),
            )
        };

        let img = match &*cache
            .get(CapHashOrRef::Hash(new_image_hash))
            .ok_or(VmError::ImageNotFound)?
        {
            Cap::Image(i) => i.clone(),
            _ => return Err(VmError::ImageNotFound),
        };
        let program = self.image_cache.get_or_decode(
            new_image_hash,
            img.code.as_slice().to_vec(),
            img.jump_table.as_slice().to_vec(),
            img.jump_table_offsets.as_slice().to_vec(),
        );
        let pinned_slots: Vec<SlotIdx> = img.pinned.iter().map(|e| e.slot).collect();

        let running = self
            .stack
            .running_instance_mut()
            .ok_or(VmError::CallStackEmpty)?;
        running.image_hash_chain = extended_chain;
        running.image_hash = new_image_hash;
        running.program = program;
        running.pinned_slots = pinned_slots;
        running.yield_marker_slot = img.yield_marker_slot;
        Ok(())
    }

    /// `host_derive_spawn(image_slot=φ[7], dst_slot=φ[8])` — uncached
    /// fallback that only records the extended chain hash. CacheDirectory-less
    /// callers (no `dispatch_host_call_cached` borrow) can't publish a
    /// real `Cap::Instance`, so this writes the chain-hash placeholder
    /// for back-compat with pre-Stage-4 fixtures.
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

    /// `host_derive_spawn(image_slot=φ[7], cnode_slot=φ[8],
    /// dst_slot=φ[9])` — full spec form.
    ///
    /// Builds a fresh child `Cap::Instance`:
    /// 1. Read the `Cap::Image` hash at `image_slot` and the prepared
    ///    `Cap::CNode` hash at `cnode_slot`.
    /// 2. `child.image_hash_chain = blake2b(parent.chain ||
    ///    hash(image))`.
    /// 3. Build the child's root cnode = prepared cnode + the
    ///    spawned image's pinned slots overlaid on top. Publish.
    /// 4. Publish a fresh `Cap::Instance` referencing the image and
    ///    new root cnode with default initial state (mem_size from
    ///    image mappings, no overlays, zeroed regs/pc/gas).
    /// 5. Consume (clear) the prepared cnode slot in the caller's
    ///    cnode — spec MOVE semantics.
    /// 6. Write `Hash(new_instance_hash)` to `dst_slot`.
    fn dispatch_derive_spawn_cached(
        &mut self,
        regs: &mut Regs,
        cache: &mut CacheDirectory,
    ) -> Result<(), VmError> {
        let image_slot = SlotIdx((regs.gpr[7] & 0xFF) as u32);
        let cnode_slot = SlotIdx((regs.gpr[8] & 0xFF) as u32);
        let dst_slot = SlotIdx((regs.gpr[9] & 0xFF) as u32);

        // 1. Resolve image_hash, cnode_hash, parent chain.
        let (image_hash, cnode_hash, parent_chain) = {
            let running = self
                .stack
                .running_instance()
                .ok_or(VmError::CallStackEmpty)?;
            let img_h = match running.root_cnode.get(image_slot) {
                Some(CapHashOrRef::Hash(h)) => h,
                Some(CapHashOrRef::Ref(_)) => {
                    return Err(VmError::SlotKindMismatch(image_slot.get()));
                }
                None => return Err(VmError::SlotEmpty(image_slot.get())),
            };
            let cn_h = match running.root_cnode.get(cnode_slot) {
                Some(CapHashOrRef::Hash(h)) => h,
                Some(CapHashOrRef::Ref(_)) => {
                    return Err(VmError::SlotKindMismatch(cnode_slot.get()));
                }
                None => return Err(VmError::SlotEmpty(cnode_slot.get())),
            };
            (img_h, cn_h, running.image_hash_chain)
        };

        // 2. Child chain hash.
        let child_chain = Blake2b256::hash_pair(&parent_chain, &image_hash);

        // 3. Build child cnode = prepared cnode + image's pinned +
        //    initial slots overlaid. Spec strictly says initial is
        //    ignored for parented instances; V1 simplification: also
        //    apply initial when the prepared slot is empty, so the
        //    parent doesn't have to mint stack/heap/rw_data caps
        //    by hand on every spawn. A future spec-strict mode can
        //    skip the initial overlay.
        let img_cap = match &*cache
            .get(CapHashOrRef::Hash(image_hash))
            .ok_or(VmError::ImageNotFound)?
        {
            Cap::Image(i) => i.clone(),
            _ => return Err(VmError::ImageNotFound),
        };
        let mut child_cn = match &*cache
            .get(CapHashOrRef::Hash(cnode_hash))
            .ok_or(VmError::Invariant("derive_spawn: prepared cnode missing"))?
        {
            Cap::CNode(c) => c.clone(),
            _ => {
                return Err(VmError::Invariant(
                    "derive_spawn: cnode_slot does not hold Cap::CNode",
                ));
            }
        };
        for e in img_cap.pinned.iter() {
            child_cn.set(e.slot, Some(CapHashOrRef::Hash(e.cap_hash)))?;
        }
        for e in img_cap.initial.iter() {
            if child_cn.get(e.slot).is_none() {
                child_cn.set(e.slot, Some(CapHashOrRef::Hash(e.cap_hash)))?;
            }
        }
        let new_cnode_hash = cache.put_cap(&Cap::CNode(child_cn))?;

        // 4. Build the child's `rw_overlays` by walking the image's
        //    memory mappings and resolving each source slot to a
        //    `Cap::Data` in the (post-overlay) cnode. Each mapping
        //    becomes one (start, bytes) overlay; the build_entry side
        //    lays them into RW memory at CALL time. The base RW
        //    region is sized to cover the max(start+size) span.
        let new_cnode_cap = cache
            .get(CapHashOrRef::Hash(new_cnode_hash))
            .ok_or(VmError::Invariant("derive_spawn: new cnode missing"))?;
        let new_cnode = match &*new_cnode_cap {
            Cap::CNode(c) => c.clone(),
            _ => return Err(VmError::Invariant("derive_spawn: cnode hash misroutes")),
        };
        let mut overlay_bufs: Vec<(u32, Vec<u8>)> = Vec::new();
        let mut mem_size: u32 = 0;
        for m in img_cap.mappings.iter() {
            let end = (m.start + m.size) as u32;
            if end > mem_size {
                mem_size = end;
            }
            if m.source_path_len == 0 {
                continue;
            }
            // V1: only single-step source paths are exercised.
            let src_slot = m.source_path[0];
            let target = match new_cnode.get(src_slot) {
                Some(t) => t,
                None => continue,
            };
            let data_arc = cache.get(target);
            let bytes_vec = match data_arc.as_deref() {
                Some(Cap::Data(d)) => match &d.content {
                    javm_cap::DataContent::Inline(v) => v.as_slice().to_vec(),
                    javm_cap::DataContent::Paged { .. } => continue,
                },
                _ => continue,
            };
            if !bytes_vec.is_empty() {
                overlay_bufs.push((m.start as u32, bytes_vec));
            }
        }
        let overlay_slices: Vec<(u32, &[u8])> = overlay_bufs
            .iter()
            .map(|(s, b)| (*s, b.as_slice()))
            .collect();

        let inst_cap = Cap::instance_with_overlays(
            child_chain,
            image_hash,
            new_cnode_hash,
            &overlay_slices,
            mem_size,
            [0u64; javm_cap::NUM_REGS],
            0,
            0,
        );
        let new_instance_hash = cache.put_cap(&inst_cap)?;

        // 5+6. Consume prepared cnode, write child instance hash to
        //      dst (rejects pinned).
        let running = self
            .stack
            .running_instance_mut()
            .ok_or(VmError::CallStackEmpty)?;
        if running.pinned_slots.binary_search(&dst_slot).is_ok() {
            return Err(javm_cap::OpError::SlotPinned(dst_slot.get()).into());
        }
        running.root_cnode.take(cnode_slot)?;
        running
            .root_cnode
            .set(dst_slot, Some(CapHashOrRef::Hash(new_instance_hash)))?;
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

    fn dispatch_host_type_of(
        &mut self,
        regs: &mut Regs,
        cache: &mut CacheDirectory,
    ) -> Result<(), VmError> {
        let src = SlotIdx((regs.gpr[7] & 0xFF) as u32);
        let dst = SlotIdx((regs.gpr[8] & 0xFF) as u32);
        let target = self
            .stack
            .running_instance()
            .ok_or(VmError::CallStackEmpty)?
            .root_cnode
            .get(src)
            .ok_or(VmError::SlotEmpty(src.get()))?;
        let image_hash_chain = match &*cache.get(target).ok_or(VmError::InstanceNotFound)? {
            Cap::Instance(i) => i.image_hash_chain,
            _ => return Err(VmError::InstanceNotFound),
        };
        let cap = Cap::Type(TypeCap { image_hash_chain });
        let h = cap.cap_hash();
        cache.put_cap_with_hash(h, &cap)?;

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

    fn dispatch_host_read_data_cap(
        &mut self,
        regs: &mut Regs,
        mem: &mut dyn Memory,
        cache: &CacheDirectory,
    ) -> Result<(), VmError> {
        let src = SlotIdx((regs.gpr[7] & 0xFF) as u32);
        let dst_offset = regs.gpr[8] as u32;
        let len = regs.gpr[9] as usize;
        let target = self
            .stack
            .running_instance()
            .ok_or(VmError::CallStackEmpty)?
            .root_cnode
            .get(src)
            .ok_or(VmError::SlotEmpty(src.get()))?;
        let data_arc = cache
            .get(target)
            .ok_or(VmError::Invariant("data cap missing"))?;
        let data = match &*data_arc {
            Cap::Data(d) => d,
            _ => return Err(VmError::Invariant("slot does not hold Cap::Data")),
        };
        let bytes = data_cap_prefix(data, len);
        mem.write(dst_offset, &bytes)
            .map_err(|_| VmError::Invariant("host_read_data_cap memory write failed"))?;
        regs.gpr[7] = bytes.len() as u64;
        Ok(())
    }

    fn dispatch_host_mint_data_cap(
        &mut self,
        regs: &mut Regs,
        mem: &mut dyn Memory,
        cache: &mut CacheDirectory,
    ) -> Result<(), VmError> {
        let src_offset = regs.gpr[7] as u32;
        let len = regs.gpr[8] as usize;
        let quota_id = regs.gpr[9];
        let dst = SlotIdx((regs.gpr[10] & 0xFF) as u32);
        let bytes = mem
            .read(src_offset, len)
            .map_err(|_| VmError::Invariant("host_mint_data_cap memory read failed"))?;
        // DataCap content is page-multiple by construction: pad the
        // caller's bytes up to the next 4 KiB boundary with zeros.
        // Quota is debited by the padded length — the kernel owns
        // a full page-aligned allocation regardless of caller's slice
        // length, so callers pay for what they store.
        let mut inline = javm_cap::cap::data::alloc_page_aligned_zeroed(bytes.len());
        inline[..bytes.len()].copy_from_slice(&bytes);
        let debit = inline.len() as u64;
        let quota = self.kernel_assist.storage_quota_get(quota_id);
        if quota < debit {
            return Err(VmError::Invariant("storage quota exhausted"));
        }
        self.kernel_assist
            .storage_quota_set(quota_id, quota - debit);
        let cap = Cap::Data(DataCap {
            content: DataContent::Inline(inline),
        });
        let h = cap.cap_hash();
        cache.put_cap_with_hash(h, &cap)?;

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

    fn dispatch_host_open(
        &mut self,
        regs: &mut Regs,
        cache: &mut CacheDirectory,
    ) -> Result<(), VmError> {
        let file_id = regs.gpr[7];
        let dst = SlotIdx((regs.gpr[8] & 0xFF) as u32);
        let data_ref = self
            .kernel_assist
            .host_open(file_id)
            .ok_or(VmError::Invariant("unknown file id"))?;
        match &*cache
            .get(data_ref.clone())
            .ok_or(VmError::Invariant("file data missing"))?
        {
            Cap::Data(_) => {}
            _ => return Err(VmError::Invariant("file target is not Cap::Data")),
        }
        let h = cache.settle(data_ref)?;

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

    fn dispatch_host_save(
        &mut self,
        regs: &mut Regs,
        cache: &CacheDirectory,
    ) -> Result<(), VmError> {
        let src = SlotIdx((regs.gpr[7] & 0xFF) as u32);
        let quota_id = regs.gpr[8];
        let target = self
            .stack
            .running_instance()
            .ok_or(VmError::CallStackEmpty)?
            .root_cnode
            .get(src)
            .ok_or(VmError::SlotEmpty(src.get()))?;
        let size = match &*cache
            .get(target.clone())
            .ok_or(VmError::Invariant("host_save data missing"))?
        {
            Cap::Data(d) => d.content_len(),
            _ => return Err(VmError::Invariant("host_save source is not Cap::Data")),
        };
        let file_id = self
            .kernel_assist
            .host_save(target, quota_id, size)
            .ok_or(VmError::Invariant("host_save failed"))?;
        regs.gpr[7] = file_id;
        Ok(())
    }

    /// `host_call(instance_slot=φ[7], endpoint_idx=φ[8])`.
    ///
    /// Resolve the `Cap::Instance` at `instance_slot` in the running
    /// cnode, build a child `InstanceEntry` via [`Vm::build_entry`],
    /// move the caller's `slot[0]` into the child's `slot[0]` (CALL
    /// scratchpad), and push the child. The dispatcher returns; the
    /// caller (in `dispatch_host_call`) wraps the result as
    /// `EcallResult::Exit(ExitReason::HostCall(HOST_CALL))` so the
    /// `drive_and_translate` loop re-enters `Interpreter::run` on the
    /// new top frame.
    ///
    /// Child gas: V1 threads the parent's live `GasCounter` through to
    /// the child (shared pool). The child's `entry.gas` field is left
    /// as the build_entry placeholder; the live counter is owned by
    /// `drive_and_translate`.
    fn dispatch_host_call_cached(
        &mut self,
        regs: &mut Regs,
        cache: &mut CacheDirectory,
    ) -> Result<(), VmError> {
        let inst_slot = SlotIdx((regs.gpr[7] & 0xFF) as u32);
        let endpoint_idx = (regs.gpr[8] & 0xFF) as u8;

        // 1. Resolve target Cap::Instance from caller's cnode.
        let target_ref = self
            .stack
            .running_instance()
            .ok_or(VmError::CallStackEmpty)?
            .root_cnode
            .get(inst_slot)
            .ok_or(VmError::SlotEmpty(inst_slot.get()))?;
        let target_arc = cache.get(target_ref.clone());
        match target_arc.as_deref() {
            Some(Cap::Instance(_)) => {}
            _ => return Err(VmError::InstanceNotFound),
        }

        // 2. Move caller's slot[0] (CALL scratchpad). Empty is fine.
        let scratch = self
            .stack
            .running_instance_mut()
            .ok_or(VmError::CallStackEmpty)?
            .root_cnode
            .take(SlotIdx(0))?;

        // 3. Build the child entry + its initial regs/mem. Gas budget
        //    is irrelevant — V1 shares the parent's live counter, so
        //    this is a throwaway.
        let (mut child, child_mem, child_regs, _child_gas, _) =
            self.build_entry(cache, target_ref, endpoint_idx, [0u64; 4], 0)?;

        // 4. Plant slot[0] in the child's cnode.
        if let Some(cap) = scratch {
            child.root_cnode.set(SlotIdx(0), Some(cap))?;
        }

        // 5. Stash child's initial regs/mem in the entry so the
        //    `drive_and_translate` loop can pick them up on the next
        //    iteration. Gas stays threaded via the loop's live
        //    counter; the entry.gas placeholder isn't read.
        child.regs = child_regs;
        child.mem = child_mem;

        // 6. Push. push_instance flips the parent's status
        //    Running→Waiting; the child becomes Running.
        self.stack.push_instance(child)?;
        Ok(())
    }
}

fn data_cap_prefix(data: &DataCap, len: usize) -> Vec<u8> {
    let actual_len = len.min(data.content_len() as usize);
    let mut out = vec![0u8; actual_len];
    match &data.content {
        DataContent::Inline(bytes) => {
            let copy_len = actual_len.min(bytes.len());
            out[..copy_len].copy_from_slice(&bytes[..copy_len]);
        }
        DataContent::Paged { page_size, pages } => {
            let page_size = *page_size as usize;
            for (page_idx, page) in pages.iter().enumerate() {
                let start = page_idx * page_size;
                if start >= actual_len {
                    break;
                }
                let end = (start + page_size).min(actual_len);
                if let javm_cap::cap::page::PageSlot::Loaded(page_ref) = page {
                    let page_bytes = &page_ref.bytes;
                    out[start..end].copy_from_slice(&page_bytes[..end - start]);
                }
            }
        }
    }
    out
}

impl<K: KernelAssist> Vm<K> {
    /// Plain `ecall` (opcode 3, no immediate). Spec §4 reads φ[11]
    /// (mgmt_op) and φ[12] (subject|object) for the management
    /// dispatch. Stage 3 routes the same way as `ecalli imm`, treating
    /// φ[11] as the op.
    fn dispatch_ecall(
        &mut self,
        regs: &mut Regs,
        mem: &mut dyn Memory,
        cache: Option<&mut CacheDirectory>,
    ) -> EcallResult {
        let op = regs.gpr[11] as u32;
        self.dispatch_ecalli(op, regs, mem, cache)
    }

    fn dispatch_mgmt(
        &mut self,
        op: u32,
        regs: &mut Regs,
        cache: Option<&mut CacheDirectory>,
    ) -> Result<(), VmError> {
        let a = SlotIdx((regs.gpr[7] & 0xFF) as u32);
        let b = SlotIdx((regs.gpr[8] & 0xFF) as u32);
        match op {
            mgmt_op::COPY => self.mgmt_copy(a, b),
            mgmt_op::MOVE => self.mgmt_move(a, b),
            mgmt_op::DROP => self.mgmt_drop(a),
            mgmt_op::CNODE_SWAP => self.mgmt_cnode_swap(a, b),
            mgmt_op::CNODE_MINT => {
                let size_log = (regs.gpr[8] & 0xFF) as u8;
                self.mgmt_cnode_mint(a, size_log, cache)
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

    fn mgmt_cnode_mint(
        &mut self,
        dst: SlotIdx,
        size_log: u8,
        cache: Option<&mut CacheDirectory>,
    ) -> Result<(), VmError> {
        let cap = Cap::CNode(javm_cap::CNodeCap::new(size_log)?);
        let cap_hash = cap.cap_hash();
        let h = match cache {
            Some(cache) => {
                cache.put_cap_with_hash(cap_hash, &cap)?;
                cap_hash
            }
            None => cap_hash,
        };
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
    use javm_cap::image::Image;
    use javm_cap::{CNodeCap, NUM_REGS};
    use javm_exec::{Access, GasCounter, Mem, PAGE_SIZE, Regs, interp::Program};
    use std::sync::Arc;

    fn fixture_vm() -> Vm<InProcessKernelAssist> {
        let mut vm = Vm::new(InProcessKernelAssist::new());
        let mut cnode = CNodeCap::new(4).unwrap();
        // Seed slot 2 with a Hash-form target (treated as an Image hash).
        cnode
            .set(SlotIdx(2), Some(CapHashOrRef::Hash([0xAA; 32])))
            .unwrap();
        // Trivial PVM2 blob: single `trap` (custom-0 funct3=000).
        let prog = Arc::new(Program::new(vec![0x0B, 0x00, 0x00, 0x00], vec![], vec![0]));
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

    fn handle_cached(
        vm: &mut Vm<InProcessKernelAssist>,
        cache: &mut CacheDirectory,
        op: u32,
        regs: &mut Regs,
        mem: &mut Mem,
    ) -> EcallResult {
        let mut handler = CachedEcallHandler { vm, cache };
        handler.handle(EcallKind::Ecalli(op), regs, mem)
    }

    fn publish_data_inline(cache: &mut CacheDirectory, bytes: &[u8]) -> javm_cap::CapHash {
        cache.put_cap(&Cap::data_inline(bytes)).unwrap()
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
    fn mgmt_cnode_mint_publishes_cnode_when_cache_threaded() {
        let mut vm = fixture_vm();
        let mut cache = CacheDirectory::new();
        let mut regs = Regs::new();
        regs.gpr[7] = 5;
        regs.gpr[8] = 3;
        let mut mem = Mem::new();
        let r = handle_cached(
            &mut vm,
            &mut cache,
            mgmt_op::CNODE_MINT,
            &mut regs,
            &mut mem,
        );
        assert!(matches!(r, EcallResult::Continue));
        let cnode = &vm.stack.running_instance().unwrap().root_cnode;
        let target = cnode.get(SlotIdx(5)).unwrap();
        assert!(matches!(cache.get(target).as_deref(), Some(Cap::CNode(_))));
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
    fn set_image_reloads_program_from_cache() {
        let mut vm = fixture_vm();
        let mut cache = CacheDirectory::new();
        let mut img = Image::empty();
        // PVM2 `ecalli 0` — 32-bit custom-0 word at PC 0.
        img.code = 0x0000_200Bu32.to_le_bytes().to_vec();
        img.jump_table_offsets = vec![0, 0];
        let image_hash = cache
            .put_cap(&Cap::image_with_slots(&img, &[], &[]).unwrap())
            .unwrap();
        vm.stack
            .running_instance_mut()
            .unwrap()
            .root_cnode
            .set(SlotIdx(3), Some(CapHashOrRef::Hash(image_hash)))
            .unwrap();

        let mut regs = Regs::new();
        regs.gpr[7] = 3;
        let mut mem = Mem::new();
        let r = handle_cached(&mut vm, &mut cache, host_op::SET_IMAGE, &mut regs, &mut mem);
        assert!(
            matches!(r, EcallResult::Exit(ExitReason::HostCall(op)) if op == host_op::SET_IMAGE)
        );
        let running = vm.stack.running_instance().unwrap();
        assert_eq!(running.image_hash, image_hash);
        assert_eq!(running.program.code, 0x0000_200Bu32.to_le_bytes().to_vec());
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
    fn host_type_of_publishes_type_cap() {
        let mut vm = fixture_vm();
        let mut cache = CacheDirectory::new();
        // Instance references image + cnode by hash; both must be in
        // the cache for `put_cap` to accept the Instance.
        let image_hash = cache
            .put_cap(&Cap::image_with_slots(&Image::empty(), &[], &[]).unwrap())
            .unwrap();
        let cnode_hash = cache.put_cap(&Cap::empty_cnode(0).unwrap()).unwrap();
        let inst_hash = cache
            .put_cap(&Cap::instance_with_overlays(
                [0x42; 32],
                image_hash,
                cnode_hash,
                &[],
                0,
                [0u64; NUM_REGS],
                0,
                0,
            ))
            .unwrap();
        vm.stack
            .running_instance_mut()
            .unwrap()
            .root_cnode
            .set(SlotIdx(3), Some(CapHashOrRef::Hash(inst_hash)))
            .unwrap();

        let mut regs = Regs::new();
        regs.gpr[7] = 3;
        regs.gpr[8] = 6;
        let mut mem = Mem::new();
        let r = handle_cached(
            &mut vm,
            &mut cache,
            host_op::HOST_TYPE_OF,
            &mut regs,
            &mut mem,
        );
        assert!(matches!(r, EcallResult::Continue));
        let target = vm
            .stack
            .running_instance()
            .unwrap()
            .root_cnode
            .get(SlotIdx(6))
            .unwrap();
        assert!(matches!(
            cache.get(target).as_deref(),
            Some(Cap::Type(TypeCap {
                image_hash_chain
            })) if *image_hash_chain == [0x42; 32]
        ));
    }

    #[test]
    fn host_read_data_cap_copies_bytes_from_cache() {
        // After the page-aligned DataCap refactor, the cap'\''s content
        // is always page-multiple. `host_read_data_cap` copies up to
        // `len` bytes (capped at `content_len()`), so callers asking
        // for fewer bytes than a page get exactly that many — with
        // the meaningful prefix at the start and trailing zero-pad.
        let mut vm = fixture_vm();
        let mut cache = CacheDirectory::new();
        let data_hash = publish_data_inline(&mut cache, b"hello");
        vm.stack
            .running_instance_mut()
            .unwrap()
            .root_cnode
            .set(SlotIdx(3), Some(CapHashOrRef::Hash(data_hash)))
            .unwrap();
        let mut mem = Mem::new();
        mem.map_region(0, PAGE_SIZE as u64, Access::ReadWrite, None)
            .unwrap();
        let mut regs = Regs::new();
        regs.gpr[7] = 3;
        regs.gpr[8] = 16;
        regs.gpr[9] = 8;

        let r = handle_cached(
            &mut vm,
            &mut cache,
            host_op::HOST_READ_DATA_CAP,
            &mut regs,
            &mut mem,
        );
        assert!(matches!(r, EcallResult::Continue));
        // Asked for 8 bytes; the cap has 4096 bytes available so we
        // get all 8: 5 meaningful "hello" plus 3 trailing zeros.
        assert_eq!(regs.gpr[7], 8);
        assert_eq!(mem.read(16, 8).unwrap(), b"hello\0\0\0");
    }

    #[test]
    fn host_mint_data_cap_publishes_page_padded_bytes() {
        // After the page-aligned DataCap refactor, mint pads the
        // caller's bytes up to the next 4 KiB boundary and debits
        // quota by the padded length (1 page = 4096 bytes).
        let mut vm = fixture_vm();
        let mut cache = CacheDirectory::new();
        vm.kernel_assist.storage_quota_set(0, 8192);
        let mut mem = Mem::new();
        mem.map_region(0, PAGE_SIZE as u64, Access::ReadWrite, None)
            .unwrap();
        mem.write(32, b"abc\0\0").unwrap();
        let mut regs = Regs::new();
        regs.gpr[7] = 32;
        regs.gpr[8] = 5;
        regs.gpr[9] = 0;
        regs.gpr[10] = 6;

        let r = handle_cached(
            &mut vm,
            &mut cache,
            host_op::HOST_MINT_DATA_CAP,
            &mut regs,
            &mut mem,
        );
        assert!(matches!(r, EcallResult::Continue));
        // Debit = one page (4096), starting from 8192 leaves 4096.
        assert_eq!(vm.kernel_assist.storage_quota_get(0), 4096);
        let target = vm
            .stack
            .running_instance()
            .unwrap()
            .root_cnode
            .get(SlotIdx(6))
            .unwrap();
        let target_arc = cache.get(target).unwrap();
        match &*target_arc {
            Cap::Data(d) => {
                assert_eq!(d.content_len(), javm_cap::PAGE_SIZE as u64);
                // First 5 bytes echo what we wrote, including the
                // two trailing zeros — no stripping.
                assert_eq!(data_cap_prefix(d, 5), b"abc\0\0");
            }
            _ => panic!("expected Data cap"),
        }
    }

    #[test]
    fn host_open_places_registered_file_data_in_slot() {
        let mut vm = fixture_vm();
        let mut cache = CacheDirectory::new();
        let data_hash = publish_data_inline(&mut cache, b"file");
        vm.kernel_assist
            .register_file(9, CapHashOrRef::Hash(data_hash));
        let mut regs = Regs::new();
        regs.gpr[7] = 9;
        regs.gpr[8] = 6;
        let mut mem = Mem::new();
        let r = handle_cached(&mut vm, &mut cache, host_op::HOST_OPEN, &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Continue));
        let target = vm
            .stack
            .running_instance()
            .unwrap()
            .root_cnode
            .get(SlotIdx(6))
            .unwrap();
        assert!(matches!(cache.get(target).as_deref(), Some(Cap::Data(_))));
    }

    #[test]
    fn host_save_debits_actual_data_size_and_returns_file_id() {
        // Page-aligned DataCap: `host_save` debits by the full
        // page-multiple content length (4 KiB for the padded "stored"
        // cap). Quota seeded with enough headroom for one save.
        let mut vm = fixture_vm();
        let mut cache = CacheDirectory::new();
        let data_hash = publish_data_inline(&mut cache, b"stored");
        vm.kernel_assist.storage_quota_set(0, 8192);
        vm.stack
            .running_instance_mut()
            .unwrap()
            .root_cnode
            .set(SlotIdx(3), Some(CapHashOrRef::Hash(data_hash)))
            .unwrap();
        let mut regs = Regs::new();
        regs.gpr[7] = 3;
        regs.gpr[8] = 0;
        let mut mem = Mem::new();
        let r = handle_cached(&mut vm, &mut cache, host_op::HOST_SAVE, &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Continue));
        assert_eq!(regs.gpr[7], 1);
        // Debit one page (4096) from initial 8192 → 4096 remaining.
        assert_eq!(vm.kernel_assist.storage_quota_get(0), 4096);
        assert_eq!(
            vm.kernel_assist.host_open(1),
            Some(CapHashOrRef::Hash(data_hash))
        );
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
    fn cache_dependent_host_calls_without_cache_still_trap() {
        // Direct `Vm` handler calls don't carry a cache borrow, so
        // cache-dependent host calls still trap outside invoke_cached.
        for op in [
            host_op::HOST_TYPE_OF,
            host_op::HOST_READ_DATA_CAP,
            host_op::HOST_MINT_DATA_CAP,
            host_op::HOST_OPEN,
            host_op::HOST_SAVE,
            host_op::HOST_CALL,
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

    /// `derive_spawn_cached` publishes a fresh `Cap::Instance` whose
    /// `image_hash_chain` extends the parent's, references the
    /// caller-prepared CNode (with the image's pinned slots overlaid
    /// on top), and lands by hash in the dst slot. Consumes the
    /// prepared-cnode slot.
    #[test]
    fn derive_spawn_cached_publishes_child_instance() {
        let mut vm = fixture_vm();
        let mut cache = CacheDirectory::new();

        // Publish a tiny child image with no pinned/initial slots.
        let mut child_img = javm_cap::image::Image::empty();
        // PVM2 `ecalli 0` — 32-bit custom-0 word at PC 0.
        child_img.code = 0x0000_200Bu32.to_le_bytes().to_vec();
        child_img.jump_table_offsets = vec![0, 0];
        let image_hash = cache
            .put_cap(&Cap::image_with_slots(&child_img, &[], &[]).unwrap())
            .unwrap();

        // Publish an empty prepared cnode.
        let prep_cnode_hash = cache.put_cap(&Cap::empty_cnode(4).unwrap()).unwrap();

        // Put both into the running instance's cnode at known slots.
        let parent_chain = [0xC1; 32];
        {
            let running = vm.stack.running_instance_mut().unwrap();
            running.image_hash_chain = parent_chain;
            running
                .root_cnode
                .set(SlotIdx(3), Some(CapHashOrRef::Hash(image_hash)))
                .unwrap();
            running
                .root_cnode
                .set(SlotIdx(4), Some(CapHashOrRef::Hash(prep_cnode_hash)))
                .unwrap();
        }

        let mut regs = Regs::new();
        regs.gpr[7] = 3; // image slot
        regs.gpr[8] = 4; // prepared cnode slot
        regs.gpr[9] = 7; // dst
        let mut mem = Mem::new();
        let mut handler = CachedEcallHandler {
            vm: &mut vm,
            cache: &mut cache,
        };
        let r = handler.handle(
            EcallKind::Ecalli(host_op::DERIVE_SPAWN),
            &mut regs,
            &mut mem,
        );
        assert!(matches!(r, EcallResult::Continue), "got {:?}", r);

        // dst slot now holds Hash(new_instance_hash).
        let new_target = vm
            .stack
            .running_instance()
            .unwrap()
            .root_cnode
            .get(SlotIdx(7))
            .expect("dst slot populated");
        let new_instance_hash = match new_target {
            CapHashOrRef::Hash(h) => h,
            _ => panic!("expected Hash target"),
        };

        // The published Cap::Instance has the extended chain.
        let cap = cache.get(new_target).expect("instance in cache");
        let inst = match &*cap {
            Cap::Instance(i) => i,
            _ => panic!("expected Cap::Instance"),
        };
        let expected_chain = Blake2b256::hash_pair(&parent_chain, &image_hash);
        assert_eq!(inst.image_hash_chain, expected_chain);
        assert_eq!(inst.image_hash, image_hash);
        assert!(matches!(inst.root_cnode, CapHashOrRef::Hash(_)));

        // The prepared cnode slot is now empty (MOVE semantics).
        assert!(
            vm.stack
                .running_instance()
                .unwrap()
                .root_cnode
                .get(SlotIdx(4))
                .is_none()
        );

        // Hash hygiene: the new instance hash actually matches what
        // cap_hash computes on the published cap.
        assert_eq!(new_instance_hash, cap.cap_hash());
    }

    /// `dispatch_host_call_cached` pushes a child entry on top of
    /// the running instance and moves caller's slot[0] into the
    /// child's slot[0].
    #[test]
    fn host_call_cached_pushes_child_and_moves_slot0() {
        let mut vm = fixture_vm();
        let mut cache = CacheDirectory::new();

        // Publish a no-op image (one Halt instruction) + empty cnode
        // + Cap::Instance referencing them.
        let mut child_img = javm_cap::image::Image::empty();
        child_img.code = 0x0000_200Bu32.to_le_bytes().to_vec();
        child_img.jump_table_offsets = vec![0, 0];
        let image_hash = cache
            .put_cap(&Cap::image_with_slots(&child_img, &[], &[]).unwrap())
            .unwrap();
        let cnode_hash = cache.put_cap(&Cap::empty_cnode(4).unwrap()).unwrap();
        let child_instance_hash = cache
            .put_cap(&Cap::instance_with_overlays(
                [0xCC; 32],
                image_hash,
                cnode_hash,
                &[],
                0,
                [0u64; javm_cap::NUM_REGS],
                0,
                0,
            ))
            .unwrap();

        // Wire the parent: slot 9 → Cap::Instance(child); slot 0 →
        // some marker the child should see in its slot 0.
        let marker_hash = [0xAB; 32];
        {
            let running = vm.stack.running_instance_mut().unwrap();
            running
                .root_cnode
                .set(SlotIdx(9), Some(CapHashOrRef::Hash(child_instance_hash)))
                .unwrap();
            running
                .root_cnode
                .set(SlotIdx(0), Some(CapHashOrRef::Hash(marker_hash)))
                .unwrap();
        }

        let mut regs = Regs::new();
        regs.gpr[7] = 9; // instance_slot
        regs.gpr[8] = 0; // endpoint_idx (the only endpoint, default)
        let mut mem = Mem::new();
        let mut handler = CachedEcallHandler {
            vm: &mut vm,
            cache: &mut cache,
        };
        let r = handler.handle(EcallKind::Ecalli(host_op::HOST_CALL), &mut regs, &mut mem);
        assert!(
            matches!(r, EcallResult::Exit(ExitReason::HostCall(op)) if op == host_op::HOST_CALL),
            "got {:?}",
            r,
        );

        // Stack grew by 1; child is Running.
        assert_eq!(vm.stack.len(), 2);
        assert_eq!(vm.stack.entries()[0].status(), EntryStatus::Waiting);
        assert_eq!(vm.stack.entries()[1].status(), EntryStatus::Running);
        let child = vm.stack.running_instance().unwrap();
        // Child's image identity matches what we published.
        assert_eq!(child.image_hash, image_hash);
        // The scratchpad moved into child's slot[0].
        assert_eq!(
            child.root_cnode.get(SlotIdx(0)),
            Some(CapHashOrRef::Hash(marker_hash))
        );
        // Parent's slot[0] was emptied (MOVE).
        let parent = match &vm.stack.entries()[0] {
            Entry::Instance(e) => e.as_ref(),
            _ => panic!("entry 0 not Instance"),
        };
        assert!(parent.root_cnode.get(SlotIdx(0)).is_none());
    }
}
