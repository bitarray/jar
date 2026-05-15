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

use jar_cap::{
    Blake2b256, Cap, Hash, InstanceCap, SlotIdx, TypeCap, mgmt_cnode_mint, mgmt_cnode_swap,
    mgmt_copy, mgmt_drop, mgmt_move,
};
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
    /// `set_image(image_slot=φ[7])` — atomically swap the running
    /// Instance's image: extend `image_hash_chain`, reload program
    /// from the kernel-assist's image registry.
    pub const SET_IMAGE: u32 = 17;
    /// `host_derive_spawn(image_slot=φ[7], dst_slot=φ[8])` —
    /// mint a fresh Cap::Instance whose image_hash_chain is
    /// chain_extend(spawner.image_hash_chain, image.content_hash).
    pub const DERIVE_SPAWN: u32 = 18;
    /// `host_make_image(...)` — Stage 3.9 stub. Lands when the
    /// in-memory parts encoding is fully spec'd; jar-kernel-v3
    /// validates structurally at host_make_image time.
    pub const MAKE_IMAGE: u32 = 19;
    /// `host_same_type(slot_a=φ[7], slot_b=φ[8])` — compare
    /// `image_hash_chain` of two Cap::Instance values; result (0 or
    /// 1) returned in φ[7].
    pub const HOST_SAME_TYPE: u32 = 20;
    /// `host_type_of(src_slot=φ[7], dst_slot=φ[8])` — mint a
    /// Cap::Type carrying the source Cap::Instance's
    /// `image_hash_chain`; place at dst.
    pub const HOST_TYPE_OF: u32 = 21;
    /// `host_read_data_cap(cap_slot=φ[7], dst_addr=φ[8], len=φ[9])`
    /// — copy bytes from the Cap::Data at `cap_slot` into mapped
    /// memory at `dst_addr`. Honors `DataCap.size`; copies
    /// `min(len, size)` bytes.
    pub const HOST_READ_DATA_CAP: u32 = 22;
    /// `host_mint_data_cap(src_addr=φ[7], len=φ[8], quota_slot=φ[9],
    /// dst_slot=φ[10])` — read bytes from memory; strip trailing
    /// zeros (canonical form §2); content-hash; debit StorageQuota
    /// via KernelAssist; mint Cap::Data; place at dst_slot.
    pub const HOST_MINT_DATA_CAP: u32 = 23;
    /// `host_open(file_slot=φ[7], dst_slot=φ[8])` — materialize the
    /// σ-resident FileCap at `file_slot` into a `Cap::Data` and
    /// place at `dst_slot`. The FileCap is a `Cap::Instance` whose
    /// `image_hash_chain` matches `KernelImage::File` and whose
    /// `content_hash` low 8 bytes encode the `file_id`.
    pub const HOST_OPEN: u32 = 24;
    /// `host_save(data_slot=φ[7], quota_slot=φ[8], dst_slot=φ[9])` —
    /// mint a fresh FileCap from the Cap::Data at `data_slot`,
    /// debiting StorageQuota at `quota_slot`. Result Cap::Instance
    /// (kernel:file) placed at `dst_slot`.
    pub const HOST_SAVE: u32 = 25;
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
                // Stage 3.9 stub. The in-memory parts encoding for
                // host_make_image is not finalized; jar-kernel-v3
                // will land the proper memory-pointer-based variant
                // when chain Images need runtime construction.
                EcallResult::Exit(ExitReason::Trap)
            }
            host_op::HOST_SAME_TYPE => trap_on_err(self.dispatch_host_same_type(regs), |()| {
                EcallResult::Continue
            }),
            host_op::HOST_TYPE_OF => {
                trap_on_err(self.dispatch_host_type_of(regs), |()| EcallResult::Continue)
            }
            host_op::HOST_READ_DATA_CAP => {
                trap_on_err(self.dispatch_host_read_data_cap(regs, _mem), |()| {
                    EcallResult::Continue
                })
            }
            host_op::HOST_MINT_DATA_CAP => {
                trap_on_err(self.dispatch_host_mint_data_cap(regs, _mem), |()| {
                    EcallResult::Continue
                })
            }
            host_op::HOST_OPEN => {
                trap_on_err(self.dispatch_host_open(regs), |()| EcallResult::Continue)
            }
            host_op::HOST_SAVE => {
                trap_on_err(self.dispatch_host_save(regs), |()| EcallResult::Continue)
            }
            _ => {
                // Chain-user host calls (64+) land later. Continue
                // silently for now.
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

    /// `set_image(image_slot=φ[7])`.
    ///
    /// Reads the Cap::Image at the named slot; chain_extends the
    /// running InstanceCap's image_hash_chain with the image's
    /// content_hash; looks up the full Image bytes via
    /// `KernelAssist::image_lookup`; reloads the InstanceEntry's
    /// image, program (via ImageCache), and instance.image_hash_chain.
    ///
    /// Errors:
    /// - `VmError::CallStackEmpty` if no running entry.
    /// - `VmError::SlotKindMismatch` / `SlotEmpty` if the slot does
    ///   not hold a Cap::Image.
    /// - `VmError::ImageNotFound` if the kernel-assist's image
    ///   registry doesn't know this content_hash.
    fn dispatch_set_image(&mut self, regs: &mut Regs) -> Result<(), VmError> {
        let image_slot = SlotIdx((regs.gpr[7] & 0xFF) as u32);

        // 1. Resolve the Cap::Image content_hash from the slot.
        let new_image_hash: jar_cap::CapHash = {
            let running = self
                .stack
                .running_instance()
                .ok_or(VmError::CallStackEmpty)?;
            match running.cnode.get(image_slot)? {
                Some(Cap::Image(c)) => c.content_hash,
                Some(_) => return Err(VmError::SlotKindMismatch(image_slot.get())),
                None => return Err(VmError::SlotEmpty(image_slot.get())),
            }
        };

        // 2. Resolve the full Image bytes via the kernel-assist.
        let new_image = self
            .kernel_assist
            .image_lookup(new_image_hash)
            .ok_or(VmError::ImageNotFound)?;

        // 3. Extend the chain hash.
        let extended_chain = {
            let running = self
                .stack
                .running_instance()
                .ok_or(VmError::CallStackEmpty)?;
            Blake2b256::hash_pair(&running.instance.image_hash_chain, &new_image_hash)
        };

        // 4. Predecode the new image (cached on second invocation).
        let program = self.image_cache.get_or_decode(
            new_image_hash,
            new_image.code.clone(),
            vec![1u8; new_image.code.len()],
            Vec::new(),
        )?;

        // 5. Install the swap into the running InstanceEntry.
        let running = self
            .stack
            .running_instance_mut()
            .ok_or(VmError::CallStackEmpty)?;
        running.instance.image_hash_chain = extended_chain;
        // content_hash semantics post-set_image are a Stage 4 concern
        // (depends on canonical state digest). For Stage 3 we leave
        // the previous content_hash; the chain hash captures the
        // image lineage which is sufficient for type queries.
        running.image = new_image;
        running.program = program;
        Ok(())
    }

    /// `host_derive_spawn(image_slot=φ[7], dst_slot=φ[8])`.
    ///
    /// Mint a fresh `Cap::Instance` whose image_hash_chain is
    /// `chain_extend(self.image_hash_chain, image.content_hash)`.
    /// content_hash is a placeholder for Stage 3 (zeroed) — Stage 4
    /// jar-kernel-v3 defines the canonical state digest and will
    /// populate it.
    fn dispatch_derive_spawn(&mut self, regs: &mut Regs) -> Result<(), VmError> {
        let image_slot = SlotIdx((regs.gpr[7] & 0xFF) as u32);
        let dst_slot = SlotIdx((regs.gpr[8] & 0xFF) as u32);

        // 1. Read Cap::Image at image_slot.
        let new_image_hash: jar_cap::CapHash = {
            let running = self
                .stack
                .running_instance()
                .ok_or(VmError::CallStackEmpty)?;
            match running.cnode.get(image_slot)? {
                Some(Cap::Image(c)) => c.content_hash,
                Some(_) => return Err(VmError::SlotKindMismatch(image_slot.get())),
                None => return Err(VmError::SlotEmpty(image_slot.get())),
            }
        };

        // 2. Derive the child chain hash + cap.
        let child = {
            let running = self
                .stack
                .running_instance()
                .ok_or(VmError::CallStackEmpty)?;
            let extended =
                Blake2b256::hash_pair(&running.instance.image_hash_chain, &new_image_hash);
            InstanceCap {
                image_hash_chain: extended,
                content_hash: [0u8; 32], // Stage 4 fills with canonical state digest.
            }
        };

        // 3. Place the new Cap::Instance at dst_slot (rejects pinned).
        let running = self
            .stack
            .running_instance_mut()
            .ok_or(VmError::CallStackEmpty)?;
        let pinned: Vec<SlotIdx> = running.image.pinned_slots.keys().copied().collect();
        if pinned.contains(&dst_slot) {
            return Err(jar_cap::OpError::SlotPinned(dst_slot.get()).into());
        }
        running.cnode.set(dst_slot, Some(Cap::Instance(child)))?;
        Ok(())
    }

    /// `host_same_type(slot_a=φ[7], slot_b=φ[8])`.
    ///
    /// Result (1 if same image_hash_chain, 0 otherwise) in φ[7].
    fn dispatch_host_same_type(&mut self, regs: &mut Regs) -> Result<(), VmError> {
        let a = SlotIdx((regs.gpr[7] & 0xFF) as u32);
        let b = SlotIdx((regs.gpr[8] & 0xFF) as u32);
        let running = self
            .stack
            .running_instance()
            .ok_or(VmError::CallStackEmpty)?;
        let chain_a = type_chain_at(running.cnode.as_ref(), a)?;
        let chain_b = type_chain_at(running.cnode.as_ref(), b)?;
        regs.gpr[7] = if chain_a == chain_b { 1 } else { 0 };
        Ok(())
    }

    /// `host_type_of(src_slot=φ[7], dst_slot=φ[8])`.
    ///
    /// Reads Cap::Instance at src; mints Cap::Type carrying the same
    /// image_hash_chain; places at dst.
    fn dispatch_host_type_of(&mut self, regs: &mut Regs) -> Result<(), VmError> {
        let src = SlotIdx((regs.gpr[7] & 0xFF) as u32);
        let dst = SlotIdx((regs.gpr[8] & 0xFF) as u32);
        let running = self
            .stack
            .running_instance_mut()
            .ok_or(VmError::CallStackEmpty)?;
        let chain = match running.cnode.get(src)? {
            Some(Cap::Instance(ic)) => ic.image_hash_chain,
            Some(Cap::Type(tc)) => tc.image_hash_chain,
            Some(_) => return Err(VmError::SlotKindMismatch(src.get())),
            None => return Err(VmError::SlotEmpty(src.get())),
        };
        let pinned: Vec<SlotIdx> = running.image.pinned_slots.keys().copied().collect();
        if pinned.contains(&dst) {
            return Err(jar_cap::OpError::SlotPinned(dst.get()).into());
        }
        running.cnode.set(
            dst,
            Some(Cap::Type(TypeCap {
                image_hash_chain: chain,
            })),
        )?;
        Ok(())
    }

    /// `host_read_data_cap(cap_slot=φ[7], dst_addr=φ[8], len=φ[9])`.
    ///
    /// Reads the Cap::Data at `cap_slot`; looks up its bytes via
    /// `KernelAssist::data_lookup`; copies `min(len, size)` bytes
    /// into memory at `dst_addr`. Pads zeros if the stored bytes
    /// (after canonical-form strip) are shorter than `size`.
    fn dispatch_host_read_data_cap(
        &mut self,
        regs: &mut Regs,
        mem: &mut Mem,
    ) -> Result<(), VmError> {
        let cap_slot = SlotIdx((regs.gpr[7] & 0xFF) as u32);
        let dst_addr = regs.gpr[8] as u32;
        let len = regs.gpr[9] as usize;

        let (content_hash, size) = {
            let running = self
                .stack
                .running_instance()
                .ok_or(VmError::CallStackEmpty)?;
            match running.cnode.get(cap_slot)? {
                Some(Cap::Data(c)) => (c.content_hash, c.size),
                Some(_) => return Err(VmError::SlotKindMismatch(cap_slot.get())),
                None => return Err(VmError::SlotEmpty(cap_slot.get())),
            }
        };

        // Canonical-form data may be shorter than `size` (trailing
        // zeros stripped). Pad with zeros up to the declared size.
        let mut bytes = self
            .kernel_assist
            .data_lookup(content_hash)
            .unwrap_or_default();
        if (bytes.len() as u64) < size {
            bytes.resize(size as usize, 0);
        }

        let copy_len = len.min(size as usize);
        mem.write(dst_addr, &bytes[..copy_len])
            .map_err(|_| VmError::Invariant("host_read_data_cap: memory write OOB / RO"))?;
        Ok(())
    }

    /// `host_mint_data_cap(src_addr=φ[7], len=φ[8], quota_slot=φ[9],
    /// dst_slot=φ[10])`.
    ///
    /// Reads bytes from mem[src_addr..src_addr+len]; strips trailing
    /// zeros (canonical form); content-hashes; debits the
    /// StorageQuota referenced by `quota_slot` (Cap::Instance[Quota])
    /// for `size` bytes; mints Cap::Data{content_hash, size: pre-strip};
    /// places at `dst_slot`.
    fn dispatch_host_mint_data_cap(
        &mut self,
        regs: &mut Regs,
        mem: &mut Mem,
    ) -> Result<(), VmError> {
        let src_addr = regs.gpr[7] as u32;
        let len = regs.gpr[8] as usize;
        let quota_slot = SlotIdx((regs.gpr[9] & 0xFF) as u32);
        let dst_slot = SlotIdx((regs.gpr[10] & 0xFF) as u32);

        // 1. Read bytes from memory.
        let raw = mem
            .read(src_addr, len)
            .map_err(|_| VmError::Invariant("host_mint_data_cap: memory read OOB"))?;
        let stripped_len = strip_trailing_zeros_len(&raw);
        let canonical = &raw[..stripped_len];

        // 2. Hash + store.
        let content_hash = self.kernel_assist.data_store(canonical);

        // 3. Debit storage quota.
        let quota_id = {
            let running = self
                .stack
                .running_instance()
                .ok_or(VmError::CallStackEmpty)?;
            match running.cnode.get(quota_slot)? {
                Some(Cap::Instance(ic)) => {
                    // Convention: Quota{id}.content_hash low 8 bytes = quota_id LE.
                    u64::from_le_bytes(
                        ic.content_hash[..8]
                            .try_into()
                            .map_err(|_| VmError::Invariant("quota content_hash too short"))?,
                    )
                }
                Some(_) => return Err(VmError::SlotKindMismatch(quota_slot.get())),
                None => return Err(VmError::SlotEmpty(quota_slot.get())),
            }
        };
        let current = self.kernel_assist.storage_quota_get(quota_id);
        let charge = len as u64;
        if current < charge {
            return Err(VmError::Op(jar_cap::OpError::SlotPinned(0))); // generic op fail
        }
        self.kernel_assist
            .storage_quota_set(quota_id, current - charge);

        // 4. Mint Cap::Data and place at dst.
        let running = self
            .stack
            .running_instance_mut()
            .ok_or(VmError::CallStackEmpty)?;
        let pinned: Vec<SlotIdx> = running.image.pinned_slots.keys().copied().collect();
        if pinned.contains(&dst_slot) {
            return Err(jar_cap::OpError::SlotPinned(dst_slot.get()).into());
        }
        running.cnode.set(
            dst_slot,
            Some(Cap::Data(jar_cap::DataCap {
                content_hash,
                size: len as u64,
            })),
        )?;
        Ok(())
    }

    /// `host_open(file_slot=φ[7], dst_slot=φ[8])`.
    ///
    /// The FileCap is a `Cap::Instance` with low 8 content_hash
    /// bytes = file_id. Materialize the file via
    /// `KernelAssist::host_open` (returns a Cap::Data), then place
    /// at `dst_slot`.
    fn dispatch_host_open(&mut self, regs: &mut Regs) -> Result<(), VmError> {
        let file_slot = SlotIdx((regs.gpr[7] & 0xFF) as u32);
        let dst_slot = SlotIdx((regs.gpr[8] & 0xFF) as u32);

        let file_id = {
            let running = self
                .stack
                .running_instance()
                .ok_or(VmError::CallStackEmpty)?;
            match running.cnode.get(file_slot)? {
                Some(Cap::Instance(ic)) => u64::from_le_bytes(
                    ic.content_hash[..8]
                        .try_into()
                        .map_err(|_| VmError::Invariant("file content_hash too short"))?,
                ),
                Some(_) => return Err(VmError::SlotKindMismatch(file_slot.get())),
                None => return Err(VmError::SlotEmpty(file_slot.get())),
            }
        };

        let data = self
            .kernel_assist
            .host_open(file_id)
            .ok_or(VmError::Invariant("host_open: file_id not registered"))?;

        let running = self
            .stack
            .running_instance_mut()
            .ok_or(VmError::CallStackEmpty)?;
        let pinned: Vec<SlotIdx> = running.image.pinned_slots.keys().copied().collect();
        if pinned.contains(&dst_slot) {
            return Err(jar_cap::OpError::SlotPinned(dst_slot.get()).into());
        }
        running.cnode.set(dst_slot, Some(Cap::Data(data)))?;
        Ok(())
    }

    /// `host_save(data_slot=φ[7], quota_slot=φ[8], dst_slot=φ[9])`.
    ///
    /// Mint a fresh FileCap from the Cap::Data at `data_slot`,
    /// debiting StorageQuota at `quota_slot`. The new FileCap is a
    /// `Cap::Instance` carrying the kernel `File` image_hash; low 8
    /// content_hash bytes encode the new file_id.
    fn dispatch_host_save(&mut self, regs: &mut Regs) -> Result<(), VmError> {
        let data_slot = SlotIdx((regs.gpr[7] & 0xFF) as u32);
        let quota_slot = SlotIdx((regs.gpr[8] & 0xFF) as u32);
        let dst_slot = SlotIdx((regs.gpr[9] & 0xFF) as u32);

        let (data, quota_id) = {
            let running = self
                .stack
                .running_instance()
                .ok_or(VmError::CallStackEmpty)?;
            let data = match running.cnode.get(data_slot)? {
                Some(Cap::Data(d)) => *d,
                Some(_) => return Err(VmError::SlotKindMismatch(data_slot.get())),
                None => return Err(VmError::SlotEmpty(data_slot.get())),
            };
            let quota_id = match running.cnode.get(quota_slot)? {
                Some(Cap::Instance(ic)) => u64::from_le_bytes(
                    ic.content_hash[..8]
                        .try_into()
                        .map_err(|_| VmError::Invariant("quota content_hash too short"))?,
                ),
                Some(_) => return Err(VmError::SlotKindMismatch(quota_slot.get())),
                None => return Err(VmError::SlotEmpty(quota_slot.get())),
            };
            (data, quota_id)
        };

        let new_file_id =
            self.kernel_assist
                .host_save(&data, quota_id)
                .ok_or(VmError::Invariant(
                    "host_save: quota exhausted or kernel-assist unsupported",
                ))?;

        let mut file_content_hash = [0u8; 32];
        file_content_hash[..8].copy_from_slice(&new_file_id.to_le_bytes());
        let new_file_cap = Cap::Instance(InstanceCap {
            image_hash_chain: crate::kernel_assist::kernel_image_hash(
                crate::kernel_assist::KernelImage::File,
            ),
            content_hash: file_content_hash,
        });

        let running = self
            .stack
            .running_instance_mut()
            .ok_or(VmError::CallStackEmpty)?;
        let pinned: Vec<SlotIdx> = running.image.pinned_slots.keys().copied().collect();
        if pinned.contains(&dst_slot) {
            return Err(jar_cap::OpError::SlotPinned(dst_slot.get()).into());
        }
        running.cnode.set(dst_slot, Some(new_file_cap))?;
        Ok(())
    }
}

/// Canonical-form length: number of leading bytes before trailing
/// zeros. Per v3 spec §2 "Cap::Data canonical form": trailing zeros
/// are stripped from the byte buffer before content-hashing.
pub(crate) fn strip_trailing_zeros_len(bytes: &[u8]) -> usize {
    let mut n = bytes.len();
    while n > 0 && bytes[n - 1] == 0 {
        n -= 1;
    }
    n
}

/// Read the `image_hash_chain` for a Cap::Instance or Cap::Type at
/// the named slot (used by host_same_type and host_type_eq). Errors
/// if the slot is empty or holds a different cap kind.
fn type_chain_at(
    cnode: &(dyn jar_cap::CNodeBackend<Cap> + Send + Sync),
    slot: SlotIdx,
) -> Result<jar_cap::CapHash, VmError> {
    match cnode.get(slot)? {
        Some(Cap::Instance(ic)) => Ok(ic.image_hash_chain),
        Some(Cap::Type(tc)) => Ok(tc.image_hash_chain),
        Some(_) => Err(VmError::SlotKindMismatch(slot.get())),
        None => Err(VmError::SlotEmpty(slot.get())),
    }
}

impl<K: KernelAssist> Vm<K> {
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

    // -- 3.9 host calls --

    #[test]
    fn set_image_extends_chain_hash() {
        let mut vm = fixture_vm();
        // Register the target image keyed by [0xAA; 32] (the slot-2
        // ImageCap content_hash).
        let new_img = Arc::new(empty_image());
        vm.kernel_assist.register_image([0xAA; 32], new_img);

        let original_chain = vm
            .stack
            .running_instance()
            .unwrap()
            .instance
            .image_hash_chain;

        let mut regs = Regs::new();
        regs.gpr[7] = 2; // image slot
        let mut mem = Mem::new();
        let r = vm.handle(EcallKind::Ecalli(host_op::SET_IMAGE), &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Continue));

        let new_chain = vm
            .stack
            .running_instance()
            .unwrap()
            .instance
            .image_hash_chain;
        assert_ne!(original_chain, new_chain);
    }

    #[test]
    fn set_image_without_registry_traps() {
        let mut vm = fixture_vm();
        // No register_image call: [0xAA;32] won't resolve.
        let mut regs = Regs::new();
        regs.gpr[7] = 2;
        let mut mem = Mem::new();
        let r = vm.handle(EcallKind::Ecalli(host_op::SET_IMAGE), &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Exit(ExitReason::Trap)));
    }

    #[test]
    fn derive_spawn_mints_extended_chain_instance() {
        let mut vm = fixture_vm();
        let parent_chain = vm
            .stack
            .running_instance()
            .unwrap()
            .instance
            .image_hash_chain;

        let mut regs = Regs::new();
        regs.gpr[7] = 2; // image slot (Cap::Image with content_hash [0xAA;32])
        regs.gpr[8] = 5; // dst slot
        let mut mem = Mem::new();
        let r = vm.handle(
            EcallKind::Ecalli(host_op::DERIVE_SPAWN),
            &mut regs,
            &mut mem,
        );
        assert!(matches!(r, EcallResult::Continue));

        let cnode = &vm.stack.running_instance().unwrap().cnode;
        let child = match cnode.get(SlotIdx(5)).unwrap() {
            Some(Cap::Instance(c)) => *c,
            other => panic!("expected Cap::Instance at dst slot, got {:?}", other),
        };
        assert_ne!(child.image_hash_chain, parent_chain);
    }

    #[test]
    fn host_same_type_compares_chain() {
        let mut vm = fixture_vm();
        let inst_a = InstanceCap {
            image_hash_chain: [0x33; 32],
            content_hash: [0xCC; 32],
        };
        let inst_b = InstanceCap {
            image_hash_chain: [0x33; 32],
            content_hash: [0xDD; 32],
        };
        let inst_c = InstanceCap {
            image_hash_chain: [0x99; 32],
            content_hash: [0xEE; 32],
        };
        {
            let running = vm.stack.running_instance_mut().unwrap();
            running
                .cnode
                .set(SlotIdx(3), Some(Cap::Instance(inst_a)))
                .unwrap();
            running
                .cnode
                .set(SlotIdx(4), Some(Cap::Instance(inst_b)))
                .unwrap();
            running
                .cnode
                .set(SlotIdx(6), Some(Cap::Instance(inst_c)))
                .unwrap();
        }

        let mut regs = Regs::new();
        regs.gpr[7] = 3;
        regs.gpr[8] = 4;
        let mut mem = Mem::new();
        let r = vm.handle(
            EcallKind::Ecalli(host_op::HOST_SAME_TYPE),
            &mut regs,
            &mut mem,
        );
        assert!(matches!(r, EcallResult::Continue));
        assert_eq!(regs.gpr[7], 1);

        regs.gpr[7] = 3;
        regs.gpr[8] = 6;
        let r = vm.handle(
            EcallKind::Ecalli(host_op::HOST_SAME_TYPE),
            &mut regs,
            &mut mem,
        );
        assert!(matches!(r, EcallResult::Continue));
        assert_eq!(regs.gpr[7], 0);
    }

    #[test]
    fn host_type_of_mints_type_cap() {
        let mut vm = fixture_vm();
        let inst = InstanceCap {
            image_hash_chain: [0x77; 32],
            content_hash: [0x11; 32],
        };
        vm.stack
            .running_instance_mut()
            .unwrap()
            .cnode
            .set(SlotIdx(3), Some(Cap::Instance(inst)))
            .unwrap();

        let mut regs = Regs::new();
        regs.gpr[7] = 3;
        regs.gpr[8] = 4;
        let mut mem = Mem::new();
        let r = vm.handle(
            EcallKind::Ecalli(host_op::HOST_TYPE_OF),
            &mut regs,
            &mut mem,
        );
        assert!(matches!(r, EcallResult::Continue));

        let cnode = &vm.stack.running_instance().unwrap().cnode;
        match cnode.get(SlotIdx(4)).unwrap() {
            Some(Cap::Type(tc)) => assert_eq!(tc.image_hash_chain, [0x77; 32]),
            other => panic!("expected Cap::Type at dst, got {:?}", other),
        }
    }

    #[test]
    fn make_image_stubbed_traps() {
        let mut vm = fixture_vm();
        let mut regs = Regs::new();
        let mut mem = Mem::new();
        let r = vm.handle(EcallKind::Ecalli(host_op::MAKE_IMAGE), &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Exit(ExitReason::Trap)));
    }

    // -- 3.10 host calls --

    #[test]
    fn host_read_data_cap_copies_bytes_into_mem() {
        let mut vm = fixture_vm();
        // Seed kernel_assist with bytes at content_hash [0x55; 32].
        let bytes = vec![0x11u8, 0x22, 0x33, 0x44];
        vm.kernel_assist.register_data([0x55; 32], bytes.clone());
        // Place a Cap::Data referencing them at slot 4.
        vm.stack
            .running_instance_mut()
            .unwrap()
            .cnode
            .set(
                SlotIdx(4),
                Some(Cap::Data(jar_cap::DataCap {
                    content_hash: [0x55; 32],
                    size: 4,
                })),
            )
            .unwrap();

        let mut mem = javm_exec::Mem::with_pages(1, javm_exec::perm::RW);
        let mut regs = Regs::new();
        regs.gpr[7] = 4; // cap slot
        regs.gpr[8] = 0x100; // dst addr
        regs.gpr[9] = 4; // len
        let r = vm.handle(
            EcallKind::Ecalli(host_op::HOST_READ_DATA_CAP),
            &mut regs,
            &mut mem,
        );
        assert!(matches!(r, EcallResult::Continue));
        assert_eq!(mem.read(0x100, 4).unwrap(), bytes);
    }

    #[test]
    fn host_mint_data_cap_round_trip() {
        let mut vm = fixture_vm();
        // Seed a Quota cap at slot 5 with quota_id = 7.
        let mut quota_hash = [0u8; 32];
        quota_hash[..8].copy_from_slice(&7u64.to_le_bytes());
        vm.stack
            .running_instance_mut()
            .unwrap()
            .cnode
            .set(
                SlotIdx(5),
                Some(Cap::Instance(InstanceCap {
                    image_hash_chain: [0xCAu8; 32],
                    content_hash: quota_hash,
                })),
            )
            .unwrap();
        vm.kernel_assist.storage_quota_set(7, 1000);

        let mut mem = javm_exec::Mem::with_pages(1, javm_exec::perm::RW);
        let payload = b"hello world";
        mem.write(0x200, payload).unwrap();

        let mut regs = Regs::new();
        regs.gpr[7] = 0x200;
        regs.gpr[8] = payload.len() as u64;
        regs.gpr[9] = 5;
        regs.gpr[10] = 6;
        let r = vm.handle(
            EcallKind::Ecalli(host_op::HOST_MINT_DATA_CAP),
            &mut regs,
            &mut mem,
        );
        assert!(matches!(r, EcallResult::Continue));

        let cnode = &vm.stack.running_instance().unwrap().cnode;
        match cnode.get(SlotIdx(6)).unwrap() {
            Some(Cap::Data(c)) => assert_eq!(c.size, payload.len() as u64),
            other => panic!("expected Cap::Data at dst, got {:?}", other),
        }
        assert_eq!(
            vm.kernel_assist.storage_quota_get(7),
            1000 - payload.len() as u64
        );
    }

    #[test]
    fn host_mint_data_cap_exhausts_quota_traps() {
        let mut vm = fixture_vm();
        let mut quota_hash = [0u8; 32];
        quota_hash[..8].copy_from_slice(&7u64.to_le_bytes());
        vm.stack
            .running_instance_mut()
            .unwrap()
            .cnode
            .set(
                SlotIdx(5),
                Some(Cap::Instance(InstanceCap {
                    image_hash_chain: [0xCAu8; 32],
                    content_hash: quota_hash,
                })),
            )
            .unwrap();
        vm.kernel_assist.storage_quota_set(7, 3); // less than payload

        let mut mem = javm_exec::Mem::with_pages(1, javm_exec::perm::RW);
        mem.write(0x200, b"too much").unwrap();
        let mut regs = Regs::new();
        regs.gpr[7] = 0x200;
        regs.gpr[8] = 8;
        regs.gpr[9] = 5;
        regs.gpr[10] = 6;
        let r = vm.handle(
            EcallKind::Ecalli(host_op::HOST_MINT_DATA_CAP),
            &mut regs,
            &mut mem,
        );
        assert!(matches!(r, EcallResult::Exit(ExitReason::Trap)));
    }

    #[test]
    fn strip_trailing_zeros_basic() {
        assert_eq!(strip_trailing_zeros_len(&[1, 2, 3]), 3);
        assert_eq!(strip_trailing_zeros_len(&[1, 2, 3, 0, 0]), 3);
        assert_eq!(strip_trailing_zeros_len(&[0, 0, 0]), 0);
        assert_eq!(strip_trailing_zeros_len(&[]), 0);
    }

    // -- 3.12 host_open / host_save --

    #[test]
    fn host_open_materializes_registered_file_as_data() {
        let mut vm = fixture_vm();
        // Register file_id 99 → DataCap{hash=[0x77;32], size=12}.
        let data = jar_cap::DataCap {
            content_hash: [0x77u8; 32],
            size: 12,
        };
        vm.kernel_assist.register_file(99, data);
        // Place a FileCap (Cap::Instance with content_hash low 8
        // bytes = file_id 99) at slot 3.
        let mut file_hash = [0u8; 32];
        file_hash[..8].copy_from_slice(&99u64.to_le_bytes());
        vm.stack
            .running_instance_mut()
            .unwrap()
            .cnode
            .set(
                SlotIdx(3),
                Some(Cap::Instance(InstanceCap {
                    image_hash_chain: crate::kernel_assist::kernel_image_hash(
                        crate::kernel_assist::KernelImage::File,
                    ),
                    content_hash: file_hash,
                })),
            )
            .unwrap();

        let mut regs = Regs::new();
        regs.gpr[7] = 3; // file slot
        regs.gpr[8] = 4; // dst slot
        let mut mem = Mem::new();
        let r = vm.handle(EcallKind::Ecalli(host_op::HOST_OPEN), &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Continue));

        let cnode = &vm.stack.running_instance().unwrap().cnode;
        match cnode.get(SlotIdx(4)).unwrap() {
            Some(Cap::Data(c)) => {
                assert_eq!(c.content_hash, [0x77u8; 32]);
                assert_eq!(c.size, 12);
            }
            other => panic!("expected Cap::Data at dst, got {:?}", other),
        }
    }

    #[test]
    fn host_save_mints_file_after_quota_debit() {
        let mut vm = fixture_vm();
        // Quota{quota_id=4} at slot 3 with 1000 bytes.
        let mut quota_hash = [0u8; 32];
        quota_hash[..8].copy_from_slice(&4u64.to_le_bytes());
        vm.stack
            .running_instance_mut()
            .unwrap()
            .cnode
            .set(
                SlotIdx(3),
                Some(Cap::Instance(InstanceCap {
                    image_hash_chain: [0xCAu8; 32],
                    content_hash: quota_hash,
                })),
            )
            .unwrap();
        vm.kernel_assist.storage_quota_set(4, 1000);
        // Data cap at slot 4 (size 100).
        vm.stack
            .running_instance_mut()
            .unwrap()
            .cnode
            .set(
                SlotIdx(4),
                Some(Cap::Data(jar_cap::DataCap {
                    content_hash: [0x66u8; 32],
                    size: 100,
                })),
            )
            .unwrap();

        let mut regs = Regs::new();
        regs.gpr[7] = 4; // data slot
        regs.gpr[8] = 3; // quota slot
        regs.gpr[9] = 5; // dst slot
        let mut mem = Mem::new();
        let r = vm.handle(EcallKind::Ecalli(host_op::HOST_SAVE), &mut regs, &mut mem);
        assert!(matches!(r, EcallResult::Continue));

        // dst should hold a Cap::Instance (FileCap) with kernel:file image_hash.
        let cnode = &vm.stack.running_instance().unwrap().cnode;
        let file_id = match cnode.get(SlotIdx(5)).unwrap() {
            Some(Cap::Instance(ic)) => {
                assert_eq!(
                    ic.image_hash_chain,
                    crate::kernel_assist::kernel_image_hash(
                        crate::kernel_assist::KernelImage::File
                    )
                );
                u64::from_le_bytes(ic.content_hash[..8].try_into().unwrap())
            }
            other => panic!("expected Cap::Instance FileCap at dst, got {:?}", other),
        };
        // file_id should be 1 (the first id minted).
        assert_eq!(file_id, 1);
        // Quota debited by 100.
        assert_eq!(vm.kernel_assist.storage_quota_get(4), 900);

        // Re-open the newly-minted file → DataCap with the original
        // content_hash + size.
        let data = vm.kernel_assist.host_open(file_id).unwrap();
        assert_eq!(data.content_hash, [0x66u8; 32]);
        assert_eq!(data.size, 100);
    }
}
