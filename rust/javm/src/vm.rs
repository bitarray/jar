//! The v3 `Vm` driver.
//!
//! Composes:
//! - The call stack (`crate::callstack::CallStack`).
//! - The kernel-assist hook (`crate::kernel_assist::KernelAssist`).
//! - The image bytecode cache (`crate::image_cache::ImageCache`).
//!
//! Top-level verbs:
//! - [`Vm::invoke_cached`] — resolve an Instance hash from a caller-
//!   supplied `CacheDirectory`, push a working `InstanceEntry`, drive
//!   `javm_exec::Interpreter::run` to completion, return a
//!   [`CallResult`]. The cache holds the Cap::Instance + Cap::Image
//!   content; the Vm holds only the call-stack-side working copy and
//!   ephemeral kernel state.
//! - [`Vm::call_resume`] — resume a Paused stack after a yield.
//!
//! The CacheDirectory is borrowed per invocation (not owned by the Vm) so the
//! same cache can serve both pre-publish (the caller publishes caps
//! into it) and in-flight resolution (host calls read referenced caps
//! by their `CapHashOrRef` target).

use javm_cap::{CacheDirectory, Cap, CapHash, CapHashOrRef, NUM_REGS, SlotKey};
use javm_exec::{Access, CopyingMemory, ExitReason, GasCounter, Mem, Regs, interp::Interpreter};

use crate::callstack::{CallStack, DEFAULT_MAX_DEPTH, Entry, EntryStatus, InstanceEntry};
use crate::ecall::{CachedEcallHandler, host_op};
use crate::error::VmError;
use crate::image_cache::ImageCache;
use crate::kernel_assist::{KernelAssist, KernelImage, kernel_image_hash};

/// Result of a top-level `invoke_cached` / `call_resume`.
///
/// Mirrors v3 spec §5 "Apply terminations":
/// - `Halt`: REPLY-style termination; `return_value = φ[7]`.
/// - `Faulted`: Trap / Panic / PageFault / OOG hard-fault.
/// - `Paused`: yielded.
#[derive(Debug)]
pub enum CallResult {
    Halt {
        /// φ\[7\] (A0) at REPLY time.
        return_value: u64,
        /// Settled hash of the post-HALT Instance state. Identifies a
        /// fresh `Cap::Instance` blob in the cache.
        post_instance_hash: CapHash,
        /// The reflected slot\[0\] target (target's slot\[0\] at HALT).
        /// `None` if the slot was empty.
        reflected_slot0: Option<CapHashOrRef>,
        /// Gas consumed by the apply.
        gas_used: u64,
    },
    Faulted {
        reason: ExitReason,
        /// Reflected slot\[0\] target at fault point.
        reflected_slot0: Option<CapHashOrRef>,
        gas_used: u64,
    },
    Paused {
        /// Marker payload — the cap target read from the yielding
        /// Instance's marker slot at yield time.
        marker_payload: Option<CapHashOrRef>,
        gas_used: u64,
    },
}

/// The v3 VM driver. Parameterized over a `KernelAssist` impl so the
/// integration crate can be tested with the in-process default while
/// jar-kernel-v3 swaps in a σ-aware implementation.
pub struct Vm<K: KernelAssist> {
    pub stack: CallStack,
    pub kernel_assist: K,
    pub image_cache: ImageCache,
}

impl<K: KernelAssist> Vm<K> {
    pub fn new(kernel_assist: K) -> Self {
        Self::with_max_depth(kernel_assist, DEFAULT_MAX_DEPTH)
    }

    pub fn with_max_depth(kernel_assist: K, max_depth: usize) -> Self {
        Self {
            stack: CallStack::new(max_depth),
            kernel_assist,
            image_cache: ImageCache::new(),
        }
    }

    /// CacheDirectory-driven entry point: look up a published `Cap::Instance`
    /// in `cache` by hash, pull its referenced `Cap::Image` from the
    /// same cache, predecode bytecode (cached by `image_hash`), seed
    /// regs + memory + gas, push a working `InstanceEntry`, drive the
    /// interpreter to a termination.
    ///
    /// The cache stays caller-owned and is borrowed for the duration
    /// of the call (host calls walk back through it to resolve nested
    /// cap targets).
    pub fn invoke_cached(
        &mut self,
        cache: &mut CacheDirectory,
        instance_hash: CapHash,
        endpoint_idx: u8,
        args: [u64; 4],
        gas_budget: u64,
    ) -> Result<CallResult, VmError> {
        // 1. Resolve the Cap::Instance + Cap::Image from the cache and
        //    capture the predecode-relevant bits up front so we can
        //    release the borrow before mutating cache via call paths.
        let (entry, mem, regs, gas, gas_initial) = self.build_entry(
            cache,
            CapHashOrRef::Hash(instance_hash),
            endpoint_idx,
            args,
            gas_budget,
        )?;

        // 2. Push and drive.
        let pushed_pos = self.stack.entries().len();
        self.stack.push_instance(entry)?;
        self.drive_and_translate(cache, regs, mem, gas, gas_initial, pushed_pos)
    }

    /// Build an [`InstanceEntry`] + initial registers/memory/gas from
    /// the published cap at `inst_ref`. Used by both `invoke_cached`
    /// and `derive_spawn`/host_call paths that need to push a child
    /// instance.
    pub(crate) fn build_entry(
        &mut self,
        cache: &CacheDirectory,
        inst_ref: CapHashOrRef,
        endpoint_idx: u8,
        args: [u64; 4],
        gas_budget: u64,
    ) -> Result<(InstanceEntry, Mem, Regs, GasCounter, u64), VmError> {
        let instance_cap = cache
            .get(inst_ref.clone())
            .ok_or(VmError::InstanceNotFound)?;
        let inst = match &*instance_cap {
            Cap::Instance(i) => i.clone(),
            _ => return Err(VmError::InstanceNotFound),
        };
        let image_cap = cache
            .get(CapHashOrRef::Hash(inst.image_hash))
            .ok_or(VmError::ImageNotFound)?;
        let img = match &*image_cap {
            Cap::Image(i) => i.clone(),
            _ => return Err(VmError::ImageNotFound),
        };

        // Snapshot the working root cnode.
        let root_cnode_cap = cache
            .get(inst.root_cnode.clone())
            .ok_or(VmError::Invariant("instance root_cnode missing in cache"))?;
        let root_cnode = match &*root_cnode_cap {
            Cap::CNode(cn) => cn.clone(),
            _ => {
                return Err(VmError::Invariant(
                    "root_cnode does not point at Cap::CNode",
                ));
            }
        };

        // Predecode the image bytecode (cache hit when seen before).
        let (code_base, code_bytes) = img
            .code_mapping()
            .ok_or(VmError::Invariant("image has no executable code mapping"))?;
        let program =
            self.image_cache
                .get_or_decode(inst.image_hash, code_bytes.to_vec(), code_base);

        // Locate the endpoint definition (dense array, sentinel =
        // entry_pc == 0).
        let endpoint = img
            .endpoints
            .get(endpoint_idx as usize)
            .ok_or(VmError::Invariant("endpoint index out of range"))?;

        // Memory layout: the data region lives at [DATA_BASE, DATA_BASE +
        // mem.size); the flat buffer is based at DATA_BASE so [0, DATA_BASE)
        // (null guard + code) is out of range and faults — matching the
        // recompiler's page table.
        let mut mem = CopyingMemory::new();
        mem.base = javm_cap::layout::DATA_BASE;
        let data_extent = inst.mem.content_len();
        let mut mem_image = vec![0u8; data_extent as usize];
        if data_extent > 0 {
            // Seed the whole extent from the Instance's memory image (the
            // immutable backing, holding both initial and pinned content).
            inst.mem.copy_into(0, &mut mem_image);
            mem.map_region(
                javm_cap::layout::DATA_BASE as u64,
                data_extent,
                Access::ReadWrite,
                Some(&mem_image),
            )
            .map_err(VmError::MapRegion)?;
        }
        // Re-lay pinned mappings read-only (same bytes, from the seeded image)
        // so a guest store faults — matching the recompiler's PinnedCapRo
        // direct map. No cache lookup needed: the content is already in mem.
        let data_base = javm_cap::layout::DATA_BASE as u64;
        for m in img.mappings.iter() {
            if m.path().is_empty() || !img.mapping_is_pinned(m.start as u32) {
                continue;
            }
            let off = (m.start.saturating_sub(data_base)) as usize;
            let len = (m.size as usize).min(mem_image.len().saturating_sub(off));
            if len > 0 {
                overlay_into(
                    &mut mem,
                    m.start as u32,
                    &mem_image[off..off + len],
                    Access::ReadOnly,
                )?;
            }
        }
        // Category #3: guest PIC data loads of the program's own bytecode
        // page-in the touched code page(s) on first read (read-only), just
        // like the recompiler's lazy code materialization.
        mem.set_code_region(code_base, code_bytes.len() as u32);

        // Regs: endpoint baseline → instance persisted regs (non-zero
        // wins) → caller args at φ[7..=10].
        let mut regs = Regs::new();
        regs.pc = endpoint.entry_pc;
        // The persisted register file is the 13 host-mapped slots; x3/x4
        // (slots 13/14) are invocation-local and start at 0 (Regs::new zeros
        // them), matching the recompiler.
        regs.gpr[..NUM_REGS].copy_from_slice(&endpoint.initial_regs);
        for (i, v) in inst.regs.iter().enumerate() {
            if *v != 0 {
                regs.gpr[i] = *v;
            }
        }
        for (i, v) in args.iter().enumerate() {
            regs.gpr[7 + i] = *v;
        }

        // Gas counter seeded directly from gas_budget. (Gas slot
        // tracking on the Image moved to InstanceCap.gas_remaining in
        // the new model; tests can still observe per-call totals via
        // the local counter.)
        let gas = GasCounter::new(gas_budget);
        let gas_initial = gas_budget;

        // CacheDirectory image-side metadata on the entry for fast host-call
        // lookups (pinned check, yield routing).
        let pinned_slots: Vec<SlotKey> = img.pinned.iter().map(|e| e.slot.clone()).collect();

        let entry = InstanceEntry {
            instance_ref: inst_ref,
            image_hash_chain: inst.image_hash_chain,
            image_hash: inst.image_hash,
            program,
            root_cnode,
            yield_marker_slot: img.yield_marker_slot.clone(),
            pinned_slots,
            regs: Regs::new(),       // placeholder; live regs are in `regs`
            mem: Mem::new(),         // placeholder
            gas: GasCounter::new(0), // placeholder
            status: EntryStatus::Waiting,
        };
        Ok((entry, mem, regs, gas, gas_initial))
    }

    /// Resume the top `ReferenceEntry`: pop it, re-enter the
    /// interpreter on the InstanceEntry it points at (which already
    /// has its saved regs/mem/gas from the yield site), and translate
    /// the next termination.
    ///
    /// Optionally reflects `scratchpad` into the resumed Instance's
    /// slot\[0\] before re-entering — the spec's CALL_RESUME(payload)
    /// pattern.
    ///
    /// Errors:
    /// - `VmError::Invariant` if the top isn't a `ReferenceEntry`.
    /// - `VmError::CallStackEmpty` if the resolved target Instance is
    ///   missing.
    pub fn call_resume(
        &mut self,
        cache: &mut CacheDirectory,
        scratchpad: Option<CapHashOrRef>,
    ) -> Result<CallResult, VmError> {
        // 1. Verify and pop the top ReferenceEntry.
        match self.stack.running() {
            Some(Entry::Reference(_)) => {}
            _ => {
                return Err(VmError::Invariant(
                    "call_resume: top is not a ReferenceEntry",
                ));
            }
        }
        self.stack.pop().ok_or(VmError::CallStackEmpty)?;

        // 2. Find the now-running InstanceEntry's position; reflect
        //    scratchpad into its slot[0] if supplied.
        let pos = self.stack.entries().len() - 1;
        if let Some(target) = scratchpad {
            let inst = self
                .stack
                .running_instance_mut()
                .ok_or(VmError::Invariant("call_resume: no instance after pop"))?;
            inst.root_cnode.set(&SlotKey::from(0u8), Some(target))?;
        }

        // 3. Take the resumed Instance's saved regs/mem/gas out into
        //    locals (replacing with placeholders) for driving the
        //    interpreter.
        let (regs, mem, gas, gas_initial) = {
            let target = self
                .stack
                .running_instance_mut()
                .ok_or(VmError::Invariant("call_resume: no instance"))?;
            let regs = core::mem::replace(&mut target.regs, Regs::new());
            let mem = core::mem::replace(&mut target.mem, Mem::new());
            let gas = core::mem::replace(&mut target.gas, GasCounter::new(0));
            let gas_initial = gas.remaining();
            (regs, mem, gas, gas_initial)
        };

        self.drive_and_translate(cache, regs, mem, gas, gas_initial, pos)
    }

    /// Stub for DROP_PAUSED. Lands with the σ-resident Paused state
    /// machine (Stage 4).
    pub fn drop_paused(&mut self, _target_slot: javm_cap::SlotPath) -> Result<(), VmError> {
        Err(VmError::Invariant(
            "DROP_PAUSED requires σ-resident Paused state (Stage 4)",
        ))
    }

    /// Drive `Interpreter::run` on the InstanceEntry at `pushed_pos`
    /// using the supplied regs/mem/gas, then translate the
    /// termination.
    ///
    /// Paused-on-yield is detected by a structural side-effect:
    /// `host_yield` (Stage 3.8) pushes a `ReferenceEntry` on top of
    /// the yielder. After `Interpreter::run` returns, if the stack is
    /// taller than `pushed_pos + 1`, a yield occurred — leave the
    /// stack in that shape and return `CallResult::Paused`. Otherwise
    /// pop the entry and translate Halt / Fault as usual.
    fn drive_and_translate(
        &mut self,
        cache: &mut CacheDirectory,
        mut regs: Regs,
        mut mem: Mem,
        mut gas: GasCounter,
        gas_initial: u64,
        pushed_pos: usize,
    ) -> Result<CallResult, VmError> {
        // `cur_pos` tracks which InstanceEntry the interpreter is
        // driving right now. Starts at `pushed_pos` (the entry
        // `invoke_cached`/`call_resume` pushed); grows by 1 on each
        // nested HOST_CALL, shrinks by 1 on each nested HALT. The
        // loop exits when the entry at `pushed_pos` itself terminates
        // (Halt/Fault) or yields (host_yield pushes a ReferenceEntry
        // above us — detected post-loop).
        let mut cur_pos = pushed_pos;
        let exit = loop {
            let program = match &self.stack.entries()[cur_pos] {
                Entry::Instance(e) => e.program.clone(),
                _ => return Err(VmError::Invariant("cur_pos points at non-Instance")),
            };
            let mut handler = CachedEcallHandler { vm: self, cache };
            let exit = Interpreter::run_program(
                program.as_ref(),
                &mut regs,
                &mut mem,
                &mut gas,
                &mut handler,
            );

            // SET_IMAGE re-entry: the running entry's image+program
            // were swapped by `dispatch_set_image_cached`; re-enter
            // `Interpreter::run` on the same frame with the same
            // live state.
            if matches!(exit, ExitReason::HostCall(op) if op == host_op::SET_IMAGE) {
                continue;
            }

            // HOST_CALL push: `dispatch_host_call_cached` pushed a
            // child InstanceEntry above us. Save the parent's live
            // regs/mem into its entry so we can restore them when the
            // child halts; take the child's stashed initial state.
            // Gas stays threaded (shared pool).
            if matches!(exit, ExitReason::HostCall(op) if op == host_op::HOST_CALL) {
                if self.stack.entries().len() != cur_pos + 2 {
                    return Err(VmError::Invariant(
                        "HOST_CALL exit without expected child push",
                    ));
                }
                if let Some(Entry::Instance(parent)) = self.stack.entries_mut().get_mut(cur_pos) {
                    parent.regs = regs;
                    parent.mem = mem;
                }
                cur_pos += 1;
                let child = self
                    .stack
                    .running_instance_mut()
                    .ok_or(VmError::Invariant("no child after HOST_CALL push"))?;
                regs = core::mem::replace(&mut child.regs, Regs::new());
                mem = core::mem::replace(&mut child.mem, Mem::new());
                continue;
            }

            // Nested HALT: a child halted while a parent waits below.
            // Take the child's slot[0] (the spec's reflected
            // scratchpad), pop the child, restore the parent's
            // regs/mem, plant slot[0] in the parent.
            if matches!(exit, ExitReason::Halt) && cur_pos > pushed_pos {
                let child_slot0 = self
                    .stack
                    .running_instance_mut()
                    .ok_or(VmError::Invariant("no child to halt"))?
                    .root_cnode
                    .take(&SlotKey::from(0u8))
                    .ok()
                    .flatten();
                self.stack.pop();
                cur_pos -= 1;
                let parent = self
                    .stack
                    .running_instance_mut()
                    .ok_or(VmError::Invariant("parent gone after child pop"))?;
                regs = core::mem::replace(&mut parent.regs, Regs::new());
                mem = core::mem::replace(&mut parent.mem, Mem::new());
                if let Some(s0) = child_slot0 {
                    parent.root_cnode.set(&SlotKey::from(0u8), Some(s0))?;
                }
                continue;
            }

            break exit;
        };

        let gas_used = gas_initial.saturating_sub(gas.remaining());

        // OOG: reconcile the meter to 0 and try to route a synthetic
        // OogMarker yield. On match the stack grows (push_reference)
        // and `oog_marker_payload` carries the `Gas{meter_id}` cap
        // target that the catcher receives as its payload. On no
        // match, leave the stack untouched and let the Faulted arm
        // handle it as a hard OOG.
        let oog_marker_payload = if matches!(exit, ExitReason::OutOfGas) {
            self.reconcile_and_route_oog(pushed_pos)
        } else {
            None
        };

        // Did host_yield (or OOG routing) push a ReferenceEntry above us?
        let yielded = self.stack.entries().len() > pushed_pos + 1
            && matches!(self.stack.running(), Some(Entry::Reference(_)));

        if yielded {
            // Read marker payload. For a synthetic OOG yield, the
            // payload is the Gas{meter_id} cap. For ordinary
            // host_yield, read from the yielder's slot referenced by
            // φ[7] at yield time.
            let marker_payload = if let Some(p) = oog_marker_payload {
                Some(p)
            } else {
                let marker_slot = SlotKey::from((regs.gpr[7] & 0xFF) as u8);
                let yielder = match &self.stack.entries()[pushed_pos] {
                    Entry::Instance(e) => e.as_ref(),
                    _ => return Err(VmError::Invariant("yielder is not an Instance")),
                };
                yielder.root_cnode.get(&marker_slot)
            };

            // Save live state back into the yielder InstanceEntry.
            let yielder = match &mut self.stack.entries_mut()[pushed_pos] {
                Entry::Instance(e) => e.as_mut(),
                _ => return Err(VmError::Invariant("yielder is not an Instance")),
            };
            yielder.regs = regs;
            yielder.mem = mem;
            yielder.gas = gas;

            return Ok(CallResult::Paused {
                marker_payload,
                gas_used,
            });
        }

        // Halt / Fault path: top of stack is the InstanceEntry we drove.
        if let Some(top) = self.stack.running_instance_mut() {
            top.regs = regs;
            top.mem = mem;
            top.gas = gas;
        }

        // Pop the running entry. We need to compute the post-instance
        // hash by settling the working state back into the cache;
        // this captures the cnode + overlays as a fresh blob.
        let popped = self
            .stack
            .pop()
            .ok_or(VmError::Invariant("stack empty after Interpreter::run"))?;

        let (entry, slot0_target) = match popped {
            Entry::Instance(e) => {
                let mut e = *e;
                let slot0 = e.root_cnode.take(&SlotKey::from(0u8)).ok().flatten();
                (e, slot0)
            }
            _ => return Err(VmError::Invariant("popped a non-Instance entry")),
        };

        let post_instance_hash = if matches!(exit, ExitReason::Halt) {
            self.settle_post_instance(cache, &entry)?
        } else {
            // Non-Halt terminations don't produce a fresh published
            // post-instance; surface the original hash if it was
            // hash-resolved (else zero).
            match entry.instance_ref {
                CapHashOrRef::Hash(h) => h,
                CapHashOrRef::Ref(_) => [0u8; 32],
            }
        };

        Ok(match exit {
            ExitReason::Halt => CallResult::Halt {
                return_value: entry.regs.gpr[7],
                post_instance_hash,
                reflected_slot0: slot0_target,
                gas_used,
            },
            ExitReason::HostCall(_) | ExitReason::Ecall => CallResult::Paused {
                marker_payload: slot0_target,
                gas_used,
            },
            ExitReason::Trap
            | ExitReason::Panic
            // TODO(oog-as-pause): uncaught OOG is treated as a hard
            // (terminal) fault here, but unlike Trap/Panic/PageFault it is
            // NOT semantically terminal. OOG can only fire at a per-block
            // gas check — i.e. at a `bb_start` — so it is a *sound* resume
            // point (see docs/pvm-isa/discussions/pause-and-bb-start.md).
            // It should eventually become a resumable pause
            // (Paused-persistent) so a chain can supply more gas and resume
            // at the OOG bb_start instead of discarding the instance's
            // work. (A *caught* OOG already yields via
            // reconcile_and_route_oog; this arm is the uncaught case.)
            // Open design question: data-flow "OOG-as-fault vs
            // Paused-persistent".
            | ExitReason::OutOfGas
            | ExitReason::PageFault(_) => CallResult::Faulted {
                reason: exit,
                reflected_slot0: slot0_target,
                gas_used,
            },
        })
    }

    /// Publish the post-HALT working state of `entry` back into the
    /// cache as a fresh Cap::Instance blob. Returns the new hash. The
    /// new entry references the same image and a freshly-published
    /// cnode (so the cache stores the cnode snapshot too).
    fn settle_post_instance(
        &mut self,
        cache: &mut CacheDirectory,
        entry: &InstanceEntry,
    ) -> Result<CapHash, VmError> {
        // Build the working cnode as a Cap<Global> and put it. We only
        // flatten the materialized entries; unmaterialized (`Missing`)
        // slots aren't valid mid-execution and shouldn't appear here.
        // The radix keys are physical (`Hasher(k)`), so we copy them
        // verbatim rather than re-deriving from a logical slot index.
        let cnode_hash = {
            let mut cnode = javm_cap::CNodeCap::new();
            for (key, mo) in entry.root_cnode.slots.iter() {
                if let ssz::MissingOr::Materialized(t) = mo {
                    cnode
                        .slots
                        .insert(*key, ssz::MissingOr::Materialized(t.clone()));
                }
            }
            cache.put_cap(&Cap::CNode(cnode))?
        };

        // Collect rw_overlay bytes from the live mem. We don't have
        // first-class knowledge of which mappings count as overlays
        // post-halt; for V1 we simply read each mapping at its
        // declared start/size from the image. Image references stay
        // valid as long as the cap is in the cache.
        let image_cap = cache
            .get(CapHashOrRef::Hash(entry.image_hash))
            .ok_or(VmError::ImageNotFound)?;
        let img = match &*image_cap {
            Cap::Image(i) => i.clone(),
            _ => return Err(VmError::ImageNotFound),
        };
        // Settle the evolved memory into a fresh `DataCap` (= the View folded
        // into a new immutable backing). Snapshot each mapping's live
        // `[start, start+size)` into the extent-sized buffer at its offset above
        // DATA_BASE. Pinned mappings are read-only, so they snapshot back
        // unchanged (idempotent); initial mappings carry the guest's writes.
        let data_base = javm_cap::layout::DATA_BASE as u64;
        let mem_top = img
            .mappings
            .iter()
            .map(|m| m.start + m.size)
            .max()
            .unwrap_or(data_base);
        let extent = page_round_up_u64(mem_top.saturating_sub(data_base));
        let mut buf = vec![0u8; extent as usize];
        for m in img.mappings.iter() {
            if m.path().is_empty() {
                continue;
            }
            let len = m.size as usize;
            if let Ok(bytes) = entry.mem.read(m.start as u32, len) {
                let off = (m.start - data_base) as usize;
                let n = bytes.len().min(buf.len().saturating_sub(off));
                buf[off..off + n].copy_from_slice(&bytes[..n]);
            }
        }
        let mem_dc = javm_cap::DataCap::from_bytes_sized(&buf, extent);

        let hash = cache.put_cap(&Cap::instance_with_mem(
            entry.image_hash_chain,
            entry.image_hash,
            cnode_hash,
            mem_dc,
            // Persist the 13 host-mapped slots; x3/x4 are invocation-local.
            entry.regs.gpr[..NUM_REGS]
                .try_into()
                .expect("13 persisted regs"),
            entry.regs.pc,
            entry.gas.remaining(),
        ))?;
        Ok(hash)
    }

    /// Reconcile the gas meter to 0 (the local counter has just been
    /// exhausted) and attempt to route a synthetic OogMarker yield
    /// through the call stack. On match: push a ReferenceEntry at
    /// the catcher's position and return the Gas{meter_id} cap from
    /// the yielder's gas-cap slot (the marker_payload). On no match:
    /// return None — caller surfaces this as a hard fault.
    fn reconcile_and_route_oog(&mut self, yielder_pos: usize) -> Option<CapHashOrRef> {
        // 1. Find the Gas{meter_id} cap target. In the new model we
        //    don't have an image-declared "gas_slot"; the meter id
        //    convention is encoded directly on the Instance's
        //    persisted regs[12] (placeholder convention) OR not at
        //    all. For V1 we route OOG only when the catcher chain
        //    explicitly registers the OogMarker hash.
        let oog_hash = kernel_image_hash(KernelImage::OogMarker);

        // 2. Walk stack top→bottom (skipping the yielder itself) for
        //    a YieldCatcher catching the OogMarker hash.
        let stack_len = self.stack.entries().len();
        let mut target_pos: Option<usize> = None;
        for pos in (0..yielder_pos).rev() {
            let ie = match &self.stack.entries()[pos] {
                Entry::Instance(ie) => ie.as_ref(),
                Entry::Reference(_) => continue,
            };
            let Some(catcher_slot) = ie.yield_marker_slot.clone() else {
                continue;
            };
            // Catcher hash is the image_hash_chain at the catcher
            // slot. Per the legacy model we looked up Cap::Instance;
            // here we just key on the slot target's hash form
            // (CapHashOrRef::Hash) — that's the marker template hash.
            let catcher_hash = match ie.root_cnode.get(&catcher_slot) {
                Some(CapHashOrRef::Hash(h)) => h,
                _ => continue,
            };
            let markers = self.kernel_assist.yield_catcher_markers(catcher_hash);
            if markers.contains(&oog_hash) {
                target_pos = Some(pos);
                break;
            }
        }

        // 3. On match, push the reference. The marker payload is the
        //    well-known oog_hash itself (carried as Hash form).
        let _ = stack_len;
        match target_pos {
            Some(pos) => {
                self.stack.push_reference(pos).ok()?;
                Some(CapHashOrRef::Hash(oog_hash))
            }
            None => None,
        }
    }
}

/// Round up a u64 byte count to PAGE_SIZE granularity.
fn page_round_up_u64(n: u64) -> u64 {
    let p = javm_exec::PAGE_SIZE as u64;
    n.div_ceil(p) * p
}

/// Lay `data` into mem at `start` with `access`, page-rounding the
/// size. No-op if `data` is empty.
fn overlay_into(
    mem: &mut CopyingMemory,
    start: u32,
    data: &[u8],
    access: Access,
) -> Result<(), VmError> {
    if data.is_empty() {
        return Ok(());
    }
    let size = page_round_up_u64(data.len() as u64);
    mem.map_region(start as u64, size, access, Some(data))
        .map_err(VmError::MapRegion)
}

impl<K: KernelAssist + std::fmt::Debug> std::fmt::Debug for Vm<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vm")
            .field("stack", &self.stack)
            .field("kernel_assist", &self.kernel_assist)
            .field("image_cache_len", &self.image_cache.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel_assist::InProcessKernelAssist;
    use javm_cap::image::Image;
    use javm_cap::{CacheDirectory, Cap, NUM_REGS};
    use std::collections::BTreeMap;

    fn empty_image_with_code(code: Vec<u8>) -> Image {
        Image {
            code,
            endpoints: BTreeMap::new(),
            // Code is mapped at the fixed CODE_BASE; no data mappings.
            memory_mappings: Vec::new(),
            pinned_slots: BTreeMap::new(),
            initial_slots: BTreeMap::new(),
            yield_marker_slot: None,
        }
    }

    /// Publish an Image + empty root cnode + a Cap::Instance referencing
    /// them; return the instance hash and the cache.
    fn publish_simple_instance(cache: &mut CacheDirectory, image: Image) -> CapHash {
        let image_hash = cache
            .put_cap(&Cap::image_with_slots(&image, &[], &[]).unwrap())
            .unwrap();
        let cnode_hash = cache.put_cap(&Cap::empty_cnode()).unwrap();
        cache
            .put_cap(&Cap::instance_with_mem(
                [0xAA; 32],
                image_hash,
                cnode_hash,
                javm_cap::DataCap::empty(),
                [0u64; NUM_REGS],
                0,
                0,
            ))
            .unwrap()
    }

    #[test]
    fn new_constructs_empty_vm() {
        let vm = Vm::new(InProcessKernelAssist::new());
        assert!(vm.stack.is_empty());
        assert!(vm.image_cache.is_empty());
    }

    #[test]
    fn invoke_cached_trap_returns_faulted() {
        // PVM2 `trap` = custom-0 funct3=000, word 0x0000_000B.
        let img = empty_image_with_code(0x0000_000Bu32.to_le_bytes().to_vec());
        let mut cache = CacheDirectory::new();
        let inst_hash = publish_simple_instance(&mut cache, img);

        let mut vm = Vm::new(InProcessKernelAssist::new());
        let r = vm
            .invoke_cached(&mut cache, inst_hash, 0, [0; 4], 1000)
            .unwrap();
        assert!(matches!(
            r,
            CallResult::Faulted {
                reason: ExitReason::Trap,
                ..
            }
        ));
        assert!(vm.stack.is_empty());
    }

    #[test]
    fn invoke_cached_ecalli_zero_halts() {
        // PVM2 `ecalli 0` = custom-0 funct3=010, imm=0, word 0x0000_200B.
        let img = empty_image_with_code(0x0000_200Bu32.to_le_bytes().to_vec());
        let mut cache = CacheDirectory::new();
        let inst_hash = publish_simple_instance(&mut cache, img);

        let mut vm = Vm::new(InProcessKernelAssist::new());
        let r = vm
            .invoke_cached(&mut cache, inst_hash, 0, [0; 4], 1000)
            .unwrap();
        assert!(matches!(
            r,
            CallResult::Halt {
                return_value: 0,
                ..
            }
        ));
        assert!(vm.stack.is_empty());
    }

    #[test]
    fn invoke_cached_load_imm_then_reply() {
        // PVM2 sequence: set the slot-7 register (= RV x10) to 42, then
        // `ecalli 0` to halt with the value as return-value.
        //   addi x10, x0, 42 → I-type, imm=42, rs1=0, f3=0, rd=10, op=0x13.
        //   word = (42 << 20) | (10 << 7) | 0x13 = 0x02A0_0513
        //   ecalli 0 → 0x0000_200B (as above).
        let mut code: Vec<u8> = Vec::new();
        code.extend_from_slice(&0x02A0_0513u32.to_le_bytes());
        code.extend_from_slice(&0x0000_200Bu32.to_le_bytes());
        let img = empty_image_with_code(code);

        let mut cache = CacheDirectory::new();
        let inst_hash = publish_simple_instance(&mut cache, img);

        let mut vm = Vm::new(InProcessKernelAssist::new());
        let r = vm
            .invoke_cached(&mut cache, inst_hash, 0, [0; 4], 1000)
            .unwrap();
        match r {
            CallResult::Halt {
                return_value,
                gas_used,
                ..
            } => {
                assert_eq!(return_value, 42);
                assert!(gas_used > 0);
            }
            other => panic!("expected Halt, got {:?}", other),
        }
    }

    /// End-to-end at the PVM2 level: M does `host_call(slot=9,
    /// endpoint=0)` to enter S, S halts, M halts. Verifies the
    /// `drive_and_translate` loop's HOST_CALL push + nested HALT pop
    /// arms wire up correctly. The test simply requires the chain to
    /// terminate without trapping or infinite looping.
    #[test]
    fn invoke_cached_host_call_into_child_then_halts() {
        // S's bytecode: `addi x10, x0, 42; ecalli 0` (slot 7 ↔ x10).
        let s_img = {
            let mut code: Vec<u8> = Vec::new();
            code.extend_from_slice(&0x02A0_0513u32.to_le_bytes()); // addi x10, x0, 42
            code.extend_from_slice(&0x0000_200Bu32.to_le_bytes()); // ecalli 0
            empty_image_with_code(code)
        };

        // M's bytecode:
        //   addi x10, x0, 9     ; slot 7 (= x10) = 9 (target slot for host_call)
        //   addi x11, x0, 0     ; slot 8 (= x11) = 0 (endpoint)
        //   ecalli 26           ; HOST_CALL
        //   ecalli 0            ; HALT
        let m_img = {
            let mut code: Vec<u8> = Vec::new();
            code.extend_from_slice(&0x0090_0513u32.to_le_bytes()); // addi x10, x0, 9
            code.extend_from_slice(&0x0000_0593u32.to_le_bytes()); // addi x11, x0, 0
            // ecalli 26: imm=26, f3=010, op custom-0.
            //   word = (26 << 20) | (0b010 << 12) | (0b00010 << 2) | 0b11
            //        = 0x01A0_200B
            code.extend_from_slice(&0x01A0_200Bu32.to_le_bytes());
            code.extend_from_slice(&0x0000_200Bu32.to_le_bytes()); // ecalli 0
            empty_image_with_code(code)
        };

        // Publish S as a complete Cap::Instance.
        let mut cache = CacheDirectory::new();
        let s_inst_hash = publish_simple_instance(&mut cache, s_img);

        // Publish M with a root cnode that has slot 9 = Hash(S_inst).
        let m_image_hash = cache
            .put_cap(&Cap::image_with_slots(&m_img, &[], &[]).unwrap())
            .unwrap();
        let m_cnode_hash = {
            let mut cn = javm_cap::CNodeCap::new();
            cn.set(&SlotKey::from(9u8), Some(CapHashOrRef::Hash(s_inst_hash)))
                .unwrap();
            cache.put_cap(&Cap::CNode(cn)).unwrap()
        };
        let m_inst_hash = cache
            .put_cap(&Cap::instance_with_mem(
                [0xAA; 32],
                m_image_hash,
                m_cnode_hash,
                javm_cap::DataCap::empty(),
                [0u64; NUM_REGS],
                0,
                0,
            ))
            .unwrap();

        let mut vm = Vm::new(InProcessKernelAssist::new());
        let r = vm
            .invoke_cached(&mut cache, m_inst_hash, 0, [0; 4], 100_000)
            .unwrap();
        assert!(
            matches!(r, CallResult::Halt { .. }),
            "expected Halt, got {:?}",
            r,
        );
        assert!(vm.stack.is_empty());
    }

    #[test]
    fn invoke_cached_oog_returns_faulted() {
        // PVM2 `jal x0, 0` — a 4-byte self-jump. Runs forever (each
        // iteration is a 1-instruction basic block) until the gas
        // budget runs out.
        let code = 0x0000_006Fu32.to_le_bytes().to_vec();
        let img = empty_image_with_code(code);
        let mut cache = CacheDirectory::new();
        let inst_hash = publish_simple_instance(&mut cache, img);
        let mut vm = Vm::new(InProcessKernelAssist::new());
        let r = vm
            .invoke_cached(&mut cache, inst_hash, 0, [0; 4], 3)
            .unwrap();
        assert!(matches!(
            r,
            CallResult::Faulted {
                reason: ExitReason::OutOfGas,
                ..
            }
        ));
    }
}
