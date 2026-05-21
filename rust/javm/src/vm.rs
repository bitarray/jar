//! The v3 `Vm` driver.
//!
//! Composes:
//! - The call stack (`crate::callstack::CallStack`).
//! - The kernel-assist hook (`crate::kernel_assist::KernelAssist`).
//! - The image bytecode cache (`crate::image_cache::ImageCache`).
//!
//! Top-level verbs:
//! - [`Vm::invoke_cached`] — resolve an Instance hash from a caller-
//!   supplied `Cache<Global>`, push a working `InstanceEntry`, drive
//!   `javm_exec::Interpreter::run` to completion, return a
//!   [`CallResult`]. The cache holds the Cap::Instance + Cap::Image
//!   content; the Vm holds only the call-stack-side working copy and
//!   ephemeral kernel state.
//! - [`Vm::call_resume`] — resume a Paused stack after a yield.
//!
//! The Cache is borrowed per invocation (not owned by the Vm) so the
//! same cache can serve both pre-publish (the caller publishes caps
//! into it) and in-flight resolution (host calls read referenced caps
//! by their `CapHashOrRef` target).

use allocator_api2::alloc::Global;
use javm_cap::{Cache, Cap, CapHash, CapHashOrRef, SlotIdx};
use javm_exec::{Access, CopyingMemory, ExitReason, GasCounter, Interpreter, Mem, Regs};

use crate::callstack::{CallStack, DEFAULT_MAX_DEPTH, Entry, EntryStatus, InstanceEntry};
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

    /// Cache-driven entry point: look up a published `Cap::Instance`
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
        cache: &mut Cache<Global>,
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
    fn build_entry(
        &mut self,
        cache: &Cache<Global>,
        inst_ref: CapHashOrRef,
        endpoint_idx: u8,
        args: [u64; 4],
        gas_budget: u64,
    ) -> Result<(InstanceEntry, Mem, Regs, GasCounter, u64), VmError> {
        let instance_cap = cache.get(inst_ref).ok_or(VmError::InstanceNotFound)?;
        let inst = match instance_cap {
            Cap::Instance(i) => i.clone(),
            _ => return Err(VmError::InstanceNotFound),
        };
        let image_cap = cache
            .get(CapHashOrRef::Hash(inst.image_hash))
            .ok_or(VmError::ImageNotFound)?;
        let img = match image_cap {
            Cap::Image(i) => i.clone(),
            _ => return Err(VmError::ImageNotFound),
        };

        // Snapshot the working root cnode.
        let root_cnode = match cache
            .get(inst.root_cnode)
            .ok_or(VmError::Invariant("instance root_cnode missing in cache"))?
        {
            Cap::CNode(cn) => cn.clone(),
            _ => {
                return Err(VmError::Invariant(
                    "root_cnode does not point at Cap::CNode",
                ));
            }
        };

        // Predecode the image bytecode (cache hit when seen before).
        let unpacked_bitmask = javm_exec::unpack_bitmask(img.bitmask.as_slice(), img.code.len());
        let program = self.image_cache.get_or_decode(
            inst.image_hash,
            img.code.as_slice().to_vec(),
            unpacked_bitmask,
            img.jump_table.as_slice().to_vec(),
        )?;

        // Locate the endpoint definition (dense array, sentinel =
        // entry_pc == 0).
        let endpoint = img
            .endpoints
            .get(endpoint_idx as usize)
            .ok_or(VmError::Invariant("endpoint index out of range"))?;

        // Memory layout: base RW region sized to instance.mem_size,
        // plus per-overlay regions.
        let mut mem = CopyingMemory::new();
        let mem_size_pages = page_round_up_u64(inst.mem_size as u64);
        if mem_size_pages > 0 {
            mem.map_region(0, mem_size_pages, Access::ReadWrite, None)
                .map_err(VmError::MapRegion)?;
        }
        for overlay_entry in inst.rw_overlays.iter() {
            overlay_into(
                &mut mem,
                overlay_entry.start,
                overlay_entry.bytes.as_slice(),
                Access::ReadWrite,
            )?;
        }

        // Regs: endpoint baseline → instance persisted regs (non-zero
        // wins) → caller args at φ[7..=10].
        let mut regs = Regs::new();
        regs.pc = endpoint.entry_pc;
        regs.gpr = endpoint.initial_regs;
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

        // Cache image-side metadata on the entry for fast host-call
        // lookups (pinned check, yield routing).
        let pinned_slots: Vec<SlotIdx> = img.pinned.iter().map(|e| e.slot).collect();

        let entry = InstanceEntry {
            instance_ref: inst_ref,
            image_hash_chain: inst.image_hash_chain,
            image_hash: inst.image_hash,
            program,
            root_cnode,
            yield_marker_slot: img.yield_marker_slot,
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
        cache: &mut Cache<Global>,
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
            inst.root_cnode.set(SlotIdx(0), Some(target))?;
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
        cache: &mut Cache<Global>,
        mut regs: Regs,
        mut mem: Mem,
        mut gas: GasCounter,
        gas_initial: u64,
        pushed_pos: usize,
    ) -> Result<CallResult, VmError> {
        let program = match &self.stack.entries()[pushed_pos] {
            Entry::Instance(e) => e.program.clone(),
            _ => return Err(VmError::Invariant("pushed_pos points at non-Instance")),
        };

        let exit = Interpreter::run(program.as_ref(), &mut regs, &mut mem, &mut gas, self);

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
                let marker_slot = SlotIdx((regs.gpr[7] & 0xFF) as u32);
                let yielder = match &self.stack.entries()[pushed_pos] {
                    Entry::Instance(e) => e.as_ref(),
                    _ => return Err(VmError::Invariant("yielder is not an Instance")),
                };
                yielder.root_cnode.get(marker_slot)
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
                let slot0 = e.root_cnode.take(SlotIdx(0)).ok().flatten();
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
        cache: &mut Cache<Global>,
        entry: &InstanceEntry,
    ) -> Result<CapHash, VmError> {
        // Publish the working cnode as a fresh blob. We only flatten the
        // materialized entries; unmaterialized (`Missing`) slots aren't
        // valid mid-execution and the SparseList shouldn't contain them.
        let cnode_entries: Vec<(SlotIdx, CapHashOrRef)> = entry
            .root_cnode
            .slots
            .iter()
            .filter_map(|(idx, mo)| match mo {
                ssz::MissingOr::Materialized(t) => Some((SlotIdx(idx as u32), *t)),
                ssz::MissingOr::Missing(_) => None,
            })
            .collect();
        let cnode_hash = cache.publish_cnode(entry.root_cnode.size_log, &cnode_entries)?;

        // Collect rw_overlay bytes from the live mem. We don't have
        // first-class knowledge of which mappings count as overlays
        // post-halt; for V1 we simply read each mapping at its
        // declared start/size from the image. Image references stay
        // valid as long as the cap is in the cache.
        let image_cap = cache
            .get(CapHashOrRef::Hash(entry.image_hash))
            .ok_or(VmError::ImageNotFound)?;
        let img = match image_cap {
            Cap::Image(i) => i.clone(),
            _ => return Err(VmError::ImageNotFound),
        };
        let mut overlay_bufs: Vec<(u32, Vec<u8>)> = Vec::new();
        for m in img.mappings.iter() {
            // V1: snapshot the live mem [start, start + size) into an
            // overlay buffer if the read succeeds.
            let start = m.start as u32;
            let len = m.size as usize;
            if let Ok(bytes) = entry.mem.read(start, len) {
                overlay_bufs.push((start, bytes));
            }
        }
        let overlays_borrowed: Vec<(u32, &[u8])> = overlay_bufs
            .iter()
            .map(|(s, b)| (*s, b.as_slice()))
            .collect();

        let mem_size = if let Some(last) = img.mappings.last() {
            (last.start + last.size) as u32
        } else {
            0
        };

        let hash = cache.publish_instance_blob(
            entry.image_hash_chain,
            entry.image_hash,
            cnode_hash,
            &overlays_borrowed,
            mem_size,
            entry.regs.gpr,
            entry.regs.pc,
            entry.gas.remaining(),
        )?;
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
            let Some(catcher_slot) = ie.yield_marker_slot else {
                continue;
            };
            // Catcher hash is the image_hash_chain at the catcher
            // slot. Per the legacy model we looked up Cap::Instance;
            // here we just key on the slot target's hash form
            // (CapHashOrRef::Hash) — that's the marker template hash.
            let catcher_hash = match ie.root_cnode.get(catcher_slot) {
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
    use javm_cap::{Cache, NUM_REGS};
    use std::collections::BTreeMap;

    fn empty_image_with_code(code: Vec<u8>) -> Image {
        let packed_bitmask = vec![0xFFu8; code.len().div_ceil(8)];
        Image {
            code,
            packed_bitmask,
            jump_table: Vec::new(),
            endpoints: BTreeMap::new(),
            memory_mappings: Vec::new(),
            gas_slots: Vec::new(),
            quota_slots: Vec::new(),
            pinned_slots: BTreeMap::new(),
            initial_slots: BTreeMap::new(),
            yield_marker_slot: None,
        }
    }

    /// Publish an Image + empty root cnode + a Cap::Instance referencing
    /// them; return the instance hash and the cache.
    fn publish_simple_instance(cache: &mut Cache<Global>, image: Image) -> CapHash {
        let image_hash = cache.publish_image(&image).unwrap();
        let cnode_hash = cache.publish_cnode(8, &[]).unwrap();
        cache
            .publish_instance_blob(
                [0xAA; 32],
                image_hash,
                cnode_hash,
                &[],
                0,
                [0u64; NUM_REGS],
                0,
                0,
            )
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
        // code = [trap (0)]
        let img = empty_image_with_code(vec![0u8]);
        let mut cache = Cache::new_in(Global);
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
        // ecalli 0 → Halt. Bytecode = [10, 0]; bitmask [1, 0] (op + 1
        // imm byte).
        let mut img = empty_image_with_code(vec![10u8, 0]);
        img.packed_bitmask = vec![0b01u8];
        let mut cache = Cache::new_in(Global);
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
        // load_imm_64 φ[7] = 42 (opcode 20, OneRegExtImm: [20, 7, 42, 0..])
        // ecalli 0 (opcode 10): [10, 0]
        let mut code = Vec::new();
        let mut bitmask_unpacked = Vec::new();
        code.extend_from_slice(&[20u8, 7]);
        bitmask_unpacked.extend_from_slice(&[1u8, 0]);
        for i in 0..8 {
            code.push(if i == 0 { 42 } else { 0 });
            bitmask_unpacked.push(0);
        }
        code.extend_from_slice(&[10u8, 0]);
        bitmask_unpacked.extend_from_slice(&[1u8, 0]);

        // Pack the bitmask: one bit per code byte, LSB first.
        let mut packed = vec![0u8; bitmask_unpacked.len().div_ceil(8)];
        for (i, b) in bitmask_unpacked.iter().enumerate() {
            if *b != 0 {
                packed[i / 8] |= 1 << (i % 8);
            }
        }

        let img = Image {
            code,
            packed_bitmask: packed,
            jump_table: Vec::new(),
            endpoints: BTreeMap::new(),
            memory_mappings: Vec::new(),
            gas_slots: Vec::new(),
            quota_slots: Vec::new(),
            pinned_slots: BTreeMap::new(),
            initial_slots: BTreeMap::new(),
            yield_marker_slot: None,
        };

        let mut cache = Cache::new_in(Global);
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

    #[test]
    fn invoke_cached_oog_returns_faulted() {
        // Lots of fallthroughs with a tiny budget. Opcode 1 = fallthrough.
        let code = vec![1u8; 50];
        let mut packed = vec![0xFFu8; code.len().div_ceil(8)];
        if !code.len().is_multiple_of(8) {
            // mask off the last byte's unused high bits
            let used = code.len() % 8;
            let last = packed.len() - 1;
            packed[last] = (1u8 << used) - 1;
        }
        let img = Image {
            code,
            packed_bitmask: packed,
            jump_table: Vec::new(),
            endpoints: BTreeMap::new(),
            memory_mappings: Vec::new(),
            gas_slots: Vec::new(),
            quota_slots: Vec::new(),
            pinned_slots: BTreeMap::new(),
            initial_slots: BTreeMap::new(),
            yield_marker_slot: None,
        };
        let mut cache = Cache::new_in(Global);
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
