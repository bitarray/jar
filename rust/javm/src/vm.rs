//! The v3 `Vm` driver.
//!
//! Composes:
//! - The call stack (`crate::callstack::CallStack`).
//! - The kernel-assist hook (`crate::kernel_assist::KernelAssist`).
//! - The image bytecode cache (`crate::image_cache::ImageCache`).
//!
//! Top-level verbs:
//! - [`Vm::run_instance`] — Stage 3.7's minimal entry point. Builds
//!   an [`InstanceEntry`] from a (image, cnode) pair, pushes it,
//!   drives `javm_exec::Interpreter::run` to completion, returns a
//!   [`CallResult`]. Used by the Stage 3.12 hello-world test.
//! - `Vm::call(SlotPath, …)` — the spec-canonical CALL through the
//!   active Instance's cnode at the named slot. Lands when jar-kernel-v3
//!   provides a σ-resident Instance arena; for Stage 3 callers go via
//!   `run_instance` directly.
//! - `Vm::call_resume` / `drop_paused` — stubs; the Paused state
//!   machine lands with yield routing (3.8).

use std::sync::Arc;

use jar_cap::{CNodeBackend, Cap, InstanceCap, SlotIdx, image::Image};
use javm_exec::{ExitReason, GasCounter, Interpreter, Mem, Regs};

use crate::callstack::{CallStack, DEFAULT_MAX_DEPTH, Entry, EntryStatus, InstanceEntry};
use crate::error::VmError;
use crate::image_cache::ImageCache;
use crate::kernel_assist::KernelAssist;

/// Result of a top-level `run_instance` / `call`.
///
/// Mirrors v3 spec §5 "Apply terminations":
/// - `Halt`: REPLY-style termination; `return_value = φ[7]`.
/// - `Faulted`: Trap / Panic / PageFault / OOG hard-fault.
/// - `Paused`: yielded — covered when Stage 3.8 wires host_yield.
#[derive(Debug)]
pub enum CallResult {
    Halt {
        /// φ[7] (A0) at REPLY time.
        return_value: u64,
        /// New value identity of the Instance post-HALT. Differs from
        /// the input `InstanceCap.content_hash` if state diverged.
        post_instance: InstanceCap,
        /// The reflected slot[0] payload (target's slot[0] at HALT).
        /// `None` if target's slot[0] was empty.
        reflected_slot0: Option<Cap>,
        /// Gas consumed by the apply.
        gas_used: u64,
    },
    Faulted {
        reason: ExitReason,
        /// Reflected slot[0] at fault point.
        reflected_slot0: Option<Cap>,
        gas_used: u64,
    },
    Paused {
        /// Marker payload — Stage 3.8 fills this in once yield
        /// routing lands. Reserved variant for forward compat.
        marker_payload: Option<Cap>,
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

    /// Minimal entry point: build an InstanceEntry from the supplied
    /// `image`/`cnode`/`endpoint_idx`/`gas_budget`, push it, and run
    /// the interpreter to termination. Used by Stage 3.12 fixtures
    /// and as the implementation primitive that the spec-canonical
    /// CALL (via SlotPath) calls into.
    ///
    /// `instance` carries the caller-known identity bytes; the
    /// driver doesn't validate them against the Image (the chain
    /// orchestrator does — Stage 4). On HALT, `post_instance` in
    /// `CallResult::Halt` reflects the post-apply value identity (in
    /// Stage 3 this is the same content hash since we don't
    /// recompute cnode-hash here yet — Stage 4 closes the loop).
    pub fn run_instance(
        &mut self,
        instance: InstanceCap,
        image: Arc<Image>,
        cnode: Box<dyn CNodeBackend<Cap> + Send + Sync>,
        endpoint_idx: u8,
        gas_budget: u64,
    ) -> Result<CallResult, VmError> {
        // 1. Predecode the image bytecode (cache hit if seen before).
        let program = self.image_cache.get_or_decode(
            // For Stage 3 the cache key is the InstanceCap's content
            // hash; a future refactor keys on Image content_hash
            // directly. The image bytes don't change while the cap is
            // alive so the two are equivalent for now.
            instance.content_hash,
            image.code.clone(),
            // Bitmask + jump_table aren't carried on `Image` yet —
            // Stage 3 derives a trivial bitmask "every byte is an
            // instruction start" matching v2's `Interpreter::new_simple`.
            // Production callers will pass a properly-parsed Image
            // (jar-kernel-v3 will validate at host_make_image).
            vec![1u8; image.code.len()],
            Vec::new(),
        )?;

        // 2. Determine endpoint entry_pc.
        let entry_pc = image
            .endpoints
            .get(endpoint_idx as usize)
            .and_then(|e| e.as_ref())
            .map(|e| e.entry_pc)
            .unwrap_or(0);

        // 3. Seed regs / mem / gas.
        let mut regs = Regs::new();
        regs.pc = entry_pc;
        // Calling convention §4: φ[11] = endpoint_idx.
        regs.gpr[11] = endpoint_idx as u64;
        let mem = Mem::new();
        let gas = GasCounter::new(gas_budget);

        // 4. Push the entry. `pushed_pos` is the position of *this*
        //    InstanceEntry on the stack; we use it to detect whether
        //    host_yield grew the stack while we were running.
        let pushed_pos = self.stack.entries().len();
        let entry = InstanceEntry {
            instance,
            image: image.clone(),
            program: program.clone(),
            cnode,
            regs: Regs::new(),       // placeholder; live regs are in `regs` below
            mem: Mem::new(),         // placeholder
            gas: GasCounter::new(0), // placeholder
            status: EntryStatus::Waiting,
        };
        self.stack.push_instance(entry)?;

        // 5. Drive the interpreter and translate the exit.
        self.drive_and_translate(regs, mem, gas, gas_budget, pushed_pos)
    }

    /// Resume the top `ReferenceEntry`: pop it, re-enter the
    /// interpreter on the InstanceEntry it points at (which already
    /// has its saved regs/mem/gas from the yield site), and translate
    /// the next termination.
    ///
    /// Optionally reflects `scratchpad` into the resumed Instance's
    /// slot[0] before re-entering — the spec's CALL_RESUME(payload)
    /// pattern.
    ///
    /// Errors:
    /// - `VmError::Invariant` if the top isn't a `ReferenceEntry`.
    /// - `VmError::CallStackEmpty` if the resolved target Instance is
    ///   missing.
    pub fn call_resume(
        &mut self,
        _target_slot: jar_cap::SlotPath,
        scratchpad: Option<Cap>,
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
        if let Some(cap) = scratchpad {
            let target = self
                .stack
                .running_instance_mut()
                .ok_or(VmError::Invariant("call_resume: no instance after pop"))?;
            target.cnode.set(SlotIdx(0), Some(cap))?;
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

        self.drive_and_translate(regs, mem, gas, gas_initial, pos)
    }

    /// Stub for DROP_PAUSED. Lands with the σ-resident Paused state
    /// machine (Stage 4).
    pub fn drop_paused(&mut self, _target_slot: jar_cap::SlotPath) -> Result<(), VmError> {
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

        // Did host_yield push a ReferenceEntry above us?
        let yielded = self.stack.entries().len() > pushed_pos + 1
            && matches!(self.stack.running(), Some(Entry::Reference(_)));

        if yielded {
            // Read marker payload (the Cap::Instance[YieldMarker])
            // from the yielder's slot referenced by φ[7] at yield time.
            let marker_slot = SlotIdx((regs.gpr[7] & 0xFF) as u32);
            let marker_payload = {
                let yielder = match &self.stack.entries()[pushed_pos] {
                    Entry::Instance(e) => e.as_ref(),
                    _ => return Err(VmError::Invariant("yielder is not an Instance")),
                };
                yielder.cnode.get(marker_slot).ok().flatten().cloned()
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
        let popped = self
            .stack
            .pop()
            .ok_or(VmError::Invariant("stack empty after Interpreter::run"))?;

        let (instance_post, slot0, regs_post) = match popped {
            Entry::Instance(e) => {
                let mut e = *e;
                let slot0 = e.cnode.take(SlotIdx(0)).ok().flatten();
                (e.instance, slot0, e.regs)
            }
            _ => return Err(VmError::Invariant("popped a non-Instance entry")),
        };

        Ok(match exit {
            ExitReason::Halt => CallResult::Halt {
                return_value: regs_post.gpr[7],
                post_instance: instance_post,
                reflected_slot0: slot0,
                gas_used,
            },
            ExitReason::HostCall(_) | ExitReason::Ecall => CallResult::Paused {
                marker_payload: slot0,
                gas_used,
            },
            ExitReason::Trap
            | ExitReason::Panic
            | ExitReason::OutOfGas
            | ExitReason::PageFault(_) => CallResult::Faulted {
                reason: exit,
                reflected_slot0: slot0,
                gas_used,
            },
        })
    }
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
    use jar_cap::{InMemoryCNode, SlotPath, image::Image};
    use std::collections::BTreeMap;

    fn empty_image_with_code(code: Vec<u8>) -> Image {
        Image {
            code,
            endpoints: core::array::from_fn(|_| None),
            memory_mappings: Vec::new(),
            gas_slots: Vec::new(),
            quota_slots: Vec::new(),
            pinned_slots: BTreeMap::new(),
            yield_marker_slot: None,
        }
    }

    /// Byte-PVM program: `load_imm_64 φ[7] = marker_slot_idx; ecalli 16 (HOST_YIELD); ecalli 0 (HALT)`.
    fn yield_then_halt_program(marker_slot_idx: u8) -> (Vec<u8>, Vec<u8>) {
        // load_imm_64 (opcode 20, OneRegExtImm): [20, reg=7, imm_byte]
        //   bitmask [1, 0, 0] — opcode head + reg byte + 1 imm byte.
        // ecalli 16 (opcode 10, OneImm):   [10, 16]    bitmask [1, 0]
        // ecalli 0  (opcode 10, OneImm):   [10, 0]     bitmask [1, 0]
        let code = vec![20, 7, marker_slot_idx, 10, 16, 10, 0];
        let bitmask = vec![1, 0, 0, 1, 0, 1, 0];
        (code, bitmask)
    }

    /// Build a Vm with an outer InstanceEntry already on the stack
    /// (Waiting), whose `yield_marker_slot` points at a
    /// `Cap::Instance[YieldCatcher]` registered with the
    /// `InProcessKernelAssist` to catch a particular marker
    /// image_hash. Returns the inputs needed to invoke
    /// `vm.run_instance` for the inner: an inner Instance whose
    /// program yields with a marker that the outer catches.
    fn setup_yield_routing() -> (
        Vm<InProcessKernelAssist>,
        InstanceCap,
        Arc<Image>,
        Box<dyn CNodeBackend<Cap> + Send + Sync>,
    ) {
        let mut vm = Vm::new(InProcessKernelAssist::new());

        // Outer: a YieldCatcher cap parked at slot 2.
        let catcher_content_hash = [0x42u8; 32];
        let outer_catcher = Cap::Instance(InstanceCap {
            image_hash_chain: [0xCAu8; 32],
            content_hash: catcher_content_hash,
        });
        let mut outer_cnode: Box<dyn CNodeBackend<Cap> + Send + Sync> =
            Box::new(InMemoryCNode::<Cap>::new(4).unwrap());
        outer_cnode.set(SlotIdx(2), Some(outer_catcher)).unwrap();

        let mut outer_img = empty_image_with_code(vec![0]);
        outer_img.yield_marker_slot = Some(SlotIdx(2));
        let outer_img = Arc::new(outer_img);
        let outer_prog =
            Arc::new(javm_exec::PvmProgram::new(vec![0], vec![1], vec![], 25).unwrap());
        let outer_entry = InstanceEntry {
            instance: InstanceCap {
                image_hash_chain: [0xAAu8; 32],
                content_hash: [0xBBu8; 32],
            },
            image: outer_img,
            program: outer_prog,
            cnode: outer_cnode,
            regs: Regs::new(),
            mem: Mem::new(),
            gas: GasCounter::new(0),
            status: EntryStatus::Waiting,
        };
        vm.stack.push_instance(outer_entry).unwrap();

        // Register marker template with the catcher.
        let marker_image_hash = [0x77u8; 32];
        vm.kernel_assist
            .yield_catcher_add(catcher_content_hash, marker_image_hash);

        // Inner: yields the marker at slot 1, then halts.
        let (code, bitmask) = yield_then_halt_program(1);
        let inner_img = Arc::new(empty_image_with_code(code.clone()));
        let inner_prog = Arc::new(javm_exec::PvmProgram::new(code, bitmask, vec![], 25).unwrap());
        let inner_instance = InstanceCap {
            image_hash_chain: [0xEEu8; 32],
            content_hash: [0xFFu8; 32],
        };
        let mut inner_cnode: Box<dyn CNodeBackend<Cap> + Send + Sync> =
            Box::new(InMemoryCNode::<Cap>::new(4).unwrap());
        let marker = Cap::Instance(InstanceCap {
            image_hash_chain: marker_image_hash,
            content_hash: [0x11u8; 32],
        });
        inner_cnode.set(SlotIdx(1), Some(marker)).unwrap();
        vm.image_cache
            .insert(inner_instance.content_hash, inner_prog);

        (vm, inner_instance, inner_img, inner_cnode)
    }

    #[test]
    fn new_constructs_empty_vm() {
        let vm = Vm::new(InProcessKernelAssist::new());
        assert!(vm.stack.is_empty());
        assert!(vm.image_cache.is_empty());
    }

    #[test]
    fn run_instance_trap_returns_faulted() {
        // code = [trap (0)]
        let img = Arc::new(empty_image_with_code(vec![0u8]));
        let cnode = Box::new(InMemoryCNode::<Cap>::new(8).unwrap());
        let instance = InstanceCap {
            image_hash_chain: [1u8; 32],
            content_hash: [2u8; 32],
        };
        let mut vm = Vm::new(InProcessKernelAssist::new());
        let r = vm.run_instance(instance, img, cnode, 0, 1000).unwrap();
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
    fn run_instance_ecalli_zero_halts_with_return_value() {
        // Program: ecalli 0 (REPLY). Returns Halt with A0=0.
        // ecalli (opcode 10), OneImm category: bytes [10, 0]; bitmask [1, 0]
        // → imm = 0 (1 byte).
        let img = Arc::new(empty_image_with_code(vec![10u8, 0]));
        // PvmProgram::new needs bitmask == code.len()... but our
        // simplified run_instance uses "every byte is insn start"
        // bitmask. So we need to use a PvmProgram where bitmask[0]=1,
        // bitmask[1]=1 (both bytes are insn starts) — that means the
        // ecalli is decoded as opcode-only, no imm. To exercise the
        // proper encoding we set the program manually via the cache.
        let cnode = Box::new(InMemoryCNode::<Cap>::new(8).unwrap());
        let instance = InstanceCap {
            image_hash_chain: [1u8; 32],
            content_hash: [3u8; 32],
        };
        let mut vm = Vm::new(InProcessKernelAssist::new());
        // Pre-seed the image cache with the correct bitmask:
        // [10 (ecalli), 0 (imm byte)]; bitmask [1, 0] → imm decodes as 1 byte = 0.
        let prog = Arc::new(
            javm_exec::PvmProgram::new(vec![10u8, 0], vec![1u8, 0u8], vec![], 25).unwrap(),
        );
        vm.image_cache.insert(instance.content_hash, prog);
        let r = vm.run_instance(instance, img, cnode, 0, 1000).unwrap();
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
    fn run_instance_load_imm_then_reply() {
        // Build a tiny program that loads φ[7] = 42 then REPLYs.
        // load_imm_64 (opcode 20, OneRegExtImm): [20, 7 (reg=A0), 42, 0,0,0,0,0,0,0]
        //   bitmask: [1, 0,0,0,0,0,0,0,0,0]
        // ecalli (opcode 10): [10, 0]; bitmask [1, 0]
        let mut code = Vec::new();
        let mut bitmask = Vec::new();
        // load_imm_64 φ[7] = 42
        code.extend_from_slice(&[20u8, 7]);
        bitmask.extend_from_slice(&[1u8, 0]);
        for i in 0..8 {
            code.push(if i == 0 { 42 } else { 0 });
            bitmask.push(0);
        }
        // ecalli 0
        code.extend_from_slice(&[10u8, 0]);
        bitmask.extend_from_slice(&[1u8, 0]);

        let img = Arc::new(empty_image_with_code(code.clone()));
        let cnode = Box::new(InMemoryCNode::<Cap>::new(8).unwrap());
        let instance = InstanceCap {
            image_hash_chain: [1u8; 32],
            content_hash: [4u8; 32],
        };
        let mut vm = Vm::new(InProcessKernelAssist::new());
        let prog = Arc::new(javm_exec::PvmProgram::new(code, bitmask, vec![], 25).unwrap());
        vm.image_cache.insert(instance.content_hash, prog);

        let r = vm.run_instance(instance, img, cnode, 0, 1000).unwrap();
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
    fn run_instance_yields_when_marker_caught_by_outer() {
        let (mut vm, inst, img, cnode) = setup_yield_routing();
        let r = vm.run_instance(inst, img, cnode, 0, 1000).unwrap();
        match r {
            CallResult::Paused { marker_payload, .. } => {
                // Marker payload is the Cap::Instance at the inner's
                // marker slot (image_hash_chain = 0x77).
                match marker_payload {
                    Some(Cap::Instance(ic)) => {
                        assert_eq!(ic.image_hash_chain, [0x77u8; 32]);
                    }
                    other => panic!("expected Cap::Instance marker payload, got {:?}", other),
                }
            }
            other => panic!("expected Paused, got {:?}", other),
        }
        // Stack: [outer, inner, reference(→outer)].
        assert_eq!(vm.stack.entries().len(), 3);
        assert!(matches!(vm.stack.running(), Some(Entry::Reference(_))));
    }

    #[test]
    fn call_resume_after_yield_runs_to_halt() {
        let (mut vm, inst, img, cnode) = setup_yield_routing();
        // 1. Yield.
        let r = vm.run_instance(inst, img, cnode, 0, 1000).unwrap();
        assert!(matches!(r, CallResult::Paused { .. }));
        assert_eq!(vm.stack.entries().len(), 3);
        // 2. Resume — inner continues into `ecalli 0` → Halt.
        let r = vm.call_resume(SlotPath::root(SlotIdx(0)), None).unwrap();
        assert!(matches!(r, CallResult::Halt { .. }));
        // After Halt, the inner entry is popped; outer remains.
        assert_eq!(vm.stack.entries().len(), 1);
        assert!(matches!(vm.stack.running(), Some(Entry::Instance(_))));
    }

    #[test]
    fn run_instance_unhandled_marker_faults() {
        // Build a setup where the outer has no yield_marker_slot at
        // all → no catcher → unhandled. Reuse most of the fixture but
        // override the outer image to drop its catcher slot.
        let mut vm = Vm::new(InProcessKernelAssist::new());
        let outer_img = Arc::new(empty_image_with_code(vec![0]));
        let outer_prog =
            Arc::new(javm_exec::PvmProgram::new(vec![0], vec![1], vec![], 25).unwrap());
        let outer_cnode: Box<dyn CNodeBackend<Cap> + Send + Sync> =
            Box::new(InMemoryCNode::<Cap>::new(4).unwrap());
        vm.stack
            .push_instance(InstanceEntry {
                instance: InstanceCap {
                    image_hash_chain: [0xAAu8; 32],
                    content_hash: [0xBBu8; 32],
                },
                image: outer_img,
                program: outer_prog,
                cnode: outer_cnode,
                regs: Regs::new(),
                mem: Mem::new(),
                gas: GasCounter::new(0),
                status: EntryStatus::Waiting,
            })
            .unwrap();

        // Inner: same yield-then-halt; marker at slot 1.
        let (code, bitmask) = yield_then_halt_program(1);
        let inner_img = Arc::new(empty_image_with_code(code.clone()));
        let inner_prog = Arc::new(javm_exec::PvmProgram::new(code, bitmask, vec![], 25).unwrap());
        let inner_instance = InstanceCap {
            image_hash_chain: [0xEEu8; 32],
            content_hash: [0xFEu8; 32],
        };
        let mut inner_cnode: Box<dyn CNodeBackend<Cap> + Send + Sync> =
            Box::new(InMemoryCNode::<Cap>::new(4).unwrap());
        inner_cnode
            .set(
                SlotIdx(1),
                Some(Cap::Instance(InstanceCap {
                    image_hash_chain: [0x77u8; 32],
                    content_hash: [0x11u8; 32],
                })),
            )
            .unwrap();
        vm.image_cache
            .insert(inner_instance.content_hash, inner_prog);

        let r = vm
            .run_instance(inner_instance, inner_img, inner_cnode, 0, 1000)
            .unwrap();
        assert!(matches!(
            r,
            CallResult::Faulted {
                reason: ExitReason::Trap,
                ..
            }
        ));
        // Stack should be back to just the outer.
        assert_eq!(vm.stack.entries().len(), 1);
    }

    #[test]
    fn run_instance_oog_returns_faulted() {
        // Lots of fallthroughs (opcode 1) with tiny budget.
        let code = vec![1u8; 50];
        let bitmask = vec![1u8; 50];
        let img = Arc::new(empty_image_with_code(code.clone()));
        let cnode = Box::new(InMemoryCNode::<Cap>::new(8).unwrap());
        let instance = InstanceCap {
            image_hash_chain: [1u8; 32],
            content_hash: [5u8; 32],
        };
        let mut vm = Vm::new(InProcessKernelAssist::new());
        let prog = Arc::new(javm_exec::PvmProgram::new(code, bitmask, vec![], 25).unwrap());
        vm.image_cache.insert(instance.content_hash, prog);

        let r = vm.run_instance(instance, img, cnode, 0, 3).unwrap();
        assert!(matches!(
            r,
            CallResult::Faulted {
                reason: ExitReason::OutOfGas,
                ..
            }
        ));
    }
}
