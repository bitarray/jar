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

use jar_cap::{CNodeBackend, Cap, InstanceCap, image::Image};
use javm_exec::{ExitReason, GasCounter, Interpreter, Mem, Regs};

use crate::callstack::{CallStack, DEFAULT_MAX_DEPTH, EntryStatus, InstanceEntry};
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
        let gas_initial = gas_budget;

        // 4. Push the entry.
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

        // 5. Drive the interpreter. `&mut self` flows in as the
        //    EcallHandler; the running entry's cnode stays on the
        //    stack (accessible via `self.stack.running_instance_mut()`).
        //    The entry's regs/mem/gas fields are placeholders during
        //    this scope — the MGMT dispatcher uses the function-arg
        //    regs (which IS the live `regs` here).
        let mut regs_live = regs;
        let mut mem_live = mem;
        let mut gas_live = gas;
        let exit = Interpreter::run(
            program.as_ref(),
            &mut regs_live,
            &mut mem_live,
            &mut gas_live,
            self,
        );

        // 6. Restore the live state into the entry, then pop.
        if let Some(entry) = self.stack.running_instance_mut() {
            entry.regs = regs_live;
            entry.mem = mem_live;
            entry.gas = gas_live;
        }
        let popped = self
            .stack
            .pop()
            .ok_or(VmError::Invariant("stack empty after Interpreter::run"))?;

        // 7. Translate the exit into a CallResult.
        let (instance_post, slot0, regs_post, gas_remaining) = match popped {
            crate::callstack::Entry::Instance(e) => {
                let e = *e;
                // Take slot[0] for reflection.
                let mut cnode = e.cnode;
                let slot0 = cnode.take(jar_cap::SlotIdx(0)).ok().flatten();
                let _ = cnode; // dropped here
                (e.instance, slot0, e.regs, e.gas.remaining())
            }
            _ => return Err(VmError::Invariant("popped a non-Instance entry")),
        };
        let gas_used = gas_initial.saturating_sub(gas_remaining);

        Ok(match exit {
            ExitReason::Halt => CallResult::Halt {
                return_value: regs_post.gpr[7],
                post_instance: instance_post,
                reflected_slot0: slot0,
                gas_used,
            },
            ExitReason::HostCall(_) | ExitReason::Ecall => {
                // Stage 3.8 / 3.9: host calls and yields will be
                // handled before the Interpreter returns. Reaching
                // here means the EcallHandler returned Exit on a host
                // call we don't yet recognize — surface as Paused so
                // the caller can decide.
                CallResult::Paused {
                    marker_payload: slot0,
                    gas_used,
                }
            }
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

    /// Stub for spec-canonical CALL_RESUME. Lands once Stage 3.8
    /// wires the yield-routing path.
    pub fn call_resume(
        &mut self,
        _target_slot: jar_cap::SlotPath,
        _scratchpad: Cap,
    ) -> Result<CallResult, VmError> {
        Err(VmError::Invariant(
            "CALL_RESUME requires yield routing (Stage 3.8)",
        ))
    }

    /// Stub for DROP_PAUSED. Lands with the σ-resident Paused state
    /// machine (Stage 3.8 / Stage 4).
    pub fn drop_paused(&mut self, _target_slot: jar_cap::SlotPath) -> Result<(), VmError> {
        Err(VmError::Invariant(
            "DROP_PAUSED requires σ-resident Paused state (Stage 4)",
        ))
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
    use jar_cap::{InMemoryCNode, image::Image};
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
