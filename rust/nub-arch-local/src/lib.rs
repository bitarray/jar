//! In-process `Arch` impl: simulates the CPU + MMU substrate with
//! Rust data structures. Runs directly in the host process; no
//! sandbox, no cross-compilation.
//!
//! `run_invocation_spec` is the Stage-3 wiring from a SCALE-shaped
//! [`InvocationSpec`] to the byte-PVM interpreter
//! ([`javm_exec::Interpreter::run`]) — the in-process counterpart
//! to nub-arch-x86's JIT-driven `run_pvm_with_mem`.

use javm_exec::{
    Access, CopyingMemory, EcallHandler, EcallKind, EcallResult, ExitReason, GasCounter,
    Interpreter, PAGE_SIZE, PvmProgram, Regs, gas_cost::DEFAULT_MEM_CYCLES,
};
use nub_arch_x86_abi::{InvocationResult, InvocationSpec, PublishSpec};
use nub_kernel::{Arch, CapHash, InstanceRef, InvokeOptions, InvokeOutcome};

/// In-process Arch backend.
#[derive(Default)]
pub struct LocalArch {
    state_root: CapHash,
}

impl LocalArch {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Stub error type for the skeleton — the local backend cannot fail
/// today. Replace with a real error enum when invocation lands.
#[derive(Debug)]
pub enum LocalArchError {}

impl Arch for LocalArch {
    type Error = LocalArchError;

    fn invoke(
        &mut self,
        _target: InstanceRef,
        _endpoint: u16,
        _args: &[u8],
        _opts: InvokeOptions,
    ) -> Result<InvokeOutcome, Self::Error> {
        Ok(InvokeOutcome {
            return_value: 42,
            gas_used: 0,
        })
    }

    fn state_root(&self) -> CapHash {
        self.state_root
    }
}

/// Run an [`InvocationSpec`] through the byte-PVM interpreter and
/// return an [`InvocationResult`] in the same shape `nub-arch-x86`'s
/// JIT path produces. The exit-reason mapping matches the JIT exit
/// codes (HostCall=4, Trap=7, etc.) so the two backends agree on a
/// well-formed program.
pub fn run_invocation_spec(spec: &InvocationSpec) -> InvocationResult {
    let program = PvmProgram::new(
        spec.code.clone(),
        spec.bitmask.clone(),
        spec.jump_table.clone(),
        DEFAULT_MEM_CYCLES,
    )
    .expect("PvmProgram (bitmask len must match code len)");

    let mut mem = CopyingMemory::new();
    let mem_size_pages = page_round_up_u64(spec.mem_size as u64);
    // Cover the whole accessible range as RW first; ro/rw_data
    // overlays below downgrade or refill specific subranges. The JIT
    // path's per-invocation PT maps `[0, mem_size)` uniformly user-RW
    // and lets the recompiler-side bounds-check via the PT itself;
    // here we approximate that with per-page perms in CopyingMemory.
    mem.map_region(0, mem_size_pages, Access::ReadWrite, None)
        .expect("map base RW region");
    overlay(&mut mem, spec.ro_start, &spec.ro_data, Access::ReadOnly);
    overlay(&mut mem, spec.rw_start, &spec.rw_data, Access::ReadWrite);
    overlay(&mut mem, spec.arg_start, &spec.arg_data, Access::ReadWrite);

    let mut regs = Regs::new();
    regs.pc = spec.entry_pc as u64;
    regs.gpr = spec.initial_regs.into_array();

    let mut gas = GasCounter::new(spec.initial_gas);
    let mut handler = LocalEcallHandler;
    let exit = Interpreter::run(&program, &mut regs, &mut mem, &mut gas, &mut handler);

    let (exit_reason, exit_arg) = match exit {
        ExitReason::Halt => (0, 0),
        ExitReason::Panic => (1, 0),
        ExitReason::OutOfGas => (2, 0),
        ExitReason::PageFault(addr) => (3, addr),
        ExitReason::HostCall(imm) => (4, imm),
        ExitReason::Ecall => (6, 0),
        ExitReason::Trap => (7, 0),
    };
    InvocationResult {
        exit_reason,
        exit_arg,
        return_value: regs.gpr[7],
        gas_remaining: gas.remaining(),
    }
}

/// Run a `PublishSpec` (cache path's host-side type) through the
/// byte-PVM interpreter, returning the same `InvocationResult` shape
/// as `run_invocation_spec`. Endpoint dispatch: `endpoint_idx` selects
/// `spec.entry_pcs[endpoint_idx]`; caller-supplied `args` overlay
/// φ[7..=10] on top of the baseline `spec.initial_regs`.
pub fn run_published(
    spec: &PublishSpec,
    endpoint_idx: u8,
    args: [u64; 4],
    initial_gas: u64,
) -> InvocationResult {
    let program = PvmProgram::new(
        spec.code.clone(),
        spec.bitmask.clone(),
        spec.jump_table.clone(),
        DEFAULT_MEM_CYCLES,
    )
    .expect("PvmProgram (bitmask len must match code len)");

    let mut mem = CopyingMemory::new();
    let mem_size_pages = page_round_up_u64(spec.mem_size as u64);
    mem.map_region(0, mem_size_pages, Access::ReadWrite, None)
        .expect("map base RW region");
    overlay(&mut mem, spec.ro_start, &spec.ro_data, Access::ReadOnly);
    overlay(&mut mem, spec.rw_start, &spec.rw_data, Access::ReadWrite);
    overlay(&mut mem, spec.arg_start, &spec.arg_data, Access::ReadWrite);

    let entry_pc = spec
        .entry_pcs
        .get(endpoint_idx as usize)
        .copied()
        .unwrap_or(0);

    let mut regs = Regs::new();
    regs.pc = entry_pc;
    regs.gpr = spec.initial_regs;
    for (i, v) in args.iter().enumerate() {
        regs.gpr[7 + i] = *v;
    }

    let mut gas = GasCounter::new(initial_gas);
    let mut handler = LocalEcallHandler;
    let exit = Interpreter::run(&program, &mut regs, &mut mem, &mut gas, &mut handler);

    let (exit_reason, exit_arg) = match exit {
        ExitReason::Halt => (0, 0),
        ExitReason::Panic => (1, 0),
        ExitReason::OutOfGas => (2, 0),
        ExitReason::PageFault(addr) => (3, addr),
        ExitReason::HostCall(imm) => (4, imm),
        ExitReason::Ecall => (6, 0),
        ExitReason::Trap => (7, 0),
    };
    InvocationResult {
        exit_reason,
        exit_arg,
        return_value: regs.gpr[7],
        gas_remaining: gas.remaining(),
    }
}

fn page_round_up_u64(n: u64) -> u64 {
    let p = PAGE_SIZE as u64;
    n.div_ceil(p) * p
}

/// Overlay a sub-region of mem with a permission + initial bytes. No-op
/// if `data` is empty (the spec carries empty arg/ro/rw vectors when
/// the program has no such region).
fn overlay(mem: &mut CopyingMemory, start: u32, data: &[u8], access: Access) {
    if data.is_empty() {
        return;
    }
    let size = page_round_up_u64(data.len() as u64);
    mem.map_region(start as u64, size, access, Some(data))
        .expect("map_region overlay");
}

/// Minimal `EcallHandler` for the local backend: every `ecall` /
/// `ecalli` ends the run by surfacing the corresponding `ExitReason`,
/// matching the JIT trampoline's exit shape (no in-engine ecall
/// dispatch — the integration layer above us, if any, would re-enter
/// with updated state).
struct LocalEcallHandler;

impl EcallHandler for LocalEcallHandler {
    fn handle(
        &mut self,
        kind: EcallKind,
        _regs: &mut Regs,
        _mem: &mut dyn javm_exec::Memory,
    ) -> EcallResult {
        match kind {
            EcallKind::Ecalli(imm) => EcallResult::Exit(ExitReason::HostCall(imm)),
            EcallKind::Ecall => EcallResult::Exit(ExitReason::Ecall),
        }
    }
}
