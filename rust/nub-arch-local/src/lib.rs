//! In-process `Arch` impl: simulates the CPU + MMU substrate with
//! Rust data structures. Runs directly in the host process; no
//! sandbox, no cross-compilation.
//!
//! [`run_instance`] is the in-process counterpart to nub-arch-x86's
//! JIT-driven `run_pvm_with_mem`: takes a published
//! [`javm_cap::InstanceCap`] + its referenced
//! [`javm_cap::image_cap::ImageCap`] (both `Global`-allocated
//! locally), wires the bytecode + memory layout to
//! [`javm_exec::Interpreter::run`], and produces an
//! [`InvocationResult`].

use allocate::Global;
use javm_cap::image_cap::ImageCap;
use javm_cap::instance::InstanceCap;
use javm_exec::{
    Access, CopyingMemory, EcallHandler, EcallKind, EcallResult, ExitReason, GasCounter,
    Interpreter, PAGE_SIZE, PvmProgram, Regs, gas_cost::DEFAULT_MEM_CYCLES, unpack_bitmask,
};
use nub_arch_x86_abi::InvocationResult;
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

/// Run an Instance through the byte-PVM interpreter, returning the
/// same `InvocationResult` shape `nub-arch-x86`'s JIT path produces.
/// The exit-reason mapping matches the JIT exit codes (HostCall=4,
/// Trap=7, etc.) so the two backends agree on a well-formed program.
///
/// Endpoint dispatch: `endpoint_idx` selects
/// `image.endpoints[endpoint_idx]`; the endpoint's `entry_pc` is used
/// as the start PC. Caller-supplied `args` overlay φ[7..=10] on top
/// of the endpoint's `initial_regs`. Memory is sized from
/// `instance.mem_size` and seeded with each entry in
/// `instance.rw_overlays` laid at its declared `start`.
pub fn run_instance(
    instance: &InstanceCap<Global>,
    image: &ImageCap<Global>,
    endpoint_idx: u8,
    args: [u64; 4],
    initial_gas: u64,
) -> InvocationResult {
    // ImageCap stores the packed bitmask (1 bit per code byte). The
    // interpreter wants the unpacked form (1 byte per code byte).
    let unpacked_bitmask = unpack_bitmask(image.bitmask.as_slice(), image.code.len());
    let program = PvmProgram::new(
        image.code.as_slice().to_vec(),
        unpacked_bitmask,
        image.jump_table.as_slice().to_vec(),
        DEFAULT_MEM_CYCLES,
    )
    .expect("PvmProgram (bitmask len must match code len)");

    let mut mem = CopyingMemory::new();
    let mem_size_pages = page_round_up_u64(instance.mem_size as u64);
    mem.map_region(0, mem_size_pages, Access::ReadWrite, None)
        .expect("map base RW region");
    for overlay_entry in instance.rw_overlays.iter() {
        overlay(
            &mut mem,
            overlay_entry.start,
            overlay_entry.bytes.as_slice(),
            Access::ReadWrite,
        );
    }

    let endpoint = image
        .endpoints
        .get(endpoint_idx as usize)
        .expect("endpoint index out of range");

    let mut regs = Regs::new();
    regs.pc = endpoint.entry_pc;
    // Endpoint baseline first, then layer the InstanceCap's persisted
    // regs on top (publish_instance writes them; subsequent invokes
    // observe them). Args overlay φ[7..=10] last.
    regs.gpr = endpoint.initial_regs;
    for (i, v) in instance.regs.iter().enumerate() {
        if *v != 0 {
            regs.gpr[i] = *v;
        }
    }
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
/// if `data` is empty.
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
/// matching the JIT trampoline's exit shape.
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
