//! In-process `Arch` impl: simulates the CPU + MMU substrate with
//! Rust data structures. Runs directly in the host process; no
//! sandbox, no cross-compilation.
//!
//! Personality-agnostic: [`run_program`] takes a prepared
//! [`ProgramSpec`] (code, flat memory image, overlays, registers)
//! plus an [`EcallHandler`], wires it to
//! [`nub_exec::interp::Interpreter::run`], and produces an
//! [`InvocationResult`]. This is the in-process counterpart to
//! nub-arch-x86's JIT-driven `enter_frame` / `build_frame_runtime`.
//! The personality lowers its own object types into a `ProgramSpec`
//! (JAVM: `javm::JavmLocal`'s `run_instance`). For a program with no
//! personality at all, [`program::PreparedProgram`] lowers a
//! `nub_program::ProgramBlob` directly.

pub mod program;

pub use program::{PrepareError, PreparedProgram, run_blob};

use nub_arch_x86_abi::{InvocationResult, SCRATCHPAD_HEAD_LEN};
use nub_exec::{
    Access, CopyingMemory, EcallHandler, EcallKind, EcallResult, ExitReason, GasCounter, PAGE_SIZE,
    Regs, gas_const, interp::Interpreter, predecode::predecode_rv_with_mem_cycles,
};
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

/// A read-only overlay re-laid on top of the flat memory image: the
/// bytes at `image[image_off..image_off + len]` become read-only at
/// guest address `start`, so guest stores fault (matching the
/// recompiler's pinned direct maps).
#[derive(Clone, Copy, Debug)]
pub struct RoOverlay {
    pub start: u32,
    pub image_off: usize,
    pub len: usize,
}

/// Personality-agnostic program description for [`run_program`]: what
/// to execute, over what memory, starting from which register file.
/// The personality (JAVM: `javm::JavmLocal`'s `run_instance`) is
/// responsible for lowering its own object types into this shape.
pub struct ProgramSpec<'a> {
    /// The executable code region, mapped RO with PC = `code_base` +
    /// byte offset.
    pub code_base: u32,
    pub code: &'a [u8],
    /// Base guest address of the flat RW data image. `[0, data_base)`
    /// (null guard + code window) faults on data access.
    pub data_base: u32,
    /// Initial contents of the RW region `[data_base, data_base +
    /// mem_image.len())`.
    pub mem_image: &'a [u8],
    /// Read-only re-lays over the seeded image.
    pub ro_overlays: &'a [RoOverlay],
    /// Declared memory footprint (high-water mark) used to pick the
    /// load/store gas tier — must match what the JIT backend derives
    /// so both engines charge identically.
    pub declared_mem_size: u32,
    /// Fully prepared register file (entry PC + initial GPRs).
    pub regs: Regs,
}

/// Run a prepared [`ProgramSpec`] through the PVM2 (RISC-V)
/// interpreter, returning the same `InvocationResult` shape
/// `nub-arch-x86`'s JIT path produces. The exit-reason mapping matches
/// the JIT exit codes (HostCall=4, Trap=7, etc.) so the two backends
/// agree on a well-formed program.
///
/// `handler` decides what ecall/ecalli mean; [`ExitingEcallHandler`]
/// surfaces them as exits, matching the JIT trampoline.
pub fn run_program(
    spec: &ProgramSpec<'_>,
    handler: &mut dyn EcallHandler,
    initial_gas: u64,
) -> InvocationResult {
    // Base the flat buffer at data_base so [0, data_base) faults,
    // matching the recompiler's page table.
    let mut mem = CopyingMemory::new();
    mem.base = spec.data_base;
    if !spec.mem_image.is_empty() {
        mem.map_region(
            spec.data_base as u64,
            spec.mem_image.len() as u64,
            Access::ReadWrite,
            Some(spec.mem_image),
        )
        .expect("map base RW region");
    }
    for o in spec.ro_overlays {
        overlay(
            &mut mem,
            o.start,
            &spec.mem_image[o.image_off..o.image_off + o.len],
            Access::ReadOnly,
        );
    }

    let mut regs = spec.regs.clone();
    let mut gas = GasCounter::new(initial_gas);

    // Category #3: guest PIC data loads of the program's own bytecode
    // page-in the touched code page(s) on first read (read-only forever),
    // identical to the recompiler's lazy code materialization.
    mem.set_code_region(spec.code_base, spec.code.len() as u32);

    // Category #2: the load/store base latency (mem_cycles) is scaled
    // ×1..4 by the declared memory footprint, the same value the
    // recompiler derives, so both engines pick the same tier.
    let mem_cycles = gas_const::mem_cycles_for(gas_const::accessible_pages(
        spec.declared_mem_size,
        spec.data_base,
    ));
    let predecode = predecode_rv_with_mem_cycles(spec.code, mem_cycles);
    let exit = Interpreter::run(
        &predecode,
        spec.code,
        spec.code_base,
        &mut regs,
        &mut mem,
        &mut gas,
        handler,
    );

    let (exit_reason, exit_arg) = match exit {
        ExitReason::Halt => (0, 0),
        ExitReason::Panic => (1, 0),
        ExitReason::OutOfGas => (2, 0),
        ExitReason::PageFault(addr) => (3, addr),
        ExitReason::HostCall(imm) => (4, imm),
        ExitReason::Ecall => (6, 0),
        ExitReason::Trap => (7, 0),
    };

    // Surface the scratchpad head — the effective bytes of
    // `[data_base, data_base + SCRATCHPAD_HEAD_LEN)` from the final
    // flat memory. The recompiler reads the identical window from its
    // post-run CoW pages, so the two engines surface byte-identical
    // result data.
    let mut scratchpad_head = [0u8; SCRATCHPAD_HEAD_LEN];
    for (i, byte) in scratchpad_head.iter_mut().enumerate() {
        *byte = mem.read_u8(spec.data_base + i as u32).unwrap_or(0);
    }

    InvocationResult {
        exit_reason,
        exit_arg,
        return_value: regs.gpr[7],
        gas_remaining: gas.remaining(),
        scratchpad_head,
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

/// Minimal `EcallHandler`: every `ecall` / `ecalli` ends the run by
/// surfacing the corresponding `ExitReason`, matching the JIT
/// trampoline's exit shape.
pub struct ExitingEcallHandler;

impl EcallHandler for ExitingEcallHandler {
    fn handle(
        &mut self,
        kind: EcallKind,
        _regs: &mut Regs,
        _mem: &mut dyn nub_exec::Memory,
    ) -> EcallResult {
        match kind {
            EcallKind::Ecalli(imm) => EcallResult::Exit(ExitReason::HostCall(imm)),
            EcallKind::Ecall => EcallResult::Exit(ExitReason::Ecall),
        }
    }
}
