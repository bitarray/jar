//! In-process `Arch` impl: simulates the CPU + MMU substrate with
//! Rust data structures. Runs directly in the host process; no
//! sandbox, no cross-compilation.
//!
//! [`run_instance`] is the in-process counterpart to nub-arch-x86's
//! JIT-driven `enter_frame` / `build_frame_runtime`: takes a published
//! [`javm_cap::cap::instance::InstanceCap`] + its referenced
//! [`javm_cap::cap::image::ImageCap`] (both `Global`-allocated
//! locally), wires the bytecode + memory layout to
//! [`javm_exec::interp::Interpreter::run`], and produces an
//! [`InvocationResult`].

use javm_cap::cap::image::ImageCap;
use javm_cap::cap::instance::InstanceCap;
use javm_exec::{
    Access, CopyingMemory, EcallHandler, EcallKind, EcallResult, ExitReason, GasCounter, PAGE_SIZE,
    Regs, gas_const, interp::Interpreter, predecode::predecode_rv_with_mem_cycles,
};
use nub_arch_x86_abi::{InvocationResult, SCRATCHPAD_HEAD_LEN};
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

/// Run an Instance through the PVM2 (RISC-V) interpreter, returning the
/// same `InvocationResult` shape `nub-arch-x86`'s JIT path produces.
/// The exit-reason mapping matches the JIT exit codes (HostCall=4,
/// Trap=7, etc.) so the two backends agree on a well-formed program.
///
/// Endpoint dispatch: `endpoint_idx` selects
/// `image.endpoints[endpoint_idx]`; the endpoint's `entry_pc` is used
/// as the start PC. Caller-supplied `args` overlay φ[7..=10] on top
/// of the endpoint's `initial_regs`. Memory is seeded from the
/// Instance's `mem` DataCap (the whole RW extent), with pinned mappings
/// re-laid read-only.
pub fn run_instance(
    instance: &InstanceCap,
    image: &ImageCap,
    endpoint_idx: u8,
    args: [u64; 4],
    initial_gas: u64,
) -> InvocationResult {
    // Data lives at [DATA_BASE, mem_size); base the flat buffer at
    // DATA_BASE so [0, DATA_BASE) (null guard + code) faults, matching
    // the recompiler's page table.
    let mut mem = CopyingMemory::new();
    mem.base = javm_cap::layout::DATA_BASE;
    let data_extent = instance.mem.content_len();
    let mut mem_image = vec![0u8; data_extent as usize];
    if data_extent > 0 {
        // Seed the whole extent from the Instance's memory image (the immutable
        // backing — both initial and pinned content). No cache lookup needed.
        instance.mem.copy_into(0, &mut mem_image);
        mem.map_region(
            javm_cap::layout::DATA_BASE as u64,
            data_extent,
            Access::ReadWrite,
            Some(&mem_image),
        )
        .expect("map base RW region");
    }
    // Re-lay pinned mappings read-only (same bytes, from the seeded image) so a
    // guest store faults, matching the recompiler's PinnedCapRo direct map.
    let data_base = javm_cap::layout::DATA_BASE as u64;
    for m in image.mappings.iter() {
        if m.path().is_empty() || !image.mapping_is_pinned(m.start as u32) {
            continue;
        }
        let off = (m.start.saturating_sub(data_base)) as usize;
        let len = (m.size as usize).min(mem_image.len().saturating_sub(off));
        if len > 0 {
            overlay(
                &mut mem,
                m.start as u32,
                &mem_image[off..off + len],
                Access::ReadOnly,
            );
        }
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
    // Persisted file is the 13 host-mapped slots; x3/x4 (slots 13/14) start
    // at 0 (Regs::new zeros them), matching the recompiler.
    regs.gpr[..javm_cap::NUM_REGS].copy_from_slice(&endpoint.initial_regs);
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

    // The executable code region, mapped RO at the fixed CODE_BASE
    // (PC = CODE_BASE + byte_offset).
    let (code_base, code_bytes) = image
        .code_mapping()
        .expect("image has no executable code mapping");

    // Category #3: guest PIC data loads of the program's own bytecode
    // page-in the touched code page(s) on first read (read-only forever),
    // identical to the recompiler's lazy code materialization.
    mem.set_code_region(code_base, code_bytes.len() as u32);

    // Category #2: the load/store base latency (mem_cycles) is scaled
    // ×1..4 by the Instance's declared memory footprint. `mem_size`
    // (high-water-mark over the Image's memory_mappings) is the same
    // value the recompiler derives, so both engines pick the same tier.
    let mem_cycles = gas_const::mem_cycles_for(gas_const::accessible_pages(
        instance.mem_size(),
        javm_cap::layout::DATA_BASE,
    ));
    let predecode = predecode_rv_with_mem_cycles(code_bytes, mem_cycles);
    let exit = Interpreter::run(
        &predecode,
        code_bytes,
        code_base,
        &mut regs,
        &mut mem,
        &mut gas,
        &mut handler,
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

    // Surface the running Instance's scratchpad (slot[0]) region head — the
    // effective bytes of `[DATA_BASE, DATA_BASE + SCRATCHPAD_HEAD_LEN)` from the
    // final flat memory (the guest's writes landed here during the run). The
    // recompiler reads the identical window from its post-run CoW pages, so the
    // two engines surface byte-identical result data.
    let mut scratchpad_head = [0u8; SCRATCHPAD_HEAD_LEN];
    let sig_base = javm_cap::layout::DATA_BASE;
    for (i, byte) in scratchpad_head.iter_mut().enumerate() {
        *byte = mem.read_u8(sig_base + i as u32).unwrap_or(0);
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
