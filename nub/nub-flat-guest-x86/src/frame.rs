//! The flat frame: one program, one register file, one address space.

use alloc::sync::Arc;
use alloc::vec::Vec;

use nub_arch_x86::execution_lane::ExecutionLane;
use nub_arch_x86::jit_run::MatRange;
use nub_arch_x86::jit_run::{self, FrameRuntime};
use nub_arch_x86::paging::PAGE_SIZE;
use nub_arch_x86::personality::{ExecFrame, FrameParts, NUM_REGS};
use nub_exec::mat::PageKind;
use nub_program::abi::{CODE_BASE, DATA_BASE};

use crate::mem::FlatMem;
use crate::store::PublishedProgram;

/// Error codes surfaced to the host. Distinct values so a failure is
/// diagnosable from the exit alone.
pub const ERR_PROGRAM_NOT_FOUND: u32 = 0x1000;
pub const ERR_NO_SUCH_ENDPOINT: u32 = 0x1001;
pub const ERR_CODE_PA: u32 = 0x1002;
pub const ERR_JIT_FAILED: u32 = 0x1003;
pub const ERR_UNSUPPORTED_ECALL: u32 = 0x1004;

/// One executable frame.
pub struct FlatFrame {
    /// Keeps the program — and the physical pages its page table points
    /// at — alive for the frame's lifetime.
    pub program: Arc<PublishedProgram>,
    pub pc: u64,
    pub regs: [u64; NUM_REGS],
    pub mem: FlatMem,
    /// Per-page materialization tags, owned by the substrate.
    pub mat_state: Vec<u8>,
    /// Read-only page-table units, owned by the substrate.
    pub ro_units: Vec<u32>,
    pub runtime: Option<FrameRuntime>,
}

impl FlatFrame {
    /// Build a frame entering `endpoint` with `args` in φ[7..=10].
    ///
    /// The register seeding must match `nub_arch_local::PreparedProgram`
    /// exactly — the two engines are required to agree on gas, and gas
    /// is a function of the starting state.
    pub fn new(program: Arc<PublishedProgram>, endpoint: u8, args: [u64; 4]) -> Result<Self, u32> {
        let ep = program
            .blob
            .endpoints
            .get(&endpoint)
            .ok_or(ERR_NO_SUCH_ENDPOINT)?;

        let mut regs = [0u64; NUM_REGS];
        for (&idx, &value) in &ep.initial_regs {
            if let Some(slot) = regs.get_mut(idx as usize) {
                *slot = value;
            }
        }
        for (i, v) in args.iter().enumerate() {
            regs[7 + i] = *v;
        }

        let pc = ep.entry_pc;
        let mem = FlatMem::new(Arc::clone(&program));
        Ok(FlatFrame {
            pc,
            regs,
            // One tag per data page, indexed directly by page number by
            // the #PF handler — it does not bounds-check, so this must
            // be pre-sized to the full extent rather than grown.
            mat_state: alloc::vec![0u8; mem.pages()],
            mem,
            // Grown by the substrate as read-only units are mapped.
            ro_units: Vec::new(),
            program,
            runtime: None,
        })
    }
}

impl ExecFrame for FlatFrame {
    type Mem = FlatMem;

    fn parts(&mut self) -> FrameParts<'_, FlatMem> {
        FrameParts {
            pc: &mut self.pc,
            regs: &mut self.regs,
            mem: &mut self.mem,
            mat_state: &mut self.mat_state,
            ro_units: &mut self.ro_units,
            runtime: &mut self.runtime,
        }
    }

    /// Build the per-frame ring-3 runtime.
    ///
    /// Two materialization ranges, which is the whole of the flat
    /// memory model: the read-only region is `PinnedCapRo` so a guest
    /// store faults, and everything else is one catch-all
    /// `UnpinnedCapCow`. Order matters — `mat_range_for` takes the
    /// first match, so the RO range must be pushed first or the
    /// catch-all would swallow it and `.rodata` would become writable.
    fn build_runtime(&self, lane: ExecutionLane) -> Result<FrameRuntime, u32> {
        let (code, code_pa) = self.program.code();
        if code_pa == 0 {
            return Err(ERR_CODE_PA);
        }

        let extent = (self.mem.pages() * PAGE_SIZE) as u32;
        let mem_size = DATA_BASE.saturating_add(extent);

        let mut mat_ranges: Vec<MatRange> = Vec::new();
        for region in self.program.blob.regions.iter() {
            if !region.kind.is_read_only() {
                continue;
            }
            mat_ranges.push(MatRange {
                start: region.start() as u32,
                end: (region.start() + region.size()) as u32,
                kind: PageKind::PinnedCapRo.as_u8(),
            });
        }
        if extent > 0 {
            mat_ranges.push(MatRange {
                start: DATA_BASE,
                end: mem_size,
                kind: PageKind::UnpinnedCapCow.as_u8(),
            });
        }

        // SAFETY: `code` borrows the program's page-aligned buffer and
        // `code_pa` is its physical address; both live as long as the
        // `Arc<PublishedProgram>` this frame holds, which outlives the
        // returned runtime. The JIT slot is never evicted while a
        // runtime borrows into it (programs are insert-only).
        unsafe {
            jit_run::build_frame_runtime(
                lane,
                &*self.program,
                code,
                CODE_BASE,
                code_pa,
                DATA_BASE,
                mem_size,
                mat_ranges,
            )
        }
        .ok_or(ERR_JIT_FAILED)
    }
}
