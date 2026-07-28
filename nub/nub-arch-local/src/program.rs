//! Lower a [`ProgramBlob`] into a runnable [`ProgramSpec`].
//!
//! This is the "no personality" personality: the shortest path from a
//! linked program to a running one, with no capability graph, no
//! content addressing and no store. A personality that has those does
//! this lowering itself from its own object types (JAVM:
//! `javm::JavmLocal::run_instance`) — and must arrive at exactly the
//! same `ProgramSpec`, since gas is a function of it.

use nub_exec::Regs;
use nub_program::ProgramBlob;
use nub_program::abi::{CODE_BASE, DATA_BASE};

use crate::{ProgramSpec, RoOverlay};

/// Why a [`ProgramBlob`] could not be prepared for execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareError {
    /// The blob declares no endpoint with this index.
    NoSuchEndpoint(u8),
}

impl core::fmt::Display for PrepareError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PrepareError::NoSuchEndpoint(i) => write!(f, "program declares no endpoint {i}"),
        }
    }
}

impl core::error::Error for PrepareError {}

/// A [`ProgramBlob`] lowered to the buffers a [`ProgramSpec`] borrows.
///
/// `ProgramSpec` borrows its memory image and overlay list, so
/// something has to own them; that is this type. Build it once, then
/// hand out `spec()` as often as you like.
pub struct PreparedProgram {
    code: Vec<u8>,
    mem_image: Vec<u8>,
    ro_overlays: Vec<RoOverlay>,
    declared_mem_size: u32,
    regs: Regs,
}

impl PreparedProgram {
    /// Prepare `endpoint` of `blob` for entry with `args` in φ[7..=10].
    ///
    /// Mirrors the cap-path lowering exactly: the whole data extent is
    /// materialized flat from `DATA_BASE`, the read-only region is
    /// re-laid as an [`RoOverlay`] so guest stores fault, the register
    /// file starts from the endpoint's `initial_regs` (which the linker
    /// seeded with the stack top), and `declared_mem_size` is the data
    /// high-water mark that selects the load/store gas tier.
    pub fn new(blob: &ProgramBlob, endpoint: u8, args: [u64; 4]) -> Result<Self, PrepareError> {
        let ep = blob
            .endpoints
            .get(&endpoint)
            .ok_or(PrepareError::NoSuchEndpoint(endpoint))?;

        let mem_image = blob.memory_image();

        // The read-only region is re-laid over the seeded image, same
        // bytes, so a guest store faults — matching the recompiler's
        // pinned direct map.
        let ro_overlays = blob
            .regions
            .iter()
            .filter(|r| r.kind.is_read_only())
            .map(|r| RoOverlay {
                start: r.start() as u32,
                image_off: (r.start() - u64::from(DATA_BASE)) as usize,
                len: r.size() as usize,
            })
            .collect();

        let mut regs = Regs::new();
        regs.pc = ep.entry_pc;
        for (&idx, &value) in &ep.initial_regs {
            if let Some(slot) = regs.gpr.get_mut(idx as usize) {
                *slot = value;
            }
        }
        for (i, v) in args.iter().enumerate() {
            regs.gpr[7 + i] = *v;
        }

        Ok(PreparedProgram {
            code: blob.code.clone(),
            declared_mem_size: DATA_BASE + blob.regions.data_extent() as u32,
            mem_image,
            ro_overlays,
            regs,
        })
    }

    /// Borrow the prepared spec, ready for
    /// [`run_program`](crate::run_program).
    pub fn spec(&self) -> ProgramSpec<'_> {
        ProgramSpec {
            code_base: CODE_BASE,
            code: &self.code,
            data_base: DATA_BASE,
            mem_image: &self.mem_image,
            ro_overlays: &self.ro_overlays,
            declared_mem_size: self.declared_mem_size,
            regs: self.regs.clone(),
        }
    }

    /// Entry PC of the endpoint this was prepared for.
    pub fn entry_pc(&self) -> u64 {
        self.regs.pc
    }
}

/// Convenience: prepare and run `endpoint` of `blob` once.
///
/// Each call builds a fresh address space, so guest statics do not
/// persist between calls.
pub fn run_blob(
    blob: &ProgramBlob,
    endpoint: u8,
    args: [u64; 4],
    initial_gas: u64,
) -> Result<nub_arch_x86_abi::InvocationResult, PrepareError> {
    let prepared = PreparedProgram::new(blob, endpoint, args)?;
    let mut handler = crate::ExitingEcallHandler;
    Ok(crate::run_program(
        &prepared.spec(),
        &mut handler,
        initial_gas,
    ))
}
