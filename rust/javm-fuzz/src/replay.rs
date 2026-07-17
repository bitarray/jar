//! Dual-engine replay: run a [`Program`] through the interpreter and the x86
//! recompiler and compare. Gated to linux/x86_64 (the recompiler needs the
//! Hyperlight host stack, so the whole `javm-bench` crate is gated to it).
//!
//! Both engines are driven through the *same* `javm-bench` `BuiltCaps` →
//! `invoke_cached` path, so they receive byte-identical caps/initial-state —
//! any divergence is a real engine disagreement, never a setup skew.

use crate::{Program, SIG_BASE, encode};
use javm_bench::{BuiltCaps, RawRun, run_interpreter_raw, run_recompiler_raw};
use javm_cap::abi::SCRATCHPAD_SLOT;
use javm_cap::image::{EndpointDef, Image, ImageBuilder, MemoryMapping};
use javm_cap::slot::{Key, SlotPath};
use std::collections::BTreeMap;

/// Cnode slot the fuzz memory window's backing data cap occupies.
const WINDOW_SLOT: u32 = 1;

/// One page — the scratchpad (`slot[0]`) signature region size (the program's
/// signature epilogue stores the `SIG_BYTES`-byte register file into its head).
const SIG_REGION_BYTES: u64 = 4096;

/// Map the scratchpad (`slot[0]`) signature region at [`SIG_BASE`] into the
/// builder: an empty-content initial data slot of one page. The guest's
/// signature epilogue CoWs this region during the run; both engines surface its
/// effective bytes as the run's register signature.
fn add_signature_region(b: ImageBuilder) -> ImageBuilder {
    let slot = Key::from(SCRATCHPAD_SLOT);
    b.mapping(MemoryMapping {
        start: SIG_BASE as u64,
        size: SIG_REGION_BYTES,
        source: SlotPath::root(slot.clone()),
    })
    .initial_data(slot, Vec::new(), SIG_REGION_BYTES)
}

/// Build an `Image` from raw instruction `words` (+ `ecalli 0` terminator)
/// with a **pinned read-only** data cap of `ro_bytes` mapped at `ro_start`
/// — for category-#3 read-only-cluster differential tests. Both engines
/// materialize it `PinnedCapRo` (interp perm-RO, recompiler MatRange) and
/// charge it per 2 MiB cluster.
pub fn image_with_ro(words: &[u32], ro_start: u32, ro_bytes: &[u8]) -> Image {
    let mut code = encode::enc(words);
    code.extend_from_slice(&encode::enc(&[encode::HALT]));
    let slot = Key::from((WINDOW_SLOT + 1) as u8);
    ImageBuilder::new()
        .code(code)
        .endpoint(
            Key::from(0u8),
            EndpointDef {
                entry_pc: 0,
                arg_registers: 0,
                arg_cnode_size: 0,
                initial_regs: BTreeMap::new(),
            },
        )
        .mapping(MemoryMapping {
            start: ro_start as u64,
            size: ro_bytes.len() as u64,
            source: SlotPath::root(slot.clone()),
        })
        .pinned_data(slot, ro_bytes.to_vec(), ro_bytes.len() as u64)
        .build()
}

/// Build an `Image` from raw `words` with **several** pinned read-only data
/// caps, each `(start, bytes)` — for multi-cap read-only-cluster differential
/// tests (e.g. two distinct caps sharing one 2 MiB cluster). Each cap takes its
/// own cnode slot, so the recompiler resolves each as a separate `PinnedCapRo`
/// `MatRange` with its own source PA, exactly as production does.
pub fn image_with_ro_caps(words: &[u32], caps: &[(u32, &[u8])]) -> Image {
    let mut code = encode::enc(words);
    code.extend_from_slice(&encode::enc(&[encode::HALT]));
    let mut b = ImageBuilder::new().code(code).endpoint(
        Key::from(0u8),
        EndpointDef {
            entry_pc: 0,
            arg_registers: 0,
            arg_cnode_size: 0,
            initial_regs: BTreeMap::new(),
        },
    );
    for (i, (start, bytes)) in caps.iter().enumerate() {
        let slot = Key::from((WINDOW_SLOT + 1 + i as u32) as u8);
        b = b
            .mapping(MemoryMapping {
                start: *start as u64,
                size: bytes.len() as u64,
                source: SlotPath::root(slot.clone()),
            })
            .pinned_data(slot, bytes.to_vec(), bytes.len() as u64);
    }
    b.build()
}

/// Run a pre-built `Image` through both engines and compare.
pub fn diff_image(img: &Image) -> Diff {
    let built = BuiltCaps::for_image(img, 0);
    let interp = run_interpreter_raw(&built);
    let recomp = run_recompiler_raw(&built);
    Diff { interp, recomp }
}

/// Build the `Image` for a program: its code (body + signature epilogue) plus
/// the appended `ecalli 0` terminator, entered at pc 0 with the program's
/// initial register seed.
///
/// The Image always maps the scratchpad (`slot[0]`) signature region at
/// [`SIG_BASE`] (via `add_signature_region`); the program's signature epilogue
/// stores its register file there, and both engines surface the region's
/// effective bytes for the lossless differential.
///
/// When the program declares an `init_mem` window, the Image declares a
/// matching RW data mapping so **both** engines size their data extent to
/// cover it and lazily materialize (category #3) the same pages. The window is
/// backed by an *empty* initial slot (zero-filled, page-aligned `mem_buf`), so
/// both engines treat it as ephemeral — the lazy-materialization charge is
/// identical regardless, and this keeps the differential off the cap-PA
/// page-in path (whose alignment is a separate concern).
pub fn image_for(prog: &Program) -> Image {
    let mut code = prog.code_bytes();
    code.extend_from_slice(&encode::enc(&[encode::HALT]));

    let mut b = ImageBuilder::new().code(code).endpoint(
        Key::from(0u8),
        EndpointDef {
            entry_pc: 0,
            arg_registers: 0,
            arg_cnode_size: 0,
            initial_regs: prog.init_regs.clone(),
        },
    );
    b = add_signature_region(b);
    if let Some(mem) = &prog.init_mem {
        let slot = Key::from((WINDOW_SLOT) as u8);
        // Empty content → no overlay; the mapping only sizes the data extent,
        // and the window materializes as ephemeral zero pages on both engines.
        b = b
            .mapping(MemoryMapping {
                start: mem.start as u64,
                size: mem.bytes.len() as u64,
                source: SlotPath::root(slot.clone()),
            })
            .initial_data(slot, Vec::new(), mem.bytes.len() as u64);
    }
    b.build()
}

/// Interpreter outcome for `prog`.
pub fn replay_interp(prog: &Program) -> RawRun {
    run_interpreter_raw(&BuiltCaps::for_image(&image_for(prog), 0))
}

/// Recompiler outcome for `prog`.
pub fn replay_recomp(prog: &Program) -> RawRun {
    run_recompiler_raw(&BuiltCaps::for_image(&image_for(prog), 0))
}

/// Both engines' outcomes for one program.
#[derive(Debug, Clone, Copy)]
pub struct Diff {
    pub interp: RawRun,
    pub recomp: RawRun,
}

impl Diff {
    /// True iff the engines disagree on the exit reason, the full scratchpad
    /// register signature, `x10`, or gas — any of which is a consensus
    /// divergence. The signature comparison is the lossless upgrade over the old
    /// x10 fold: a divergence in *any* captured register is caught, even one
    /// that a fold would have cancelled.
    pub fn diverges(&self) -> bool {
        self.interp.exit_reason != self.recomp.exit_reason
            || self.interp.return_value != self.recomp.return_value
            || self.interp.gas_used != self.recomp.gas_used
            || self.interp.scratchpad_head != self.recomp.scratchpad_head
    }

    /// One-line human description of the disagreement (for triage logs). Names
    /// the first divergent signature slot (→ register) when the registers
    /// disagree, else reports the exit/gas mismatch.
    pub fn describe(&self) -> String {
        let slot = self.first_divergent_slot();
        let sig = match slot {
            Some(s) => format!(
                " sig@slot{s}(x{}): {:#018x} vs {:#018x}",
                crate::oracle::slot_to_xreg(s as u8),
                self.sig_reg(&self.interp, s),
                self.sig_reg(&self.recomp, s),
            ),
            None => String::new(),
        };
        format!(
            "interp{{exit={} x10={:#018x} gas={}}} vs recomp{{exit={} x10={:#018x} gas={}}}{sig}",
            self.interp.exit_reason,
            self.interp.return_value,
            self.interp.gas_used,
            self.recomp.exit_reason,
            self.recomp.return_value,
            self.recomp.gas_used,
        )
    }

    /// Index of the first signature slot (0..`SIG_REGS`) whose register bytes
    /// differ between the engines, if any.
    fn first_divergent_slot(&self) -> Option<usize> {
        (0..encode::SIG_REGS).find(|&s| {
            self.interp.scratchpad_head[s * 8..s * 8 + 8]
                != self.recomp.scratchpad_head[s * 8..s * 8 + 8]
        })
    }

    /// The LE `u64` at signature slot `s` of `run`'s scratchpad head.
    fn sig_reg(&self, run: &RawRun, s: usize) -> u64 {
        u64::from_le_bytes(run.scratchpad_head[s * 8..s * 8 + 8].try_into().unwrap())
    }
}

/// Run `prog` through both engines (sharing one `BuiltCaps`) and compare.
pub fn diff(prog: &Program) -> Diff {
    let built = BuiltCaps::for_image(&image_for(prog), 0);
    // Interpreter first (never aborts the host); then the recompiler (which
    // self-heals its sandbox on a guest abort).
    let interp = run_interpreter_raw(&built);
    let recomp = run_recompiler_raw(&built);
    Diff { interp, recomp }
}

/// Run a batch through [`diff`], returning `(index, Diff)` for each diverging
/// program. One long-lived sandbox handles the whole batch — no rebuilds (those
/// were the source of host-heap corruption; a single sandbox runs thousands of
/// distinct programs cleanly).
pub fn diff_batch(progs: &[Program]) -> Vec<(usize, Diff)> {
    let mut diverged = Vec::new();
    for (i, prog) in progs.iter().enumerate() {
        let d = diff(prog);
        if d.diverges() {
            diverged.push((i, d));
        }
    }
    diverged
}

/// Convenience: seed register `xreg` (by x-number) to `val` in a slot-keyed
/// init map. Mirrors the generator's seeding; handy for hand-built programs.
pub fn seed_reg(init: &mut BTreeMap<u8, u64>, xreg: u8, val: u64) {
    let slot = nub_exec::regs::reg_slot_or_ff(xreg);
    if slot != 0xFF {
        init.insert(slot, val);
    }
}
