//! Dual-engine replay: run a [`Program`] through the interpreter and the x86
//! recompiler and compare. Gated to linux/x86_64 (the recompiler needs the
//! Hyperlight host stack, so the whole `javm-bench` crate is gated to it).
//!
//! Both engines are driven through the *same* `javm-bench` `BuiltCaps` →
//! `invoke_cached` path, so they receive byte-identical caps/initial-state —
//! any divergence is a real engine disagreement, never a setup skew.

use crate::{Program, encode};
use javm_bench::{BuiltCaps, RawRun, run_interpreter_raw, run_recompiler_raw};
use javm_cap::image::{EndpointDef, Image};
use std::collections::BTreeMap;

/// Build the `Image` for a program: its code (body + fold) plus the appended
/// `ecalli 0` terminator, entered at pc 0 with the program's initial register
/// seed. (v1 programs declare no memory window.)
pub fn image_for(prog: &Program) -> Image {
    let mut code = prog.code_bytes();
    code.extend_from_slice(&encode::enc(&[encode::HALT]));

    let mut img = Image::empty();
    img.code = code;
    img.endpoints.insert(
        0,
        EndpointDef {
            entry_pc: 0,
            arg_registers: 0,
            arg_cnode_size: 0,
            initial_regs: prog.init_regs.clone(),
        },
    );
    img
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
    /// True iff the engines disagree on the exit reason, the returned `x10`
    /// fold, or gas — any of which is a consensus divergence.
    pub fn diverges(&self) -> bool {
        self.interp.exit_reason != self.recomp.exit_reason
            || self.interp.return_value != self.recomp.return_value
            || self.interp.gas_used != self.recomp.gas_used
    }

    /// One-line human description of the disagreement (for triage logs).
    pub fn describe(&self) -> String {
        format!(
            "interp{{exit={} x10={:#018x} gas={}}} vs recomp{{exit={} x10={:#018x} gas={}}}",
            self.interp.exit_reason,
            self.interp.return_value,
            self.interp.gas_used,
            self.recomp.exit_reason,
            self.recomp.return_value,
            self.recomp.gas_used,
        )
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

/// Rebuild the recompiler's singleton Hyperlight sandbox.
///
/// The sandbox accumulates state across **distinct** Instance-cap publishes and
/// starts to misbehave after ~13 (the bench harness documents this and resets
/// between workloads). A fuzz sweep publishes a fresh cap per program, so it
/// MUST rebuild periodically — otherwise late programs return corrupt results
/// (spurious panics / host heap corruption), not real divergences.
pub fn reset_sandbox() {
    javm_bench::reset_nub_hyperlight();
}

/// Run a batch through [`diff`], rebuilding the sandbox every `reset_every`
/// programs to stay under the accumulation threshold. Returns `(index, Diff)`
/// for each diverging program. `reset_every` should be ≤ ~10.
pub fn diff_batch(progs: &[Program], reset_every: usize) -> Vec<(usize, Diff)> {
    let reset_every = reset_every.max(1);
    let mut diverged = Vec::new();
    for (i, prog) in progs.iter().enumerate() {
        if i % reset_every == 0 {
            reset_sandbox();
        }
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
    let slot = javm_exec::regs::reg_slot_or_ff(xreg);
    if slot != 0xFF {
        init.insert(slot, val);
    }
}
