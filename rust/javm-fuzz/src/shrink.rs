//! Delta-debugging minimizer: shrink a failing program to a minimal reproducer.
//!
//! Generic over a `fails` predicate (typically "the Spike oracle, interpreter,
//! and recompiler don't all agree"), so this module stays portable — the engine
//! plumbing lives in the caller (`live.rs`).

use crate::Program;
use crate::encode;
use std::collections::BTreeMap;

fn rebuild(body: &[u32], regs: &BTreeMap<u8, u64>) -> Program {
    let mut code = body.to_vec();
    code.extend(encode::signature_epilogue(crate::SIG_BASE));
    Program {
        code,
        init_regs: regs.clone(),
        init_mem: None,
    }
}

/// Minimize `prog` while `fails` keeps returning `true`. The trailing signature
/// epilogue (length `sig_len`) is treated as fixed and regenerated each trial;
/// the body (everything before it) is shrunk by greedily removing instructions,
/// then unneeded seed registers are dropped. `fails` re-runs the comparison and
/// returns `true` iff the divergence still reproduces.
pub fn shrink(prog: &Program, sig_len: usize, mut fails: impl FnMut(&Program) -> bool) -> Program {
    let body_end = prog.code.len().saturating_sub(sig_len);
    let mut body: Vec<u32> = prog.code[..body_end].to_vec();
    let mut regs = prog.init_regs.clone();

    // 1. Greedily drop body instructions (repeat to a fixpoint).
    let mut changed = true;
    while changed {
        changed = false;
        let mut i = 0;
        while i < body.len() {
            let mut trial = body.clone();
            trial.remove(i);
            if fails(&rebuild(&trial, &regs)) {
                body = trial;
                changed = true;
            } else {
                i += 1;
            }
        }
    }

    // 2. Drop seed registers that aren't needed to reproduce.
    for slot in regs.keys().copied().collect::<Vec<_>>() {
        let mut trial = regs.clone();
        trial.remove(&slot);
        if fails(&rebuild(&body, &trial)) {
            regs = trial;
        }
    }

    rebuild(&body, &regs)
}
