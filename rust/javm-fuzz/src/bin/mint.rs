//! Offline regression-vector minting: construct the minimal reproducer of each
//! known recompiler bug, run it on the **Spike** oracle for its golden `x10`,
//! and write `res/vectors/<name>.json`. Run after fixing a bug to capture a
//! permanent guard. **Never** in CI — CI replays the committed vectors
//! (`tests/vectors.rs`); only this tool needs Spike.
//!
//! (The other recompiler bug, INT_MIN/-1 div = B8, was captured live by
//! `live.rs` as `intmin_div.json`; these are the two whose reproducers are
//! known, parked here so a re-mint is deterministic.)
//!
//! Usage: `cargo run -p javm-fuzz --bin mint -- res/vectors`

use javm_fuzz::{FOLD_VERSION, Gold, ISA, Program, Vector, VectorFile, VectorMeta, encode, oracle};
use std::collections::BTreeMap;
use std::process::Command;

fn spec(name: &str) -> &'static encode::OpSpec {
    encode::OPS
        .iter()
        .find(|o| o.name == name)
        .unwrap_or_else(|| panic!("no op named {name}"))
}

fn seed(init: &mut BTreeMap<u8, u64>, xreg: u8, val: u64) {
    init.insert(javm_exec::regs::reg_slot_or_ff(xreg), val);
}

fn git_sha() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

/// (file stem, vector id, program). Each is the minimal reproducer of a bug.
fn repros() -> Vec<(&'static str, &'static str, Program)> {
    let mut out = Vec::new();

    // B9 — `sllw` high-bits divergence. The destination x15 maps to the host
    // RCX (= the CL shift-count register), and `emit_shift_by_reg32`'s
    // dst==RCX path read the operand *after* clobbering RCX, shifting the
    // count instead of the value. rs1=x8=0x12345678, shift x9=4 → the buggy
    // and correct results differ sharply (0x40 vs 0x23456780). (rs1/rs2 are
    // x8/x9, seedable registers — x10–x13 are the arg registers and start 0.)
    {
        let mut init = BTreeMap::new();
        seed(&mut init, 8, 0x1234_5678); // rs1
        seed(&mut init, 9, 4); // rs2 (shift amount)
        let mut code = vec![encode::encode_op(spec("sllw"), 15, 8, 9, 0)];
        code.extend(encode::fold_epilogue(None));
        out.push((
            "sllw_x15",
            "live/sllw_dst_rcx",
            Program {
                code,
                init_regs: init,
                init_mem: None,
            },
        ));
    }

    // B12 — the 32-bit signed div/rem zero-divisor guard tested the *full*
    // 64-bit divisor register (`test r64,r64`), but `idivl`/`divl` divide by
    // the low 32 bits only. A divisor like 0x8000_0000_0000_0000 (low half
    // zero, high half set) slipped past the guard and #DE-faulted the
    // recompiler. RISC-V treats low32==0 as division by zero: `divw` → -1,
    // `remw` → the (sign-extended low-32) dividend. rs1=x8, rs2=x9 are seedable.
    {
        let mut init = BTreeMap::new();
        seed(&mut init, 8, 100); // dividend
        seed(&mut init, 9, 0x8000_0000_0000_0000); // divisor: low32 == 0, high set
        let mut code = vec![encode::encode_op(spec("divw"), 14, 8, 9, 0)];
        code.extend(encode::fold_epilogue(None));
        out.push((
            "divw_low32_zero",
            "live/divw_low32_zero_divisor",
            Program {
                code,
                init_regs: init,
                init_mem: None,
            },
        ));
    }
    {
        let mut init = BTreeMap::new();
        seed(&mut init, 8, 100); // dividend
        seed(&mut init, 9, 0x8000_0000_0000_0000); // divisor: low32 == 0, high set
        let mut code = vec![encode::encode_op(spec("remw"), 15, 8, 9, 0)];
        code.extend(encode::fold_epilogue(None));
        out.push((
            "remw_low32_zero",
            "live/remw_low32_zero_divisor",
            Program {
                code,
                init_regs: init,
                init_mem: None,
            },
        ));
    }

    // B10 — `orc.b` was an unimplemented panic stub in the recompiler. A value
    // with a mix of zero, nonzero, and high-bit-only bytes exercises the SWAR
    // implementation (each byte → 0xFF iff nonzero).
    {
        let mut init = BTreeMap::new();
        seed(&mut init, 8, 0xFF00_FF00_0012_8000); // rs1 (mixed bytes)
        let mut code = vec![encode::encode_op(spec("orc.b"), 14, 8, 0, 0)];
        code.extend(encode::fold_epilogue(None));
        out.push((
            "orcb",
            "live/orcb_swar",
            Program {
                code,
                init_regs: init,
                init_mem: None,
            },
        ));
    }

    out
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: mint <res/vectors dir>");
        std::process::exit(2);
    });
    let sha = git_sha();
    for (stem, id, prog) in repros() {
        let x10 = oracle::spike_x10(&prog).unwrap_or_else(|e| {
            eprintln!("spike failed for {stem}: {e}");
            std::process::exit(1);
        });
        let file = VectorFile {
            meta: VectorMeta {
                gen_sha: sha.clone(),
                seed: 0,
                oracle: "spike-1.1.1-dev".into(),
                isa: ISA.into(),
                fold_version: FOLD_VERSION,
            },
            vectors: vec![Vector::from_program(
                id,
                &prog,
                Gold {
                    x10,
                    exit: 4,
                    exit_arg: 0,
                },
            )],
        };
        let path = format!("{dir}/{stem}.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&file).expect("serialize"),
        )
        .expect("write vector");
        eprintln!("wrote {path} (gold x10={x10:#018x})");
    }
}
