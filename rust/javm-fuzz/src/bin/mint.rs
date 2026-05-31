//! Offline golden-vector minting: generate RV64E-subset programs, run each on
//! the **Spike** oracle to obtain its golden `x10` (the fold signature), and
//! write a committed `VectorFile` JSON. **Never** run in CI — CI replays the
//! committed vectors (see `tests/vectors.rs`); only this tool needs Spike.
//!
//! This run mints the **division family** (`div`/`rem` and their unsigned/word
//! variants) over a curated set of corner `(dividend, divisor)` pairs: the
//! highest-value external-truth gate, validating the INT_MIN/-1 fix (B8),
//! divide-by-zero, and sign handling against the formal model. The set is kept
//! small so the committed replay test stays fast and under the recompiler's
//! sandbox-accumulation threshold; the full cross-product can be re-minted on
//! demand (`javm_fuzz::generate::OPERANDS`).
//!
//! Usage: `cargo run -p javm-fuzz --bin mint -- <out.json>`

use javm_fuzz::{FOLD_VERSION, Gold, ISA, Program, Vector, VectorFile, VectorMeta, encode, oracle};
use std::collections::BTreeMap;
use std::process::Command;

/// Curated `(dividend, divisor)` corners — covers i64 and i32 INT_MIN/-1
/// overflow, divide-by-zero, -1/-1, and a normal case.
const PAIRS: &[(u64, u64)] = &[
    (0x8000_0000_0000_0000, 0xFFFF_FFFF_FFFF_FFFF), // i64::MIN / -1  (64-bit overflow)
    (0xFFFF_FFFF_8000_0000, 0xFFFF_FFFF_FFFF_FFFF), // i32::MIN / -1  (W overflow)
    (0x7FFF_FFFF_FFFF_FFFF, 0x0000_0000_0000_0000), // i64::MAX / 0   (divide-by-zero)
    (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF), // -1 / -1
    (0x0000_0000_0000_0007, 0x0000_0000_0000_0003), // 7 / 3         (normal)
];

fn seed(init: &mut BTreeMap<u8, u64>, xreg: u8, val: u64) {
    let slot = javm_exec::regs::reg_slot_or_ff(xreg);
    if slot != 0xFF {
        init.insert(slot, val);
    }
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

fn main() {
    let out = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: mint <out.json>");
            std::process::exit(2);
        }
    };

    let mut vectors = Vec::new();
    for spec in encode::OPS {
        // Division family only: `div`, `divu`, `rem`, `remu`, and the W variants.
        if !(spec.name.starts_with("div") || spec.name.starts_with("rem")) {
            continue;
        }
        for &(a, b) in PAIRS {
            let mut init = BTreeMap::new();
            seed(&mut init, 8, a); // x8 = dividend
            seed(&mut init, 9, b); // x9 = divisor
            let mut code = vec![encode::encode_op(spec, 10, 8, 9, 0)];
            code.extend(encode::fold_epilogue(None));
            let prog = Program {
                code,
                init_regs: init,
                init_mem: None,
            };
            let x10 = oracle::spike_x10(&prog).unwrap_or_else(|e| {
                eprintln!("spike failed for {}: {e}", spec.name);
                std::process::exit(1);
            });
            let id = format!("{}/a={a:#018x}_b={b:#018x}", spec.name);
            // Every program is total → the engine halts cleanly on HostCall(0).
            vectors.push(Vector::from_program(
                id,
                &prog,
                Gold {
                    x10,
                    exit: 4,
                    exit_arg: 0,
                },
            ));
        }
    }

    let file = VectorFile {
        meta: VectorMeta {
            gen_sha: git_sha(),
            seed: 0, // deterministic enumeration, no PRNG
            oracle: "spike-1.1.1-dev".into(),
            isa: ISA.into(),
            fold_version: FOLD_VERSION,
        },
        vectors,
    };

    let json = serde_json::to_string_pretty(&file).expect("serialize vectors");
    std::fs::write(&out, json).expect("write vectors file");
    eprintln!("wrote {} vectors to {out}", file.vectors.len());
}
