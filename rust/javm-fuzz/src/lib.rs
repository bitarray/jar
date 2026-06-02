//! `javm-fuzz` — differential fuzzer for the JAVM PVM2 ISA.
//!
//! PVM2 is RV64E + standard extensions (M, C, Zba, Zbb, Zbs, Zicond) + the
//! custom Xjar/EEI. We have strong confidence the interpreter and the x86
//! recompiler agree on *legitimate* programs (the conformance suite), but no
//! systematic coverage of value-domain **edge cases** — INT_MIN/-1 division,
//! shift-amount masking, W-op sign-extension, `mulhsu`, Zbb corner inputs.
//! Those are exactly where a future ARM JIT lowering could silently diverge.
//!
//! This crate **generates** RV64E-subset programs ([`generate`]), runs each through
//! the interpreter and the recompiler ([`replay`], linux/x86_64 only), and —
//! offline — through a Sail/Spike oracle to mint static golden vectors. CI
//! replays committed vectors and compares to the baked-in gold; the oracle
//! never enters the build graph.
//!
//! ## State readout (interim): fold-into-x10
//!
//! Neither engine exposes the full final register file to the host today — only
//! `x10` (`return_value`), gas, and the exit reason escape. So a generated
//! program ends with a deterministic **fold epilogue**
//! ([`encode::fold_epilogue`]) that mixes its live registers (and any written
//! memory window) into `x10`. Comparing `x10` + exit + gas catches value and
//! trap divergences. The lossless, model-conformant DataCap readback is
//! deferred — see `~/docs/plans/javm-fuzz-state-readback.md`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub mod encode;
pub mod generate;
pub mod oracle;
pub mod shrink;

// The dual-engine replay needs the Hyperlight recompiler host stack, gated to
// linux/x86_64 (via `javm-bench`). The generator, encoders, and vector types
// above are all portable.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod replay;

/// Bump when [`encode::fold_epilogue`] or the encoders change in a way that
/// alters the golden `x10` of an unchanged program. Committed vectors record
/// the version they were minted against; the replay test refuses a mismatch.
pub const FOLD_VERSION: u32 = 1;

/// The frozen ISA string PVM2's compute core conforms to (RV64E run as the
/// RV64I superset for the oracle, never naming x16–x31).
pub const ISA: &str = "rv64imc_zba_zbb_zbs_zicond";

/// A generated test program: instruction words (body + fold, **no
/// terminator**), the initial register seed, and an optional initial RW memory
/// window. The replay harness appends the `ecalli 0` terminator.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Program {
    /// Instruction words, body followed by the fold epilogue. No terminator.
    pub code: Vec<u32>,
    /// Initial registers **by slot index 0..=12** (slot 0 = x1, 1 = x2,
    /// s ≥ 2 = x(s+3); so x10 = slot 7). Matches `EndpointDef.initial_regs`
    /// keying. x3/x4 (slots 13/14) are not seedable and start at 0 — the
    /// generator never names them.
    pub init_regs: BTreeMap<u8, u64>,
    /// Optional initial RW data window (the generator confines all loads/stores
    /// here, in-bounds and aligned, so every program is total on the oracle).
    pub init_mem: Option<MemWindow>,
}

/// A contiguous RW memory window backing the program's loads/stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemWindow {
    /// Guest virtual address of the window start (must be ≥ `DATA_BASE`).
    pub start: u32,
    /// Initial bytes; the window size is `bytes.len()`.
    pub bytes: Vec<u8>,
}

impl Program {
    /// The little-endian byte encoding of `code` (body + fold, no terminator).
    pub fn code_bytes(&self) -> Vec<u8> {
        encode::enc(&self.code)
    }
}

// ============================================================================
// Committed golden-vector schema (serde / JSON)
// ============================================================================

/// One committed vector file: provenance + a batch of vectors.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VectorFile {
    pub meta: VectorMeta,
    pub vectors: Vec<Vector>,
}

impl VectorFile {
    /// Parse a committed vector file from JSON.
    pub fn from_json(s: &str) -> serde_json::Result<Self> {
        serde_json::from_str(s)
    }
}

/// Provenance for a vector batch — enough to reproduce and to detect staleness.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VectorMeta {
    /// git SHA of the generator at mint time.
    pub gen_sha: String,
    /// PRNG seed that produced this batch.
    pub seed: u64,
    /// Which oracle minted the golds, e.g. `"spike-1.1.1-dev"` or
    /// `"interp-provisional"` (the interpreter as a stand-in before the
    /// external oracle is wired).
    pub oracle: String,
    /// Frozen ISA string ([`ISA`]).
    pub isa: String,
    /// [`FOLD_VERSION`] these golds were minted against.
    pub fold_version: u32,
}

/// One golden vector: program + initial state + the oracle's projected
/// post-state (`x10` fold + exit).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Vector {
    /// Stable, human-readable id, e.g. `"div_signed/intmin_div_neg1"`.
    pub id: String,
    #[serde(default)]
    pub init: Init,
    /// Hex of the program body + fold bytes (no terminator).
    pub code_hex: String,
    pub gold: Gold,
}

/// Initial state seed for a vector.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Init {
    /// Initial registers by slot index 0..=12 (see [`Program::init_regs`]).
    #[serde(default)]
    pub regs: BTreeMap<u8, u64>,
    /// Optional initial RW data window.
    #[serde(default)]
    pub mem: Option<MemInit>,
}

/// Serialized form of [`MemWindow`].
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemInit {
    pub start: u32,
    /// Hex of the initial window bytes; window size is the decoded length.
    pub bytes_hex: String,
}

/// The oracle-computed expected post-state projection.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Gold {
    /// Golden `return_value` — the fold result in x10.
    pub x10: u64,
    /// Golden exit reason (4 = HostCall(0) for every total program).
    pub exit: u32,
    #[serde(default)]
    pub exit_arg: u32,
}

impl Vector {
    /// Decode this vector's program (body + fold words) and initial state.
    pub fn to_program(&self) -> Program {
        let bytes = hex::decode(self.code_hex.trim_start_matches("0x"))
            .expect("vector code_hex is valid hex");
        let code: Vec<u32> = bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        let init_mem = self.init.mem.as_ref().map(|m| MemWindow {
            start: m.start,
            bytes: hex::decode(m.bytes_hex.trim_start_matches("0x"))
                .expect("vector mem bytes_hex is valid hex"),
        });
        Program {
            code,
            init_regs: self.init.regs.clone(),
            init_mem,
        }
    }

    /// Build a vector from a program + the oracle's golden projection.
    pub fn from_program(id: impl Into<String>, prog: &Program, gold: Gold) -> Self {
        let mem = prog.init_mem.as_ref().map(|m| MemInit {
            start: m.start,
            bytes_hex: hex::encode(&m.bytes),
        });
        Vector {
            id: id.into(),
            init: Init {
                regs: prog.init_regs.clone(),
                mem,
            },
            code_hex: hex::encode(prog.code_bytes()),
            gold,
        }
    }
}
