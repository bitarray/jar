//! Shared harness for nub's benchmarks and end-to-end tests.
//!
//! Every program in `nub/programs` is cross-compiled and linked by this
//! crate's `build.rs`, then exposed here as a decoded
//! [`ProgramBlob`]. Both the criterion benches and the conformance
//! tests drive the same list, so a new program is one line away from
//! being both measured and checked.

use nub_program::ProgramBlob;

/// Gas ceiling for a benchmark run. `i64::MAX`, not `u64::MAX`: the
/// JIT's gas counter is an `i64` and it detects exhaustion by sign, so
/// a `u64::MAX` budget would present as already-negative.
pub const BENCH_GAS: u64 = i64::MAX as u64;

/// Clean-halt exit reason: `nub-rt`'s endpoint trampoline ends in a
/// bare `ecall`, which the linker rewrites to `custom-0 ecalli imm=0`
/// and the engine surfaces as `HostCall(0)`.
pub const EXIT_HOST_CALL: u32 = 4;

/// One benchmark program: its name, its linked blob, and the
/// `(return_value, gas_used)` its endpoint 0 must produce.
///
/// The pinned pair is the durable invariant across every refactor of
/// the linker or the program pipeline. It is deliberately duplicated
/// with jar's `javm-bench/tests/workloads.rs`: both engines and both
/// program formats must agree on the same numbers, so the duplication
/// is the cross-check.
pub struct Program {
    pub name: &'static str,
    pub blob: &'static [u8],
    pub expected_value: u64,
    pub expected_gas: u64,
}

impl Program {
    /// Decode the blob, panicking with the program's name on failure.
    pub fn decode(&self) -> ProgramBlob {
        ProgramBlob::from_bytes(self.blob)
            .unwrap_or_else(|e| panic!("[{}] decode ProgramBlob: {e}", self.name))
    }
}

/// Every program, in a stable order.
pub const PROGRAMS: &[Program] = &[
    Program {
        name: "prime_sieve",
        blob: include_bytes!(env!("PRIME_SIEVE_BLOB")),
        expected_value: 0x2578,
        expected_gas: 8_972_959,
    },
    Program {
        name: "ed25519",
        blob: include_bytes!(env!("ED25519_BLOB")),
        expected_value: 0x1,
        expected_gas: 2_360_953,
    },
    Program {
        name: "keccak",
        blob: include_bytes!(env!("KECCAK_BLOB")),
        expected_value: 0x39e5_0259,
        expected_gas: 100_934,
    },
    Program {
        name: "blake2b",
        blob: include_bytes!(env!("BLAKE2B_BLOB")),
        expected_value: 0xee1f_55f1,
        expected_gas: 62_396,
    },
    Program {
        name: "ecrecover",
        blob: include_bytes!(env!("ECRECOVER_BLOB")),
        expected_value: 0x1,
        expected_gas: 6_811_560,
    },
    Program {
        name: "goldilocks_mul",
        blob: include_bytes!(env!("GOLDILOCKS_MUL_BLOB")),
        expected_value: 0x2cf7_3e57,
        expected_gas: 2_400_166,
    },
    Program {
        name: "poseidon2_perm",
        blob: include_bytes!(env!("POSEIDON2_PERM_BLOB")),
        expected_value: 0x3ce3_3156,
        expected_gas: 14_561_457,
    },
    Program {
        name: "mini_verifier",
        blob: include_bytes!(env!("MINI_VERIFIER_BLOB")),
        expected_value: 0xf98f_c4ab,
        expected_gas: 5_879_175,
    },
    Program {
        name: "poly_eval",
        blob: include_bytes!(env!("POLY_EVAL_BLOB")),
        expected_value: 0x01da_34e2,
        expected_gas: 9_005_925,
    },
    Program {
        name: "fri_fold_tree",
        blob: include_bytes!(env!("FRI_FOLD_TREE_BLOB")),
        expected_value: 0x37e6_76f4,
        expected_gas: 6_194_372,
    },
];

/// Run endpoint 0 of `blob` on the interpreter, returning
/// `(return_value, gas_used)`.
///
/// Panics unless the program halts cleanly, so a benchmark can never
/// silently measure a trapping program.
pub fn run_interpreter(name: &str, blob: &ProgramBlob) -> (u64, u64) {
    let result = nub_arch_local::run_blob(blob, 0, [0; 4], BENCH_GAS)
        .unwrap_or_else(|e| panic!("[{name}] prepare: {e}"));
    assert_eq!(
        result.exit_reason, EXIT_HOST_CALL,
        "[{name}] did not halt cleanly: exit_reason={} exit_arg={}",
        result.exit_reason, result.exit_arg,
    );
    assert_eq!(result.exit_arg, 0, "[{name}] unexpected host call");
    (result.return_value, BENCH_GAS - result.gas_remaining)
}
